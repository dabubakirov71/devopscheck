"""
GitHub App installation flow.

The Personal Access Token flow is the most expensive step in the funnel: leave
the product, create a token, pick scopes, come back, paste. A GitHub App is one
click, covers a whole organisation, issues short-lived credentials, and carries
the permission needed to comment on pull requests.

Set up in .env after creating the App on GitHub:
    GITHUB_APP_ID, GITHUB_APP_SLUG, GITHUB_APP_PRIVATE_KEY, GITHUB_APP_WEBHOOK_SECRET

Required App permissions: Contents (read), Metadata (read), Pull requests
(write, for PR comments and fix pull requests), Administration (read, for
branch protection). Subscribe to the Push, Pull request, Installation and
Installation repositories events, delivered to one URL configured on the App
itself — GitHub → Settings → Developer settings → the App → Webhook →
Webhook URL: `{BASE_URL}/webhook/github/app/`, secret = `GITHUB_APP_WEBHOOK_SECRET`.
See `app.views.github_app_webhook`, which every installation's events arrive
at without the customer configuring anything on their own repository (the
one-click advantage over the per-user webhook a PAT connection still needs —
`app.views.github_webhook_auto`).
"""
import logging
import time

import jwt
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

API = 'https://api.github.com'
TIMEOUT = 15


def is_configured() -> bool:
    return bool(settings.GITHUB_APP_ID and settings.GITHUB_APP_PRIVATE_KEY)


def install_url(state: str = '') -> str:
    """Where to send someone to install the App."""
    slug = settings.GITHUB_APP_SLUG
    if not slug:
        return ''
    url = f'https://github.com/apps/{slug}/installations/new'
    return f'{url}?state={state}' if state else url


def app_jwt() -> str:
    """Short-lived JWT signed with the App's private key, used to mint tokens."""
    now = int(time.time())
    payload = {'iat': now - 60, 'exp': now + 540, 'iss': str(settings.GITHUB_APP_ID)}
    return jwt.encode(payload, settings.GITHUB_APP_PRIVATE_KEY, algorithm='RS256')


def installation_token(installation_id: int) -> tuple[str, str]:
    """
    (token, expires_at) for an installation. Tokens last one hour, so they are
    minted on demand rather than stored long-term.
    """
    resp = requests.post(
        f'{API}/app/installations/{installation_id}/access_tokens',
        headers={
            'Authorization': f'Bearer {app_jwt()}',
            'Accept': 'application/vnd.github.v3+json',
        },
        timeout=TIMEOUT,
    )
    if resp.status_code != 201:
        raise GitHubAppError(f'GitHub returned {resp.status_code} minting an installation token')
    data = resp.json()
    return data['token'], data.get('expires_at', '')


def installation_account(installation_id: int) -> dict:
    resp = requests.get(
        f'{API}/app/installations/{installation_id}',
        headers={
            'Authorization': f'Bearer {app_jwt()}',
            'Accept': 'application/vnd.github.v3+json',
        },
        timeout=TIMEOUT,
    )
    if resp.status_code != 200:
        raise GitHubAppError(f'GitHub returned {resp.status_code} reading the installation')
    return resp.json().get('account', {}) or {}


def list_repositories(installation_id: int) -> list[dict]:
    token, _expires = installation_token(installation_id)
    repos, page = [], 1
    while page <= 10:
        resp = requests.get(
            f'{API}/installation/repositories',
            headers={'Authorization': f'token {token}', 'Accept': 'application/vnd.github.v3+json'},
            params={'per_page': 100, 'page': page},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            break
        batch = resp.json().get('repositories', [])
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return repos


class GitHubAppError(Exception):
    """The GitHub App API call failed."""
