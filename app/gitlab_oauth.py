"""
Refreshing a gitlab.com OAuth2 access token.

"Continue with GitLab" only ever authenticates against gitlab.com —
`SOCIALACCOUNT_PROVIDERS['gitlab']['GITLAB_URL']` is fixed, and this product
offers no OAuth login for a self-hosted instance, only a personal access
token (`GitlabProfile.gitlab_url` for an OAuth-derived connection is always
`https://gitlab.com`, set by `app.signals._link_gitlab`). So this module
never needs to know which instance to talk to, unlike `repo_client.py` or
`gitlab_writer.py`, which do.

GitLab's OAuth2 provider always expires the access token from the standard
Authorization Code grant (currently two hours) and issues a refresh token
alongside it — there is no way to opt out of this from the application side.
`GitlabProfile.current_token` calls `refresh()` here when the stored token is
at or past that expiry, rather than trusting a token minted at connect time
the way the pre-fix GitHub App code did (see `GithubProfile.current_token`
and docs/CHANGELOG_INTERNAL.md for that history).
"""
import logging
from datetime import timedelta

import requests
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

TOKEN_URL = 'https://gitlab.com/oauth/token'
TIMEOUT = 15


class GitlabOAuthError(Exception):
    """Refreshing the token failed for a reason worth showing the user."""


def refresh(profile) -> str:
    """
    Exchange the stored refresh token for a fresh access token, save both,
    and return the new access token.

    GitLab rotates the refresh token on every use — the one this call
    started with stops working the moment it succeeds, so what gets stored
    is the new one the response carries, not the one that was spent.
    """
    resp = requests.post(TOKEN_URL, data={
        'grant_type': 'refresh_token',
        'refresh_token': profile.refresh_token,
        'client_id': settings.GITLAB_APP_ID,
        'client_secret': settings.GITLAB_APP_SECRET,
    }, timeout=TIMEOUT)
    if resp.status_code != 200:
        logger.warning('GitLab OAuth refresh failed for user_id=%s: HTTP %s',
                       profile.user_id, resp.status_code)
        raise GitlabOAuthError(
            f'Could not refresh the GitLab connection ({resp.status_code}). '
            'Reconnect on the profile page.'
        )

    data = resp.json()
    profile.access_token = data['access_token']
    # A response missing a fresh refresh_token would be unusual, but keeping
    # the previous one is safer than discarding a still-valid credential.
    profile.refresh_token = data.get('refresh_token') or profile.refresh_token
    expires_in = data.get('expires_in')
    profile.token_expires_at = (
        timezone.now() + timedelta(seconds=int(expires_in)) if expires_in else None
    )
    profile.save(update_fields=['access_token', 'refresh_token', 'token_expires_at'])
    logger.info('GitLab OAuth token refreshed for user_id=%s', profile.user_id)
    return profile.access_token
