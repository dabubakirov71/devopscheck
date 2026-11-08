"""
Write operations against the GitHub API.

The audit produces ready-to-use files; this turns one of them into a pull
request on a fresh branch. Nothing is ever committed to the default branch —
the change always arrives as a reviewable PR.

Telling somebody their Dockerfile runs as root is advice. Opening the pull
request that fixes it is the product, and it is the one thing here that the
free scanners do not do.
"""
import base64
import logging
import re
import time

import requests
from django.utils.translation import gettext_lazy

logger = logging.getLogger(__name__)

API = 'https://api.github.com'
TIMEOUT = 20

# What marks a badge as ours, in a README that may carry a dozen of them. The
# shields.io label is stable across score changes and colour changes, so it
# finds the badge this product added on a previous run — which is what keeps a
# second click from stacking a second badge.
BADGE_MARKER = 'DevOps_Score'


class GitHubWriteError(Exception):
    """
    A write to GitHub failed for a reason worth showing the user.

    `reconnect` says whether connecting the account again could fix it. The
    page only offers "Reconnect" when it could — an empty repository answered
    with a reconnect link sends people to fix a token that was never broken.
    """

    def __init__(self, message, reconnect=False):
        super().__init__(message)
        self.reconnect = reconnect


EMPTY_REPOSITORY = gettext_lazy(
    'This repository is empty — it has no commits yet, so there is no branch to open a '
    'pull request against. Push a first commit, then try again.')


class NothingToChange(Exception):
    """The repository already says what the pull request would have said."""


def _headers(token):
    return {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }


def _slug(text: str) -> str:
    slug = re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')
    return slug[:40] or 'fix'


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# ── The shared machinery ──────────────────────────────────────────────────────
#
# Both pull requests below do the same four things: check we may push, cut a
# branch off the default, commit one file to it, and open the PR. Only the file
# and the wording differ.

class _Repo:
    """A thin session against one repository, holding what every step needs."""

    def __init__(self, token, repo_full_name):
        self.headers = _headers(token)
        self.name = repo_full_name
        self.default_branch = 'main'

    def get(self, path, **kw):
        return requests.get(f'{API}{path}', headers=self.headers, timeout=TIMEOUT, **kw)

    def post(self, path, payload):
        return requests.post(f'{API}{path}', headers=self.headers, json=payload, timeout=TIMEOUT)

    def put(self, path, payload):
        return requests.put(f'{API}{path}', headers=self.headers, json=payload, timeout=TIMEOUT)

    def require_push_access(self):
        resp = self.get(f'/repos/{self.name}')
        # Each of these is something the reader can act on, and a bare status
        # code is not. "GitHub returned 401" was the whole message, which told
        # a customer nothing about a token they could simply replace.
        if resp.status_code == 401:
            raise GitHubWriteError(
                'GitHub rejected the connected token (401). It has expired or been revoked — '
                'create a new one and reconnect on the profile page.',
                reconnect=True,
            )
        if resp.status_code == 403:
            raise GitHubWriteError(
                'GitHub refused the request (403). The token is valid but not allowed here — '
                'it is missing the "repo" scope, or an organisation has not approved it. '
                'A fine-grained token needs Contents: write and Pull requests: write.',
                reconnect=True,
            )
        if resp.status_code == 404:
            raise GitHubWriteError(
                'Repository not found, or the token cannot see it. A fine-grained token has to '
                'list this repository explicitly, and a classic token needs the "repo" scope to '
                'see private ones.',
                reconnect=True,
            )
        if resp.status_code != 200:
            raise GitHubWriteError(f'GitHub returned {resp.status_code} for the repository.')
        repo = resp.json()
        if not repo.get('permissions', {}).get('push', False):
            raise GitHubWriteError(
                'The connected token can read this repository but not write to it, so it cannot '
                'open a pull request. Reconnect with a token that has the "repo" scope, or a '
                'fine-grained token with Contents: write and Pull requests: write.',
                reconnect=True,
            )
        self.default_branch = repo.get('default_branch') or 'main'
        return repo

    def branch_from_default(self, prefix: str) -> str:
        ref = self.get(f'/repos/{self.name}/git/ref/heads/{self.default_branch}')
        if ref.status_code == 409:
            # GitHub's answer for a repository with no commits at all.
            raise GitHubWriteError(str(EMPTY_REPOSITORY))
        if ref.status_code != 200:
            logger.warning('Reading %s@%s failed: HTTP %s', self.name, self.default_branch,
                           ref.status_code)
            raise GitHubWriteError(f'Could not read the {self.default_branch} branch '
                                   f'(GitHub returned {ref.status_code}).')
        # The timestamp keeps a second attempt from colliding with the branch
        # left behind by the first, which would fail with a bare 422.
        branch = f'devopscheck/{_slug(prefix)}-{int(time.time())}'
        created = self.post(f'/repos/{self.name}/git/refs', {
            'ref': f'refs/heads/{branch}',
            'sha': ref.json()['object']['sha'],
        })
        if created.status_code not in (200, 201):
            raise GitHubWriteError(f'Could not create the branch ({created.status_code}).')
        return branch

    def read_file(self, path: str):
        """`(text, blob_sha)` for a file on the default branch, or `(None, None)`."""
        resp = self.get(f'/repos/{self.name}/contents/{path}',
                        params={'ref': self.default_branch})
        if resp.status_code != 200:
            return None, None
        data = resp.json()
        if not isinstance(data, dict) or data.get('encoding') != 'base64':
            return None, None
        try:
            return base64.b64decode(data['content']).decode('utf-8'), data.get('sha')
        except (KeyError, ValueError, UnicodeDecodeError):
            return None, None

    def commit_file(self, branch: str, path: str, content: str, message: str, sha=None):
        payload = {'message': message, 'content': _b64(content), 'branch': branch}
        if sha is None:
            # An existing file needs its blob SHA, or GitHub refuses the write.
            _, sha = self.read_file(path)
        if sha:
            payload['sha'] = sha
        resp = self.put(f'/repos/{self.name}/contents/{path}', payload)
        if resp.status_code not in (200, 201):
            raise GitHubWriteError(f'Could not commit {path} ({resp.status_code}).')

    def open_pull_request(self, branch: str, title: str, body: str) -> str:
        pr = self.post(f'/repos/{self.name}/pulls', {
            'title': title,
            'head': branch,
            'base': self.default_branch,
            'body': body,
            'maintainer_can_modify': True,
        })
        if pr.status_code not in (200, 201):
            detail = ''
            try:
                errors = pr.json().get('errors') or []
                detail = '; '.join(e.get('message', '') for e in errors if e.get('message'))
            except Exception:
                pass
            raise GitHubWriteError(
                f'Could not open the pull request ({pr.status_code}). {detail}'.strip())
        return pr.json().get('html_url', '')


# ── A fix, as a pull request ──────────────────────────────────────────────────

def open_fix_pull_request(token, repo_full_name, filename, content,
                          check_name, recommendation='', audit_url=''):
    """
    Create a branch, add the file, and open a pull request. Returns the PR URL.

    Raises GitHubWriteError with a message meant for the user — most failures
    here are permission problems they can fix themselves.
    """
    return open_fix_pull_request_details(token, repo_full_name, filename, content,
                                         check_name, recommendation, audit_url)['url']


def open_fix_pull_request_details(token, repo_full_name, filename, content,
                                  check_name, recommendation='', audit_url='') -> dict:
    """Same as open_fix_pull_request, returning {url, number, branch} for the fix agent."""
    repo = _Repo(token, repo_full_name)
    repo.require_push_access()
    branch = repo.branch_from_default(check_name)
    repo.commit_file(branch, filename, content,
                     f'chore: {check_name}\n\nGenerated by DevOpsCheck.')

    body_lines = [
        f'Fixes the failed check **{check_name}** found by DevOpsCheck.',
        '',
        f'Adds `{filename}`.',
    ]
    if recommendation:
        body_lines += ['', '**Why this matters**', '', recommendation.strip()]
    if audit_url:
        body_lines += ['', f'[Full audit report]({audit_url})']

    url = repo.open_pull_request(branch, f'chore: {check_name}', '\n'.join(body_lines))
    logger.info('Opened fix PR for %s: %s', repo_full_name, url)
    number = 0
    m = re.search(r'/pull/(\d+)', url or '')
    if m:
        number = int(m.group(1))
    return {'url': url, 'number': number, 'branch': branch}


# ── The badge, as a pull request ──────────────────────────────────────────────

def insert_badge(readme: str, badge: str) -> str:
    """
    Put `badge` into `readme`, replacing any badge this product added before.

    Raises `NothingToChange` when the README already carries exactly this badge,
    which is what stops a second click stacking a second badge — a pull request
    that adds a duplicate is worse than no pull request at all.

    Placement follows what a README already does: a badge goes under the title,
    and onto the end of an existing badge row if the file has one, because that
    is where a reader looks for it.
    """
    if badge in readme:
        raise NothingToChange('The badge is already in the README, unchanged.')

    lines = readme.split('\n')

    # Already ours? Rewrite it where it stands and leave the rest of the line
    # alone — the badge is often one of several on a shared row.
    for i, line in enumerate(lines):
        if BADGE_MARKER not in line:
            continue
        replaced = re.sub(
            r'\[?!\[[^\]]*\]\([^)]*' + re.escape(BADGE_MARKER) + r'[^)]*\)\]?(\([^)]*\))?',
            badge.replace('\\', '\\\\'), line, count=1,
        )
        if replaced == line:
            # The marker is there in some shape this cannot safely rewrite.
            # Leaving the README alone beats adding a second badge beside it.
            raise NothingToChange('A DevOpsCheck badge is already in the README.')
        new_lines = list(lines)
        new_lines[i] = replaced
        return '\n'.join(new_lines)

    # A row of badges directly under the title is the convention; join it.
    heading = next((i for i, l in enumerate(lines) if l.lstrip().startswith('# ')), None)
    if heading is not None:
        probe = heading + 1
        while probe < len(lines) and not lines[probe].strip():
            probe += 1
        if probe < len(lines) and _is_badge_row(lines[probe]):
            new_lines = list(lines)
            new_lines[probe] = lines[probe].rstrip() + ' ' + badge
            return '\n'.join(new_lines)
        new_lines = lines[:heading + 1] + ['', badge] + lines[heading + 1:]
        return '\n'.join(new_lines)

    # No title to sit under. The top of the file is the only honest default.
    return badge + '\n\n' + readme


def _is_badge_row(line: str) -> bool:
    """A line that is nothing but image links — the badge row READMEs open with."""
    stripped = line.strip()
    if not stripped:
        return False
    without_badges = re.sub(r'\[?!\[[^\]]*\]\([^)]*\)\]?(\([^)]*\))?', '', stripped)
    return not without_badges.strip() and '![' in stripped


README_CANDIDATES = ('README.md', 'readme.md', 'Readme.md', 'README.markdown')


def open_badge_pull_request(token, repo_full_name, badge, report_url=''):
    """
    Add the score badge to the README and open the pull request.

    A badge in a README is a backlink, an impression on every visitor to that
    repository, and an entry point for the next reader — the loop shields.io,
    Codecov and Snyk all grew on. Offering it as text to copy by hand is where
    that loop stopped.
    """
    repo = _Repo(token, repo_full_name)
    repo.require_push_access()

    path = content = sha = None
    for candidate in README_CANDIDATES:
        text, blob = repo.read_file(candidate)
        if text is not None:
            path, content, sha = candidate, text, blob
            break
    if content is None:
        raise GitHubWriteError(
            'This repository has no README.md to add the badge to. '
            'Add one first and the badge can go in it.'
        )

    updated = insert_badge(content, badge)   # raises NothingToChange

    branch = repo.branch_from_default('score-badge')
    repo.commit_file(branch, path, updated,
                     'docs: add the DevOpsCheck score badge', sha=sha)

    body = '\n'.join([
        'Adds the DevOpsCheck score badge to the README.',
        '',
        'The badge reads the current score and updates itself — there is nothing',
        'to regenerate when the score changes.',
        '',
        f'[See the full report]({report_url})' if report_url else '',
    ]).strip()

    url = repo.open_pull_request(branch, 'docs: add the DevOpsCheck score badge', body)
    logger.info('Opened badge PR for %s: %s', repo_full_name, url)
    return url
