"""
Write operations against the GitLab API.

The GitHub half of the product opens a fix as a pull request; a GitLab-
connected repository could generate the exact same fix and then hit "Pull
requests are supported for GitHub repositories" — a real wall, not a
hypothetical one, since the fix button on the report page has never checked
`audit.source` before letting someone click it. This is that missing half,
for the one thing GitLab audits could generate but never apply: a fix, as a
merge request.

GitLab's write API is shaped differently enough from GitHub's that this is
its own implementation rather than a port of `github_writer.py` — a merge
request's source commit is created through the Commits API's `actions` list
(one call describes every file change) rather than one `PUT` per file, and
"can I push here" comes back as a `permissions` object on the project itself
instead of a `push` boolean nested under the read.
"""
import base64
import logging
import re
import time
import urllib.parse

import requests
from django.utils.translation import gettext_lazy

from app.dns_utils import custom_dns_server

logger = logging.getLogger(__name__)

TIMEOUT = 20

# Developer (30) is the lowest GitLab role that can push a branch and open a
# merge request against one it does not own outright. Below it, GitLab's own
# API calls would already refuse the write — checked here first so the
# customer gets an explanation in our terms instead of a bare 403 partway
# through a five-call sequence.
MIN_ACCESS_LEVEL = 30


class GitlabWriteError(Exception):
    """
    A write to GitLab failed for a reason worth showing the user.

    `reconnect` says whether connecting the account again could fix it — see
    `github_writer.GitHubWriteError`.
    """

    def __init__(self, message, reconnect=False):
        super().__init__(message)
        self.reconnect = reconnect


EMPTY_REPOSITORY = gettext_lazy(
    'This project is empty — it has no commits yet, so there is no branch to open a '
    'merge request against. Push a first commit, then try again.')


class GitlabScopeError(GitlabWriteError):
    """The token is valid and can read, but was not granted the `api` scope.

    Separate from a plain `GitlabWriteError` because the fix differs by how the
    token was obtained: a personal access token has to be recreated by hand,
    while an OAuth ("Continue with GitLab") connection can be sent back
    through GitLab's consent screen with `api` added — `views.fix_open_pr`
    tells the two apart and offers that re-authorisation instead of a dead end.
    """


# The only GitLab scope that can create a branch, commit through the Commits
# API and open a merge request. `write_repository` sounds right but covers
# git-over-HTTP pushes only, not the REST calls this module makes.
WRITE_SCOPE = 'api'


class NothingToChange(Exception):
    """The repository already says what the merge request would have said."""


class _Project:
    """A thin session against one GitLab project, holding what every step needs."""

    def __init__(self, token, project_id, gitlab_url='https://gitlab.com',
                verify_ssl=True, custom_dns=''):
        self.token = token
        self.project_id = project_id
        self.gitlab_url = gitlab_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.custom_dns = custom_dns
        self.base = f'{self.gitlab_url}/api/v4/projects/{project_id}'
        self.default_branch = 'main'

    def _headers(self):
        # Bearer, not PRIVATE-TOKEN: GitLab only looks up a PRIVATE-TOKEN value
        # as a personal/project/group access token, so an OAuth token sent that
        # way is a 401. Bearer is accepted for both kinds.
        return {'Authorization': f'Bearer {self.token}', 'Accept': 'application/json'}

    def _request(self, method, path, **kw):
        with custom_dns_server(self.custom_dns):
            return requests.request(
                method, f'{self.base}{path}', headers=self._headers(),
                timeout=TIMEOUT, verify=self.verify_ssl, **kw,
            )

    def get(self, path, **kw):
        return self._request('GET', path, **kw)

    def post(self, path, payload):
        return self._request('POST', path, json=payload)

    def require_push_access(self):
        resp = self.get('')
        if resp.status_code == 401:
            raise GitlabWriteError(
                'GitLab rejected the connected token (401). It has expired or been revoked — '
                'create a new one with the api scope and reconnect on the profile page.',
                reconnect=True,
            )
        if resp.status_code == 404:
            raise GitlabWriteError(
                'Project not found, or the token cannot see it. A project token has to be '
                'granted access to this specific project.',
                reconnect=True,
            )
        if resp.status_code != 200:
            raise GitlabWriteError(f'GitLab returned {resp.status_code} for the project.')
        project = resp.json()
        if project.get('empty_repo'):
            raise GitlabWriteError(str(EMPTY_REPOSITORY))
        self.default_branch = project.get('default_branch') or 'main'

        access_levels = [
            (project.get('permissions', {}).get('project_access') or {}).get('access_level') or 0,
            (project.get('permissions', {}).get('group_access') or {}).get('access_level') or 0,
        ]
        if max(access_levels) < MIN_ACCESS_LEVEL:
            raise GitlabWriteError(
                'The connected token can read this project but not write to it, so it cannot '
                'open a merge request. Reconnect with a token from an account that has at least '
                'the Developer role on this project, and the api scope.',
                reconnect=True,
            )
        return project

    def token_scopes(self):
        """
        The scopes this token was granted, or None if GitLab would not say.

        An OAuth token answers at `/oauth/token/info`; a personal, project or
        group access token answers at `/personal_access_tokens/self` instead
        (each endpoint refuses the other kind). None means "unknown", not
        "none" — the caller then lets the write itself be the judge, exactly
        as it did before this check existed, rather than blocking on a guess.
        """
        with custom_dns_server(self.custom_dns):
            try:
                info = requests.request(
                    'GET', f'{self.gitlab_url}/oauth/token/info', headers=self._headers(),
                    timeout=TIMEOUT, verify=self.verify_ssl,
                )
                if info.status_code == 200:
                    body = info.json()
                    return list(body.get('scope') or body.get('scopes') or [])
                pat = requests.request(
                    'GET', f'{self.gitlab_url}/api/v4/personal_access_tokens/self',
                    headers=self._headers(), timeout=TIMEOUT, verify=self.verify_ssl,
                )
                if pat.status_code == 200:
                    return list(pat.json().get('scopes') or [])
            except (requests.RequestException, ValueError):
                logger.warning('GitLab token scope lookup failed for project %s',
                               self.project_id, exc_info=True)
        return None

    def require_write_scope(self):
        scopes = self.token_scopes()
        if scopes is not None and WRITE_SCOPE not in scopes:
            raise GitlabScopeError(
                'The connected GitLab token can read repositories but was not granted the '
                'api scope, which opening a merge request needs.'
            )

    def branch_from_default(self, prefix: str) -> str:
        ref = self.get(f'/repository/branches/{urllib.parse.quote(self.default_branch, safe="")}')
        if ref.status_code != 200:
            logger.warning('Reading project %s@%s failed: HTTP %s', self.project_id,
                           self.default_branch, ref.status_code)
            raise GitlabWriteError(f'Could not read the {self.default_branch} branch '
                                   f'(GitLab returned {ref.status_code}).')
        sha = ref.json().get('commit', {}).get('id')
        # The timestamp keeps a second attempt from colliding with the branch
        # left behind by the first, which would fail with a bare 400.
        branch = f'devopscheck/{_slug(prefix)}-{int(time.time())}'
        created = self.post('/repository/branches', {'branch': branch, 'ref': sha})
        if created.status_code not in (200, 201):
            raise GitlabWriteError(f'Could not create the branch ({created.status_code}).')
        return branch

    def file_exists(self, path: str, ref: str) -> bool:
        resp = self.get(f'/repository/files/{_encode_path(path)}', params={'ref': ref})
        return resp.status_code == 200

    def read_file(self, path: str, ref: str):
        """Text content of a file on `ref`, or None if it does not exist there."""
        resp = self.get(f'/repository/files/{_encode_path(path)}', params={'ref': ref})
        if resp.status_code != 200:
            return None
        data = resp.json()
        try:
            return base64.b64decode(data['content']).decode('utf-8')
        except (KeyError, ValueError, UnicodeDecodeError):
            return None

    def commit_file(self, branch: str, path: str, content: str, message: str):
        # One call describes the whole commit — GitLab's Commits API takes a
        # list of file actions rather than one write per file, and needs to
        # be told up front whether this path is new or already exists on the
        # branch it is about to land on.
        action = 'update' if self.file_exists(path, branch) else 'create'
        resp = self.post('/repository/commits', {
            'branch': branch,
            'commit_message': message,
            'actions': [{'action': action, 'file_path': path, 'content': content}],
        })
        if resp.status_code not in (200, 201):
            raise GitlabWriteError(f'Could not commit {path} ({resp.status_code}).')

    def open_merge_request(self, branch: str, title: str, description: str) -> str:
        resp = self.post('/merge_requests', {
            'source_branch': branch,
            'target_branch': self.default_branch,
            'title': title,
            'description': description,
        })
        if resp.status_code not in (200, 201):
            detail = ''
            try:
                body = resp.json()
                detail = body.get('message') or body.get('error') or ''
                if isinstance(detail, list):
                    detail = '; '.join(str(d) for d in detail)
            except Exception:
                pass
            raise GitlabWriteError(
                f'Could not open the merge request ({resp.status_code}). {detail}'.strip())
        return resp.json().get('web_url', '')


def _slug(text: str) -> str:
    slug = re.sub(r'[^a-z0-9]+', '-', text.lower()).strip('-')
    return slug[:40] or 'fix'


def _encode_path(path: str) -> str:
    """GitLab addresses a file by its full path, percent-encoded as one segment."""
    return urllib.parse.quote(path, safe='')


def open_fix_merge_request(token, project_id, filename, content, check_name,
                           recommendation='', audit_url='', gitlab_url='https://gitlab.com',
                           verify_ssl=True, custom_dns=''):
    """
    Create a branch, add the file, and open a merge request. Returns the MR URL.

    Mirrors `github_writer.open_fix_pull_request` — same shape, same caller
    contract (`GitlabWriteError` carries a message meant for the user, same
    as `GitHubWriteError` does) — so `views.fix_open_pr` can dispatch on
    `audit.source` and otherwise treat the two the same way.
    """
    project = _Project(token, project_id, gitlab_url, verify_ssl, custom_dns)
    project.require_push_access()
    project.require_write_scope()
    branch = project.branch_from_default(check_name)
    project.commit_file(branch, filename, content, f'chore: {check_name}\n\nGenerated by DevOpsCheck.')

    body_lines = [
        f'Fixes the failed check **{check_name}** found by DevOpsCheck.',
        '',
        f'Adds `{filename}`.',
    ]
    if recommendation:
        body_lines += ['', '**Why this matters**', '', recommendation.strip()]
    if audit_url:
        body_lines += ['', f'[Full audit report]({audit_url})']

    url = project.open_merge_request(branch, f'chore: {check_name}', '\n'.join(body_lines))
    logger.info('Opened fix MR for project %s: %s', project_id, url)
    return url
