"""
Provider-agnostic read access to a repository.

The audit engine used to answer "does this file exist?" with one HTTP request
per candidate path — around 90 sequential calls per audit, each with a 10s
timeout, and the same file fetched more than once. This client fetches the
whole file tree in a single request instead, so existence checks become set
lookups and a miss costs nothing at all.

Both concrete clients expose the same surface, which is what lets one check
engine serve GitHub and GitLab.
"""
import base64
import io
import logging
import tarfile
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)

TIMEOUT = 15
MAX_CONTENT_BYTES = 512 * 1024
# File contents are fetched one HTTP request each, so they are fetched together.
# Kept modest: providers rate-limit bursts, and eight in flight already turns a
# 100-file read from ~20 seconds into ~3.
FETCH_CONCURRENCY = 8

# One archive download replaces one HTTP request per file. GitHub serves the
# whole repository as a tarball, so a full audit costs three API calls instead
# of seventy — which is what makes the free public scanner viable at all
# (unauthenticated GitHub allows 60 requests per hour).
ARCHIVE_MAX_DOWNLOAD = 40 * 1024 * 1024   # compressed bytes we are willing to pull
ARCHIVE_MAX_MEMBER = 512 * 1024           # per-file cap when extracting
ARCHIVE_MAX_TOTAL = 24 * 1024 * 1024      # total extracted text held in memory
ARCHIVE_MAX_FILES = 4000


def _empty_repository_message():
    return _('This repository is empty — it has no commits yet, so there is nothing to audit. '
             'Push a first commit and run the audit again.')


class RepoClient:
    """Base class holding the tree index and the content cache."""

    provider = ''
    # Whether the repository can be cloned for the history scan and its
    # findings checked with the provider. Only the real provider clients can.
    supports_deep_scan = False

    def __init__(self):
        self.full_name = ''
        self.repo_url = ''
        self.description = ''
        self.default_branch = 'main'
        # The branch, tag or commit to read. Empty means the default branch,
        # resolved during load(). CI has to audit the commit under test —
        # grading the default branch and calling it a gate on a pull request
        # would report on code the change has not touched.
        self.ref = ''
        self.pushed_at = None
        self.stars = 0
        self.primary_language = ''
        self.is_private = True
        self.head_sha = ''
        # Repository size in KB when the provider reports it (GitHub does).
        self.size_kb = None
        # Every blob path in the repository, and every directory path.
        self.files: set[str] = set()
        self.dirs: set[str] = set()
        # Set when the provider could not return the full tree (very large repos);
        # existence checks then fall back to per-path requests.
        self.tree_truncated = False
        self._content_cache: dict[str, str | None] = {}
        # Populated when the whole repository was pulled as one archive.
        self._archive: dict[str, str] | None = None
        self._archive_paths: set[str] = set()
        self.api_calls = 0

    # ── existence ─────────────────────────────────────────────────────────────

    def exists(self, path: str) -> bool:
        path = path.strip('/')
        if path in self.files or path in self.dirs:
            return True
        if self.tree_truncated:
            return self._remote_exists(path)
        return False

    def any_exists(self, paths) -> str | None:
        """First path from `paths` that exists, or None."""
        for p in paths:
            if self.exists(p):
                return p
        return None

    def list_dir(self, path: str) -> list[str]:
        """File names (not paths) directly inside `path`."""
        prefix = path.strip('/') + '/'
        names = []
        for f in self.files:
            if f.startswith(prefix):
                rest = f[len(prefix):]
                if '/' not in rest:
                    names.append(rest)
        return sorted(names)

    def walk(self, suffixes=(), max_files=None) -> list[str]:
        """All blob paths ending in one of `suffixes` (all files when empty)."""
        out = [p for p in sorted(self.files) if not suffixes or p.endswith(tuple(suffixes))]
        return out[:max_files] if max_files else out

    # ── content ───────────────────────────────────────────────────────────────

    def get_content(self, path: str) -> str | None:
        path = path.strip('/')
        if path in self._content_cache:
            return self._content_cache[path]
        if not self.tree_truncated and path not in self.files:
            self._content_cache[path] = None
            return None
        if self._archive is not None:
            content = self._archive.get(path)
            self._content_cache[path] = content
            return content
        content = self._remote_content(path)
        self._content_cache[path] = content
        return content

    def local_text(self, path: str) -> str | None:
        """
        A file's text if it is already in memory, else None — never a request.

        For analyses that read every source file (CVE reachability): worth
        doing from the archive, not worth a request per file.
        """
        path = path.strip('/')
        if path in self._content_cache:
            return self._content_cache[path]
        if self._archive is not None:
            return self._archive.get(path)
        return None

    def prefetch(self, paths) -> None:
        """
        Warm the content cache for many paths at once.

        Callers that are about to read a lot of files (the secret scanner, the
        CI inspection) call this first so the reads happen in parallel instead
        of one blocking request after another.
        """
        if self._archive is not None:
            return  # everything is already in memory
        wanted = [
            p.strip('/') for p in paths
            if p.strip('/') not in self._content_cache
            and (self.tree_truncated or p.strip('/') in self.files)
        ]
        if not wanted:
            return
        if len(wanted) == 1:
            self.get_content(wanted[0])
            return
        with ThreadPoolExecutor(max_workers=FETCH_CONCURRENCY) as pool:
            for path, content in zip(wanted, pool.map(self._safe_remote_content, wanted)):
                self._content_cache[path] = content

    def _store_archive(self, extracted):
        """Keep the extracted contents and the full path listing from an archive."""
        if extracted is None:
            self._archive = None
            self._archive_paths = set()
            return
        self._archive, self._archive_paths = extracted

    def _index_from_archive(self, force=False):
        """
        Build the path index from the archive itself.

        The archive already lists every file, so a provider whose tree endpoint
        is paginated (GitLab needs one request per hundred entries) does not need
        to be asked at all. Also covers the case where the tree came back
        truncated on a very large repository.
        """
        if self._archive is None or not (force or self.tree_truncated):
            return
        for path in (self._archive_paths or self._archive):
            self.files.add(path)
            parts = path.split('/')
            for i in range(1, len(parts)):
                self.dirs.add('/'.join(parts[:i]))
        self.tree_truncated = False
        logger.info('Path index built from archive for %s: %d files', self.full_name, len(self.files))

    def _safe_remote_content(self, path):
        try:
            return self._remote_content(path)
        except Exception:
            logger.warning('Failed to read %s from %s', path, self.full_name)
            return None

    def first_content(self, paths):
        """(path, content) for the first readable path, or (None, None)."""
        for p in paths:
            c = self.get_content(p)
            if c:
                return p, c
        return None, None

    # ── to be implemented by subclasses ───────────────────────────────────────

    def _remote_exists(self, path: str) -> bool:
        raise NotImplementedError

    def _remote_content(self, path: str) -> str | None:
        raise NotImplementedError


class GithubRepoClient(RepoClient):
    provider = 'github'
    supports_deep_scan = True

    def __init__(self, full_name: str, token: str = '', ref: str = ''):
        super().__init__()
        self.full_name = full_name
        self.token = token
        self.ref = (ref or '').strip()
        self.base = f'https://api.github.com/repos/{full_name}'
        self._session = requests.Session()
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if token:
            headers['Authorization'] = f'token {token}'
        self._session.headers.update(headers)
        self.repo_url = f'https://github.com/{full_name}'

    def _get(self, path, **kw):
        self.api_calls += 1
        try:
            return self._session.get(f'{self.base}{path}', timeout=TIMEOUT, **kw)
        except requests.RequestException as exc:
            logger.warning('GitHub request failed for %s%s: %s', self.full_name, path, exc)
            return None

    def load(self) -> 'GithubRepoClient':
        r = self._get('')
        if r is not None and r.status_code in (403, 429) and \
                r.headers.get('X-RateLimit-Remaining') == '0':
            raise RateLimitedError(
                'GitHub API rate limit reached. Connect an account, or try again shortly.'
            )
        if r is None or r.status_code != 200:
            # A status code is not a message. Each of these is something the
            # customer can act on, and "GitHub returned 401" told them nothing
            # about a token they could simply replace.
            raise RepoAccessError(_github_access_message(r, self.full_name))
        meta = r.json()
        self.default_branch = meta.get('default_branch') or 'main'
        self.ref = self.ref or self.default_branch
        self.description = meta.get('description') or ''
        self.stars = meta.get('stargazers_count') or 0
        self.primary_language = meta.get('language') or ''
        self.is_private = bool(meta.get('private'))
        self.size_kb = meta.get('size')
        self.repo_url = meta.get('html_url') or self.repo_url
        pushed = meta.get('pushed_at')
        if pushed:
            try:
                self.pushed_at = datetime.strptime(pushed, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        self._load_tree()
        self._load_archive()
        return self

    def _load_archive(self):
        """
        Download the repository as one tarball and keep the text files in memory.

        Falls back silently to per-file requests when the archive is too large or
        the request fails — correctness never depends on this working.
        """
        url = f'{self.base}/tarball/{self.ref}'
        self.api_calls += 1
        try:
            resp = self._session.get(url, timeout=60, stream=True)
            if resp.status_code != 200:
                logger.info('Archive unavailable for %s (HTTP %s) — reading files individually',
                            self.full_name, resp.status_code)
                return
            buf = io.BytesIO()
            downloaded = 0
            for chunk in resp.iter_content(chunk_size=256 * 1024):
                downloaded += len(chunk)
                if downloaded > ARCHIVE_MAX_DOWNLOAD:
                    logger.info('Archive for %s exceeds %d bytes — reading files individually',
                                self.full_name, ARCHIVE_MAX_DOWNLOAD)
                    return
                buf.write(chunk)
            buf.seek(0)
            self._store_archive(_extract_text_files(buf, self.full_name))
            self._index_from_archive()
        except Exception as exc:
            logger.info('Archive download failed for %s (%s) — reading files individually',
                        self.full_name, exc)
            self._archive = None

    def _load_tree(self):
        r = self._get(f'/git/trees/{self.ref}', params={'recursive': '1'})
        if r is not None and r.status_code == 409:
            # "Git Repository is empty": no commit, so nothing to audit — and
            # a report scoring an empty tree is a report about nothing.
            raise RepoAccessError(_empty_repository_message())
        if r is None or r.status_code != 200:
            logger.warning('GitHub tree unavailable for %s — falling back to per-path checks', self.full_name)
            self.tree_truncated = True
            return
        data = r.json()
        self.head_sha = data.get('sha', '') or ''
        self.tree_truncated = bool(data.get('truncated'))
        for node in data.get('tree', []):
            path = node.get('path', '')
            if node.get('type') == 'blob':
                self.files.add(path)
            elif node.get('type') == 'tree':
                self.dirs.add(path)
        logger.info(
            'GitHub tree loaded for %s: %d files, %d dirs, truncated=%s (%d API calls)',
            self.full_name, len(self.files), len(self.dirs), self.tree_truncated, self.api_calls,
        )

    def _remote_exists(self, path: str) -> bool:
        r = self._get(f'/contents/{urllib.parse.quote(path)}', params={'ref': self.ref})
        return r is not None and r.status_code == 200

    def _remote_content(self, path: str) -> str | None:
        r = self._get(f'/contents/{urllib.parse.quote(path)}', params={'ref': self.ref})
        if r is None or r.status_code != 200:
            return None
        data = r.json()
        if isinstance(data, dict) and data.get('encoding') == 'base64':
            if (data.get('size') or 0) > MAX_CONTENT_BYTES:
                return None
            try:
                return base64.b64decode(data['content']).decode('utf-8', errors='ignore')
            except Exception:
                return None
        return None

    # GitHub-only signals used by a few checks.

    # Rules that stop a direct push or a force-push — what "protected" means
    # to the reader of the report. A ruleset holding only, say, a naming
    # rule does not count.
    PROTECTING_RULES = {'pull_request', 'non_fast_forward', 'deletion', 'required_status_checks',
                        'update', 'required_signatures', 'required_linear_history'}

    def branch_is_protected(self) -> bool | None:
        """
        True / False when the provider said; None when it could not be read.

        `protected` on /branches reflects classic protection only, so a repo
        guarded by a ruleset read as unprotected. /rules/branches/<b> is
        public and returns what applies to the branch from either source.
        """
        branch = urllib.parse.quote(self.default_branch, safe='')
        r = self._get(f'/branches/{branch}')
        if r is None or r.status_code != 200:
            return None
        if r.json().get('protected'):
            return True
        rules = self._get(f'/rules/branches/{branch}')
        if rules is None or rules.status_code != 200:
            return None
        try:
            return any(rule.get('type') in self.PROTECTING_RULES for rule in rules.json())
        except (ValueError, AttributeError):
            return None


class GitlabRepoClient(RepoClient):
    provider = 'gitlab'
    supports_deep_scan = True

    def __init__(self, project_id: int, token: str, gitlab_url: str = 'https://gitlab.com',
                 verify_ssl: bool = True, custom_dns: str = '', ref: str = ''):
        super().__init__()
        self.ref = (ref or '').strip()
        self.project_id = project_id
        self.token = token
        self.gitlab_url = gitlab_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.custom_dns = custom_dns
        self.base = f'{self.gitlab_url}/api/v4/projects/{project_id}'

    def _get(self, path, **kw):
        from app.dns_utils import custom_dns_server
        self.api_calls += 1
        try:
            with custom_dns_server(self.custom_dns):
                return requests.get(
                    f'{self.base}{path}',
                    headers={'Authorization': f'Bearer {self.token}', 'Accept': 'application/json'},
                    timeout=TIMEOUT, verify=self.verify_ssl, **kw,
                )
        except requests.RequestException as exc:
            logger.warning('GitLab request failed for project %s%s: %s', self.project_id, path, exc)
            return None

    def load(self) -> 'GitlabRepoClient':
        r = self._get('')
        if r is None or r.status_code != 200:
            raise RepoAccessError(_gitlab_access_message(r, self.project_id))
        meta = r.json()
        if meta.get('empty_repo'):
            raise RepoAccessError(_empty_repository_message())
        self.full_name = meta.get('path_with_namespace') or str(self.project_id)
        self.default_branch = meta.get('default_branch') or 'main'
        self.ref = self.ref or self.default_branch
        self.description = meta.get('description') or ''
        self.stars = meta.get('star_count') or 0
        self.repo_url = meta.get('web_url') or ''
        self.is_private = meta.get('visibility') != 'public'
        last = meta.get('last_activity_at')
        if last:
            try:
                self.pushed_at = datetime.fromisoformat(last.replace('Z', '+00:00'))
            except ValueError:
                pass
        # Archive first: it lists every file, so the paginated tree walk (one
        # request per hundred entries) is only needed when the archive fails.
        self._load_archive()
        if self._archive is not None:
            self._index_from_archive(force=True)
        else:
            self._load_tree()
        return self

    def _load_archive(self):
        """Same single-request trick for GitLab: /repository/archive.tar.gz."""
        from app.dns_utils import custom_dns_server
        self.api_calls += 1
        try:
            with custom_dns_server(self.custom_dns):
                resp = requests.get(
                    f'{self.base}/repository/archive.tar.gz',
                    headers={'Authorization': f'Bearer {self.token}'},
                    params={'sha': self.ref},
                    timeout=60, verify=self.verify_ssl, stream=True,
                )
                if resp.status_code != 200:
                    return
                buf = io.BytesIO()
                downloaded = 0
                for chunk in resp.iter_content(chunk_size=256 * 1024):
                    downloaded += len(chunk)
                    if downloaded > ARCHIVE_MAX_DOWNLOAD:
                        return
                    buf.write(chunk)
            buf.seek(0)
            self._store_archive(_extract_text_files(buf, self.full_name))
        except Exception as exc:
            logger.info('GitLab archive download failed for %s (%s)', self.full_name, exc)
            self._archive = None

    def _load_tree(self):
        page = 1
        while page <= 20:  # 20 * 100 = 2000 entries is plenty for an audit
            r = self._get('/repository/tree', params={
                'recursive': 'true', 'per_page': 100, 'page': page, 'ref': self.ref,
            })
            if r is None or r.status_code != 200:
                if page == 1:
                    logger.warning('GitLab tree unavailable for project %s', self.project_id)
                    self.tree_truncated = True
                return
            nodes = r.json()
            if not isinstance(nodes, list) or not nodes:
                break
            for node in nodes:
                if node.get('type') == 'blob':
                    self.files.add(node.get('path', ''))
                elif node.get('type') == 'tree':
                    self.dirs.add(node.get('path', ''))
            if len(nodes) < 100:
                break
            page += 1
        else:
            self.tree_truncated = True
        logger.info(
            'GitLab tree loaded for project %s: %d files, %d dirs (%d API calls)',
            self.project_id, len(self.files), len(self.dirs), self.api_calls,
        )

    def _encoded(self, path):
        return urllib.parse.quote(path, safe='')

    def _remote_exists(self, path: str) -> bool:
        r = self._get(f'/repository/files/{self._encoded(path)}', params={'ref': self.ref})
        return r is not None and r.status_code == 200

    def _remote_content(self, path: str) -> str | None:
        r = self._get(f'/repository/files/{self._encoded(path)}', params={'ref': self.ref})
        if r is None or r.status_code != 200:
            return None
        data = r.json()
        if data.get('encoding') == 'base64':
            try:
                return base64.b64decode(data['content']).decode('utf-8', errors='ignore')
            except Exception:
                return None
        return data.get('content')

    def branch_is_protected(self) -> bool | None:
        r = self._get(f'/protected_branches/{urllib.parse.quote(self.default_branch, safe="")}')
        if r is None or r.status_code in (401, 403) or r.status_code >= 500:
            return None     # could not see, which is not "unprotected"
        return r.status_code == 200


def _extract_text_files(fileobj, label=''):
    """
    Read a repository tarball into (text_contents, every_path).

    The archive's top-level directory is a generated name like
    "pallets-flask-a1b2c3", so it is stripped to leave repository-relative paths.
    Binary and oversized members contribute their path — a check may care that
    `bun.lockb` exists — but not their bytes, which nothing here needs.

    Returns None when the archive cannot be read at all.
    """
    files: dict[str, str] = {}
    paths: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=fileobj, mode='r:gz') as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = member.name.split('/', 1)
                if len(parts) < 2 or not parts[1]:
                    continue
                path = parts[1]
                paths.add(path)
                if member.size > ARCHIVE_MAX_MEMBER:
                    continue
                if len(files) >= ARCHIVE_MAX_FILES or total >= ARCHIVE_MAX_TOTAL:
                    continue
                try:
                    handle = tar.extractfile(member)
                    if handle is None:
                        continue
                    raw = handle.read()
                except Exception:
                    continue
                if b'\x00' in raw[:1024]:
                    continue  # binary
                files[path] = raw.decode('utf-8', errors='ignore')
                total += len(raw)
    except (tarfile.TarError, EOFError, OSError) as exc:
        logger.info('Could not read archive for %s: %s', label, exc)
        return None
    logger.info('Archive read for %s: %d path(s), %d text file(s), %d bytes',
                label, len(paths), len(files), total)
    return files, paths


class RepoAccessError(Exception):
    """The repository could not be read — bad token, missing repo, or network failure."""


class RateLimitedError(RepoAccessError):
    """The provider refused the request because the API quota is spent."""


class StaticRepoClient(RepoClient):
    """
    In-memory client backed by a dict of {path: content}. Used by the test suite
    so check logic can be exercised without touching a provider API.
    """

    provider = 'static'

    def __init__(self, files: dict, full_name='acme/demo', default_branch='main',
                 pushed_at=None, provider='github'):
        super().__init__()
        self.provider = provider
        self.full_name = full_name
        self.default_branch = default_branch
        self.pushed_at = pushed_at
        self._files = dict(files)
        self.files = set(files)
        for path in files:
            parts = path.split('/')
            for i in range(1, len(parts)):
                self.dirs.add('/'.join(parts[:i]))
        self._protected = False

    def _remote_exists(self, path):
        return path in self._files

    def _remote_content(self, path):
        return self._files.get(path)

    def get_content(self, path):
        return self._files.get(path.strip('/'))

    def local_text(self, path):
        return self._files.get(path.strip('/'))

    def prefetch(self, paths):
        return None

    def branch_is_protected(self):
        return self._protected


class LocalDirClient(RepoClient):
    """
    A repository read from a local directory — the evaluation harness's source
    (accuracy spec, stage 1.1): synthetic fixtures under tests/fixtures/repos/
    and cached snapshots of the live golden set.

    What a directory cannot say — the provider, default branch, last push,
    stars, visibility, branch protection — comes from an optional
    `metadata.yaml` next to it (or `metadata_path`), so a fixture can state
    it instead of the harness guessing.
    """

    provider = 'local'
    SKIP_DIRS = {'.git'}
    META_FILES = {'metadata.yaml', 'expected.yaml'}

    def __init__(self, root: str, full_name: str = '', metadata: dict | None = None,
                 metadata_path: str = ''):
        super().__init__()
        import os
        self.root = os.path.abspath(root)
        self.full_name = full_name or os.path.basename(self.root)
        self._meta = dict(metadata or {})
        meta_file = metadata_path or os.path.join(self.root, 'metadata.yaml')
        if not metadata and os.path.exists(meta_file):
            import yaml
            with open(meta_file, encoding='utf-8') as fh:
                self._meta = yaml.safe_load(fh) or {}
        self._text: dict[str, str | None] = {}

    def load(self) -> 'LocalDirClient':
        import os
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]
            rel_dir = os.path.relpath(dirpath, self.root)
            for name in filenames:
                rel = name if rel_dir == '.' else f'{rel_dir}/{name}'.replace(os.sep, '/')
                if rel in self.META_FILES:
                    continue
                self.files.add(rel)
                parts = rel.split('/')
                for i in range(1, len(parts)):
                    self.dirs.add('/'.join(parts[:i]))
        meta = self._meta
        self.provider = meta.get('provider', 'github')
        self.default_branch = meta.get('default_branch', 'main')
        self.ref = self.default_branch
        self.description = meta.get('description', '')
        self.stars = meta.get('stars', 0)
        self.is_private = bool(meta.get('private', False))
        self.head_sha = meta.get('ref', '') or ''
        pushed = meta.get('pushed_at')
        if pushed:
            self.pushed_at = pushed if isinstance(pushed, datetime) else \
                datetime.fromisoformat(str(pushed).replace('Z', '+00:00'))
            if self.pushed_at.tzinfo is None:
                self.pushed_at = self.pushed_at.replace(tzinfo=timezone.utc)
        if not self.files:
            raise RepoAccessError(_('This repository is empty — it has no commits yet, so there is '
                                    'nothing to audit. Push a first commit and run the audit again.'))
        return self

    def _read(self, path):
        import os
        if path not in self._text:
            full = os.path.join(self.root, path)
            try:
                with open(full, 'rb') as fh:
                    raw = fh.read(MAX_CONTENT_BYTES + 1)
            except OSError:
                raw = None
            if raw is None or len(raw) > MAX_CONTENT_BYTES or b'\x00' in raw[:1024]:
                self._text[path] = None
            else:
                self._text[path] = raw.decode('utf-8', errors='ignore')
        return self._text[path]

    def _remote_exists(self, path):
        return path in self.files

    def _remote_content(self, path):
        return self._read(path) if path in self.files else None

    def get_content(self, path):
        path = path.strip('/')
        return self._read(path) if path in self.files else None

    def local_text(self, path):
        return self.get_content(path)

    def prefetch(self, paths):
        return None

    def branch_is_protected(self):
        # What the provider would say. None when the fixture does not know —
        # the stage-2 `unknown` status is for exactly this.
        return self._meta.get('branch_protected')


def _github_access_message(resp, full_name):
    code = resp.status_code if resp is not None else None
    if code == 401:
        return _('GitHub rejected the connected token. It has expired or been revoked — '
                 'create a new one and reconnect on the profile page.')
    if code == 403:
        return _('GitHub refused the request. The token is valid but not allowed to read '
                 '%(repo)s — it may be missing the "repo" scope, or an organisation has not '
                 'approved it.') % {'repo': full_name}
    if code == 404:
        return _('%(repo)s could not be read. It may have been renamed, deleted or made '
                 'private, or the token cannot see it — a fine-grained token has to list the '
                 'repository explicitly.') % {'repo': full_name}
    if code is None:
        return _('Could not reach GitHub. This is usually temporary — try the audit again.')
    return _('GitHub returned an unexpected error (%(code)s) for %(repo)s.') % {
        'code': code, 'repo': full_name}


def _gitlab_access_message(resp, project_id):
    code = resp.status_code if resp is not None else None
    if code == 401:
        return _('GitLab rejected the connected token. It has expired or been revoked — '
                 'create a new one with the read_api scope and reconnect on the profile page.')
    if code == 403:
        return _('GitLab refused the request. The token is missing the read_api scope, or the '
                 'account cannot read this project.')
    if code == 404:
        return _('The project could not be read. It may have been renamed, deleted or moved, '
                 'or the token cannot see it.')
    if code is None:
        return _('Could not reach GitLab. If this is a self-hosted instance, check that the '
                 'server is reachable and the URL is right.')
    return _('GitLab returned an unexpected error (%(code)s).') % {'code': code}


def build_client_for_audit(audit) -> RepoClient:
    """Construct and load the right client for an Audit record."""
    if audit.source == 'gitlab':
        # A deleted or never-created profile used to surface as Django's own
        # "User has no gitlab_profile." — an internal sentence shown to a
        # customer as the reason their audit failed.
        profile = getattr(audit.user, 'gitlab_profile', None)
        if profile is None:
            raise RepoAccessError(_('No GitLab account is connected. Connect one on the '
                                    'profile page and run the audit again.'))
        parts = audit.repo_full_name.split('::')
        project_id = int(parts[1]) if len(parts) > 1 else 0
        return GitlabRepoClient(
            project_id, profile.current_token, profile.gitlab_url,
            profile.verify_ssl, profile.custom_dns, ref=audit.ref,
        ).load()
    profile = audit.user.github_profiles.first()
    if profile is None:
        raise RepoAccessError(_('No GitHub account is connected. Connect one on the profile '
                                'page and run the audit again.'))
    token = profile.current_token
    return GithubRepoClient(audit.repo_full_name, token, ref=audit.ref).load()
