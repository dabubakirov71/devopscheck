"""
Secrets in git history, not just in the current tree.

Deleting a leaked key in a later commit does not un-leak it: anyone who can
clone the repository can check out the commit that added it. The tree scan in
`checks_secrets` reads one snapshot from the provider's archive, which is what
keeps an audit at three API calls; history needs the object database, so this
module makes a bare, blob-size-filtered clone into a temporary directory,
walks every blob reachable from any ref once, and runs the same rules over it.

Runs only for audits of repositories their owner connected (see
`tasks.run_audit_task`). The public scanner never clones: its three-request
budget is what the free tier rests on.

Everything is bounded — repository size, blob size, number of blobs, bytes
read, wall-clock time — and every failure degrades to "history not scanned"
with a reason, never to a failed audit.
"""
import base64
import logging
import os
import shutil
import subprocess
import tempfile

logger = logging.getLogger(__name__)

# Repositories bigger than this (as the provider reports it) are not cloned.
MAX_REPO_KB = 150 * 1024
# Blobs above this are left on the server by the partial clone and never read.
MAX_BLOB_BYTES = 256 * 1024
MAX_BLOBS = 5000
MAX_TOTAL_BYTES = 32 * 1024 * 1024
CLONE_TIMEOUT = 90
GIT_TIMEOUT = 60
# Commit lookups are one `git log` each, so only this many findings get one.
MAX_COMMIT_LOOKUPS = 20


class HistoryResult:
    def __init__(self, scanned=False, reason='', findings=None, blobs=0):
        self.scanned = scanned
        # Why history was not scanned, for the report. Empty when it was.
        self.reason = reason
        self.findings = findings or []
        self.blobs = blobs


def clone_source(client):
    """
    (url, auth header, verify_ssl) for cloning the repository `client` reads,
    or None when it cannot be cloned from here.

    The token travels in an HTTP header set through the environment, never in
    the URL: a URL with credentials ends up in the clone's config, in process
    listings and in git's own error messages.
    """
    token = getattr(client, 'token', '') or ''
    if client.provider == 'github':
        url = f'https://github.com/{client.full_name}.git'
        user = 'x-access-token'
        verify = True
    elif client.provider == 'gitlab':
        if getattr(client, 'custom_dns', ''):
            # git resolves hosts itself; the custom resolver the API client
            # uses cannot be handed to it.
            return None
        url = f'{client.gitlab_url}/{client.full_name}.git'
        user = 'oauth2'
        verify = bool(getattr(client, 'verify_ssl', True))
    else:
        return None
    header = ''
    if token:
        header = 'Authorization: Basic ' + base64.b64encode(f'{user}:{token}'.encode()).decode()
    return url, header, verify


def _git_env(header='', verify=True):
    env = {
        'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        'HOME': tempfile.gettempdir(),
        'GIT_TERMINAL_PROMPT': '0',
        'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': os.devnull,
        # A partial clone fetches a missing blob the moment anything asks for
        # it. Nothing here should, but if it did, it must fail, not download.
        'GIT_NO_LAZY_FETCH': '1',
        'LC_ALL': 'C',
    }
    pairs = []
    if header:
        pairs.append(('http.extraHeader', header))
    if not verify:
        pairs.append(('http.sslVerify', 'false'))
    env['GIT_CONFIG_COUNT'] = str(len(pairs))
    for i, (key, value) in enumerate(pairs):
        env[f'GIT_CONFIG_KEY_{i}'] = key
        env[f'GIT_CONFIG_VALUE_{i}'] = value
    return env


def _git(repo, *args, env, input_bytes=None, timeout=GIT_TIMEOUT):
    return subprocess.run(
        ['git', '-C', repo, *args], env=env, input=input_bytes,
        capture_output=True, timeout=timeout, check=True,
    ).stdout


def _blob_paths(repo, env):
    """{blob sha: first path it was seen at} for every blob reachable from any ref."""
    out = _git(repo, 'rev-list', '--objects', '--all', '--missing=allow-promisor', env=env)
    paths = {}
    for line in out.decode('utf-8', 'replace').splitlines():
        sha, _sep, path = line.partition(' ')
        if path and sha not in paths:
            paths[sha] = path
    return paths


def _blob_sizes(repo, shas, env):
    """{sha: size} for the shas that are blobs present locally."""
    out = _git(repo, 'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)',
               env=env, input_bytes='\n'.join(shas).encode() + b'\n')
    sizes = {}
    for line in out.decode().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == 'blob':
            sizes[parts[0]] = int(parts[2])
    return sizes


def _read_blobs(repo, shas, env):
    """Yield (sha, text) for each sha, read in one `cat-file --batch` pass."""
    out = _git(repo, 'cat-file', '--batch', env=env,
               input_bytes='\n'.join(shas).encode() + b'\n')
    pos = 0
    while pos < len(out):
        header_end = out.index(b'\n', pos)
        header = out[pos:header_end].split()
        pos = header_end + 1
        if len(header) < 3:
            continue
        size = int(header[2])
        body = out[pos:pos + size]
        pos += size + 1
        if b'\x00' in body[:8000]:
            continue
        yield header[0].decode(), body.decode('utf-8', 'ignore')


def _head_blobs(repo, env):
    try:
        out = _git(repo, 'ls-tree', '-r', 'HEAD', env=env)
    except subprocess.CalledProcessError:
        return set()
    return {line.split()[2] for line in out.decode('utf-8', 'replace').splitlines()
            if len(line.split()) >= 3}


def _introduced_by(repo, sha, env):
    """(short commit, ISO date) of the oldest commit that added this blob."""
    try:
        out = _git(repo, 'log', '--all', '--reverse', '--format=%h %cs',
                   f'--find-object={sha}', env=env)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return '', ''
    first = out.decode().strip().splitlines()[:1]
    if not first:
        return '', ''
    commit, _sep, date = first[0].partition(' ')
    return commit, date


def scan_history(client, allow_paths=(), source=None) -> HistoryResult:
    """
    Scan every blob in the repository's history with the tree scanner's rules.

    Findings carry the same keys as `checks_secrets.find_secrets` plus
    `commit`, `date` and `in_head` (the blob is still in the default branch).
    `source` overrides `clone_source(client)`; tests point it at a local repo.
    """
    from app.checks_ai_agents import is_agent_file
    from app.checks_secrets import _should_scan, scan_text

    size_kb = getattr(client, 'size_kb', None)
    if size_kb and size_kb > MAX_REPO_KB:
        return HistoryResult(reason='too_large')
    source = source or clone_source(client)
    if source is None:
        return HistoryResult(reason='unsupported')
    if shutil.which('git') is None:
        logger.warning('History scan skipped: git is not installed')
        return HistoryResult(reason='unavailable')

    url, header, verify = source
    env = _git_env(header, verify)
    allow_paths = tuple(p for p in allow_paths if p)
    workdir = tempfile.mkdtemp(prefix='hist-')
    repo = os.path.join(workdir, 'repo.git')
    try:
        subprocess.run(
            ['git', 'clone', '--bare', '--quiet', '--no-tags',
             f'--filter=blob:limit={MAX_BLOB_BYTES}', url, repo],
            env=env, capture_output=True, timeout=CLONE_TIMEOUT, check=True,
        )
        paths = _blob_paths(repo, env)
        wanted = {
            sha: path for sha, path in paths.items()
            if (_should_scan(path) or is_agent_file(path))
            and not (allow_paths and path.startswith(allow_paths))
        }
        sizes = _blob_sizes(repo, list(wanted), env) if wanted else {}
        chosen, total = [], 0
        for sha, size in sorted(sizes.items(), key=lambda kv: kv[1]):
            if size > MAX_BLOB_BYTES or len(chosen) >= MAX_BLOBS or total + size > MAX_TOTAL_BYTES:
                continue
            chosen.append(sha)
            total += size

        findings, seen = [], set()
        for sha, text in (_read_blobs(repo, chosen, env) if chosen else ()):
            for f in scan_text(wanted[sha], text):
                # One credential committed to five files, or rewritten in ten
                # commits, is one credential to rotate.
                if (f['rule'], f['value']) in seen:
                    continue
                seen.add((f['rule'], f['value']))
                f['blob'] = sha
                findings.append(f)

        head = _head_blobs(repo, env)
        for i, f in enumerate(findings):
            f['in_head'] = f['blob'] in head
            f['commit'], f['date'] = (_introduced_by(repo, f['blob'], env)
                                      if i < MAX_COMMIT_LOOKUPS else ('', ''))
        logger.info('History scan [%s]: %d blob(s) read, %d finding(s)',
                    client.full_name, len(chosen), len(findings))
        return HistoryResult(scanned=True, findings=findings, blobs=len(chosen))
    except subprocess.TimeoutExpired:
        logger.info('History scan timed out for %s', client.full_name)
        return HistoryResult(reason='timeout')
    except (subprocess.CalledProcessError, OSError, ValueError) as exc:
        # stderr is not logged: git echoes the remote URL and, on some
        # versions, the header it was given.
        logger.info('History scan failed for %s (%s)', client.full_name, type(exc).__name__)
        return HistoryResult(reason='failed')
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
