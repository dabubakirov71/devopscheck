"""
Fixes that edit the repository's own files (growth plan B8).

The template fixes in fix_templates.py add a new file. For the two findings a
maintainer cares most about in GitHub Actions that was the wrong shape: a
`pin-actions.sh` to run by hand is advice, not a fix, and nobody merges it.
These rewrite the workflows themselves, change nothing else, and say in the
pull request exactly what they did and what they left alone.

Each fixer is pure — `fix(files, resolve) -> Result` over {path: text} — so it
is tested on fixtures; `open_pull_request` does the GitHub part.
"""
import logging
import re
from dataclasses import dataclass, field

from app.github_writer import GitHubWriteError

logger = logging.getLogger(__name__)

WORKFLOW_DIR = '.github/workflows'


class WorkflowScopeError(GitHubWriteError):
    """The token cannot write to .github/workflows/ — GitHub's separate `workflow` permission."""

_SHA = re.compile(r'^[0-9a-f]{40}$')
_USES = re.compile(
    r'^(?P<lead>\s*(?:-\s+)?uses:\s*)(?P<q>["\']?)(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s"\']*)?)'
    r'@(?P<ref>[^\s"\'#]+)(?P=q)(?P<tail>[ \t]*(?:#.*)?)$', re.MULTILINE)


@dataclass
class Result:
    changes: dict = field(default_factory=dict)      # path -> new text
    done: list = field(default_factory=list)         # human lines for the PR body
    skipped: list = field(default_factory=list)


# ── actions.pinned_sha ────────────────────────────────────────────────────────

def pin_actions(files: dict, resolve) -> Result:
    """
    `uses: owner/repo@v4` → `uses: owner/repo@<40-char sha> # v4`.

    `resolve(owner_repo, ref)` returns the commit sha or None. A reference
    that cannot be resolved is left exactly as it was and listed as skipped —
    a guessed sha would be worse than a tag.
    """
    result = Result()
    cache = {}

    for path, text in sorted(files.items()):
        def repl(m):
            action, ref = m.group('action'), m.group('ref')
            if _SHA.match(ref) or action.startswith('./'):
                return m.group(0)
            owner_repo = '/'.join(action.split('/')[:2])
            key = (owner_repo, ref)
            if key not in cache:
                cache[key] = resolve(owner_repo, ref)
            sha = cache[key]
            if not sha:
                result.skipped.append(f'`{action}@{ref}` in `{path}` — could not resolve the tag')
                return m.group(0)
            result.done.append(f'`{action}@{ref}` → `{sha[:12]}…` in `{path}`')
            q = m.group('q')
            return f"{m.group('lead')}{q}{action}@{sha}{q} # {ref}"

        new = _USES.sub(repl, text)
        if new != text:
            result.changes[path] = new
    return result


# ── actions.broad_permissions ─────────────────────────────────────────────────

#: Signs a workflow needs more than read access to the repository. Any one
#: of them and the file is left alone: a fix that breaks a release pipeline
#: is a revert, not a merge.
WRITE_HINTS = re.compile(
    r'git\s+push|gh\s+(?:release|pr|issue|api|repo|workflow)|create-pull-request|action-gh-release|'
    r'github-script|git-auto-commit|deploy-pages|upload-pages-artifact|codeql-action|upload-sarif|'
    r'sticky-pull-request-comment|actions/labeler|actions/stale|release-please|semantic-release|'
    r'changesets/action|docker/login-action|ghcr\.io|npm\s+publish|twine|pypa/gh-action-pypi-publish|'
    r'id-token|dependabot|auto-merge|pull_request_target|workflow_run|issue_comment|\$\{\{\s*secrets\.GITHUB_TOKEN',
    re.IGNORECASE)
_TOP_PERMISSIONS = re.compile(r'^permissions\s*:', re.MULTILINE)
_ANY_PERMISSIONS = re.compile(r'^\s+permissions\s*:', re.MULTILINE)
_JOBS = re.compile(r'^jobs\s*:', re.MULTILINE)


def least_privilege(files: dict, resolve=None) -> Result:
    """Add a top-level `permissions: contents: read` where nothing needs more."""
    result = Result()
    for path, text in sorted(files.items()):
        if _TOP_PERMISSIONS.search(text):
            continue
        if _ANY_PERMISSIONS.search(text):
            result.skipped.append(f'`{path}` — sets permissions per job already')
            continue
        hint = WRITE_HINTS.search(text)
        if hint:
            result.skipped.append(f'`{path}` — uses `{hint.group(0).strip()}`, which may need write access; '
                                  'set its permissions by hand')
            continue
        jobs = _JOBS.search(text)
        if not jobs:
            continue
        block = ('# Least privilege: this workflow only reads the repository.\n'
                 'permissions:\n  contents: read\n\n')
        result.changes[path] = text[:jobs.start()] + block + text[jobs.start():]
        result.done.append(f'`{path}`: `permissions: contents: read`')
    return result


FIXERS = {
    'actions.pinned_sha': (pin_actions, 'ci: pin GitHub Actions to commit SHAs',
                           'Every third-party action is pinned to the full commit SHA of the tag it '
                           'used, with the tag kept as a comment so Dependabot or Renovate can keep '
                           'it current. A tag can be moved by whoever controls the action; a SHA cannot.'),
    'actions.broad_permissions': (least_privilege, 'ci: least-privilege GITHUB_TOKEN permissions',
                                  'Workflows that only read the repository now say so. Without a '
                                  '`permissions` block the token may have write access to everything, '
                                  'and any compromised step inherits it.'),
}


def has_fixer(check_id: str, host: str) -> bool:
    return host == 'github' and check_id in FIXERS


# ── GitHub ───────────────────────────────────────────────────────────────────

def _workflows(repo) -> dict:
    resp = repo.get(f'/repos/{repo.name}/contents/{WORKFLOW_DIR}', params={'ref': repo.default_branch})
    if resp.status_code != 200 or not isinstance(resp.json(), list):
        return {}
    files = {}
    for item in resp.json()[:40]:
        path = item.get('path', '')
        if item.get('type') == 'file' and path.endswith(('.yml', '.yaml')):
            text, _sha = repo.read_file(path)
            if text:
                files[path] = text
    return files


def _resolver(repo):
    def resolve(owner_repo, ref):
        resp = repo.get(f'/repos/{owner_repo}/commits/{ref}')
        if resp.status_code == 200:
            sha = resp.json().get('sha', '')
            return sha if _SHA.match(sha or '') else None
        return None
    return resolve


def open_pull_request(token, repo_full_name, check_id, audit_url='') -> dict:
    """Run the fixer on the repository's workflows and open one PR. Returns {url, files}."""
    from app.github_writer import NothingToChange, _Repo
    fixer, title, why = FIXERS[check_id]
    repo = _Repo(token, repo_full_name)
    repo.require_push_access()
    result = fixer(_workflows(repo), _resolver(repo))
    if not result.changes:
        raise NothingToChange('Nothing to change: ' + ('; '.join(result.skipped) or 'the workflows are already fine.'))
    branch = repo.branch_from_default(title)
    for path, text in result.changes.items():
        try:
            repo.commit_file(branch, path, text, f'{title}\n\n{path}\n\nGenerated by DevOpsCheck.')
        except GitHubWriteError as exc:
            # GitHub guards workflow files with their own permission: the
            # classic `workflow` scope, or "Workflows: write" on the App.
            raise WorkflowScopeError(
                'GitHub needs one more permission to change files in .github/workflows/: the '
                '"workflow" scope on a classic token, or "Workflows: write" on a fine-grained token '
                f'or the GitHub App. Nothing was changed on your default branch. ({exc})',
                reconnect=True) from exc
    body = [why, '', '**Changed**', ''] + [f'- {line}' for line in result.done]
    if result.skipped:
        body += ['', '**Left alone**', ''] + [f'- {line}' for line in result.skipped]
    body += ['', 'Only the lines listed above changed. Review, run CI, merge.']
    if audit_url:
        body += ['', f'[Full audit report]({audit_url})']
    url = repo.open_pull_request(branch, title, '\n'.join(body))
    logger.info('Opened content fix PR for %s (%s): %s', repo_full_name, check_id, url)
    return {'url': url, 'files': sorted(result.changes)}
