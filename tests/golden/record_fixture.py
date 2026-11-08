"""
Record one real repository as a golden-corpus fixture.

Run manually, from the `web` container, against the live GitHub API — this is
not part of the test suite and does not run in CI. Re-run only when a fixture
needs to be refreshed (the repository changed in a way worth re-testing) or a
new repository is added to the corpus.

    docker compose -f docker/docker-compose.yml run --rm web \\
        python tests/golden/record_fixture.py fastapi/fastapi
        python tests/golden/record_fixture.py gitlab:gitlab-org/cli

A fixture is not a copy of the repository — most files matter only for their
*existence* (path counts, "is there a Dockerfile"), so only their path is
kept, with empty content. Real content is kept only for the files the engine
actually reads: everything `checks.py`/`checks_iac.py`/`checks_extra.py`/
`repo_kind.py` look up by name, every Terraform/workflow/Kubernetes file, and
the same secret-scan candidates `checks_secrets.find_secrets` would read,
using its own path-priority so the fixture exercises the real scanner rather
than a hand-picked subset of it.
"""
import json
import os
import sys

import django

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from app.checks import (  # noqa: E402
    CHANGELOG_FILES, CODEOWNERS_FILES, COMPOSE_FILES, CONTRIBUTING_FILES,
    DEP_FILES, DOCKERFILES as CHECKS_DOCKERFILES, ENV_EXAMPLE_FILES,
    LICENSE_FILES, LINTER_FILES, LOCK_FILES, README_FILES,
)
from app.checks_secrets import _priority, _should_scan  # noqa: E402
from app.repo_client import GithubRepoClient, GitlabRepoClient  # noqa: E402
from app.repo_kind import DOCS_SITE_MARKERS, DOCKERFILES, MONOREPO_MARKERS  # noqa: E402
from app.checks_ai_agents import is_agent_file  # noqa: E402

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')

NAMED_FILES = (
    ('.gitignore',), CHANGELOG_FILES, CODEOWNERS_FILES, COMPOSE_FILES,
    CONTRIBUTING_FILES, DEP_FILES, ENV_EXAMPLE_FILES, LICENSE_FILES,
    LINTER_FILES, LOCK_FILES, README_FILES, CHECKS_DOCKERFILES, DOCKERFILES,
    DOCS_SITE_MARKERS, MONOREPO_MARKERS,
    ('.gitlab-ci.yml', '.circleci/config.yml', 'Jenkinsfile', '.drone.yml',
     'pyproject.toml', 'setup.py', 'setup.cfg', 'Cargo.toml', 'package.json',
     'go.mod', 'go.sum', 'Pipfile', 'composer.json'),
)

K8S_DIR_PREFIXES = ('k8s/', 'kubernetes/', 'deploy/', 'manifests/', '.k8s/', 'kube/', 'helm/', 'charts/')
GITLAB_CI_PREFIXES = ('.gitlab/', 'ci/', '.ci/', '.gitlab-ci/')
MAX_SECRET_CANDIDATES = 45


def _content_worth_keeping(client) -> set:
    keep = set()
    for group in NAMED_FILES:
        keep.update(p for p in group if client.exists(p))

    for path in client.files:
        if path.startswith('.github/workflows/') and path.endswith(('.yml', '.yaml')):
            keep.add(path)
        elif path.endswith(('.tf', '.tfvars')) and 'examples/' not in path:
            keep.add(path)
        elif path.startswith(K8S_DIR_PREFIXES) and path.endswith(('.yaml', '.yml')):
            keep.add(path)
        elif is_agent_file(path):
            # MCP configs and CLAUDE.md/AGENTS.md: checks_ai_agents reads them.
            keep.add(path)
        elif (path.startswith(GITLAB_CI_PREFIXES) or '/' not in path) and path.endswith(('.yaml', '.yml')):
            # Candidates for a `.gitlab-ci.yml` local include.
            keep.add(path)

    candidates = sorted(
        (p for p in client.files if _should_scan(p)),
        key=lambda p: (_priority(p), p),
    )[:MAX_SECRET_CANDIDATES]
    keep.update(candidates)
    return keep


def record(full_name: str, token: str = ''):
    if full_name.startswith('gitlab:'):
        # gitlab.com's API takes a URL-encoded path wherever it takes a
        # project id, and serves a public project's archive with no token.
        full_name = full_name[len('gitlab:'):]
        client = GitlabRepoClient(full_name.replace('/', '%2F'), '').load()
        provider = 'gitlab'
    else:
        client = GithubRepoClient(full_name, token).load()
        provider = 'github'
    keep = _content_worth_keeping(client)

    files = {}
    for path in sorted(client.files):
        files[path] = client.get_content(path) if path in keep else ''

    fixture = {
        'full_name': client.full_name,
        'provider': provider,
        'is_private': client.is_private,
        'default_branch': client.default_branch,
        'pushed_at': client.pushed_at.isoformat() if client.pushed_at else None,
        'stars': client.stars,
        'primary_language': client.primary_language or '',
        'description': client.description or '',
        'file_count': len(files),
        'content_kept': len(keep),
        'files': files,
    }

    prefix = 'gitlab__' if provider == 'gitlab' else ''
    out_path = os.path.join(FIXTURE_DIR, prefix + full_name.replace('/', '__') + '.json')
    os.makedirs(FIXTURE_DIR, exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(fixture, f, indent=1, sort_keys=True)

    print(f'{full_name}: {len(files)} paths, content kept for {len(keep)} -> {out_path}')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: record_fixture.py owner/repo|gitlab:group/project [...]', file=sys.stderr)
        sys.exit(1)
    from django.conf import settings
    tok = getattr(settings, 'PUBLIC_SCAN_GITHUB_TOKEN', '') or ''
    for name in sys.argv[1:]:
        record(name, tok)
