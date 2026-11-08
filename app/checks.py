"""
Repository audit engine.

One engine serves both GitHub and GitLab: it reads the repository through a
RepoClient (app/repo_client.py), which loads the whole file tree in a single
request, so "does this file exist?" is a set lookup rather than an HTTP call.

Every check returns:
    {check_id, name, description, severity, passed, recommendation, category}

`check_id` is the stable key — fix templates, built-in AI suggestions and
compliance control mappings all look up by it, never by the display name.
Display strings are English source, translated at audit time into the language
the audit was requested in.
"""
import logging
import re
from datetime import datetime, timezone, timedelta

from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)


CATEGORIES = {
    'security':   'Security',
    'ci_cd':      'CI/CD',
    'docker':     'Docker',
    'docs':       'Documentation',
    'deps':       'Dependencies',
    'code':       'Code quality',
    'ops':        'Operations',
    'iac':        'Infrastructure as Code',
    'ai_agents':  'AI agent safety',
}

SEVERITY_WEIGHTS = {'crit': 30, 'warn': 15, 'info': 5}

# Bump only when `calculate_score()`, `SEVERITY_WEIGHTS`, or which checks count
# toward `scored()` changes — never for a new check_id or wording change, which
# shift the score through the normal earned/total math and need no explanation.
# `Audit.score_version` records which one produced a given row, so a trend
# chart can mark the point where the definition itself moved instead of
# presenting it as a plain rise or fall.
SCORE_VERSION = 3
# v3 (accuracy spec, docs/accuracy/): four statuses, checks with no object are
# na instead of pass, detectors look everywhere, applicability by repo kind.

# Repository hygiene: worth seeing, not worth a score. A missing CHANGELOG or
# CODEOWNERS is not a risk the way a leaked key or an unpinned action is, and
# weighing them together made the score read like a checklist — the complaint
# that moved them out (score version 2). They still run, still show in their
# own collapsed section, and still feed the compliance mapping.
HYGIENE_CATEGORY = 'hygiene'
HYGIENE_CHECKS = frozenset({
    'security.codeowners', 'security.security_policy',
    'docs.readme', 'docs.readme_quality', 'docs.changelog', 'docs.contributing', 'docs.templates',
    'ops.license', 'ops.activity', 'ops.env_example', 'ops.gitignore',
})


def counts(check) -> bool:
    """Whether a check dict counts toward the score, the findings and the plan."""
    return check.get('applicable', True) and check.get('category') != HYGIENE_CATEGORY


def _c(check_id, name, description, severity, passed, category, recommendation=''):
    return {
        'check_id': check_id,
        'name': name,
        'description': description,
        'severity': severity,
        'passed': bool(passed),
        'category': category,
        'recommendation': recommendation if not passed else '',
        # repo_kind.apply() clears this for checks the repository cannot act on.
        'applicable': True,
        'not_applicable_reason': '',
        # pass / fail / na / unknown — set once, in finalize_statuses(), after
        # repo_kind and .devopsaudit.yml have had their say.
        'status': '',
        # Where the check looked and what it found: the one line an engineer
        # needs to agree with the verdict or prove it wrong in a minute.
        'evidence': '',
        'unknown': False,
    }


def _find_named(client, stems, dirs=None):
    from app.detectors import DOC_DIRS, find_named
    return find_named(client, stems, dirs or DOC_DIRS)


def _evidence(check, text):
    check['evidence'] = text[:500]
    return check


# ── Candidate path tables ─────────────────────────────────────────────────────

LINTER_FILES = ['.eslintrc', '.eslintrc.js', '.eslintrc.json', '.eslintrc.yml', 'eslint.config.js',
                '.pylintrc', 'pyproject.toml', '.flake8', 'setup.cfg', 'ruff.toml', '.ruff.toml',
                '.rubocop.yml', '.golangci.yml', 'biome.json', '.prettierrc', '.prettierrc.json']
DEP_FILES = ['requirements.txt', 'requirements/base.txt', 'Pipfile', 'pyproject.toml', 'package.json',
             'go.mod', 'Cargo.toml', 'pom.xml', 'build.gradle', 'build.gradle.kts',
             'composer.json', 'Gemfile', 'mix.exs', 'pubspec.yaml']
LOCK_FILES = ['requirements.lock', 'Pipfile.lock', 'package-lock.json', 'yarn.lock',
              'pnpm-lock.yaml', 'bun.lockb', 'go.sum', 'Cargo.lock', 'poetry.lock',
              'uv.lock', 'composer.lock', 'Gemfile.lock', 'mix.lock']
README_FILES = ['README.md', 'README.rst', 'README.txt', 'README', 'readme.md',
                'Readme.md', 'docs/README.md', 'docs/index.md']
CHANGELOG_FILES = ['CHANGELOG.md', 'CHANGELOG.rst', 'CHANGELOG', 'CHANGES.md', 'CHANGES.rst',
                   'CHANGES', 'HISTORY.md', 'HISTORY.rst', 'NEWS.rst', 'RELEASES.md',
                   'docs/changes.rst', 'CHANGELOG.txt']
CONTRIBUTING_FILES = ['CONTRIBUTING.md', 'CONTRIBUTING.rst', '.github/CONTRIBUTING.md',
                      '.github/CONTRIBUTING.rst', 'docs/CONTRIBUTING.md']
LICENSE_FILES = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENSE.rst', 'LICENCE',
                 'LICENCE.md', 'LICENSE-MIT', 'LICENSE-APACHE', 'COPYING']
CODEOWNERS_FILES = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS', '.gitlab/CODEOWNERS']
DOCKERFILES = ['Dockerfile', 'docker/Dockerfile', 'build/Dockerfile', 'deploy/Dockerfile']
COMPOSE_FILES = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml',
                 'docker/docker-compose.yml', 'docker/docker-compose.yaml']
ENV_EXAMPLE_FILES = ['.env.example', '.env.sample', '.env.template', '.env.dist', 'env.example']


# ── Category blocks ───────────────────────────────────────────────────────────

def _security_checks(client, ctx):
    checks = []

    # Secrets: delegated to the full-tree scanner.
    from app.checks_secrets import scan_secrets
    checks += scan_secrets(client, config=ctx.get('config'), deep=ctx.get('deep', False))

    gitignore = ctx['gitignore']
    env_hidden = bool(re.search(r'^\s*!?\*?\.env', gitignore, re.MULTILINE))
    # Only meaningful for projects that actually use a .env file — otherwise this
    # is a rule about a file that does not exist, and failing it is noise.
    uses_dotenv = ctx['uses_dotenv']
    checks.append(_c(
        'security.env_gitignored',
        _('.env is ignored by git'),
        _('A .env file holding secrets must never be committed to the repository.')
        if uses_dotenv else _('This project does not use a .env file.'),
        'crit', (not uses_dotenv) or env_hidden, 'security',
        _('Add a `.env` line to .gitignore, then confirm the file is not already tracked '
          'with `git ls-files .env`. If it is, remove it from history and rotate every value in it.'),
    ))
    if not uses_dotenv:
        _not_applicable(checks[-1], _('This project does not use a .env file.'))

    # GitLab has no Dependabot, Actions or pull requests: advice written for
    # GitHub sent GitLab users to create files that do nothing there.
    on_gitlab = client.provider == 'gitlab'
    has_dependabot = client.any_exists(['.github/dependabot.yml', '.github/dependabot.yaml'])
    has_renovate = client.any_exists(['renovate.json', '.renovaterc', '.renovaterc.json', '.github/renovate.json'])
    checks.append(_c(
        'security.dependency_updates',
        _('Automated dependency updates'),
        _('Dependabot or Renovate opens pull requests as soon as a security patch is released.'),
        'warn', bool(has_dependabot or has_renovate), 'security',
        _('Add renovate.json and enable Renovate for this project (the Mend Renovate app on '
          'gitlab.com, or the renovate-runner pipeline on a self-managed instance) so security '
          'patches arrive as merge requests instead of waiting for someone to notice them. '
          'Dependabot does not run on GitLab.') if on_gitlab else
        _('Add .github/dependabot.yml so security patches arrive as pull requests instead of waiting '
          'for someone to notice them.'),
    ))

    has_security_md = client.any_exists(['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md']) \
        or _find_named(client, ('security',))
    checks.append(_c(
        'security.security_policy',
        _('Security policy (SECURITY.md)'),
        _('Tells researchers how to report a vulnerability privately instead of opening a public issue.'),
        'info', bool(has_security_md), 'security',
        _('Add SECURITY.md with a contact address and your expected response time.'),
    ))

    has_codeowners = client.any_exists(CODEOWNERS_FILES)
    checks.append(_c(
        'security.codeowners',
        _('CODEOWNERS is configured'),
        _('CODEOWNERS automatically requests review from the right people on security-critical paths.'),
        'warn', bool(has_codeowners), 'security',
        _('Create .gitlab/CODEOWNERS:\n* @team-lead\n/config/ @security-team\nThen turn on '
          '"Code owner approval" for the protected branch.') if on_gitlab else
        _('Create .github/CODEOWNERS:\n* @team-lead\n/config/ @security-team'),
    ))

    return checks


def _ci_checks(client, ctx):
    checks = []

    workflow_files = [f for f in client.list_dir('.github/workflows') if f.endswith(('.yml', '.yaml'))]
    has_actions = bool(workflow_files)
    has_gitlab_ci = client.exists('.gitlab-ci.yml')
    has_circle = client.exists('.circleci/config.yml')
    has_jenkins = client.exists('Jenkinsfile')
    has_drone = client.exists('.drone.yml')
    has_ci = has_actions or has_gitlab_ci or has_circle or has_jenkins or has_drone
    ci_tool = ('GitHub Actions' if has_actions else 'GitLab CI' if has_gitlab_ci
               else 'CircleCI' if has_circle else 'Jenkins' if has_jenkins
               else 'Drone' if has_drone else '')
    ctx['ci_tool'] = ci_tool
    ctx['workflow_files'] = workflow_files
    checks.append(_c(
        'ci.pipeline',
        _('CI/CD pipeline configured'),
        _('Detected: %(tool)s.') % {'tool': ci_tool} if has_ci else
        _('No CI configuration found. Every deploy is a manual step that can be skipped or done wrong.'),
        'warn', has_ci, 'ci_cd',
        _('Add .gitlab-ci.yml that runs your tests and linter on every push and merge request.')
        if client.provider == 'gitlab' else
        _('Add .github/workflows/ci.yml (or .gitlab-ci.yml) that runs your tests and linter on every push.'),
    ))

    ci_paths = [f'.github/workflows/{name}' for name in workflow_files[:15]]
    ci_paths += ['.gitlab-ci.yml', '.circleci/config.yml', 'Jenkinsfile', '.drone.yml']
    client.prefetch(ci_paths)
    ci_texts = [c for c in (client.get_content(p) for p in ci_paths) if c]
    ci_blob = '\n'.join(ci_texts).lower()
    ctx['ci_blob'] = ci_blob

    # Direct invocations, plus the task runners that stand in front of them.
    # Looking only for `pytest` marked psf/requests as having no tests in CI —
    # it runs an eight-version matrix through a Makefile.
    test_words = ['pytest', 'npm test', 'npm run test', 'yarn test', 'go test', 'rspec',
                  'jest', 'phpunit', 'cargo test', 'mvn test', 'gradle test', 'manage.py test',
                  'vitest', 'unittest', 'dotnet test', 'bazel test', 'ctest', 'mix test',
                  'make test', 'make ci', 'nox', 'tox', 'hatch test', 'just test',
                  'poetry run test', 'pdm run test', 'npm run ci', 'karma', 'mocha',
                  'playwright test', 'cypress run', 'testthat', 'swift test', 'clj -m',
                  'uv run']
    sources = {p: t for p in ci_paths if (t := client.get_content(p))}
    hit, where = _first_test_command(test_words, sources)
    followed = {}
    if not hit and sources:
        from app.detectors import expand_ci
        followed = expand_ci(client, ci_paths, sources)
        hit, where = _first_test_command(test_words, followed)
    tests_in_ci = bool(hit)
    tests_evidence = f'{where}: {hit}' if hit else ''
    if not tests_in_ci:
        # A workflow that calls itself a test run is a test run. Its steps may
        # be a shell script we cannot read from here — as may the script a
        # `run:` step hands off to, so a path that just says "test" in its own
        # name is read the same way a workflow filename already is below.
        tests_in_ci = (
            any('test' in name.lower() for name in workflow_files)
            or bool(re.search(r'^\s*name:\s*.*test', ci_blob, re.M | re.I))
            or bool(re.search(r'[\w./-]*\btest[\w./-]*\.(?:sh|ps1)\b', ci_blob))
            # A reusable workflow — this repo's own `on: workflow_call` is
            # already in `ci_blob` since it lives under .github/workflows/ and
            # was fetched above; what cannot be read is a *called* workflow
            # defined in another repository. Its path is still visible on the
            # `uses:` line. Matched on "test" only, not "ci" — a filename like
            # `deploy-ci.yml` is common CI branding with no test step in it,
            # and a false pass here inflates a score exactly the way Phase 1
            # exists to stop.
            or bool(re.search(r'uses:\s*\S*\.github/workflows/\S*test\S*\.ya?ml', ci_blob))
            # GitLab: a job in the `test` stage, or a job named after tests,
            # in the pipeline or a file it includes.
            or any(re.search(r'^\s+stage:\s*["\']?test', t, re.M | re.I)
                   or re.search(r'^[a-z0-9][^\n:]*\btests?\b[^\n:]*:\s*$', t, re.M | re.I)
                   for p, t in {**sources, **followed}.items() if 'gitlab-ci' in p or p.endswith('.yml'))
        )
    checks.append(_evidence(_c(
        'ci.tests',
        _('Tests run in CI'),
        _('Running the test suite on every commit is what stops a regression from reaching production.'),
        'warn', tests_in_ci, 'ci_cd',
        _('Add a test step to the pipeline (pytest, jest, go test — whatever your stack uses).'),
    ), tests_evidence or (_('Matched by workflow or job name.') if tests_in_ci else
        _('Checked %(n)d CI file(s) and what they call (%(followed)s) — no test command found.')
        % {'n': len(ci_texts), 'followed': ', '.join(followed) or '—'} if ci_texts else
        _('No CI configuration found.'))))

    protected = client.branch_is_protected()
    checks.append(_c(
        'ci.branch_protection',
        _('Default branch is protected'),
        _('Branch protection stops anyone pushing straight to %(branch)s without review.')
        % {'branch': client.default_branch},
        'warn', protected, 'ci_cd',
        (_('Protect %(branch)s in Settings → Repository → Protected branches: "Allowed to push" '
           'No one, merges through a merge request with at least one approval.')
         if client.provider == 'gitlab' else
         _('Turn on branch protection for %(branch)s: require a pull request and at least one approval '
           'before merging.')) % {'branch': client.default_branch},
    ))
    if protected is None:
        _unknown(checks[-1], _('The provider did not say whether %(branch)s is protected — reading '
                               'protection rules needs a token with admin rights on the repository.')
                 % {'branch': client.default_branch})

    has_linter = client.any_exists(LINTER_FILES)
    checks.append(_c(
        'ci.linter',
        _('Linter or formatter configured'),
        _('A single enforced code style removes a whole class of review comments.'),
        'info', bool(has_linter), 'ci_cd',
        _('Add a linter config: ruff.toml or pyproject.toml for Python, eslint.config.js for JavaScript, '
          '.golangci.yml for Go.'),
    ))

    # Security scanning in the pipeline — a real DevOps practice, not a file-exists check.
    scanner_words = ['trivy', 'snyk', 'semgrep', 'gitleaks', 'bandit', 'codeql', 'grype',
                     'osv-scanner', 'dependency-check', 'checkov', 'tfsec', 'npm audit', 'pip-audit',
                     # GitLab's own scanners arrive as an include, not a command:
                     # `template: Jobs/SAST.gitlab-ci.yml`, `Security/Secret-Detection...`,
                     # or the CI/CD catalog components (`components/sast/sast@1`).
                     # gitlab-org/cli includes two and was marked as having none.
                     'sast.gitlab-ci.yml', 'secret-detection', 'dependency-scanning',
                     'container-scanning', 'components/sast/', 'dast.gitlab-ci.yml']
    has_scanner = any(w in ci_blob for w in scanner_words)
    checks.append(_c(
        'ci.security_scan',
        _('Security scanning in the pipeline'),
        _('A scanner in CI catches vulnerable dependencies and leaked secrets before they merge.'),
        'warn', has_scanner, 'ci_cd',
        _('Add a scanning step to CI. Free options: Trivy for images and dependencies, gitleaks for '
          'secrets, CodeQL for code. Each is a single job in your existing workflow.'),
    ))

    return checks


def _first_test_command(words, sources):
    for path, text in sources.items():
        low = text.lower()
        for w in words:
            if w in low:
                return w, path
    return '', ''


def _docker_checks(client, ctx):
    checks = []
    from app.detectors import find_dockerfiles
    dockerfile_paths = find_dockerfiles(client)
    client.prefetch(dockerfile_paths)
    dockerfiles = {p: c for p in dockerfile_paths if (c := client.get_content(p))}
    dockerfile_path = next(iter(dockerfiles), None)
    dockerfile = dockerfiles.get(dockerfile_path, '') if dockerfile_path else ''
    compose_path, compose = client.first_content(COMPOSE_FILES)
    compose = compose or ''
    ctx['dockerfile'] = dockerfile
    ctx['compose'] = compose
    has_compose = bool(compose)

    checks.append(_c(
        'docker.dockerfile',
        _('Dockerfile present'),
        _('A Dockerfile gives everyone — and production — the same reproducible runtime.'),
        'warn', bool(dockerfile), 'docker',
        _('Add a Dockerfile at the repository root. Use a multi-stage build to keep the final image small.'),
    ))

    dockerfile_check = checks[-1]
    _evidence(dockerfile_check, ', '.join(dockerfiles) if dockerfile else
              _('Searched the whole tree for Dockerfile, Dockerfile.* and *.Dockerfile '
                '(outside tests and examples) — none found.'))

    has_dockerignore = client.exists('.dockerignore') or any(
        client.exists(f'{p.rsplit("/", 1)[0]}/.dockerignore') or client.exists(f'{p}.dockerignore')
        for p in dockerfiles if '/' in p)
    dockerignore = _c(
        'docker.dockerignore',
        _('.dockerignore configured'),
        _('.dockerignore keeps .git, node_modules and secrets out of the build context.'),
        'info', has_dockerignore, 'docker',
        _('Create .dockerignore with at least: .git, node_modules, __pycache__, .env, *.log'),
    )
    if not dockerfile:
        _not_applicable(dockerignore, _('No Dockerfile, so there is no build context to trim.'))
    checks.append(dockerignore)

    has_healthcheck = 'healthcheck' in compose.lower() or any('HEALTHCHECK' in c for c in dockerfiles.values())
    healthcheck = _c(
        'docker.healthcheck',
        _('Healthcheck defined'),
        _('Without a healthcheck the orchestrator cannot tell a starting container from a broken one.'),
        'warn', has_healthcheck, 'docker',
        _('Add to docker-compose.yml:\nhealthcheck:\n  test: ["CMD", "curl", "-f", "http://localhost:8000/health/"]\n'
          '  interval: 30s\n  timeout: 10s\n  retries: 3'),
    )
    if not has_compose and not dockerfile:
        _not_applicable(healthcheck, _('No Dockerfile or compose file to define a healthcheck in.'))
    checks.append(healthcheck)

    def _runs_as_user(text):
        users = re.findall(r'^\s*USER\s+(\S+)', text, re.MULTILINE | re.IGNORECASE)
        # The last USER wins: `USER root` to install, then `USER app` is fine.
        return bool(users) and users[-1].split(':')[0].lower() not in ('root', '0')
    as_root = [p for p, c in dockerfiles.items() if not _runs_as_user(c)]
    has_nonroot = bool(dockerfiles) and not as_root
    nonroot = _c(
        'docker.nonroot',
        _('Container runs as a non-root user'),
        _('A container running as root turns a process escape into host access.'),
        'warn', has_nonroot, 'docker',
        _('Add to the Dockerfile:\nRUN addgroup -S app && adduser -S app -G app\nUSER app'),
    )
    if not dockerfile:
        _not_applicable(nonroot, _('No Dockerfile, so there is no container user to set.'))
    else:
        _evidence(nonroot, (_('Runs as root: %(files)s') % {'files': ', '.join(as_root)}) if as_root
                  else _('USER set to a non-root user in: %(files)s') % {'files': ', '.join(dockerfiles)})
    checks.append(nonroot)

    if dockerfile:
        from_images, unpinned = [], []
        for text in dockerfiles.values():
            stages = {a.lower() for a in re.findall(r'^\s*FROM\s+.*?\s+AS\s+(\S+)', text, re.MULTILINE | re.IGNORECASE)}
            for img in re.findall(r'^\s*FROM\s+(?:--\S+\s+)*(\S+)', text, re.MULTILINE | re.IGNORECASE):
                from_images.append(img)
                if img.lower() in stages or img.lower() == 'scratch' or '$' in img or '@sha256:' in img:
                    continue
                tag = img.rsplit('/', 1)[-1].partition(':')[2]
                # No tag, :latest, or a tag with no version in it at all
                # (python:slim, node:lts-alpine) all float to a new image.
                if not tag or tag.lower() == 'latest' or not re.search(r'\d', tag):
                    unpinned.append(img)
        pinned_ok = not unpinned
        pin_example = unpinned[0] if unpinned else ''
    else:
        pinned_ok, pin_example = True, ''
    pinned = _c(
        'docker.pinned_base',
        _('Base image is pinned (not :latest)'),
        _('FROM %(image)s resolves to something different on every build — including in production.')
        % {'image': pin_example} if pin_example else
        _('Base images are pinned to explicit tags.'),
        'warn', pinned_ok, 'docker',
        _('Replace floating tags with explicit ones, for example FROM python:3.11-slim or FROM node:20-alpine. '
          'Pin by digest for the strongest guarantee.'),
    )
    if not dockerfile:
        _not_applicable(pinned, _('No Dockerfile, so there is no base image to pin.'))
    else:
        _evidence(pinned, ('%s: FROM %s' % (', '.join(dockerfiles), ', '.join(dict.fromkeys(from_images))))[:500])
    checks.append(pinned)

    if dockerfile:
        multistage = any(len(re.findall(r'^\s*FROM\s+', c, re.MULTILINE | re.IGNORECASE)) > 1
                         for c in dockerfiles.values())
    else:
        multistage = True
    multistage_check = _c(
        'docker.multistage',
        _('Dockerfile uses a multi-stage build'),
        _('A multi-stage build leaves compilers and build tools out of the shipped image.'),
        'warn', multistage, 'docker',
        _('Split the build:\nFROM python:3.11 AS builder\nRUN pip install --prefix=/install -r requirements.txt\n'
          'FROM python:3.11-slim\nCOPY --from=builder /install /usr/local'),
    )
    if not dockerfile:
        _not_applicable(multistage_check, _('No Dockerfile to build in stages.'))
    checks.append(multistage_check)

    if has_compose:
        has_limits = 'mem_limit' in compose or ('deploy' in compose and 'limits' in compose)
    else:
        has_limits = True
    limits = _c(
        'docker.resource_limits',
        _('Resource limits set in compose'),
        _('Without memory limits one runaway container can take the whole host down with it.'),
        'warn', has_limits, 'docker',
        _('Add to each service:\ndeploy:\n  resources:\n    limits:\n      memory: 512M\n      cpus: "0.5"'),
    )
    if not has_compose:
        _not_applicable(limits, _('No compose file to set resource limits in.'))
    checks.append(limits)

    return checks


def _docs_checks(client, ctx):
    checks = []
    readme_path, readme = client.first_content(README_FILES)
    readme = readme or ''

    checks.append(_c(
        'docs.readme',
        _('README exists'),
        _('The README is the first thing anyone opening the repository reads.'),
        'info', bool(readme_path), 'docs',
        _('Add README.md covering what the project does, how to run it locally, and how to run the tests.'),
    ))

    # Quality of the README, not just its presence.
    if readme:
        lower = readme.lower()
        has_setup = any(w in lower for w in ['install', 'setup', 'getting started', 'quick start',
                                             'quickstart', 'usage', 'запуск', 'установка'])
        substantial = len(readme.strip()) > 500
        readme_ok = has_setup and substantial
    else:
        readme_ok = False
    checks.append(_c(
        'docs.readme_quality',
        _('README explains how to run the project'),
        _('A README without setup instructions costs every new developer their first day.'),
        'warn', readme_ok, 'docs',
        _('Expand the README with a Getting started section: prerequisites, install command, '
          'how to run the app, how to run the tests.'),
    ))

    from app.detectors import find_changelog
    changelog_path = client.any_exists(CHANGELOG_FILES) or find_changelog(client)
    checks.append(_evidence(_c(
        'docs.changelog',
        _('CHANGELOG maintained'),
        _('A changelog tells users and your own team what actually changed between releases.'),
        'info', bool(changelog_path), 'docs',
        _('Add CHANGELOG.md and follow the keepachangelog.com format.'),
    ), changelog_path if changelog_path and isinstance(changelog_path, str) else
        '' if changelog_path else _('Looked for CHANGELOG, CHANGES, HISTORY, NEWS, RELEASES and release notes '
                                    '(any case and extension) in the root, .github/ and docs/, and for changelog '
                                    'tooling — none found.')))

    checks.append(_c(
        'docs.contributing',
        _('CONTRIBUTING guide'),
        _('A contribution guide lowers the barrier for the next person who wants to help.'),
        'info', bool(client.any_exists(CONTRIBUTING_FILES) or _find_named(client, ('contributing',))), 'docs',
        _('Add CONTRIBUTING.md describing the flow: fork, branch, merge request, review.')
        if client.provider == 'gitlab' else
        _('Add CONTRIBUTING.md describing the flow: fork, branch, pull request, review.'),
    ))

    has_pr_tpl = client.any_exists([
        '.github/pull_request_template.md', '.github/PULL_REQUEST_TEMPLATE.md',
        '.gitlab/merge_request_templates', 'docs/pull_request_template.md',
    ]) or bool(client.list_dir('.github/PULL_REQUEST_TEMPLATE'))
    has_issue_tpl = bool(client.list_dir('.github/ISSUE_TEMPLATE')) or client.any_exists([
        '.github/issue_template.md', '.gitlab/issue_templates',
    ])
    checks.append(_c(
        'docs.templates',
        _('Pull request / issue templates'),
        _('Templates make sure every PR and bug report arrives with the context reviewers need.'),
        'info', has_pr_tpl or has_issue_tpl, 'docs',
        _('Add .gitlab/merge_request_templates/Default.md and .gitlab/issue_templates/Bug.md.')
        if client.provider == 'gitlab' else
        _('Add .github/pull_request_template.md and .github/ISSUE_TEMPLATE/bug_report.md.'),
    ))

    return checks


def _deps_checks(client, ctx):
    checks = []

    found_dep = client.any_exists(DEP_FILES)
    checks.append(_evidence(_c(
        'deps.manifest',
        _('Dependency manifest present'),
        _('Without a manifest the environment cannot be reproduced or scanned for vulnerabilities.'),
        'crit', bool(found_dep), 'deps',
        _('Add a dependency file: requirements.txt or pyproject.toml (Python), package.json (Node), '
          'go.mod (Go), Cargo.toml (Rust).'),
    ), found_dep if isinstance(found_dep, str) else
        '' if found_dep else _('Looked in: %(paths)s — none found.') % {'paths': ', '.join(DEP_FILES)}))

    lock_path = client.any_exists(LOCK_FILES)
    lockfile = _evidence(_c(
        'deps.lockfile',
        _('Lock file present'),
        _('A lock file pins exact versions so the build you tested is the build you ship.'),
        'warn', bool(lock_path), 'deps',
        _('Generate a lock file: `pip freeze > requirements.lock`, `npm install`, `poetry lock`, '
          '`go mod tidy` or `cargo build` depending on your stack.'),
    ), lock_path if isinstance(lock_path, str) else '')
    if not found_dep:
        _not_applicable(lockfile, _('No dependency manifest, so there is nothing to lock.'))
    checks.append(lockfile)

    req = client.get_content('requirements.txt') or ''
    if req:
        lines = [l.strip() for l in req.splitlines()
                 if l.strip() and not l.strip().startswith(('#', '-', '.')) and not l.strip().startswith('git+')]
        unpinned = [l for l in lines if '==' not in l and '~=' not in l]
        pinned_ok = not unpinned
    else:
        pinned_ok = True
    pinned = _c(
        'deps.pinned',
        _('Dependencies pinned to exact versions'),
        _('Ranges such as >= mean two builds of the same commit can install different code.'),
        'warn', pinned_ok, 'deps',
        _('Run `pip freeze > requirements.txt` to pin exact versions, and let Renovate raise them.')
        if client.provider == 'gitlab' else
        _('Run `pip freeze > requirements.txt` to pin exact versions, and let Dependabot raise them.'),
    )
    if not req:
        _not_applicable(pinned, _('No requirements.txt to check for exact versions.'))
    elif not pinned_ok:
        _evidence(pinned, 'requirements.txt: ' + ', '.join(unpinned[:5]))
    checks.append(pinned)

    return checks


def _ops_checks(client, ctx):
    checks = []
    gitignore = ctx['gitignore']

    checks.append(_c(
        'ops.gitignore',
        _('.gitignore configured'),
        _('Without .gitignore, build output and local secrets end up committed sooner or later.'),
        'crit', bool(gitignore), 'ops',
        _('Add a .gitignore for your stack — gitignore.io generates one from a language list.'),
    ))

    env_in_gitignore = '.env' in gitignore
    has_env_example = client.any_exists(ENV_EXAMPLE_FILES)
    env_example = _c(
        'ops.env_example',
        _('.env.example documents required variables'),
        _('When .env is ignored and undocumented, nobody new can start the project.'),
        'warn', (not env_in_gitignore) or bool(has_env_example), 'ops',
        _('Add .env.example listing every variable the app reads, with placeholder values.'),
    )
    if not ctx['uses_dotenv']:
        _not_applicable(env_example, _('This project does not use a .env file.'))
    checks.append(env_example)

    license_path = client.any_exists(LICENSE_FILES) or _find_named(
        client, ('license', 'licence', 'copying', 'unlicense', 'license-mit', 'license-apache'), ('',))
    checks.append(_evidence(_c(
        'ops.license',
        _('License specified'),
        _('Without a license, nobody else has legal permission to use the code.'),
        'info', bool(license_path), 'ops',
        _('Add a LICENSE file — MIT or Apache 2.0 for open source, or a proprietary notice for closed code.'),
    ), license_path or _('Looked in: %(paths)s — none found.') % {'paths': ', '.join(LICENSE_FILES)}))

    pushed_at = client.pushed_at
    if pushed_at:
        age = datetime.now(timezone.utc) - pushed_at
        is_active = age < timedelta(days=180)
        days_ago = age.days
    else:
        is_active, days_ago = False, 999
    checks.append(_c(
        'ops.activity',
        _('Repository is actively maintained'),
        _('Last commit was %(days)d days ago.') % {'days': days_ago} if not is_active else
        _('Last commit is recent.'),
        'info', is_active, 'ops',
        _('Either bring the project up to date or archive it so nobody depends on it by mistake.'),
    ))

    return checks


# ── Entry point ───────────────────────────────────────────────────────────────

def run_all_checks(client, config=None, deep=False) -> list[dict]:
    """
    Run every applicable check against a loaded RepoClient.

    `config` is the repository's own `.devopsaudit.yml`; it is read here when a
    caller does not already hold one.

    `deep` is only for repositories their owner connected: it clones the git
    history to scan it for secrets and asks providers whether found keys still
    work. The public scanner leaves it off and stays at three API calls.
    """
    logger.info('Audit [%s/%s]: starting checks', client.provider, client.full_name)

    # The repository's own say, if it ships one. Read first: `kind:` overrides
    # what detection would guess, and `allow_secrets:` reaches the scanner.
    from app import audit_config
    if config is None:
        config = audit_config.load(client)

    # A handful of files are read by several checks; fetch them together once.
    client.prefetch(['.gitignore', 'requirements.txt', 'pyproject.toml', 'package.json',
                     'go.mod', 'Cargo.toml', *DOCKERFILES, *COMPOSE_FILES, *README_FILES])

    gitignore = client.get_content('.gitignore') or ''
    dep_blob = ' '.join(filter(None, [
        client.get_content('requirements.txt'), client.get_content('pyproject.toml'),
        client.get_content('package.json'), client.get_content('go.mod'),
    ])).lower()
    ctx = {
        'config': config,
        'deep': deep,
        'gitignore': gitignore,
        # Evidence that the project reads configuration from a .env file at all.
        'uses_dotenv': (
            any(p == '.env' or p.endswith('/.env') for p in client.files)
            or bool(client.any_exists(ENV_EXAMPLE_FILES))
            or any(lib in dep_blob for lib in
                   ('python-dotenv', 'dotenv', 'django-environ', 'environs', 'godotenv', 'viper'))
        ),
    }

    checks = []
    checks += _security_checks(client, ctx)
    checks += _ci_checks(client, ctx)
    checks += _docker_checks(client, ctx)
    checks += _docs_checks(client, ctx)
    checks += _deps_checks(client, ctx)
    checks += _ops_checks(client, ctx)

    from app.checks_extra import (
        check_cve_vulnerabilities,
        check_kubernetes_security,
        check_observability,
    )
    from app.checks_cicd import check_github_actions, check_gitlab_ci
    checks += check_cve_vulnerabilities(client.get_content, client=client)
    if client.provider != 'gitlab':
        checks += check_github_actions(client)
    # Whatever the host: a GitHub mirror of a GitLab project still runs its
    # pipeline from this file.
    checks += check_gitlab_ci(client)
    checks += check_kubernetes_security(client.get_content, client.list_dir)
    checks += check_observability(client.get_content)

    from app.checks_iac import check_iac
    checks += check_iac(client)

    from app.checks_ai_agents import check_ai_agents
    checks += check_ai_agents(client)

    # Set aside the checks this kind of repository cannot act on, so the score
    # reflects what it could have done rather than what it was never going to be.
    from app import repo_kind
    kind, skipped, _reason, _confidence = repo_kind.apply(checks, client, forced_kind=config.kind)
    ignored = audit_config.apply(checks, config)
    for c in checks:
        if c['check_id'] in HYGIENE_CHECKS:
            c['category'] = HYGIENE_CATEGORY
            c['severity'] = 'info'
    finalize_statuses(checks)

    logger.info(
        'Audit [%s/%s]: %d checks (%s, %d not applicable, %d ignored by config) in %d API calls',
        client.provider, client.full_name, len(checks), kind, skipped, ignored, client.api_calls,
    )
    return checks


def _not_applicable(check, reason):
    """
    Mark a check that had nothing to inspect.

    These used to be recorded as passes: a repository with no Dockerfile
    collected four free warn-weight passes for healthcheck, pinned base image,
    multi-stage build and compose limits — sixty points for shipping no
    container at all. That is an inflated score, and an inflated score is one
    nobody can defend in front of an auditor.
    """
    check['applicable'] = False
    check['not_applicable_reason'] = reason
    check['recommendation'] = ''
    return check


def _unknown(check, reason):
    """
    Mark a check that could not be answered — no permission, API down.

    Stored like a not-applicable one (out of the score, reason shown) but with
    its own status: "we could not see" is not "does not apply", and neither is
    a fail the reader could disprove by opening the settings page.
    """
    _not_applicable(check, reason)
    check['unknown'] = True
    return check


def status_of(check) -> str:
    if check.get('unknown'):
        return 'unknown'
    if not check.get('applicable', True):
        return 'na'
    return 'pass' if check.get('passed') else 'fail'


def finalize_statuses(checks: list[dict]) -> list[dict]:
    """
    Settle each check's status and make sure it carries evidence.

    Runs last, so whatever repo_kind or .devopsaudit.yml set aside is `na`.
    A check that has nothing better falls back to its reason or description,
    so no result reaches the report without a "why".
    """
    for c in checks:
        c['status'] = status_of(c)
        if c['status'] in ('na', 'unknown'):
            c['evidence'] = c.get('not_applicable_reason') or c.get('evidence') or ''
        elif not c.get('evidence'):
            c['evidence'] = c.get('description', '')[:500]
    return checks


def scored(checks: list[dict]) -> list[dict]:
    """The checks that count. A repository is not marked down for what it cannot be."""
    return [c for c in checks if counts(c)]


def calculate_score(checks: list[dict]) -> int:
    total = earned = 0
    for c in scored(checks):
        w = SEVERITY_WEIGHTS.get(c['severity'], 5)
        total += w
        if c['passed']:
            earned += w
    return round(earned / total * 100) if total else 0


def get_category_scores(checks: list[dict]) -> dict:
    """Score per category, on the same weighting as the overall score."""
    from collections import defaultdict
    cat_total = defaultdict(int)
    cat_earned = defaultdict(int)
    for c in scored(checks):
        cat = c.get('category', 'ops')
        w = SEVERITY_WEIGHTS.get(c['severity'], 5)
        cat_total[cat] += w
        if c['passed']:
            cat_earned[cat] += w
    return {
        cat: round(cat_earned[cat] / cat_total[cat] * 100) if cat_total[cat] else 0
        for cat in cat_total
    }
