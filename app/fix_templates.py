"""
One-click Fix: статические шаблоны файлов для каждого типа проверки.

detect_ecosystem(audit_checks) — определяет стек (python/node/go/rust) по пройденным проверкам.
FIXABLE_CHECKS — отображение имени проверки на (filename, template_fn(ecosystem, repo_name)).
get_fix(check_name, ecosystem, repo_name, host) — возвращает (filename, content) или None.
"""
import logging

logger = logging.getLogger(__name__)


# ── Определение стека ─────────────────────────────────────────────────────────

def detect_ecosystem(checks) -> str:
    """
    Определяет основной язык/стек репозитория по прошедшим проверкам.
    checks — итерабельный объект с атрибутами name и passed (QuerySet или list[dict]).
    """
    passed_names: set[str] = set()
    for c in checks:
        if isinstance(c, dict):
            if c.get('passed'):
                passed_names.add(c.get('name', ''))
        else:
            if c.passed:
                passed_names.add(c.name)

    name_str = ' '.join(passed_names).lower()

    if 'requirements' in name_str or 'pipfile' in name_str or 'pyproject' in name_str:
        return 'python'
    if 'package.json' in name_str or 'node' in name_str or 'npm' in name_str:
        return 'node'
    if 'go.mod' in name_str or 'golang' in name_str:
        return 'go'
    if 'cargo' in name_str or 'rust' in name_str:
        return 'rust'
    return 'generic'


# ── Шаблоны файлов ───────────────────────────────────────────────────────────

def _dependabot(ecosystem: str, repo_name: str) -> tuple[str, str]:
    eco_map = {
        'python': 'pip',
        'node':   'npm',
        'go':     'gomod',
        'rust':   'cargo',
    }
    pkg_eco = eco_map.get(ecosystem, 'pip')
    content = f"""version: 2
updates:
  - package-ecosystem: "{pkg_eco}"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "security"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
"""
    return '.github/dependabot.yml', content


def _renovate(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = """{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": [
    "config:recommended",
    ":dependencyDashboard",
    "security:openssf-scorecard"
  ],
  "schedule": ["every weekend"],
  "prConcurrentLimit": 10,
  "labels": ["dependencies"],
  "packageRules": [
    {
      "matchUpdateTypes": ["patch"],
      "automerge": true
    }
  ]
}
"""
    return 'renovate.json', content


def _security_md(ecosystem: str, repo_name: str) -> tuple[str, str]:
    name = repo_name.split('/')[-1] if '/' in repo_name else repo_name
    content = f"""# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing: security@{name}.example.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within **48 hours** and aim to provide
a fix within **7 days** for critical issues.

## Security Measures

- Dependencies are monitored via Dependabot
- All PRs require code review before merge
- Branch protection is enabled on `main`
"""
    return 'SECURITY.md', content


def _env_example(ecosystem: str, repo_name: str) -> tuple[str, str]:
    python_extras = """
# Database
DATABASE_URL=postgres://user:password@localhost:5432/dbname

# Cache / Broker
REDIS_URL=redis://localhost:6379/0

# Django (if applicable)
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1
""" if ecosystem == 'python' else ''

    node_extras = """
# Database
DATABASE_URL=postgres://user:password@localhost:5432/dbname

# App
NODE_ENV=production
PORT=3000
""" if ecosystem == 'node' else ''

    content = f"""# Environment variables — copy to .env and fill in values
# Never commit .env to version control!

# App
APP_ENV=development

{python_extras}{node_extras}
# External APIs (replace with actual values)
# API_KEY=
# API_SECRET=

# Email (optional)
# SMTP_HOST=
# SMTP_PORT=587
# SMTP_USER=
# SMTP_PASS=
"""
    return '.env.example', content


def _dockerignore(ecosystem: str, repo_name: str) -> tuple[str, str]:
    python_section = """
# Python
__pycache__/
*.py[cod]
*.pyo
.pytest_cache/
.mypy_cache/
.ruff_cache/
venv/
.venv/
*.egg-info/
dist/
build/
""" if ecosystem == 'python' else ''

    node_section = """
# Node
node_modules/
npm-debug.log*
.npm/
dist/
build/
.next/
""" if ecosystem == 'node' else ''

    content = f"""# Docker build context exclusions — reduces image size and speeds up builds

# Version control
.git/
.gitignore
.github/
.gitlab/
.gitlab-ci.yml

# Environment
.env
.env.*
!.env.example

# Docs & CI
*.md
.editorconfig
.prettierrc*
.eslintrc*

{python_section}{node_section}
# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Tests (not needed in prod image)
tests/
test/
*.test.*
*.spec.*
coverage/
.coverage
"""
    return '.dockerignore', content


def _codeowners(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = """# CODEOWNERS — automatically requests reviews for changed files
# Syntax: <pattern> <@user or @org/team>
# https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners

# Default: all files require review from team lead
*                           @team-lead

# Security-sensitive configuration
.github/                    @security-team @team-lead
config/                     @security-team
*.env.example               @security-team

# Infrastructure
Dockerfile                  @devops-team
docker-compose*.yml         @devops-team
k8s/                        @devops-team
terraform/                  @devops-team

# CI/CD pipelines
.github/workflows/          @devops-team @team-lead
"""
    return '.github/CODEOWNERS', content


def _pr_template(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = """## Summary

<!-- Describe the change and why it's needed. Link the issue: Closes #123 -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to change)
- [ ] Refactoring (no functional changes)
- [ ] Documentation update
- [ ] Dependencies update

## Testing

- [ ] I have added tests that prove my fix / feature works
- [ ] New and existing unit tests pass locally
- [ ] I have tested this manually

## Checklist

- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented any hard-to-understand code
- [ ] I have updated documentation if needed
- [ ] No secrets or credentials are included
"""
    return '.github/pull_request_template.md', content


def _contributing(ecosystem: str, repo_name: str) -> tuple[str, str]:
    name = repo_name.split('/')[-1] if '/' in repo_name else repo_name
    content = f"""# Contributing to {name}

Thank you for considering contributing! Here's how to get started.

## Development Setup

1. Fork the repository and clone your fork
2. Copy `.env.example` to `.env` and fill in values
3. Install dependencies and start the dev environment

## Workflow

1. Create a branch: `git checkout -b feat/your-feature`
2. Make your changes with tests
3. Run the test suite and make sure everything passes
4. Commit with a clear message: `git commit -m "feat: add X"`
5. Push and open a Pull Request

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Describe the change and link the related issue
- Ensure CI passes before requesting review
- Add or update tests for your changes

## Commit Message Format

```
type(scope): short description

feat:     new feature
fix:      bug fix
docs:     documentation
refactor: code change with no behaviour change
test:     adding or fixing tests
chore:    build process or tooling
```

## Reporting Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behaviour
- Version info
"""
    return 'CONTRIBUTING.md', content


def _changelog(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = """# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- (describe new features here)

### Changed
- (describe changes in existing functionality)

### Fixed
- (describe bug fixes)

### Removed
- (describe removed features)

## [1.0.0] - YYYY-MM-DD

### Added
- Initial release
"""
    return 'CHANGELOG.md', content


def _license_mit(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = """MIT License

Copyright (c) YYYY <Your Name>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
    return 'LICENSE', content


def _ci_workflow(ecosystem: str, repo_name: str) -> tuple[str, str]:
    if ecosystem == 'python':
        test_steps = """      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run linter
        run: flake8 . --max-line-length=120 || true

      - name: Run tests
        run: pytest --tb=short"""
        setup = """      - name: Set up Python
        uses: actions/setup-python@82c7e631bb3cdc910f68e0081d67478d79c6982d  # v5
        with:
          python-version: "3.11"
          cache: "pip" """
    elif ecosystem == 'node':
        test_steps = """      - name: Install dependencies
        run: npm ci

      - name: Run linter
        run: npm run lint --if-present

      - name: Run tests
        run: npm test"""
        setup = """      - name: Set up Node.js
        uses: actions/setup-node@cdca7365b2dadb8aad0a33bc7601856ffabcc48e  # v4
        with:
          node-version: "20"
          cache: "npm" """
    elif ecosystem == 'go':
        test_steps = """      - name: Run tests
        run: go test ./... -v

      - name: Run vet
        run: go vet ./..."""
        setup = """      - name: Set up Go
        uses: actions/setup-go@d60b41a563a30c9f8b0b4f2cbbf17dc4d6cc6d0b  # v5
        with:
          go-version: "1.22" """
    else:
        test_steps = """      - name: Run tests
        run: echo "Add your test command here" """
        setup = ''

    content = f"""name: CI

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

{setup}

{test_steps}
"""
    return '.github/workflows/ci.yml', content


def _dockerfile_nonroot(ecosystem: str, repo_name: str) -> tuple[str, str]:
    if ecosystem == 'python':
        content = """# Add this to your Dockerfile to run as non-root:

# --- Paste BEFORE your CMD/ENTRYPOINT ---
RUN groupadd -r appgroup && useradd -r -g appgroup appuser \\
    && chown -R appuser:appgroup /app
USER appuser
# ----------------------------------------

# Full example:
# FROM python:3.11-slim
# WORKDIR /app
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt
# COPY . .
# RUN groupadd -r appgroup && useradd -r -g appgroup appuser \\
#     && chown -R appuser:appgroup /app
# USER appuser
# CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
"""
    elif ecosystem == 'node':
        content = """# Add this to your Dockerfile to run as non-root:

# --- Paste BEFORE your CMD/ENTRYPOINT ---
RUN groupadd -r appgroup && useradd -r -g appgroup appuser \\
    && chown -R appuser:appgroup /app
USER appuser
# ----------------------------------------

# Full example:
# FROM node:20-alpine
# WORKDIR /app
# COPY package*.json ./
# RUN npm ci --only=production
# COPY . .
# RUN addgroup -S appgroup && adduser -S appuser -G appgroup \\
#     && chown -R appuser:appgroup /app
# USER appuser
# EXPOSE 3000
# CMD ["node", "server.js"]
"""
    else:
        content = """# Add this to your Dockerfile to run as non-root:

# --- Paste BEFORE your CMD/ENTRYPOINT ---
RUN groupadd -r appgroup && useradd -r -g appgroup appuser \\
    && chown -R appuser:appgroup /app
USER appuser
# ----------------------------------------

# Alpine-based images use different syntax:
# RUN addgroup -S appgroup && adduser -S appuser -G appgroup
# USER appuser
"""
    return 'Dockerfile.patch', content


def _k8s_resource_limits(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = """# Patch: add resource limits to your Kubernetes Deployment
# Apply with: kubectl patch deployment <name> --patch-file=k8s-limits-patch.yaml

spec:
  template:
    spec:
      containers:
        - name: app  # <-- change to your container name
          resources:
            requests:
              memory: "128Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "500m"

# Or add directly to your existing deployment YAML:
#
# spec:
#   template:
#     spec:
#       containers:
#         - name: your-container
#           image: your-image:tag
#           resources:
#             requests:
#               memory: "128Mi"
#               cpu: "100m"
#             limits:
#               memory: "512Mi"
#               cpu: "500m"
"""
    return 'k8s-limits-patch.yaml', content


def _k8s_probes(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = """# Patch: add liveness and readiness probes to your Kubernetes Deployment
# Adjust the path/port to match your application's health endpoint.

spec:
  template:
    spec:
      containers:
        - name: app  # <-- change to your container name
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
            failureThreshold: 3
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 15
            periodSeconds: 30
            failureThreshold: 3

# If your app doesn't have /health yet, add a simple endpoint:
# Python/Django: path('health/', lambda r: JsonResponse({'status': 'ok'}))
# Node/Express:  app.get('/health', (req, res) => res.json({ status: 'ok' }))
# Go:            http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
#                    w.WriteHeader(http.StatusOK)
#                })
"""
    return 'k8s-probes-patch.yaml', content


def _k8s_nonroot(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = """# Patch: enforce non-root security context in Kubernetes Deployment

spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      containers:
        - name: app  # <-- change to your container name
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 1000
            capabilities:
              drop:
                - ALL

# Note: readOnlyRootFilesystem: true may require you to mount volumes
# for directories your app writes to:
#          volumeMounts:
#            - name: tmp
#              mountPath: /tmp
#            - name: cache
#              mountPath: /app/.cache
#      volumes:
#        - name: tmp
#          emptyDir: {}
#        - name: cache
#          emptyDir: {}
"""
    return 'k8s-security-patch.yaml', content


def _github_actions_pin(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = """#!/bin/bash
# Pin all GitHub Actions in .github/workflows/ to SHA hashes
# Requires: pip install pin-github-actions  OR  npm install -g pin-github-actions

# Option 1: step-security/pin-github-actions (recommended)
pip install pin-github-actions
find .github/workflows -name '*.yml' -o -name '*.yaml' | xargs pin-github-actions

# Option 2: Manual pinning example
# Replace floating tags with SHA in your workflow files:
#
# Before:
#   uses: actions/checkout@v4
#
# After (get SHA from GitHub releases page):
#   uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
#
# Common actions with current SHAs (verify these are still current!):
# actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683          # v4.2.2
# actions/setup-python@82c7e631bb3cdc910f68e0081d67478d79c6982d      # v5.4.0
# actions/setup-node@cdca7365b2dadb8aad0a33bc7601856ffabcc48e        # v4.3.0
# actions/cache@5a3ec84eff668545956fd18022155c47e93e2684              # v4.2.0
# docker/build-push-action@471d1dc4e07e5cdcefbea4ba10cbdf5be6d48acf  # v6.12.0
"""
    return 'pin-actions.sh', content


# ── Главная таблица: имя проверки → функция-генератор ─────────────────────────

def _security_scan_workflow(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = f"""# Security scanning for {repo_name}
# Fails the build on a HIGH or CRITICAL finding. Free, no account needed.
name: security

on:
  push:
    branches: [main, master]
  pull_request:
  schedule:
    - cron: "0 6 * * 1"

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          fetch-depth: 0

      - name: Dependency and config scan
        uses: aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0  # v0.29.0
        with:
          scan-type: fs
          scan-ref: .
          severity: HIGH,CRITICAL
          exit-code: "1"
          ignore-unfixed: true

      - name: Secret scan
        uses: gitleaks/gitleaks-action@83373cf2f8c4db6e24b41c1a9b086bb9619e9cd3  # v2.3.7
        env:
          GITHUB_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
"""
    return '.github/workflows/security.yml', content


def _tf_backend(ecosystem: str, repo_name: str) -> tuple[str, str]:
    slug = repo_name.split('/')[-1]
    content = f"""# Remote state with locking for {repo_name}.
# Create the bucket and the lock table once, out of band, then run `terraform init -migrate-state`.
terraform {{
  required_version = ">= 1.6"

  backend "s3" {{
    bucket         = "{slug}-tfstate"
    key            = "prod/terraform.tfstate"
    region         = "eu-central-1"
    dynamodb_table = "{slug}-tfstate-lock"
    encrypt        = true
  }}
}}
"""
    return 'backend.tf', content


def _tf_required_providers(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = f"""# Provider version constraints for {repo_name}.
# Without these, a new provider release can change a plan with no commit on your side.
terraform {{
  required_version = ">= 1.6"

  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
    random = {{
      source  = "hashicorp/random"
      version = "~> 3.6"
    }}
  }}
}}
"""
    return 'versions.tf', content


def _tf_scan_workflow(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = f"""# Terraform scanning for {repo_name}
name: terraform-scan

on:
  pull_request:
    paths: ["**/*.tf", "**/*.tfvars"]
  push:
    branches: [main, master]

permissions:
  contents: read

jobs:
  checkov:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
      - uses: actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38  # v5.4.0
        with:
          python-version: "3.12"
      - run: pip install checkov
      - run: checkov --directory . --quiet --compact --framework terraform
"""
    return '.github/workflows/terraform-scan.yml', content


# ── GitLab ────────────────────────────────────────────────────────────────────
# The templates above are GitHub-shaped: .github/workflows, Dependabot,
# .github/CODEOWNERS, pull request templates. None of that does anything on
# GitLab, and a merge request adding it was a fix that fixed nothing. These are
# the GitLab equivalents, chosen by `host` in get_fix().

_GITLAB_IMAGES = {
    'python': ('python:3.12-slim', 'pip install -r requirements.txt',
               ['ruff check . || flake8 .', 'pytest --tb=short']),
    'node':   ('node:20-slim', 'npm ci', ['npm run lint --if-present', 'npm test']),
    'go':     ('golang:1.22', 'go mod download', ['go vet ./...', 'go test ./...']),
    'rust':   ('rust:1-slim', 'cargo fetch', ['cargo clippy -- -D warnings', 'cargo test']),
}


def _gitlab_ci(ecosystem: str, repo_name: str) -> tuple[str, str]:
    image, install, commands = _GITLAB_IMAGES.get(
        ecosystem, ('alpine:3.20', 'true', ['echo "Add your test command here"']))
    script = '\n'.join(f'    - {c}' for c in commands)
    content = f"""# GitLab CI/CD for {repo_name}: runs lint and tests on every push and merge request.
# Pin the image to a digest (image: name@sha256:...) once this runs green.
stages:
  - test

workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

test:
  stage: test
  image: {image}
  before_script:
    - {install}
  script:
{script}
"""
    return '.gitlab-ci.yml', content


def _gitlab_security_scan(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = f"""# Security scanning for {repo_name}. Fails the pipeline on a HIGH or CRITICAL finding.
#
# This file is not picked up on its own. Add it to .gitlab-ci.yml:
#
#   include:
#     - local: .gitlab/ci/security.gitlab-ci.yml
#
# (It is a separate file so this merge request cannot overwrite your pipeline.)
# GitLab's own scanners are an alternative on any tier:
#   include:
#     - template: Jobs/Secret-Detection.gitlab-ci.yml
#     - template: Jobs/SAST.gitlab-ci.yml

security:trivy:
  stage: test
  image:
    name: aquasec/trivy:0.58.1
    entrypoint: [""]
  script:
    - trivy fs --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed .

security:gitleaks:
  stage: test
  image:
    name: zricethezav/gitleaks:v8.21.2
    entrypoint: [""]
  variables:
    GIT_DEPTH: "0"
  script:
    - gitleaks detect --source . --redact --verbose
"""
    return '.gitlab/ci/security.gitlab-ci.yml', content


def _gitlab_tf_scan(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = f"""# Terraform scanning for {repo_name}.
#
# Add it to .gitlab-ci.yml (a separate file, so this merge request cannot
# overwrite your pipeline):
#
#   include:
#     - local: .gitlab/ci/terraform-scan.gitlab-ci.yml

terraform:checkov:
  stage: test
  image:
    name: bridgecrew/checkov:3.2.334
    entrypoint: [""]
  rules:
    - changes: ["**/*.tf", "**/*.tfvars"]
  script:
    - checkov --directory . --quiet --compact --framework terraform
"""
    return '.gitlab/ci/terraform-scan.gitlab-ci.yml', content


def _gitlab_renovate(ecosystem: str, repo_name: str) -> tuple[str, str]:
    # Dependabot does not exist on GitLab. Renovate does the same job there, but
    # needs a runner: the hosted Mend Renovate app for gitlab.com, or the
    # renovate-runner project on a self-managed instance. Said in the MR too.
    filename, content = _renovate(ecosystem, repo_name)
    content = content.replace('"labels": ["dependencies"],',
                              '"labels": ["dependencies"],\n  "platformAutomerge": false,')
    return filename, content


def _gitlab_codeowners(ecosystem: str, repo_name: str) -> tuple[str, str]:
    content = """# CODEOWNERS — GitLab requests approval from these owners on merge requests
# that touch matching paths. Enforce it under Settings → Repository →
# Protected branches → "Code owner approval".
# https://docs.gitlab.com/ee/user/project/codeowners/

# Default: all files require review from team lead
*                           @team-lead

# Security-sensitive configuration
config/                     @security-team
*.env.example               @security-team

# Infrastructure
Dockerfile                  @devops-team
docker-compose*.yml         @devops-team
k8s/                        @devops-team
terraform/                  @devops-team

# CI/CD pipelines
.gitlab-ci.yml              @devops-team @team-lead
.gitlab/                    @devops-team @team-lead
"""
    return '.gitlab/CODEOWNERS', content


def _gitlab_mr_template(ecosystem: str, repo_name: str) -> tuple[str, str]:
    _name, content = _pr_template(ecosystem, repo_name)
    content = content.replace('Closes #123', 'Closes #123 (GitLab closes the issue on merge)')
    return '.gitlab/merge_request_templates/Default.md', content


def _gitlab_contributing(ecosystem: str, repo_name: str) -> tuple[str, str]:
    filename, content = _contributing(ecosystem, repo_name)
    content = (content
               .replace('Fork the repository and clone your fork', 'Fork the project (or create a branch if you are a member) and clone it')
               .replace('5. Push and open a Pull Request', '5. Push and open a Merge Request')
               .replace('## Pull Request Guidelines', '## Merge Request Guidelines')
               .replace('Keep PRs focused — one feature or fix per PR', 'Keep merge requests focused — one feature or fix per MR')
               .replace('Ensure CI passes', 'Ensure the pipeline passes'))
    return filename, content


def _gitlab_security_md(ecosystem: str, repo_name: str) -> tuple[str, str]:
    filename, content = _security_md(ecosystem, repo_name)
    content = (content
               .replace('**Do not open a public GitHub issue for security vulnerabilities.**',
                        '**Do not open a public issue for security vulnerabilities** — use a '
                        'confidential issue in this project, or email:')
               .replace('- Dependencies are monitored via Dependabot', '- Dependencies are monitored via Renovate')
               .replace('- All PRs require code review before merge', '- All merge requests require approval before merge')
               .replace('- Branch protection is enabled on `main`', '- `main` is a protected branch'))
    return filename, content


# check_id → template on GitLab. None: the check has no GitLab counterpart to
# fix (GitHub Actions pinning), so no merge request is offered.
_GITLAB_FIXABLE: dict[str, callable] = {
    'security.dependency_updates':   _gitlab_renovate,
    'security.security_policy':      _gitlab_security_md,
    'security.codeowners':           _gitlab_codeowners,
    'actions.pinned_sha':            None,
    'ci.pipeline':                   _gitlab_ci,
    'ci.security_scan':              _gitlab_security_scan,
    'iac.scanning':                  _gitlab_tf_scan,
    'docs.templates':                _gitlab_mr_template,
    'docs.contributing':             _gitlab_contributing,
}


_FIXABLE: dict[str, callable] = {
    # Security
    'security.dependency_updates':   _dependabot,
    'security.security_policy':      _security_md,
    'security.codeowners':           _codeowners,
    'actions.pinned_sha':            _github_actions_pin,

    # CI/CD
    'ci.pipeline':                   _ci_workflow,
    'ci.security_scan':              _security_scan_workflow,

    # Docker
    'docker.dockerignore':           _dockerignore,
    'docker.nonroot':                _dockerfile_nonroot,

    # Docs / ops
    'ops.env_example':               _env_example,
    'docs.templates':                _pr_template,
    'docs.contributing':             _contributing,
    'docs.changelog':                _changelog,
    'ops.license':                   _license_mit,

    # Kubernetes
    'k8s.resource_limits':           _k8s_resource_limits,
    'k8s.probes':                    _k8s_probes,
    'k8s.nonroot':                   _k8s_nonroot,

    # Infrastructure as Code
    'iac.remote_state':              _tf_backend,
    'iac.pinned_providers':          _tf_required_providers,
    'iac.scanning':                  _tf_scan_workflow,
}

# Display names are translated per audit, so a check is looked up by its stable
# check_id. Older audit rows predate check_id — this table keeps them working.
_LEGACY_NAME_TO_ID = {
    'Автообновление зависимостей':          'security.dependency_updates',
    'Автообновление зависимостей (Renovate)': 'security.dependency_updates',
    'Security policy (SECURITY.md)':        'security.security_policy',
    'CODEOWNERS настроен':                  'security.codeowners',
    'GitHub Actions: закреплены по SHA':    'actions.pinned_sha',
    'CI/CD пайплайн настроен':              'ci.pipeline',
    'GitLab CI/CD пайплайн настроен':       'ci.pipeline',
    '.dockerignore настроен':               'docker.dockerignore',
    'Non-root пользователь в Dockerfile':   'docker.nonroot',
    '.env.example документирует переменные': 'ops.env_example',
    'PR / Issue шаблоны':                   'docs.templates',
    'Merge Request шаблон':                 'docs.templates',
    'CONTRIBUTING guide':                   'docs.contributing',
    'CHANGELOG ведётся':                    'docs.changelog',
    'Лицензия указана':                     'ops.license',
    'K8s: лимиты ресурсов на подах':        'k8s.resource_limits',
    'K8s: liveness и readiness пробы':      'k8s.probes',
    'K8s: контейнеры без root-привилегий':  'k8s.nonroot',
}


def resolve_check_id(check) -> str:
    """The check_id for an AuditCheck row, falling back to its display name."""
    cid = getattr(check, 'check_id', '') or ''
    if cid:
        return cid
    return _LEGACY_NAME_TO_ID.get(getattr(check, 'name', ''), '')


def _template_for(check_id: str, host: str):
    key = check_id if check_id in _FIXABLE else _LEGACY_NAME_TO_ID.get(check_id, '')
    if key not in _FIXABLE:
        return None
    if host == 'gitlab' and key in _GITLAB_FIXABLE:
        return _GITLAB_FIXABLE[key]
    return _FIXABLE[key]


def get_fix(check_id: str, ecosystem: str, repo_name: str, host: str = 'github') -> tuple[str, str] | None:
    """
    Returns (filename, content) for a fixable check, or None if no template exists.

    `host` is where the repository lives ('github' or 'gitlab'): the same
    finding needs a different file on each — see _GITLAB_FIXABLE.
    """
    fn = _template_for(check_id, host)
    if fn is None:
        logger.debug("No fix template for check: %s (host=%s)", check_id, host)
        return None
    filename, content = fn(ecosystem, repo_name)
    logger.info("Generated fix template: check=%s ecosystem=%s host=%s file=%s",
                check_id, ecosystem, host, filename)
    return filename, content


def is_fixable(check_id: str, host: str = 'github') -> bool:
    from app.content_fixes import has_fixer
    key = check_id if check_id in _FIXABLE else _LEGACY_NAME_TO_ID.get(check_id, check_id)
    return has_fixer(key, host) or _template_for(check_id, host) is not None
