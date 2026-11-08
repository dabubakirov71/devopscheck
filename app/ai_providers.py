import logging
import os
import re

import requests

from app.checks_secrets import redact
from app.checks import counts as _counts  # noqa: E402

logger = logging.getLogger(__name__)

PROVIDERS = {
    'anthropic': {'name': 'Anthropic Claude', 'env_key': 'ANTHROPIC_API_KEY', 'default_model': 'claude-haiku-4-5-20251001'},
    'openai':    {'name': 'OpenAI',            'env_key': 'OPENAI_API_KEY',    'default_model': 'gpt-4o-mini'},
    'gemini':    {'name': 'Google Gemini',     'env_key': 'GEMINI_API_KEY',    'default_model': 'gemini-3.8-flash'},
}


def _server_key_allowed(name, is_private):
    """
    Whether the server's own key for `name` may see this repository's content.

    A free-tier Gemini key (GEMINI_FREE_TIER, on by default) comes with terms
    that let Google use prompts to improve its products. Public code is public
    already; private code going there would break what /trust/ promises. So a
    free-tier key serves public repositories only, and private ones go to a
    paid provider or to the built-in rules.
    """
    if name != 'gemini' or not is_private:
        return True
    return os.environ.get('GEMINI_FREE_TIER', '1').lower() in ('0', 'false', 'no')


def _get_active_provider(user_id=None, is_private=True):
    """
    Returns (provider_name, api_key). A user's own key takes priority over env vars.

    Server keys are then chosen by what the repository is: public code may use
    the free Gemini tier and prefers it; private code never does (see
    `_server_key_allowed`). `is_private` defaults to True — unknown is private.

    `(None, None)` when the account has turned AI analysis off, which is the one
    switch that guarantees no repository content leaves for a third party. Every
    caller already falls back to the local rules, so refusing here costs the
    tailoring and keeps the feature.
    """
    if user_id:
        try:
            from app.models import UserProfile
            profile = UserProfile.objects.filter(user_id=user_id).first()
            if profile is not None and not profile.ai_analysis_enabled:
                logger.info('_get_active_provider: AI disabled for user_id=%s', user_id)
                return None, None
        except Exception:
            # A lookup failure must not be read as consent.
            logger.warning('_get_active_provider: could not read the AI preference '
                           'for user_id=%s — treating it as off', user_id, exc_info=True)
            return None, None
        try:
            from app.models import UserAISettings
            cfg = UserAISettings.objects.filter(user_id=user_id).first()
            if cfg and cfg.api_key.strip():
                p = cfg.provider or 'gemini'
                logger.info("_get_active_provider selected: provider=%s source=user_db", p)
                return p, cfg.api_key.strip()
        except Exception:
            pass

    forced = os.environ.get('AUDIT_AI_PROVIDER', '').lower()
    if forced and forced in PROVIDERS and _server_key_allowed(forced, is_private):
        key = os.environ.get(PROVIDERS[forced]['env_key'] or '', '')
        logger.info("_get_active_provider selected: provider=%s source=env_override", forced)
        return forced, key
    # Public code goes to the free tier first: it costs nothing and loses nothing.
    order = list(PROVIDERS)
    if not is_private and 'gemini' in order:
        order.remove('gemini')
        order.insert(0, 'gemini')
    for name in order:
        key = os.environ.get(PROVIDERS[name]['env_key'], '')
        if key and _server_key_allowed(name, is_private):
            logger.info("_get_active_provider selected: provider=%s source=env_key private=%s",
                        name, is_private)
            return name, key
    return None, None


# ── HTTP callers ──────────────────────────────────────────────────────────────

_MAX_TOKENS = 1500  # enough for a complete code block + explanation

def _call_anthropic(api_key, prompt, model, max_tokens=_MAX_TOKENS):
    r = requests.post('https://api.anthropic.com/v1/messages',
        headers={'x-api-key': api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
        json={'model': model, 'max_tokens': max_tokens, 'messages': [{'role': 'user', 'content': prompt}]},
        timeout=60)
    r.raise_for_status()
    return r.json()['content'][0]['text']

def _call_openai(api_key, prompt, model, max_tokens=_MAX_TOKENS):
    r = requests.post('https://api.openai.com/v1/chat/completions',
        headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
        json={'model': model, 'max_tokens': max_tokens, 'messages': [{'role': 'user', 'content': prompt}]},
        timeout=60)
    r.raise_for_status()
    return r.json()['choices'][0]['message']['content']

# Tried in order when the configured model is gone (404 — Google retires
# models for new keys without notice; gemini-2.5-flash went that way) or
# overloaded (503). The free tier sees both regularly.
GEMINI_FALLBACK_MODELS = ('gemini-3.8-flash', 'gemini-3.1-flash-lite', 'gemini-flash-lite-latest')


def _call_gemini(api_key, prompt, model, max_tokens=_MAX_TOKENS):
    import time
    payload = {
        'contents': [{'parts': [{'text': prompt}]}],
        'generationConfig': {'maxOutputTokens': max_tokens, 'temperature': 0.2},
    }
    models = [model] + [m for m in GEMINI_FALLBACK_MODELS if m != model]
    last_err = None
    for current in models:
        for attempt in range(3):
            # The key goes in a header: in the query string it ends up in every
            # exception message and log line that prints the URL.
            r = requests.post(
                f'https://generativelanguage.googleapis.com/v1beta/models/{current}:generateContent',
                headers={'Content-Type': 'application/json', 'x-goog-api-key': api_key},
                json=payload, timeout=60)
            if r.status_code == 429:
                retry_after = int(r.headers.get('Retry-After', 15))
                last_err = f'Rate limited (429), waited {min(retry_after, 30)}s'
                if attempt < 2:
                    time.sleep(min(retry_after, 30))
                    continue
                raise Exception(last_err)
            break
        if r.status_code in (404, 503):
            last_err = f'Gemini model {current} unavailable ({r.status_code})'
            logger.warning('%s — trying the next model', last_err)
            continue
        if r.status_code >= 400:
            raise Exception(f'Gemini returned HTTP {r.status_code} for model {current}')
        data = r.json()
        candidates = data.get('candidates', [])
        if not candidates:
            # Safety filter or blocked prompt
            finish = data.get('promptFeedback', {}).get('blockReason', 'UNKNOWN')
            raise Exception(f'Gemini returned no candidates (blockReason: {finish})')
        parts = (candidates[0].get('content') or {}).get('parts') or []
        text = ''.join(p.get('text', '') for p in parts if not p.get('thought'))
        if not text:
            raise Exception(f'Gemini returned no text (finishReason: {candidates[0].get("finishReason")})')
        return text
    raise Exception(last_err or 'No Gemini model available')

def _call_provider(provider, api_key, prompt, max_tokens=_MAX_TOKENS):
    model = os.environ.get('AUDIT_AI_MODEL', PROVIDERS[provider]['default_model'])
    if provider == 'anthropic': return _call_anthropic(api_key, prompt, model, max_tokens)
    if provider == 'openai':    return _call_openai(api_key, prompt, model, max_tokens)
    if provider == 'gemini':    return _call_gemini(api_key, prompt, model, max_tokens)
    return ''


# ── Files relevant to each check ─────────────────────────────────────────────

# Which file, if any, is worth showing the model for a given failed check.
#
# `security.no_secrets` is deliberately absent. Its candidate files used to be
# settings.py / config.py / app.py / main.py — exactly where the credential the
# scanner had just found would be sitting. Reporting a leaked secret and
# forwarding it to a third-party model in the same breath is not a trade any
# customer agreed to, and the advice for a leaked credential (rotate it, move it
# to a secret store, purge the history) does not need the file to be written.
_CHECK_FILES = {
    '.env скрыт в .gitignore':                ['.gitignore'],
    '.env hidden in .gitignore':              ['.gitignore'],
    'Автообновление зависимостей':            ['.github/dependabot.yml'],
    'Dependency auto-updates':                ['.github/dependabot.yml'],
    'Автообновление зависимостей (Renovate)': ['renovate.json'],
    'Dependency auto-updates (Renovate)':     ['renovate.json'],
    'GitLab CI/CD пайплайн настроен':         ['.gitlab-ci.yml'],
    'GitLab CI/CD pipeline configured':       ['.gitlab-ci.yml'],
    'CI/CD пайплайн настроен':                ['.github/workflows/ci.yml', '.github/workflows/main.yml'],
    'CI/CD pipeline configured':              ['.github/workflows/ci.yml', '.github/workflows/main.yml'],
    'Тесты запускаются в CI':                 ['.gitlab-ci.yml', '.github/workflows/ci.yml'],
    'Tests run in CI':                        ['.gitlab-ci.yml', '.github/workflows/ci.yml'],
    'Линтер/форматтер настроен':              ['pyproject.toml', '.flake8', 'setup.cfg', '.eslintrc.json'],
    'Linter/formatter configured':            ['pyproject.toml', '.flake8', 'setup.cfg', '.eslintrc.json'],
    'Dockerfile присутствует':                ['Dockerfile'],
    'Dockerfile present':                     ['Dockerfile'],
    '.dockerignore настроен':                 ['.dockerignore', 'Dockerfile'],
    '.dockerignore configured':               ['.dockerignore', 'Dockerfile'],
    'Healthcheck в docker-compose':           ['docker-compose.yml', 'docker-compose.yaml'],
    'Healthcheck in docker-compose':          ['docker-compose.yml', 'docker-compose.yaml'],
    'Non-root пользователь в Dockerfile':     ['Dockerfile'],
    'Non-root user in Dockerfile':            ['Dockerfile'],
    'Файл зависимостей присутствует':         ['requirements.txt', 'package.json', 'go.mod'],
    'Dependency file present':                ['requirements.txt', 'package.json', 'go.mod'],
    'Lock-файл присутствует':                 ['requirements.txt', 'package-lock.json', 'yarn.lock'],
    'Lock file present':                      ['requirements.txt', 'package-lock.json', 'yarn.lock'],
    '.gitignore настроен':                    ['.gitignore'],
    '.gitignore configured':                  ['.gitignore'],
    '.env.example документирует переменные':  ['.env.example', '.env.sample'],
    '.env.example documents variables':       ['.env.example', '.env.sample'],
    'Security policy (SECURITY.md)':          ['SECURITY.md'],
    'README существует':                      ['README.md'],
    'README exists':                          ['README.md'],
    'CHANGELOG ведётся':                      ['CHANGELOG.md'],
    'CHANGELOG maintained':                   ['CHANGELOG.md'],
    'CONTRIBUTING guide':                     ['CONTRIBUTING.md'],
    'PR / Issue шаблоны':                     ['.github/pull_request_template.md'],
    'PR / Issue templates':                   ['.github/pull_request_template.md'],
    'Merge Request шаблон':                   ['.gitlab/merge_request_templates/Default.md'],
    'Merge Request template':                 ['.gitlab/merge_request_templates/Default.md'],
    'Защита основной ветки':                  [],
    'Main branch protection':                 [],
}


# ── Built-in suggestions (no LLM required) ───────────────────────────────────

_BUILTIN = {
    'Нет секретов в коде': {
        'ru': (
            '**Что сделать:** Перенесите все секреты в переменные окружения и читайте их через `os.environ`.\n\n'
            '```python\n'
            '# ПЛОХО — секрет в коде:\n'
            'DATABASE_URL = "postgresql://user:s3cr3t@localhost/db"\n'
            'SECRET_KEY = "hardcoded-key-123"\n\n'
            '# ХОРОШО — из переменных окружения:\n'
            'import os\n'
            'DATABASE_URL = os.environ["DATABASE_URL"]\n'
            'SECRET_KEY = os.environ["SECRET_KEY"]\n'
            '```\n\n'
            'Добавьте `.env` в `.gitignore` и создайте `.env.example` с примерами.'
        ),
        'en': (
            '**What to do:** Move all secrets to environment variables and read them with `os.environ`.\n\n'
            '```python\n'
            '# BAD — secret hardcoded:\n'
            'DATABASE_URL = "postgresql://user:s3cr3t@localhost/db"\n'
            'SECRET_KEY = "hardcoded-key-123"\n\n'
            '# GOOD — from environment:\n'
            'import os\n'
            'DATABASE_URL = os.environ["DATABASE_URL"]\n'
            'SECRET_KEY = os.environ["SECRET_KEY"]\n'
            '```\n\n'
            'Add `.env` to `.gitignore` and create `.env.example` with sample values.'
        ),
    },
    '.env скрыт в .gitignore': {
        'ru': (
            '**Что сделать:** Добавьте `.env` и другие файлы с секретами в `.gitignore`.\n\n'
            '```gitignore\n'
            '# Файлы окружения\n'
            '.env\n'
            '.env.local\n'
            '.env.*.local\n'
            '*.env\n\n'
            '# Ключи и секреты\n'
            '*.pem\n'
            '*.key\n'
            'credentials.json\n'
            '```\n\n'
            'Если `.env` уже попал в историю git — удалите его: `git rm --cached .env`.'
        ),
        'en': (
            '**What to do:** Add `.env` and other secret files to `.gitignore`.\n\n'
            '```gitignore\n'
            '# Environment files\n'
            '.env\n'
            '.env.local\n'
            '.env.*.local\n'
            '*.env\n\n'
            '# Keys and secrets\n'
            '*.pem\n'
            '*.key\n'
            'credentials.json\n'
            '```\n\n'
            'If `.env` was already committed: `git rm --cached .env`.'
        ),
    },
    'CI/CD пайплайн настроен': {
        'ru': (
            '**Что сделать:** Создайте `.github/workflows/ci.yml` для автоматических проверок.\n\n'
            '```yaml\n'
            'name: CI\n'
            'on: [push, pull_request]\n\n'
            'jobs:\n'
            '  test:\n'
            '    runs-on: ubuntu-latest\n'
            '    steps:\n'
            '      - uses: actions/checkout@v4\n'
            '      - uses: actions/setup-python@v5\n'
            '        with: {python-version: "3.12"}\n'
            '      - run: pip install -r requirements.txt\n'
            '      - run: pytest --tb=short -q\n'
            '```'
        ),
        'en': (
            '**What to do:** Create `.github/workflows/ci.yml` for automated checks.\n\n'
            '```yaml\n'
            'name: CI\n'
            'on: [push, pull_request]\n\n'
            'jobs:\n'
            '  test:\n'
            '    runs-on: ubuntu-latest\n'
            '    steps:\n'
            '      - uses: actions/checkout@v4\n'
            '      - uses: actions/setup-python@v5\n'
            '        with: {python-version: "3.12"}\n'
            '      - run: pip install -r requirements.txt\n'
            '      - run: pytest --tb=short -q\n'
            '```'
        ),
    },
    'GitLab CI/CD пайплайн настроен': {
        'ru': (
            '**Что сделать:** Создайте `.gitlab-ci.yml` в корне репозитория.\n\n'
            '```yaml\n'
            'stages: [test, build]\n\n'
            'test:\n'
            '  stage: test\n'
            '  image: python:3.12-slim\n'
            '  script:\n'
            '    - pip install -r requirements.txt\n'
            '    - pytest --tb=short -q\n\n'
            'build:\n'
            '  stage: build\n'
            '  image: docker:24\n'
            '  services: [docker:dind]\n'
            '  script:\n'
            '    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .\n'
            '    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA\n'
            '  only: [main]\n'
            '```'
        ),
        'en': (
            '**What to do:** Create `.gitlab-ci.yml` in the repository root.\n\n'
            '```yaml\n'
            'stages: [test, build]\n\n'
            'test:\n'
            '  stage: test\n'
            '  image: python:3.12-slim\n'
            '  script:\n'
            '    - pip install -r requirements.txt\n'
            '    - pytest --tb=short -q\n\n'
            'build:\n'
            '  stage: build\n'
            '  image: docker:24\n'
            '  services: [docker:dind]\n'
            '  script:\n'
            '    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .\n'
            '    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA\n'
            '  only: [main]\n'
            '```'
        ),
    },
    'Тесты запускаются в CI': {
        'ru': (
            '**Что сделать:** Добавьте шаг запуска тестов в CI-конфиг.\n\n'
            '```yaml\n'
            '# GitHub Actions — добавьте в .github/workflows/ci.yml:\n'
            '      - name: Run tests\n'
            '        run: pytest --tb=short -q\n\n'
            '# GitLab CI — добавьте в .gitlab-ci.yml:\n'
            'test:\n'
            '  script:\n'
            '    - pytest --tb=short -q\n'
            '  coverage: \'/TOTAL.*\\s+(\\d+%)$/\'\n'
            '```'
        ),
        'en': (
            '**What to do:** Add a test step to your CI config.\n\n'
            '```yaml\n'
            '# GitHub Actions — add to .github/workflows/ci.yml:\n'
            '      - name: Run tests\n'
            '        run: pytest --tb=short -q\n\n'
            '# GitLab CI — add to .gitlab-ci.yml:\n'
            'test:\n'
            '  script:\n'
            '    - pytest --tb=short -q\n'
            '  coverage: \'/TOTAL.*\\s+(\\d+%)$/\'\n'
            '```'
        ),
    },
    'Dockerfile присутствует': {
        'ru': (
            '**Что сделать:** Создайте `Dockerfile` в корне проекта.\n\n'
            '```dockerfile\n'
            'FROM python:3.12-slim\n\n'
            'WORKDIR /app\n\n'
            'COPY requirements.txt .\n'
            'RUN pip install --no-cache-dir -r requirements.txt\n\n'
            'COPY . .\n\n'
            '# Не запускайте от root!\n'
            'RUN useradd -m appuser && chown -R appuser /app\n'
            'USER appuser\n\n'
            'EXPOSE 8000\n'
            'CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]\n'
            '```'
        ),
        'en': (
            '**What to do:** Create a `Dockerfile` in the project root.\n\n'
            '```dockerfile\n'
            'FROM python:3.12-slim\n\n'
            'WORKDIR /app\n\n'
            'COPY requirements.txt .\n'
            'RUN pip install --no-cache-dir -r requirements.txt\n\n'
            'COPY . .\n\n'
            '# Do not run as root!\n'
            'RUN useradd -m appuser && chown -R appuser /app\n'
            'USER appuser\n\n'
            'EXPOSE 8000\n'
            'CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]\n'
            '```'
        ),
    },
    'Non-root пользователь в Dockerfile': {
        'ru': (
            '**Что сделать:** Добавьте non-root пользователя в Dockerfile перед `CMD`.\n\n'
            '```dockerfile\n'
            '# Добавьте эти строки ПЕРЕД CMD/ENTRYPOINT:\n'
            'RUN useradd --create-home --shell /bin/sh --uid 1001 appuser \\\n'
            '    && chown -R appuser:appuser /app\n'
            'USER appuser\n\n'
            '# Проверка: пользователь не должен быть root\n'
            '# docker run --rm myimage id\n'
            '# → uid=1001(appuser) gid=1001(appuser)\n'
            '```'
        ),
        'en': (
            '**What to do:** Add a non-root user to your Dockerfile before `CMD`.\n\n'
            '```dockerfile\n'
            '# Add these lines BEFORE CMD/ENTRYPOINT:\n'
            'RUN useradd --create-home --shell /bin/sh --uid 1001 appuser \\\n'
            '    && chown -R appuser:appuser /app\n'
            'USER appuser\n\n'
            '# Verify: user should not be root\n'
            '# docker run --rm myimage id\n'
            '# → uid=1001(appuser) gid=1001(appuser)\n'
            '```'
        ),
    },
    'Healthcheck в docker-compose': {
        'ru': (
            '**Что сделать:** Добавьте `healthcheck` в `docker-compose.yml`.\n\n'
            '```yaml\n'
            'services:\n'
            '  web:\n'
            '    image: myapp:latest\n'
            '    healthcheck:\n'
            '      test: ["CMD", "curl", "-f", "http://localhost:8000/health/"]\n'
            '      interval: 30s\n'
            '      timeout: 10s\n'
            '      retries: 3\n'
            '      start_period: 40s\n'
            '```\n\n'
            'Также добавьте эндпоинт `/health/` в приложение, возвращающий HTTP 200.'
        ),
        'en': (
            '**What to do:** Add a `healthcheck` to `docker-compose.yml`.\n\n'
            '```yaml\n'
            'services:\n'
            '  web:\n'
            '    image: myapp:latest\n'
            '    healthcheck:\n'
            '      test: ["CMD", "curl", "-f", "http://localhost:8000/health/"]\n'
            '      interval: 30s\n'
            '      timeout: 10s\n'
            '      retries: 3\n'
            '      start_period: 40s\n'
            '```\n\n'
            'Also add a `/health/` endpoint to your app returning HTTP 200.'
        ),
    },
    '.dockerignore настроен': {
        'ru': (
            '**Что сделать:** Создайте `.dockerignore` в корне проекта.\n\n'
            '```dockerignore\n'
            '.git\n'
            '.env\n'
            '.env.*\n'
            '__pycache__/\n'
            '*.pyc\n'
            '*.pyo\n'
            '.pytest_cache/\n'
            'node_modules/\n'
            '*.log\n'
            '.DS_Store\n'
            'dist/\n'
            'build/\n'
            '```\n\n'
            'Это ускорит сборку образа и не включит секреты в образ.'
        ),
        'en': (
            '**What to do:** Create `.dockerignore` in the project root.\n\n'
            '```dockerignore\n'
            '.git\n'
            '.env\n'
            '.env.*\n'
            '__pycache__/\n'
            '*.pyc\n'
            '*.pyo\n'
            '.pytest_cache/\n'
            'node_modules/\n'
            '*.log\n'
            '.DS_Store\n'
            'dist/\n'
            'build/\n'
            '```\n\n'
            'This speeds up builds and prevents secrets from being baked into the image.'
        ),
    },
    'Линтер/форматтер настроен': {
        'ru': (
            '**Что сделать:** Добавьте конфигурацию `ruff` в `pyproject.toml`.\n\n'
            '```toml\n'
            '[tool.ruff]\n'
            'line-length = 88\n'
            'select = ["E", "F", "W", "I", "B"]\n'
            'ignore = ["E501"]\n\n'
            '[tool.ruff.format]\n'
            'quote-style = "double"\n'
            'indent-style = "space"\n'
            '```\n\n'
            'Установите: `pip install ruff` и добавьте в CI: `ruff check . && ruff format --check .`'
        ),
        'en': (
            '**What to do:** Add `ruff` config to `pyproject.toml`.\n\n'
            '```toml\n'
            '[tool.ruff]\n'
            'line-length = 88\n'
            'select = ["E", "F", "W", "I", "B"]\n'
            'ignore = ["E501"]\n\n'
            '[tool.ruff.format]\n'
            'quote-style = "double"\n'
            'indent-style = "space"\n'
            '```\n\n'
            'Install: `pip install ruff` and add to CI: `ruff check . && ruff format --check .`'
        ),
    },
    'Автообновление зависимостей': {
        'ru': (
            '**Что сделать:** Создайте `.github/dependabot.yml` для автоматических обновлений.\n\n'
            '```yaml\n'
            'version: 2\n'
            'updates:\n'
            '  - package-ecosystem: pip\n'
            '    directory: "/"\n'
            '    schedule:\n'
            '      interval: weekly\n'
            '      day: monday\n'
            '    open-pull-requests-limit: 5\n'
            '    labels: [dependencies, automated]\n'
            '```'
        ),
        'en': (
            '**What to do:** Create `.github/dependabot.yml` for automatic dependency updates.\n\n'
            '```yaml\n'
            'version: 2\n'
            'updates:\n'
            '  - package-ecosystem: pip\n'
            '    directory: "/"\n'
            '    schedule:\n'
            '      interval: weekly\n'
            '      day: monday\n'
            '    open-pull-requests-limit: 5\n'
            '    labels: [dependencies, automated]\n'
            '```'
        ),
    },
    'Автообновление зависимостей (Renovate)': {
        'ru': (
            '**Что сделать:** Создайте `renovate.json` в корне репозитория.\n\n'
            '```json\n'
            '{\n'
            '  "$schema": "https://docs.renovatebot.com/renovate-schema.json",\n'
            '  "extends": ["config:base"],\n'
            '  "schedule": ["before 5am on Monday"],\n'
            '  "automerge": true,\n'
            '  "automergeType": "pr",\n'
            '  "labels": ["dependencies"]\n'
            '}\n'
            '```\n\n'
            'Установите Renovate через GitHub Apps: renovatebot.com/github-app'
        ),
        'en': (
            '**What to do:** Create `renovate.json` in the repository root.\n\n'
            '```json\n'
            '{\n'
            '  "$schema": "https://docs.renovatebot.com/renovate-schema.json",\n'
            '  "extends": ["config:base"],\n'
            '  "schedule": ["before 5am on Monday"],\n'
            '  "automerge": true,\n'
            '  "automergeType": "pr",\n'
            '  "labels": ["dependencies"]\n'
            '}\n'
            '```\n\n'
            'Install via GitHub Apps: renovatebot.com/github-app'
        ),
    },
    'Файл зависимостей присутствует': {
        'ru': (
            '**Что сделать:** Создайте `requirements.txt` с зафиксированными версиями.\n\n'
            '```bash\n'
            '# Сгенерировать из текущего окружения:\n'
            'pip freeze > requirements.txt\n\n'
            '# Или используйте pip-tools для разделения прямых и транзитивных зависимостей:\n'
            'pip install pip-tools\n'
            '# requirements.in — только прямые зависимости:\n'
            'echo "django>=4.2" > requirements.in\n'
            'pip-compile requirements.in  # генерирует requirements.txt\n'
            '```'
        ),
        'en': (
            '**What to do:** Create `requirements.txt` with pinned versions.\n\n'
            '```bash\n'
            '# Generate from current environment:\n'
            'pip freeze > requirements.txt\n\n'
            '# Or use pip-tools for clean separation:\n'
            'pip install pip-tools\n'
            '# requirements.in — direct deps only:\n'
            'echo "django>=4.2" > requirements.in\n'
            'pip-compile requirements.in  # generates requirements.txt\n'
            '```'
        ),
    },
    'Lock-файл присутствует': {
        'ru': (
            '**Что сделать:** Зафиксируйте точные версии всех зависимостей.\n\n'
            '```bash\n'
            '# Python — pip freeze:\n'
            'pip freeze > requirements.txt\n\n'
            '# Python — pip-tools (рекомендуется):\n'
            'pip install pip-tools\n'
            'pip-compile --generate-hashes requirements.in\n\n'
            '# Node.js:\n'
            'npm install  # создаёт package-lock.json\n'
            '# или\n'
            'yarn install  # создаёт yarn.lock\n'
            '```\n\n'
            'Обязательно добавьте lock-файл в git: не добавляйте его в `.gitignore`.'
        ),
        'en': (
            '**What to do:** Pin exact versions of all dependencies.\n\n'
            '```bash\n'
            '# Python — pip freeze:\n'
            'pip freeze > requirements.txt\n\n'
            '# Python — pip-tools (recommended):\n'
            'pip install pip-tools\n'
            'pip-compile --generate-hashes requirements.in\n\n'
            '# Node.js:\n'
            'npm install  # creates package-lock.json\n'
            '# or\n'
            'yarn install  # creates yarn.lock\n'
            '```\n\n'
            'Commit the lock file to git — do NOT add it to `.gitignore`.'
        ),
    },
    '.gitignore настроен': {
        'ru': (
            '**Что сделать:** Создайте `.gitignore` в корне проекта.\n\n'
            '```gitignore\n'
            '# Python\n'
            '__pycache__/\n'
            '*.pyc\n'
            '*.pyo\n'
            '.venv/\n'
            'venv/\n'
            '.pytest_cache/\n'
            '*.egg-info/\n\n'
            '# Env / Secrets\n'
            '.env\n'
            '.env.local\n\n'
            '# IDE\n'
            '.idea/\n'
            '.vscode/\n\n'
            '# OS\n'
            '.DS_Store\n'
            'Thumbs.db\n'
            '```'
        ),
        'en': (
            '**What to do:** Create a `.gitignore` in the project root.\n\n'
            '```gitignore\n'
            '# Python\n'
            '__pycache__/\n'
            '*.pyc\n'
            '*.pyo\n'
            '.venv/\n'
            'venv/\n'
            '.pytest_cache/\n'
            '*.egg-info/\n\n'
            '# Env / Secrets\n'
            '.env\n'
            '.env.local\n\n'
            '# IDE\n'
            '.idea/\n'
            '.vscode/\n\n'
            '# OS\n'
            '.DS_Store\n'
            'Thumbs.db\n'
            '```'
        ),
    },
    '.env.example документирует переменные': {
        'ru': (
            '**Что сделать:** Создайте `.env.example` с примерами всех переменных окружения.\n\n'
            '```bash\n'
            '# База данных\n'
            'DATABASE_URL=postgresql://user:password@localhost:5432/dbname\n\n'
            '# Безопасность\n'
            'SECRET_KEY=your-secret-key-change-in-production\n'
            'DEBUG=false\n'
            'ALLOWED_HOSTS=localhost,127.0.0.1\n\n'
            '# Кэш\n'
            'REDIS_URL=redis://localhost:6379/0\n\n'
            '# Внешние сервисы\n'
            'STRIPE_SECRET_KEY=sk_test_...\n'
            'SENTRY_DSN=https://...\n'
            '```\n\n'
            'Важно: `.env.example` должен быть в git, а `.env` — в `.gitignore`.'
        ),
        'en': (
            '**What to do:** Create `.env.example` documenting all environment variables.\n\n'
            '```bash\n'
            '# Database\n'
            'DATABASE_URL=postgresql://user:password@localhost:5432/dbname\n\n'
            '# Security\n'
            'SECRET_KEY=your-secret-key-change-in-production\n'
            'DEBUG=false\n'
            'ALLOWED_HOSTS=localhost,127.0.0.1\n\n'
            '# Cache\n'
            'REDIS_URL=redis://localhost:6379/0\n\n'
            '# External services\n'
            'STRIPE_SECRET_KEY=sk_test_...\n'
            'SENTRY_DSN=https://...\n'
            '```\n\n'
            'Key rule: `.env.example` goes in git, `.env` goes in `.gitignore`.'
        ),
    },
    'Security policy (SECURITY.md)': {
        'ru': (
            '**Что сделать:** Создайте `SECURITY.md` с политикой ответственного раскрытия.\n\n'
            '```markdown\n'
            '# Security Policy\n\n'
            '## Supported Versions\n'
            '| Version | Supported |\n'
            '| ------- | --------- |\n'
            '| 1.x     | ✓         |\n\n'
            '## Reporting a Vulnerability\n'
            'Пожалуйста, НЕ создавайте публичный issue.\n'
            'Отправьте письмо на: security@yourproject.com\n\n'
            'Ответим в течение 48 часов.\n'
            'После исправления опубликуем CVE и упомянем вас (при желании).\n'
            '```'
        ),
        'en': (
            '**What to do:** Create `SECURITY.md` with a responsible disclosure policy.\n\n'
            '```markdown\n'
            '# Security Policy\n\n'
            '## Supported Versions\n'
            '| Version | Supported |\n'
            '| ------- | --------- |\n'
            '| 1.x     | ✓         |\n\n'
            '## Reporting a Vulnerability\n'
            'Please do NOT open a public issue.\n'
            'Email: security@yourproject.com\n\n'
            'We respond within 48 hours.\n'
            'After a fix, we publish a CVE and credit you (if desired).\n'
            '```'
        ),
    },
    'README существует': {
        'ru': (
            '**Что сделать:** Создайте `README.md` с описанием проекта.\n\n'
            '```markdown\n'
            '# Project Name\n\n'
            'Краткое описание проекта.\n\n'
            '## Требования\n'
            '- Python 3.12+\n'
            '- PostgreSQL 15+\n\n'
            '## Установка\n'
            '```bash\n'
            'git clone https://github.com/user/repo\n'
            'cd repo\n'
            'cp .env.example .env\n'
            'pip install -r requirements.txt\n'
            'python manage.py migrate\n'
            '```\n\n'
            '## Запуск\n'
            '```bash\n'
            'python manage.py runserver\n'
            '```\n'
        ),
        'en': (
            '**What to do:** Create a `README.md` describing the project.\n\n'
            '```markdown\n'
            '# Project Name\n\n'
            'Short project description.\n\n'
            '## Requirements\n'
            '- Python 3.12+\n'
            '- PostgreSQL 15+\n\n'
            '## Setup\n'
            '```bash\n'
            'git clone https://github.com/user/repo\n'
            'cd repo\n'
            'cp .env.example .env\n'
            'pip install -r requirements.txt\n'
            'python manage.py migrate\n'
            '```\n\n'
            '## Run\n'
            '```bash\n'
            'python manage.py runserver\n'
            '```\n'
        ),
    },
    'CHANGELOG ведётся': {
        'ru': (
            '**Что сделать:** Создайте `CHANGELOG.md` в формате Keep a Changelog.\n\n'
            '```markdown\n'
            '# Changelog\n\n'
            'Все значимые изменения документируются здесь.\n'
            'Формат: [keepachangelog.com](https://keepachangelog.com/ru)\n\n'
            '## [Unreleased]\n'
            '### Added\n'
            '- Новые возможности\n\n'
            '## [1.0.0] - 2024-01-15\n'
            '### Added\n'
            '- Первый релиз\n\n'
            '### Fixed\n'
            '- Исправлена критическая ошибка аутентификации\n'
            '```'
        ),
        'en': (
            '**What to do:** Create `CHANGELOG.md` following the Keep a Changelog format.\n\n'
            '```markdown\n'
            '# Changelog\n\n'
            'All notable changes are documented here.\n'
            'Format: [keepachangelog.com](https://keepachangelog.com/en)\n\n'
            '## [Unreleased]\n'
            '### Added\n'
            '- New features\n\n'
            '## [1.0.0] - 2024-01-15\n'
            '### Added\n'
            '- Initial release\n\n'
            '### Fixed\n'
            '- Critical authentication bug fixed\n'
            '```'
        ),
    },
    'CONTRIBUTING guide': {
        'ru': (
            '**Что сделать:** Создайте `CONTRIBUTING.md` с инструкцией для контрибьюторов.\n\n'
            '```markdown\n'
            '# Contributing Guide\n\n'
            '## Как начать\n'
            '1. Fork репозитория\n'
            '2. Создайте ветку: `git checkout -b feat/my-feature`\n'
            '3. Зафиксируйте изменения: `git commit -m "feat: add feature"`\n'
            '4. Запустите тесты: `pytest`\n'
            '5. Откройте Pull Request\n\n'
            '## Стиль кода\n'
            '- Форматирование: `ruff format .`\n'
            '- Линтер: `ruff check .`\n'
            '```'
        ),
        'en': (
            '**What to do:** Create `CONTRIBUTING.md` with contributor instructions.\n\n'
            '```markdown\n'
            '# Contributing Guide\n\n'
            '## Getting started\n'
            '1. Fork the repository\n'
            '2. Create a branch: `git checkout -b feat/my-feature`\n'
            '3. Commit: `git commit -m "feat: add feature"`\n'
            '4. Run tests: `pytest`\n'
            '5. Open a Pull Request\n\n'
            '## Code style\n'
            '- Format: `ruff format .`\n'
            '- Lint: `ruff check .`\n'
            '```'
        ),
    },
    'PR / Issue шаблоны': {
        'ru': (
            '**Что сделать:** Создайте `.github/pull_request_template.md`.\n\n'
            '```markdown\n'
            '## Описание\n'
            '<!-- Что делает этот PR? -->\n\n'
            '## Изменения\n'
            '- [ ] Описание изменения 1\n'
            '- [ ] Описание изменения 2\n\n'
            '## Тестирование\n'
            '- [ ] Ручное тестирование выполнено\n'
            '- [ ] Тесты добавлены/обновлены\n'
            '- [ ] CI проходит\n\n'
            '## Связанные задачи\n'
            'Closes #\n'
            '```'
        ),
        'en': (
            '**What to do:** Create `.github/pull_request_template.md`.\n\n'
            '```markdown\n'
            '## Description\n'
            '<!-- What does this PR do? -->\n\n'
            '## Changes\n'
            '- [ ] Change description 1\n'
            '- [ ] Change description 2\n\n'
            '## Testing\n'
            '- [ ] Manual testing done\n'
            '- [ ] Tests added/updated\n'
            '- [ ] CI passes\n\n'
            '## Related issues\n'
            'Closes #\n'
            '```'
        ),
    },
    'Merge Request шаблон': {
        'ru': (
            '**Что сделать:** Создайте `.gitlab/merge_request_templates/Default.md`.\n\n'
            '```markdown\n'
            '## Описание\n'
            '<!-- Что делает этот MR? -->\n\n'
            '## Изменения\n'
            '- [ ] Что изменилось\n\n'
            '## Тестирование\n'
            '- [ ] Тесты добавлены/обновлены\n'
            '- [ ] Pipeline проходит\n\n'
            '## Checklist\n'
            '- [ ] Код соответствует стилю проекта\n'
            '- [ ] Документация обновлена\n'
            '```'
        ),
        'en': (
            '**What to do:** Create `.gitlab/merge_request_templates/Default.md`.\n\n'
            '```markdown\n'
            '## Description\n'
            '<!-- What does this MR do? -->\n\n'
            '## Changes\n'
            '- [ ] What changed\n\n'
            '## Testing\n'
            '- [ ] Tests added/updated\n'
            '- [ ] Pipeline passes\n\n'
            '## Checklist\n'
            '- [ ] Code follows project style\n'
            '- [ ] Documentation updated\n'
            '```'
        ),
    },
    'Защита основной ветки': {
        'ru': (
            '**Что сделать:** Включите защиту ветки `main` в настройках GitHub.\n\n'
            '```\n'
            'GitHub → Settings → Branches → Branch protection rules → Add rule\n\n'
            'Branch name pattern: main\n\n'
            'Включить:\n'
            '✓ Require a pull request before merging\n'
            '  ✓ Require approvals: 1\n'
            '✓ Require status checks to pass before merging\n'
            '  ✓ Require branches to be up to date before merging\n'
            '✓ Require conversation resolution before merging\n'
            '✓ Do not allow bypassing the above settings\n'
            '```'
        ),
        'en': (
            '**What to do:** Enable branch protection for `main` in GitHub settings.\n\n'
            '```\n'
            'GitHub → Settings → Branches → Branch protection rules → Add rule\n\n'
            'Branch name pattern: main\n\n'
            'Enable:\n'
            '✓ Require a pull request before merging\n'
            '  ✓ Require approvals: 1\n'
            '✓ Require status checks to pass before merging\n'
            '  ✓ Require branches to be up to date before merging\n'
            '✓ Require conversation resolution before merging\n'
            '✓ Do not allow bypassing the above settings\n'
            '```'
        ),
    },
    'Лицензия указана': {
        'ru': (
            '**Что сделать:** Добавьте файл `LICENSE` в корень репозитория.\n\n'
            '```bash\n'
            '# MIT лицензия (самая популярная для open-source):\n'
            '# Скопируйте текст по ссылке: choosealicense.com/licenses/mit/\n'
            '# и сохраните в файл LICENSE\n\n'
            '# Или через GitHub:\n'
            '# Settings → Add file → Create new file → введите "LICENSE"\n'
            '# → GitHub предложит выбрать лицензию из шаблонов\n'
            '```\n\n'
            'Для закрытого проекта в `package.json` добавьте:\n'
            '```json\n'
            '{ "license": "UNLICENSED", "private": true }\n'
            '```'
        ),
        'en': (
            '**What to do:** Add a `LICENSE` file to the repository root.\n\n'
            '```bash\n'
            '# MIT license (most popular for open-source):\n'
            '# Copy the text from: choosealicense.com/licenses/mit/\n'
            '# and save it as LICENSE\n\n'
            '# Or via GitHub:\n'
            '# Settings → Add file → Create new file → type "LICENSE"\n'
            '# → GitHub will prompt you to choose a license template\n'
            '```\n\n'
            'For a private/commercial project add to `package.json`:\n'
            '```json\n'
            '{ "license": "UNLICENSED", "private": true }\n'
            '```'
        ),
    },
    'Репозиторий активно поддерживается': {
        'ru': (
            '**Что сделать:** Если проект активен, регулярно делайте коммиты.\n\n'
            '```bash\n'
            '# Создайте простой коммит обслуживания:\n'
            'git commit --allow-empty -m "chore: maintenance update"\n'
            'git push\n\n'
            '# Или настройте автоматический dependency bot,\n'
            '# который будет создавать PR каждую неделю.\n'
            '```\n\n'
            'Если проект завершён — пометьте его как архивный:\n'
            '```\n'
            'GitHub → Settings → Archive this repository\n'
            '```'
        ),
        'en': (
            '**What to do:** If the project is active, commit regularly.\n\n'
            '```bash\n'
            '# Create a simple maintenance commit:\n'
            'git commit --allow-empty -m "chore: maintenance update"\n'
            'git push\n\n'
            '# Or set up a dependency bot to open PRs weekly,\n'
            '# which counts as repository activity.\n'
            '```\n\n'
            'If the project is complete, archive it:\n'
            '```\n'
            'GitHub → Settings → Archive this repository\n'
            '```'
        ),
    },
}

# Map English check names to Russian equivalents for builtin lookup
_EN_TO_RU = {
    'No secrets in code': 'Нет секретов в коде',
    '.env hidden in .gitignore': '.env скрыт в .gitignore',
    'CI/CD pipeline configured': 'CI/CD пайплайн настроен',
    'GitLab CI/CD pipeline configured': 'GitLab CI/CD пайплайн настроен',
    'Tests run in CI': 'Тесты запускаются в CI',
    'Dockerfile present': 'Dockerfile присутствует',
    'Non-root user in Dockerfile': 'Non-root пользователь в Dockerfile',
    'Healthcheck in docker-compose': 'Healthcheck в docker-compose',
    '.dockerignore configured': '.dockerignore настроен',
    'Linter/formatter configured': 'Линтер/форматтер настроен',
    'Dependency auto-updates': 'Автообновление зависимостей',
    'Dependency auto-updates (Renovate)': 'Автообновление зависимостей (Renovate)',
    'Dependency file present': 'Файл зависимостей присутствует',
    'Lock file present': 'Lock-файл присутствует',
    '.gitignore configured': '.gitignore настроен',
    '.env.example documents variables': '.env.example документирует переменные',
    'README exists': 'README существует',
    'CHANGELOG maintained': 'CHANGELOG ведётся',
    'PR / Issue templates': 'PR / Issue шаблоны',
    'Merge Request template': 'Merge Request шаблон',
    'Main branch protection': 'Защита основной ветки',
    'License specified': 'Лицензия указана',
    'Repository actively maintained': 'Репозиторий активно поддерживается',
}


# Stable check_id → the Russian display name the built-in suggestion tables are
# keyed by. Check names are translated per audit, so nothing may key off them.
_ID_TO_LEGACY_KEY = {
    'security.no_secrets':          'Нет секретов в коде',
    'security.env_gitignored':      '.env скрыт в .gitignore',
    'security.env_not_committed':   '.env скрыт в .gitignore',
    'security.dependency_updates':  'Автообновление зависимостей',
    'security.security_policy':     'Security policy (SECURITY.md)',
    'security.codeowners':          'CODEOWNERS настроен',
    'ci.pipeline':                  'CI/CD пайплайн настроен',
    'ci.tests':                     'Тесты запускаются в CI',
    'ci.branch_protection':         'Защита основной ветки',
    'ci.linter':                    'Линтер/форматтер настроен',
    'docker.dockerfile':            'Dockerfile присутствует',
    'docker.dockerignore':          '.dockerignore настроен',
    'docker.healthcheck':           'Healthcheck в docker-compose',
    'docker.nonroot':               'Non-root пользователь в Dockerfile',
    'deps.manifest':                'Файл зависимостей присутствует',
    'deps.lockfile':                'Lock-файл присутствует',
    'ops.gitignore':                '.gitignore настроен',
    'ops.env_example':              '.env.example документирует переменные',
    'ops.license':                  'Лицензия указана',
    'ops.activity':                 'Репозиторий активно поддерживается',
    'docs.readme':                  'README существует',
    'docs.readme_quality':          'README существует',
    'docs.changelog':               'CHANGELOG ведётся',
    'docs.templates':               'PR / Issue шаблоны',
}


def _lookup_key(check) -> str:
    """Resolve a check dict to the key the built-in tables use."""
    cid = check.get('check_id', '') if isinstance(check, dict) else getattr(check, 'check_id', '')
    if cid and cid in _ID_TO_LEGACY_KEY:
        return _ID_TO_LEGACY_KEY[cid]
    return check.get('name', '') if isinstance(check, dict) else getattr(check, 'name', '')


def _get_builtin(check_name, language):
    """Return the built-in suggestion for a check name in the given language."""
    entry = _BUILTIN.get(check_name) or _BUILTIN.get(_EN_TO_RU.get(check_name, ''))
    if not entry:
        return ''
    return entry.get(language, entry.get('ru', ''))


def _first_sentence(text, limit=150):
    """The actionable half of a recommendation, without the paragraph."""
    text = (text or '').strip()
    if not text:
        return ''
    for stop in ('. ', '.\n', '; '):
        if stop in text[:limit + 40]:
            text = text.split(stop)[0]
            break
    text = text.strip().rstrip('.')
    return text if len(text) <= limit else text[:limit].rstrip() + '…'


_SEVERITY_ORDER = {'crit': 0, 'warn': 1, 'info': 2, 'ok': 3}

# A recommendation has to serve every ecosystem, so it lists the command for
# each and ends with "depending on your stack". By the time it is read we know
# the stack, and offering somebody a choice you could have made for them is
# exactly what makes advice feel generic.
_STACK_HINTS = {
    'Python':     ('pip ', 'poetry', 'requirements', 'pyproject', 'pipenv', 'python'),
    'JavaScript': ('npm ', 'yarn', 'pnpm', 'package.json', 'package-lock'),
    'TypeScript': ('npm ', 'yarn', 'pnpm', 'package.json', 'package-lock'),
    'Go':         ('go mod', 'go.sum', 'go build'),
    'Rust':       ('cargo',),
    'Ruby':       ('bundle', 'gemfile'),
    'PHP':        ('composer',),
    'Java':       ('maven', 'mvn ', 'gradle'),
    'Kotlin':     ('gradle', 'maven'),
}

_STACK_TAIL = re.compile(
    r'\s*(?:,?\s*(?:depending on|в зависимости от)\s+(?:your|ваш\w*)\s+\w+)\s*\.?$',
    re.IGNORECASE,
)


def _narrow_to_stack(text: str, languages) -> str:
    """
    Drop the alternatives that do not apply to this repository.

    Only ever removes options — if nothing matches, or the languages are
    unknown, the recommendation is returned exactly as written. Narrowing to
    the wrong ecosystem would be worse than not narrowing at all.
    """
    if not text or not languages:
        return text
    hints = tuple(h for lang in languages for h in _STACK_HINTS.get(lang, ()))
    if not hints:
        return text
    # Word boundaries, not substrings: "cargo build" contains "go build", which
    # offered a Go repository the Rust command.
    matcher = re.compile(
        '|'.join(r'\b' + re.escape(h.strip()) for h in hints), re.IGNORECASE)

    # Split on the separators these recommendations actually use: a comma or
    # " or " between backticked commands.
    parts = [p for p in re.split(r',\s*|\s+or\s+', text) if p.strip()]
    if len(parts) < 2:
        return text
    kept = [p for p in parts if matcher.search(p)]
    if not kept or len(kept) == len(parts):
        return text
    # Anything before the first command is the lead-in ("Generate a lock file:").
    lead = parts[0].split('`')[0] if '`' in parts[0] else ''
    if lead and not kept[0].startswith(lead):
        kept[0] = lead + kept[0].strip()
    return _STACK_TAIL.sub('', ' or '.join(k.strip() for k in kept)).strip()


def _builtin_summary(repo_name, checks, score, language, repo_context=None):
    """
    The summary written without a model.

    This is what most people actually read: the AI providers are optional, and
    with no key configured every audit lands here. It used to open with the
    repository's name and a number, then end on "Top priority fix: Dependency
    manifest present" — which names the *condition the check tests for* as if it
    were the action, and picked whichever failure happened to be first in the
    list rather than the worst one.
    """
    checks = [c for c in checks if _counts(c)]
    failed = sorted(
        (c for c in checks if not c['passed']),
        key=lambda c: _SEVERITY_ORDER.get(c.get('severity'), 3),
    )
    crit = [c for c in failed if c.get('severity') == 'crit']
    warn = [c for c in failed if c.get('severity') == 'warn']

    categories = {}
    for c in failed:
        cat = c.get('category', 'ops')
        categories[cat] = categories.get(cat, 0) + 1
    top_cats = sorted(categories.items(), key=lambda x: -x[1])[:3]

    ctx = repo_context or {}
    frameworks = ', '.join(ctx.get('frameworks', [])[:2])
    languages = ', '.join(ctx.get('languages', [])[:2])
    base = (ctx.get('docker') or {}).get('base_images', [])
    ru = language == 'ru'

    cat_names_ru = {
        'security': 'безопасность', 'ci_cd': 'CI/CD', 'docker': 'Docker',
        'docs': 'документация', 'deps': 'зависимости', 'ops': 'эксплуатация',
        'iac': 'инфраструктура как код', 'ai_agents': 'безопасность AI-агентов',
    }
    cat_names_en = {
        'security': 'security', 'ci_cd': 'CI/CD', 'docker': 'Docker',
        'docs': 'documentation', 'deps': 'dependencies', 'ops': 'operations',
        'iac': 'infrastructure as code', 'ai_agents': 'AI agent safety',
    }

    # Open with what the repository is, when the run learned it. "This Django
    # service scored 33/100" is a sentence about a repository; "Repository X
    # scored 33/100" is a sentence about a row in a database.
    if ru:
        quality = ('отличное' if score >= 80 else 'хорошее' if score >= 60
                   else 'удовлетворительное' if score >= 40 else 'неудовлетворительное')
        what = frameworks or languages
        if what:
            opening = f"{repo_name} — проект на {what}"
            if base:
                opening += f" в образе {base[0]}"
            opening += f" — набрал {score}/100, состояние {quality}."
        else:
            opening = f"Репозиторий {repo_name} набрал {score}/100 — {quality} состояние."
        parts = [opening]
        if crit:
            parts.append(f"Критических проблем: {len(crit)} — "
                         f"{', '.join(c['name'] for c in crit[:3])}.")
        elif warn:
            parts.append(f"Обнаружено предупреждений: {len(warn)}.")
        if top_cats:
            parts.append("Проблемные области: "
                         + ', '.join(cat_names_ru.get(c, c) for c, _ in top_cats) + '.')
        if failed:
            action = _first_sentence(
                _narrow_to_stack(failed[0].get('recommendation'), ctx.get('languages')))
            parts.append(f"Начать стоит с этого: {action}."
                         if action else
                         f"Начать стоит с проверки «{failed[0]['name']}».")
        else:
            parts.append("Все проверки пройдены.")
    else:
        quality = ('excellent' if score >= 80 else 'good' if score >= 60
                   else 'satisfactory' if score >= 40 else 'poor')
        what = frameworks or languages
        if what:
            opening = f"{repo_name} is a {what} project"
            if base:
                opening += f" built on {base[0]}"
            opening += f", scoring {score}/100 — {quality} overall state."
        else:
            opening = f"Repository {repo_name} scored {score}/100 — {quality} overall state."
        parts = [opening]
        if crit:
            noun = 'critical issue' if len(crit) == 1 else 'critical issues'
            parts.append(f"{len(crit)} {noun}: "
                         f"{', '.join(c['name'] for c in crit[:3])}.")
        elif warn:
            noun = 'warning' if len(warn) == 1 else 'warnings'
            parts.append(f"{len(warn)} {noun}.")
        if top_cats:
            parts.append("Problem areas: "
                         + ', '.join(cat_names_en.get(c, c) for c, _ in top_cats) + '.')
        if failed:
            action = _first_sentence(
                _narrow_to_stack(failed[0].get('recommendation'), ctx.get('languages')))
            parts.append(f"Start here: {action}."
                         if action else
                         f"Start with the \"{failed[0]['name']}\" check.")
        else:
            parts.append("All checks passed.")
    return ' '.join(parts)


# ── Public API ────────────────────────────────────────────────────────────────

def get_ai_summary(repo_name, checks, score, language='ru', user_id=None, repo_context=None,
                   is_private=True, ai_findings=None):
    """
    A paragraph about *this* repository.

    `repo_context` carries what was read from it during the run — languages,
    frameworks, base images, ports, CI, Terraform providers. Without it the
    model receives a name, a number and a list of check titles, which is not a
    repository, so the only thing it can write is advice that would fit any
    project. That is what made the summary read like filler.
    """
    provider, api_key = _get_active_provider(user_id, is_private=is_private)
    logger.info("get_ai_summary starting: provider=%s language=%s", provider, language)

    if provider:
        # Checks the repository cannot act on are set aside by the engine and
        # left out of the score. Feeding them to the model as problems produced
        # advice about a Dockerfile a library was never going to have.
        checks = [c for c in checks if _counts(c)]
        failed = [c for c in checks if not c['passed']]

        from app.repo_context import to_prompt
        facts = to_prompt(repo_context or {}, language)
        if facts:
            facts += '\n'
        # Verified findings of the file review, so "fix first" can weigh a
        # published database port against a missing lint config.
        review_block = ''
        if ai_findings:
            head = ('\nНайдено при ревью файлов:\n' if language == 'ru'
                    else '\nFound by reviewing the files:\n')
            review_block = head + '\n'.join(
                f"- [{f['severity'].upper()}] {f['file']}:{f['line']} {f['title']}"
                for f in ai_findings[:6])
        if language == 'ru':
            prompt = (
                f"Ты DevOps-эксперт. Проанализируй результаты аудита репозитория {repo_name}.\n"
                f"{facts}"
                f"Score: {score}/100 | Пройдено: {len(checks)-len(failed)}/{len(checks)}\n"
                f"Проблемы:\n"
                + '\n'.join(f"- [{c['severity'].upper()}] {c['name']}: {c.get('description', '')[:160]}"
                             for c in failed)
                + review_block
                + "\n\nОтветь на русском в таком виде:\n"
                  "Два предложения: общее состояние репозитория и главный риск.\n"
                  "Что чинить первым:\n"
                  "1. <что сделать> — <почему это важно именно здесь>\n"
                  "2. ...\n"
                  "3. ...\n"
                  "Выбирай три пункта по реальному риску (утечка, захват, простой), а не по порядку списка; "
                  "гигиену документации не выбирай. Опирайся на факты выше, называй конкретные файлы, "
                  "образы и порты. Ничего не выдумывай. Без markdown-разметки, только текст и нумерация."
            )
        else:
            prompt = (
                f"You are a DevOps expert. Analyze the audit results for repository {repo_name}.\n"
                f"{facts}"
                f"Score: {score}/100 | Passed: {len(checks)-len(failed)}/{len(checks)}\n"
                f"Issues:\n"
                + '\n'.join(f"- [{c['severity'].upper()}] {c['name']}: {c.get('description', '')[:160]}"
                             for c in failed)
                + review_block
                + "\n\nAnswer in English in exactly this shape:\n"
                  "Two sentences: the repository's overall state and its main risk.\n"
                  "Fix first:\n"
                  "1. <what to do> — <why it matters in this repository>\n"
                  "2. ...\n"
                  "3. ...\n"
                  "Pick the three by real risk (leak, takeover, outage), not by list order; never pick "
                  "documentation hygiene. Ground it in the facts above and name concrete files, images and "
                  "ports. Invent nothing. No markdown, plain text and numbering only."
            )
        try:
            text = _call_provider(provider, api_key, prompt)
            logger.info("get_ai_summary success: provider=%s", PROVIDERS[provider]['name'])
            return text.strip(), PROVIDERS[provider]['name']
        except Exception as e:
            logger.warning("get_ai_summary API error: provider=%s error=%s", provider, e)

    logger.info("get_ai_summary using builtin fallback")
    return _builtin_summary(repo_name, checks, score, language, repo_context), 'Built-in'


def _make_suggestion_prompt(name, description, file_content, file_used, language, host=''):
    from app.repo_context import host_rule
    prompt = _make_suggestion_prompt_body(name, description, file_content, file_used, language)
    rule = host_rule(host, language)
    return f'{rule}\n\n{prompt}' if rule else prompt


def _make_suggestion_prompt_body(name, description, file_content, file_used, language):
    if language == 'ru':
        if file_content:
            return (
                f"Ты опытный DevOps-инженер. Проверка репозитория провалилась:\n"
                f"Проверка: {name}\n"
                f"Что не так: {description}\n\n"
                f"Вот текущее содержимое файла `{file_used}`:\n"
                f"```\n{file_content}\n```\n\n"
                f"ЗАДАЧА: покажи точное минимальное изменение этого конкретного файла.\n"
                f"Правила:\n"
                f"- Не переписывай весь файл — покажи только то что нужно добавить/изменить\n"
                f"- Если добавляешь строки — покажи 2–3 строки контекста до и после чтобы было ясно куда вставить\n"
                f"- Если заменяешь строку — покажи: было → стало\n"
                f"- Код должен работать именно с этим файлом, не быть шаблоном\n\n"
                f"Формат:\n"
                f"**Изменение:** одна фраза что именно делаем.\n"
                f"```(язык файла)\n"
                f"# контекст + изменение\n"
                f"```\n"
                f"Только русский язык."
            )
        return (
            f"Ты опытный DevOps-инженер. Проверка репозитория провалилась:\n"
            f"Проверка: {name}\n"
            f"Что не так: {description}\n\n"
            f"Файл не найден в репозитории. Создай минимальный рабочий пример.\n"
            f"Правила:\n"
            f"- Дай реальный рабочий файл, не заглушку\n"
            f"- Адаптируй под типичный Python/Node.js/Go проект\n"
            f"- Без избыточных комментариев\n\n"
            f"Формат:\n"
            f"**Создать файл:** одна фраза что делать.\n"
            f"```(язык)\n"
            f"# содержимое файла\n"
            f"```\n"
            f"Только русский язык."
        )
    else:
        if file_content:
            return (
                f"You are an experienced DevOps engineer. This repository check failed:\n"
                f"Check: {name}\n"
                f"Issue: {description}\n\n"
                f"Current content of `{file_used}`:\n"
                f"```\n{file_content}\n```\n\n"
                f"TASK: show the minimal exact change to this specific file.\n"
                f"Rules:\n"
                f"- Do NOT rewrite the whole file — show only what to add/change\n"
                f"- If adding lines: show 2–3 lines of context before/after so placement is clear\n"
                f"- If replacing a line: show before → after\n"
                f"- The fix must work with this exact file, not be a generic template\n\n"
                f"Format:\n"
                f"**Change:** one sentence describing what we're doing.\n"
                f"```(file language)\n"
                f"# context + change\n"
                f"```\n"
                f"English only."
            )
        return (
            f"You are an experienced DevOps engineer. This repository check failed:\n"
            f"Check: {name}\n"
            f"Issue: {description}\n\n"
            f"The file was not found in the repository. Create a minimal working example.\n"
            f"Rules:\n"
            f"- Provide a real working file, not a placeholder\n"
            f"- Adapt for a typical Python/Node.js/Go project\n"
            f"- No excessive comments\n\n"
            f"Format:\n"
            f"**Create file:** one sentence on what to do.\n"
            f"```(language)\n"
            f"# file content\n"
            f"```\n"
            f"English only."
        )


# A built-in suggestion that only makes sense on GitHub.
_GITHUB_ONLY = re.compile(r'\.github/|dependabot|github actions|actions/|pull request', re.I)


def get_ai_code_suggestions(failed_checks, get_content_fn, language='ru', user_id=None,
                            is_private=True, host='github'):
    """
    Returns {check_name: suggestion_markdown} for ALL failed checks.
    LLM for first LLM_LIMIT checks (if configured), builtin/recommendation for the rest.
    """
    provider, api_key = _get_active_provider(user_id, is_private=is_private)
    logger.info("get_ai_code_suggestions starting: failed_checks=%d provider=%s", len(failed_checks), provider)
    results = {}
    LLM_LIMIT = 10  # max checks sent to LLM to avoid excessive API calls

    def _best_fallback(check):
        suggestion = _get_builtin(_lookup_key(check), language)
        # The built-in tables were written for GitHub. On GitLab a suggestion
        # naming .github/ or Dependabot is wrong; the check's own
        # recommendation is written per host, so it goes instead.
        if suggestion and not (host == 'gitlab' and _GITHUB_ONLY.search(suggestion)):
            return suggestion
        # Last resort: use the static recommendation text
        rec = check.get('recommendation', '').strip()
        if rec:
            return f'**{"Что сделать" if language == "ru" else "What to do"}:** {rec}'
        return ''

    if not provider:
        # Pure builtin mode — ALL failed checks get suggestions
        for check in failed_checks:
            name = check.get('name', '')
            suggestion = _best_fallback(check)
            if suggestion:
                results[name] = suggestion
        logger.info("get_ai_code_suggestions complete: results=%d", len(results))
        return results

    # LLM mode: first LLM_LIMIT via LLM (with builtin fallback), rest via builtin
    import time
    llm_call_count = 0
    for i, check in enumerate(failed_checks):
        name = check.get('name', '')
        description = check.get('description', '')

        if i < LLM_LIMIT:
            # Gemini's free tier allows 15 requests/minute; paid providers do not
            # need the pause, and sleeping through it made every audit ~40s slower.
            if llm_call_count > 0 and provider == 'gemini':
                time.sleep(4)

            candidate_files = _CHECK_FILES.get(_lookup_key(check), []) or _CHECK_FILES.get(name, [])
            file_content = None
            file_used = None
            for fname in candidate_files:
                content = get_content_fn(fname)
                if content:
                    # Any file can hold a credential — a compose file, a CI
                    # config, a .gitignore that lists one by name. Nothing
                    # reaches a provider without going through the same rules
                    # the scanner reports on.
                    file_content = redact(content[:4000])
                    file_used = fname
                    break

            prompt = _make_suggestion_prompt(name, description, file_content, file_used, language,
                                             host=host)
            try:
                text = _call_provider(provider, api_key, prompt)
                results[name] = text.strip()
                llm_call_count += 1
            except Exception as e:
                logger.warning("get_ai_code_suggestions API error: provider=%s check=%s error=%s", provider, name, e)
                suggestion = _best_fallback(check)
                if suggestion:
                    results[name] = suggestion
        else:
            # Beyond LLM limit — use builtin/recommendation
            suggestion = _best_fallback(check)
            if suggestion:
                results[name] = suggestion

    logger.info("get_ai_code_suggestions complete: results=%d", len(results))
    return results
