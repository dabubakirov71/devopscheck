"""
A compact, factual description of the repository, captured during the audit.

The AI summary used to receive the repository's *name*, its score, and a list of
failed check names — nothing else. Asked to "analyse this repository" from that,
a model has no repository to analyse, so it writes the only thing it can: advice
that would fit any project. The same was true of the generated fix file, which
was told to "customise this template for the project" while being shown nothing
about the project.

What is collected here is only what the archive already holds in memory, so it
costs no extra API calls. It is stored on the `Audit` row for the same reason
`sbom_components` is: the fix view runs long after the run, and re-reading the
repository there would fail the moment a token is revoked or a repo renamed.

Kept deliberately small. This goes into a prompt, and a prompt full of file
listings buys nothing that a prompt full of *facts* does not.
"""
import re

MAX_TREE = 28
MAX_LANGS = 5
MAX_SERVICES = 8
MAX_WORKFLOWS = 6

_EXT_LANG = {
    '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript',
    '.jsx': 'JavaScript', '.go': 'Go', '.rs': 'Rust', '.rb': 'Ruby', '.php': 'PHP',
    '.java': 'Java', '.kt': 'Kotlin', '.cs': 'C#', '.swift': 'Swift',
    '.scala': 'Scala', '.ex': 'Elixir', '.c': 'C', '.cpp': 'C++', '.sh': 'Shell',
    '.tf': 'Terraform',
}

_MANIFESTS = (
    'requirements.txt', 'pyproject.toml', 'Pipfile', 'setup.py', 'poetry.lock',
    'package.json', 'go.mod', 'Cargo.toml', 'Gemfile', 'composer.json',
    'pom.xml', 'build.gradle', 'build.gradle.kts',
)

# A framework is worth naming because it decides what a fix should look like:
# a healthcheck for Django is not a healthcheck for Gin.
_FRAMEWORK_MARKERS = (
    ('Django', ('django',), ('requirements.txt', 'pyproject.toml', 'Pipfile')),
    ('FastAPI', ('fastapi',), ('requirements.txt', 'pyproject.toml')),
    ('Flask', ('flask',), ('requirements.txt', 'pyproject.toml')),
    ('Express', ('"express"',), ('package.json',)),
    ('Next.js', ('"next"',), ('package.json',)),
    ('React', ('"react"',), ('package.json',)),
    ('NestJS', ('"@nestjs/core"',), ('package.json',)),
    ('Rails', ('rails',), ('Gemfile',)),
    ('Laravel', ('laravel/framework',), ('composer.json',)),
    ('Spring Boot', ('spring-boot',), ('pom.xml', 'build.gradle')),
    ('Gin', ('gin-gonic/gin',), ('go.mod',)),
)


def _truncate(text, limit):
    if text is None:
        return None
    text = text.strip()
    return text if len(text) <= limit else text[:limit].rstrip() + '\n…'


def build(client) -> dict:
    """Everything worth telling a model about this repository, and nothing else."""
    try:
        files = client.walk()
    except Exception:
        return {}

    ctx = {}
    # Where it lives decides what advice can work: .gitlab-ci.yml or
    # .github/workflows, a merge request or a pull request, Renovate or
    # Dependabot. Without it a model assumes GitHub.
    if getattr(client, 'provider', '') in ('github', 'gitlab'):
        ctx['host'] = client.provider

    # ── What it is written in ────────────────────────────────────────────────
    counts = {}
    for path in files:
        dot = path.rfind('.')
        lang = _EXT_LANG.get(path[dot:].lower()) if dot != -1 else None
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    if counts:
        ctx['languages'] = [
            name for name, _ in sorted(counts.items(), key=lambda kv: -kv[1])[:MAX_LANGS]
        ]

    # ── What it depends on ───────────────────────────────────────────────────
    manifests = [m for m in _MANIFESTS if client.exists(m)]
    if manifests:
        ctx['manifests'] = manifests

    frameworks = []
    for name, needles, sources in _FRAMEWORK_MARKERS:
        for source in sources:
            body = (client.get_content(source) or '').lower()
            if body and any(n in body for n in needles):
                frameworks.append(name)
                break
    if frameworks:
        ctx['frameworks'] = frameworks

    # ── How it ships ─────────────────────────────────────────────────────────
    dockerfile = client.get_content('Dockerfile')
    if dockerfile:
        docker = {}
        bases = re.findall(r'^\s*FROM\s+(\S+)', dockerfile, re.M | re.I)
        if bases:
            docker['base_images'] = bases[:4]
        ports = re.findall(r'^\s*EXPOSE\s+([0-9 ]+)', dockerfile, re.M | re.I)
        if ports:
            docker['exposed_ports'] = sorted({p for chunk in ports for p in chunk.split()})[:6]
        users = re.findall(r'^\s*USER\s+(\S+)', dockerfile, re.M | re.I)
        if users:
            docker['user'] = users[-1]
        cmd = re.search(r'^\s*(CMD|ENTRYPOINT)\s+(.+)$', dockerfile, re.M | re.I)
        if cmd:
            docker['start'] = cmd.group(2).strip()[:120]
        ctx['docker'] = docker

    compose_path = client.any_exists(('docker-compose.yml', 'docker-compose.yaml',
                                      'compose.yml', 'compose.yaml'))
    if compose_path:
        compose = client.get_content(compose_path) or ''
        # Service names are the keys indented exactly two spaces under services:.
        block = compose.split('services:', 1)[1] if 'services:' in compose else ''
        names = re.findall(r'^  ([A-Za-z0-9_.-]+):', block, re.M)
        ctx['compose'] = {'file': compose_path, 'services': names[:MAX_SERVICES]}

    # ── How it is built and tested ───────────────────────────────────────────
    workflows = [p for p in files
                 if p.startswith('.github/workflows/') and p.endswith(('.yml', '.yaml'))]
    if workflows:
        jobs = []
        for path in workflows[:MAX_WORKFLOWS]:
            body = client.get_content(path) or ''
            trigger = re.search(r'^on:\s*(.+)$', body, re.M)
            jobs.append({
                'file': path.rsplit('/', 1)[-1],
                'on': (trigger.group(1).strip()[:60] if trigger else
                       ('push' if '\n  push:' in body else '')),
            })
        ctx['ci'] = {'provider': 'github-actions', 'workflows': jobs}
    elif client.exists('.gitlab-ci.yml'):
        ctx['ci'] = {'provider': 'gitlab-ci'}

    # ── Infrastructure ───────────────────────────────────────────────────────
    tf = [p for p in files if p.endswith('.tf')]
    if tf:
        providers = set()
        for path in tf[:8]:
            body = client.get_content(path) or ''
            providers.update(re.findall(r'provider\s+"([a-z0-9_-]+)"', body))
        ctx['terraform'] = {'files': len(tf), 'providers': sorted(providers)[:6]}
    if any(p.startswith('charts/') or p.endswith(('deployment.yaml', 'deployment.yml'))
           for p in files):
        ctx['kubernetes'] = True

    # ── The shape of the thing ───────────────────────────────────────────────
    top = sorted({p.split('/')[0] for p in files})
    if top:
        ctx['tree'] = top[:MAX_TREE]

    _readme_path, readme = client.first_content(
        ('README.md', 'README.rst', 'readme.md', 'README'))
    if readme:
        ctx['readme_head'] = _truncate(readme, 400)

    # Everything here is destined for a third-party model, and a README or a
    # start command can carry a credential as easily as a settings file.
    from app.checks_secrets import redact
    if ctx.get('readme_head'):
        ctx['readme_head'] = redact(ctx['readme_head'])
    if ctx.get('docker', {}).get('start'):
        ctx['docker']['start'] = redact(ctx['docker']['start'])

    return ctx


def host_rule(host: str, language: str = 'en') -> str:
    """One line a prompt must carry so a model does not answer GitLab with GitHub."""
    ru = language == 'ru'
    if host == 'gitlab':
        return ('Репозиторий на GitLab. Советы — только для GitLab: .gitlab-ci.yml, merge request, '
                'protected branches, пути .gitlab/, Renovate. GitHub Actions, Dependabot и .github/ '
                'в GitLab не работают — не предлагай их.' if ru else
                'The repository is hosted on GitLab. Advice must be for GitLab: .gitlab-ci.yml, merge '
                'requests, protected branches, .gitlab/ paths, Renovate. GitHub Actions, Dependabot and '
                '.github/ do not work on GitLab — never suggest them.')
    if host == 'github':
        return ('Репозиторий на GitHub (GitHub Actions, pull request, .github/).' if ru else
                'The repository is hosted on GitHub (GitHub Actions, pull requests, .github/).')
    return ''


def with_host(ctx: dict, host: str) -> dict:
    """`ctx` with `host` filled in — rows stored before it was recorded lack it."""
    ctx = dict(ctx or {})
    if host in ('github', 'gitlab'):
        ctx.setdefault('host', host)
    return ctx


def to_prompt(ctx: dict, language: str = 'en') -> str:
    """
    Render the context as a short factual block for a prompt.

    Facts, one per line, and nothing invented — an empty context renders to an
    empty string so the caller's prompt is unchanged rather than padded with
    "unknown" everywhere, which reads to a model as something worth guessing at.
    """
    if not ctx:
        return ''

    ru = language == 'ru'
    lines = []
    if ctx.get('host'):
        lines.append('- ' + host_rule(ctx['host'], language))

    def add(label_en, label_ru, value):
        if value:
            lines.append(f'- {label_ru if ru else label_en}: {value}')

    add('Languages', 'Языки', ', '.join(ctx.get('languages', [])))
    add('Frameworks', 'Фреймворки', ', '.join(ctx.get('frameworks', [])))
    add('Dependency files', 'Файлы зависимостей', ', '.join(ctx.get('manifests', [])))

    docker = ctx.get('docker') or {}
    add('Docker base images', 'Базовые образы Docker', ', '.join(docker.get('base_images', [])))
    add('Exposed ports', 'Открытые порты', ', '.join(docker.get('exposed_ports', [])))
    add('Container user', 'Пользователь контейнера', docker.get('user'))
    add('Start command', 'Команда запуска', docker.get('start'))

    compose = ctx.get('compose') or {}
    add('Compose services', 'Сервисы compose', ', '.join(compose.get('services', [])))

    ci = ctx.get('ci') or {}
    if ci.get('provider'):
        flows = ', '.join(w['file'] for w in ci.get('workflows', [])) or ci['provider']
        add('CI', 'CI', flows)

    tf = ctx.get('terraform') or {}
    if tf:
        add('Terraform', 'Terraform',
            f"{tf.get('files', 0)} files, providers: {', '.join(tf.get('providers', [])) or 'n/a'}")
    if ctx.get('kubernetes'):
        lines.append('- Kubernetes manifests present' if not ru else '- Есть манифесты Kubernetes')

    add('Top level', 'Верхний уровень', ', '.join(ctx.get('tree', [])))

    if not lines:
        return ''
    header = 'Что это за репозиторий (факты, прочитанные из него):' if ru else \
             'What this repository actually is (read from it):'
    body = '\n'.join(lines)
    readme = ctx.get('readme_head')
    if readme:
        cap = 'Начало README:' if ru else 'README begins:'
        body += f'\n\n{cap}\n"""\n{readme}\n"""'
    return f'{header}\n{body}\n'
