"""
Is a vulnerable dependency actually used? (CVE reachability, MVP)

A CVE in a package the code never imports is a different finding from one in
the web framework every request goes through, and a report that rates them the
same trains its reader to ignore it. This module answers, per package:

    imported      the code imports it, or names it where a tool loads it
                  (a Django INSTALLED_APPS string, a Procfile command, an
                  npm script, a babel/eslint plugin list)
    not_imported  every source file was read and nothing refers to it
    unknown       not every source file is in memory, or the ecosystem is
                  not covered (only Python and JS/TS are)

It is a heuristic, and says so in the report. It errs towards `imported`:
any mention counts, and a package another dependency pulls in at runtime —
`urllib3` under `requests` — reads as `not_imported` even though it runs.
That is why `not_imported` only lowers a finding by one step and never
clears it.

Reads only what the audit already holds in memory (`RepoClient.local_text`);
it never costs an API request.
"""
import json
import re

IMPORTED, NOT_IMPORTED, UNKNOWN = 'imported', 'not_imported', 'unknown'

SKIP_PARTS = ('node_modules/', 'vendor/', 'dist/', 'build/', '.venv/', 'venv/',
              'site-packages/', 'third_party/', '.min.', 'bower_components/')

PY_SOURCE = ('.py', '.pyi')
JS_SOURCE = ('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte')
# Where a package is started or loaded by name rather than imported.
COMMAND_FILES = ('Dockerfile', 'Procfile', 'Makefile', 'docker-compose.yml', 'docker-compose.yaml',
                 'compose.yml', 'compose.yaml', 'tox.ini', 'pytest.ini', 'setup.cfg', '.flake8',
                 'mypy.ini', '.pre-commit-config.yaml', '.babelrc', '.eslintrc', '.eslintrc.json',
                 '.eslintrc.yml', '.eslintrc.yaml', '.prettierrc', '.mocharc.yml', '.mocharc.json',
                 'babel.config.json', 'nodemon.json', 'uwsgi.ini', 'gunicorn.conf.py')
COMMAND_SUFFIXES = ('.sh', '.ini', '.cfg')
MAX_BYTES = 24 * 1024 * 1024

# Distributions whose import name is not their own name.
PY_IMPORT_NAMES = {
    'pillow': ['PIL'], 'pyyaml': ['yaml'], 'beautifulsoup4': ['bs4'],
    'python-dateutil': ['dateutil'], 'scikit-learn': ['sklearn'], 'scikit-image': ['skimage'],
    'opencv-python': ['cv2'], 'opencv-python-headless': ['cv2'], 'opencv-contrib-python': ['cv2'],
    'psycopg2-binary': ['psycopg2'], 'psycopg-binary': ['psycopg'], 'python-decouple': ['decouple'],
    'django-allauth': ['allauth'], 'djangorestframework': ['rest_framework'],
    'djangorestframework-simplejwt': ['rest_framework_simplejwt'], 'pyjwt': ['jwt'],
    'protobuf': ['google'], 'attrs': ['attr', 'attrs'], 'python-dotenv': ['dotenv'],
    'pycryptodome': ['Crypto'], 'pycryptodomex': ['Cryptodome'], 'pyopenssl': ['OpenSSL'],
    'python-jose': ['jose'], 'python-multipart': ['multipart', 'python_multipart'],
    'sentry-sdk': ['sentry_sdk'], 'msgpack-python': ['msgpack'], 'mysqlclient': ['MySQLdb'],
    'python-magic': ['magic'], 'pyserial': ['serial'], 'pyzmq': ['zmq'],
    'setuptools': ['setuptools', 'pkg_resources'], 'dnspython': ['dns'],
    'google-api-python-client': ['googleapiclient'], 'ruamel.yaml': ['ruamel'],
    'python-socketio': ['socketio'], 'python-engineio': ['engineio'], 'pygithub': ['github'],
    'python-gitlab': ['gitlab'], 'python-telegram-bot': ['telegram'], 'pymupdf': ['fitz'],
    'python-docx': ['docx'], 'python-pptx': ['pptx'], 'faiss-cpu': ['faiss'],
    'tensorflow-cpu': ['tensorflow'], 'websocket-client': ['websocket'], 'discord.py': ['discord'],
    'python-ldap': ['ldap'], 'pywin32': ['win32api', 'win32con'], 'lxml-html-clean': ['lxml_html_clean'],
}


def _py_candidates(dist: str) -> set:
    lower = dist.lower()
    norm = re.sub(r'[-.]+', '_', lower)
    names = {norm, lower.replace('-', '_')}
    names.update(n.lower() for n in PY_IMPORT_NAMES.get(lower, []))
    for prefix in ('python_', 'py', 'django_', 'flask_'):
        if norm.startswith(prefix) and len(norm) > len(prefix) + 1:
            names.add(norm[len(prefix):])
    return names


def _js_candidates(pkg: str) -> set:
    names = {pkg}
    short = pkg.rsplit('/', 1)[-1]
    # Tools refer to plugins by a short name: 'eslint-plugin-react' → 'react'
    # in an eslint config, '@babel/preset-env' → 'env' is too loose to use.
    for prefix in ('eslint-plugin-', 'eslint-config-', 'babel-plugin-', 'babel-preset-',
                   'prettier-plugin-', 'postcss-', 'rollup-plugin-', 'vite-plugin-'):
        if short.startswith(prefix) and len(short) > len(prefix) + 2:
            names.add(short[len(prefix):])
    return names


_PY_IMPORT = re.compile(r'^\s*(?:from\s+([\w.]+)\s+import\b|import\s+([\w.,\s]+?)\s*(?:#.*)?$)', re.M)
_PY_DYNAMIC = re.compile(r'(?:import_module|__import__)\(\s*[\'"]([\w.]+)[\'"]')
_PY_STRING = re.compile(r'[\'"]([A-Za-z_][\w]*)(?:[.:][\w.:]*)?[\'"]')


def _py_modules(text: str) -> set:
    """Top-level module names a Python file imports or names in a dotted string."""
    found = set()
    for m in _PY_IMPORT.finditer(text):
        if m.group(1):
            found.add(m.group(1).split('.')[0])
        else:
            for part in m.group(2).split(','):
                name = part.strip().split(' ')[0]
                if name:
                    found.add(name.split('.')[0])
    for m in _PY_DYNAMIC.finditer(text):
        found.add(m.group(1).split('.')[0])
    # 'allauth.account', "whitenoise.middleware.WhiteNoiseMiddleware",
    # 'myapp.tasks:app' — how Django, Celery and friends load a package.
    for m in _PY_STRING.finditer(text):
        found.add(m.group(1))
    return {n.lower() for n in found}


_JS_SPEC = re.compile(r'[\'"`]((?:@[\w.\-]+/)?[\w.\-]+)(?:/[^\'"`\s]*)?[\'"`]')


def _js_modules(text: str) -> set:
    """
    Every bare module specifier-shaped string literal.

    Broader than import statements on purpose: a plugin list in a bundler or
    lint config names the package the same way, and it is loaded all the same.
    """
    return {m.group(1) for m in _JS_SPEC.finditer(text)}


def _words(text: str) -> set:
    """Command-line words, plus the first segment of dotted ones: `uvicorn.workers.X` → `uvicorn`."""
    words = set()
    for w in re.findall(r'[@\w][\w.\-/@]*', text):
        w = w.lower()
        words.add(w)
        words.add(w.split('.')[0])
    return words


def _package_json_scripts(text: str) -> str:
    try:
        data = json.loads(text)
    except ValueError:
        return ''
    scripts = data.get('scripts') if isinstance(data, dict) else None
    return ' '.join(str(v) for v in scripts.values()) if isinstance(scripts, dict) else ''


def _skip(path: str) -> bool:
    return any(part in path for part in SKIP_PARTS)


def analyse(client, ecosystem: str, packages) -> dict:
    """{package: IMPORTED | NOT_IMPORTED | UNKNOWN} for the given packages."""
    packages = list(packages)
    if ecosystem not in ('PyPI', 'npm') or client is None or not hasattr(client, 'local_text'):
        return {p: UNKNOWN for p in packages}
    if getattr(client, 'tree_truncated', False):
        return {p: UNKNOWN for p in packages}

    suffixes = PY_SOURCE if ecosystem == 'PyPI' else JS_SOURCE
    sources = [p for p in client.files if p.endswith(suffixes) and not _skip(p)]
    if not sources:
        # No code to read — nothing can be said about what it imports.
        return {p: UNKNOWN for p in packages}
    commands = [p for p in client.files if not _skip(p) and (
        p.rsplit('/', 1)[-1] in COMMAND_FILES or p.rsplit('/', 1)[-1].startswith('Dockerfile')
        or p.endswith(COMMAND_SUFFIXES))]

    modules, words, total = set(), set(), 0
    for path in sources:
        text = client.local_text(path)
        if text is None:
            # One source file we cannot see is enough to make "not imported"
            # a guess. Say unknown instead.
            return {p: UNKNOWN for p in packages}
        total += len(text)
        if total > MAX_BYTES:
            return {p: UNKNOWN for p in packages}
        modules |= _py_modules(text) if ecosystem == 'PyPI' else _js_modules(text)
    for path in commands:
        text = client.local_text(path)
        if text:
            words |= _words(text)
    if ecosystem == 'npm':
        words |= _words(_package_json_scripts(client.local_text('package.json') or ''))

    result = {}
    for pkg in packages:
        if ecosystem == 'PyPI':
            names = _py_candidates(pkg)
            hit = bool(names & modules) or bool(names & words) or pkg.lower() in words
        else:
            names = _js_candidates(pkg)
            hit = bool(names & modules) or bool({n.lower() for n in names} & words)
        result[pkg] = IMPORTED if hit else NOT_IMPORTED
    return result
