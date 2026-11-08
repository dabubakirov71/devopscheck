"""
Where to look for things — shared by the checks and the repo_kind classifier.

Every function here answers "is it anywhere a maintainer would reasonably put
it?", not "is it at the one path we thought of first". Each fixed list of
paths this replaces produced a FAIL an engineer could disprove in a minute:
express keeps its changelog in History.md, fastapi in
docs/en/docs/release-notes.md, django in docs/releases/, a pnpm monorepo its
Dockerfile in apps/api/ (docs/accuracy/spec.md, stage 5).
"""
import posixpath
import re

DOC_EXTS = ('', '.md', '.markdown', '.rst', '.txt', '.adoc')
DOC_DIRS = ('', '.github', 'docs', 'doc', '.gitlab')

# Directories whose files are material for something else — a Dockerfile in a
# test fixture is not how the project ships.
_NOT_THE_PROJECT = re.compile(
    r'(?:^|/)(?:tests?|testdata|test-fixtures|fixtures|examples?|samples?|vendor|'
    r'node_modules|third[_-]party|\.devcontainer|devenv|dev-env|hack|e2e|benchmarks?|contrib|'
    r'scripts|tools|\.github|\.gitlab|\.circleci)/',
    re.IGNORECASE,
)


def find_named(client, stems, dirs=DOC_DIRS) -> str | None:
    """First file whose name (any case, a documentation extension) is one of
    `stems`, in the root or a conventional docs directory."""
    stems = {s.lower() for s in stems}
    hits = []
    for f in client.files:
        d, base = posixpath.split(f)
        if d not in dirs:
            continue
        stem, ext = posixpath.splitext(base.lower())
        if stem in stems and ext in DOC_EXTS:
            hits.append((dirs.index(d), f))
    return min(hits)[1] if hits else None


CHANGELOG_STEMS = ('changelog', 'changes', 'history', 'news', 'releases', 'release_notes',
                   'release-notes', 'releasenotes')
# Tooling that writes the changelog at release time: its presence is the
# changelog process, even before the first release has generated the file.
CHANGELOG_TOOLING = ('.changeset/config.json', 'release-please-config.json', '.goreleaser.yml',
                     '.goreleaser.yaml', 'towncrier.toml', 'cliff.toml', '.release-it.json')
CHANGELOG_DIRS = ('.changeset', 'newsfragments', 'changelog.d', 'changes', 'changelogs')
_DOCS_CHANGELOG = re.compile(r'^docs?/(?:.*/)?(?:release[-_]?notes?|changelogs?|releases|changes|history)'
                             r'(?:/|\.[a-z]+$)', re.IGNORECASE)


def find_changelog(client) -> str | None:
    hit = find_named(client, CHANGELOG_STEMS)
    if hit:
        return hit
    for f in sorted(client.files):
        if _DOCS_CHANGELOG.search(f):
            return f
    for path in CHANGELOG_TOOLING:
        if path in client.files:
            return path
    for d in CHANGELOG_DIRS:
        if d in client.dirs:
            return d + '/'
    return None


# Case-sensitive on purpose: `dockerTest/`, `integration-tests/`,
# `src/test/resources/` are test material; `docs/` partials are prose.
_TEST_OR_DOCS = re.compile(
    r'(?:^|/)(?:[\w-]*[-_][Tt]ests?|[a-z]\w*Tests?|docs?|documentation|resources|smoke-test|system-test)/')


def is_dockerfile(path: str) -> bool:
    base = posixpath.basename(path).lower()
    if base.endswith(('.dockerignore', '.md', '.txt', '.patch', '.orig')):
        return False
    return base == 'dockerfile' or base.startswith('dockerfile.') or base.endswith('.dockerfile')


def find_dockerfiles(client, limit=8) -> list[str]:
    """Every Dockerfile the project builds from — root first, then shallowest."""
    found = [f for f in client.files if is_dockerfile(f) and not _NOT_THE_PROJECT.search(f)
             and not _TEST_OR_DOCS.search(f)]
    return sorted(found, key=lambda f: (f.count('/'), posixpath.basename(f).lower() != 'dockerfile', f))[:limit]


# ── CI: what a test step hands off to ────────────────────────────────────────

_MAKE_CALL = re.compile(r'\bmake\s+(?:-\S+\s+)*([\w.-]+)')
_PKG_RUN = re.compile(r'\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?([\w:.-]+)')
_SCRIPT_REF = re.compile(r'(?<![\w/.-])\.?/?((?:[\w.-]+/)*[\w.-]+\.(?:sh|bash|ps1))\b')
_BARE_SCRIPT = re.compile(r'(?<![\w/.-])\.?/?((?:scripts?|bin|ci|tools|hack|build)/[\w.-]+)')
_LOCAL_ACTION = re.compile(r'uses:\s*\.?/?(\.github/actions/[\w./-]+)')
_LOCAL_WORKFLOW = re.compile(r'uses:\s*\.?/?(\.github/workflows/[\w.-]+\.ya?ml)')
_GITLAB_INCLUDE = re.compile(r'''(?:local:\s*|^\s*-\s*)['"]?/?([\w./-]+\.ya?ml)['"]?''', re.MULTILINE)


def _make_target(makefile: str, target: str) -> str:
    """The recipe of `target` in a Makefile, plus the recipes of its prerequisites."""
    out, seen, queue = [], set(), [target]
    while queue and len(seen) < 10:
        t = queue.pop(0)
        if t in seen:
            continue
        seen.add(t)
        m = re.search(rf'^{re.escape(t)}\s*:(?!=)([^\n]*)\n((?:\t[^\n]*\n?)*)', makefile, re.MULTILINE)
        if m:
            queue += m.group(1).split()
            out.append(m.group(2))
    return '\n'.join(out)


def expand_ci(client, ci_paths: list[str], texts: dict[str, str]) -> dict[str, str]:
    """
    Follow what the CI files call, one level deep: GitLab `include:` files,
    local reusable workflows and composite actions, Makefile targets,
    package.json scripts and shell scripts. Returns {source label: text}
    for everything newly read, so evidence can name where a command lives.
    """
    extra: dict[str, str] = {}
    blob = '\n'.join(texts.values())
    files = client.files

    def add(label, text):
        if text and label not in texts and label not in extra:
            extra[label] = text

    for rx in (_GITLAB_INCLUDE, _LOCAL_WORKFLOW):
        for path in rx.findall(blob):
            path = path.lstrip('/')
            if path.startswith('./'):
                path = path[2:]
            if path in files:
                add(path, client.get_content(path))
    # A second pass: an included file may include (or call) the next one.
    for path in _GITLAB_INCLUDE.findall('\n'.join(extra.values())):
        path = path.lstrip('/')
        if path in files:
            add(path, client.get_content(path))
    for d in _LOCAL_ACTION.findall(blob):
        d = d.rstrip('/')
        for name in ('action.yml', 'action.yaml'):
            if f'{d}/{name}' in files:
                add(f'{d}/{name}', client.get_content(f'{d}/{name}'))
    blob = '\n'.join([blob, *extra.values()])

    for path in {*_SCRIPT_REF.findall(blob), *_BARE_SCRIPT.findall(blob)}:
        if path in files:
            add(path, client.get_content(path))

    makefile = client.get_content('Makefile') if 'Makefile' in files else None
    if makefile:
        for target in set(_MAKE_CALL.findall(blob)):
            add(f'Makefile:{target}', _make_target(makefile, target))

    for name, runner_file in (('package.json', 'package.json'),):
        if runner_file not in files:
            continue
        import json
        try:
            scripts = json.loads(client.get_content(runner_file) or '{}').get('scripts') or {}
        except (ValueError, AttributeError):
            scripts = {}
        for script in set(_PKG_RUN.findall(blob)):
            if script in scripts and isinstance(scripts[script], str):
                add(f'package.json:{script}', scripts[script])

    for name in ('tox.ini', 'noxfile.py', 'justfile', 'Justfile', 'Taskfile.yml'):
        low = name.lower().split('.')[0]
        if name in files and low in blob.lower():
            add(name, client.get_content(name))
    return extra


# ── Secrets: values published in documentation ───────────────────────────────

# Credentials that vendors print in their own docs so readers can copy the
# shape. They authenticate nothing, and flagging one as a critical leak is a
# FAIL any engineer disproves by pasting it into a search engine.
DOCUMENTED_EXAMPLE_VALUES = frozenset({
    'AKIAIOSF' + 'ODNN7EXAMPLE',  # split: GitHub secret scanning flags the literal
    'wJalrXUt' + 'nFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',  # split: GitHub secret scanning flags the literal
    'AKIAI44Q' + 'H8DHBEXAMPLE',  # split: GitHub secret scanning flags the literal
    'je7MtGbC' + 'lwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY',  # split: GitHub secret scanning flags the literal
    'ASIAIOSF' + 'ODNN7EXAMPLE',  # split: GitHub secret scanning flags the literal
    'sk_test_' + '4eC39HqLyjWDarjtT1zdp7dc',  # split: GitHub push protection flags the literal
    'xoxb-not-a-real-token-this-will-not-work',
})


def is_documented_example(value: str) -> bool:
    v = (value or '').strip().strip('\'"')
    return v in DOCUMENTED_EXAMPLE_VALUES or v.upper().endswith(('EXAMPLE', 'EXAMPLEKEY'))
