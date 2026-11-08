"""
What kind of repository is this, and which checks therefore have no meaning here.

The score used to assume every repository is a deployable service. `psf/requests`
was marked down for shipping no Dockerfile, no `.dockerignore` and no non-root
container user — three findings a library can never act on. Three of its five
remaining findings were unreachable by design, and the same held for every
library on the platform.

A number people do not trust is a number they will not put in a README badge or
show to an auditor, so this is the difference between a score that sells the
product and one that quietly discredits it.

The default is `service`: when the evidence is thin, every check applies and
nothing is silently forgiven. Only a repository that clearly publishes a package,
clearly ships a CLI, is clearly documentation, is clearly a workspace of several
projects, or clearly deploys nothing loses the checks that assumption does not fit.

`confidence` (0.0-1.0) says how sure the heuristic is, separately from the kind
itself — a `kind:` declared in `.devopsaudit.yml` is maximally trusted (1.0); a
heuristic match on an explicit marker (a console_scripts entry point, a
`pnpm-workspace.yaml`) is high; a heuristic match on a fuzzier signal (mostly
markdown, no code) is lower. It is recorded on `Audit`/`PublicScan` so a future
caller can decide not to trust a public page to Google when the classification
underneath it is a guess — nothing reads it for that yet; no page currently
sets noindex based on it.
"""
import logging
import re

logger = logging.getLogger(__name__)

SERVICE = 'service'
LIBRARY = 'library'
INFRASTRUCTURE = 'infrastructure'
CLI = 'cli'
MONOREPO = 'monorepo'
DOCS = 'docs'
UNKNOWN = 'unknown'

#: Artefacts that mean something here gets deployed, whatever else the repo is.
DEPLOY_ARTEFACTS = (
    'Dockerfile', 'dockerfile', 'Containerfile',
    'docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml',
    'Procfile', 'serverless.yml', 'serverless.yaml', 'app.yaml', 'fly.toml',
    'vercel.json', 'netlify.toml', 'railway.json', 'render.yaml', 'captain-definition',
    'Chart.yaml', 'skaffold.yaml', 'kustomization.yaml', 'kustomization.yml',
)
DEPLOY_DIR_PREFIXES = (
    'k8s/', 'kubernetes/', 'deploy/', 'deployment/', 'helm/', 'charts/', '.ebextensions/',
    'manifests/', 'infra/k8s/',
)

#: A container image is the strongest deploy signal there is — nothing static
#: builds one. Distinguishes an actually-containerised service (checked for
#: healthchecks, non-root, pinning) from a repo that merely has a `render.yaml`
#: pointing at a buildpack, which the DEPLOYMENT_CHECKS below have nothing to say.
DOCKERFILES = ('Dockerfile', 'docker/Dockerfile', 'build/Dockerfile', 'deploy/Dockerfile')

#: Files that declare a distributable package (importable — has a public API).
PACKAGE_MANIFESTS = (
    'setup.py', 'setup.cfg', 'pyproject.toml',
    'package.json', 'Cargo.toml', 'composer.json', 'pom.xml', 'build.gradle',
    'build.gradle.kts', 'go.mod', 'mix.exs', 'pubspec.yaml',
)

#: Suffixes that make a repository infrastructure rather than an application.
IAC_SUFFIXES = ('.tf', '.tfvars', '.bicep')
IAC_DIR_HINTS = ('ansible/', 'roles/', 'playbooks/', 'terraform/')

#: Source extensions that say an application (or library, or CLI) lives here.
CODE_SUFFIXES = (
    '.py', '.js', '.ts', '.tsx', '.jsx', '.go', '.rs', '.rb', '.php', '.java',
    '.kt', '.cs', '.ex', '.exs', '.swift', '.c', '.cc', '.cpp', '.scala',
)

DOC_SUFFIXES = ('.md', '.mdx', '.rst', '.adoc', '.txt')

#: Explicit "this is a documentation site" markers — a static-site generator
#: config is a stronger signal than "mostly markdown", which a well-documented
#: library also is.
DOCS_SITE_MARKERS = (
    'mkdocs.yml', 'mkdocs.yaml', 'docusaurus.config.js', 'docusaurus.config.ts',
    '.vuepress/config.js', '.vitepress/config.js', '.vitepress/config.ts',
    'book.toml', 'antora.yml', 'conf.py',  # conf.py: Sphinx, in a repo with no code
)

#: Explicit "this is a workspace of several projects" markers.
MONOREPO_MARKERS = (
    'pnpm-workspace.yaml', 'lerna.json', 'nx.json', 'turbo.json', 'rush.json',
    'go.work',
)

#: Checks that only make sense for something that gets deployed. A library has
#: no image to build, no container user to drop and no runtime to instrument.
#: A CLI tool run on someone's machine is in the same position.
DEPLOYMENT_CHECKS = (
    'docker.dockerfile', 'docker.dockerignore', 'docker.nonroot',
    'docker.healthcheck', 'docker.multistage', 'docker.pinned_base',
    'docker.resource_limits',
    'ops.observability',
)

#: Checks that assume application dependencies. A Terraform repository has none,
#: and neither does a documentation site (its own tooling's dependencies are not
#: the product).
APPLICATION_CHECKS = (
    'deps.manifest', 'deps.lockfile', 'deps.pinned', 'deps.cve',
)

#: `deps.*` reads a single manifest/lockfile at the repository root. Many real
#: workspaces (pnpm, yarn, cargo, and — confirmed against the real
#: tiangolo/full-stack-fastapi-template, which keeps a root package.json and
#: pyproject.toml alongside its per-service ones — plenty of polyrepo-style
#: templates too) *do* keep a meaningful root manifest, and a
#: `deps.manifest`/`deps.lockfile` pass there is real and should not be
#: hidden. Some genuinely do not: a workspace whose every manifest sits one
#: level down, with nothing at the root at all, leaves `deps.manifest` (crit,
#: 30 points) with nothing to read — failing a repository that pins its
#: dependencies just not at the one path the check looks at. `detect()` picks
#: between the two sets below by checking whether a root manifest actually
#: exists, rather than assuming either way.
MONOREPO_SKIPPED_CHECKS_NO_ROOT_MANIFEST = APPLICATION_CHECKS
MONOREPO_SKIPPED_CHECKS_WITH_ROOT_MANIFEST = ('deps.pinned',)


def _reads(client, path):
    try:
        return client.get_content(path) or ''
    except Exception:                                   # pragma: no cover - defensive
        return ''


def _declares_a_library(client):
    """
    Is there packaging metadata describing something published to a registry,
    with an importable public API? Returns (bool, confidence).

    Checked before `_declares_a_cli` in `detect()`, deliberately — a `bin`
    entry or a console-script alongside a real package declaration is a
    library that also ships a CLI convenience wrapper (fastapi, poetry, click
    itself), not a CLI. Under PEP 621 this is not even an edge case:
    `[project.scripts]` is a subtable of `[project]`, so any modern Python
    package with a console script necessarily also declares `[project]` — the
    two signals almost always coexist, and the package is the library.
    """
    if client.any_exists(('setup.py',)):
        return True, 0.75
    if any(p.endswith('.gemspec') for p in client.files):
        return True, 0.85

    pyproject = _reads(client, 'pyproject.toml')
    if '[project]' in pyproject or '[tool.poetry]' in pyproject:
        return True, 0.85

    setup_cfg = _reads(client, 'setup.cfg')
    if '[metadata]' in setup_cfg:
        return True, 0.8

    # A crate can ship both a library and a demo/companion binary — `src/lib.rs`
    # (or a `[lib]` table pointing elsewhere) is what makes it importable, and
    # its presence wins regardless of what else is in the crate.
    cargo = _reads(client, 'Cargo.toml')
    if '[package]' in cargo and ('[lib]' in cargo or client.exists('src/lib.rs')):
        return True, 0.85

    # Go: top-level .go files and none of them `package main` — an importable
    # package at the module root (gin-gonic/gin). Binaries live in cmd/ or
    # declare main at the root; either is handled by _declares_a_cli / service.
    if client.exists('go.mod'):
        top_go = [p for p in client.files if p.endswith('.go') and '/' not in p and not p.endswith('_test.go')]
        if top_go and not any(p.startswith('cmd/') for p in client.files) and not any(
                re.search(r'^package\s+main\b', _reads(client, p), re.M) for p in top_go[:40]):
            return True, 0.8

    # JVM: a build that publishes to a Maven repository (spring-boot keeps it
    # in buildSrc conventions) or declares itself a library.
    jvm_build = [p for p in ('build.gradle', 'build.gradle.kts', 'pom.xml') if client.exists(p)]
    if jvm_build:
        build_text = ' '.join(_reads(client, p) for p in jvm_build)
        build_src = [p for p in client.files if p.startswith('buildSrc/src/main/')][:200]
        if (any(s in build_text for s in ('maven-publish', 'java-library', '<distributionManagement>',
                                          'nexusPublishing', 'com.vanniktech.maven.publish'))
                or any('Publish' in p.rsplit('/', 1)[-1] for p in build_src)):
            return True, 0.75

    package_json = _reads(client, 'package.json')
    if package_json and '"name"' in package_json and '"private":true' not in package_json.replace(' ', ''):
        # "main" alone is not a library: npm init writes it into every app
        # (docker/getting-started-app, bradtraversy/devconnector — servers
        # with "main": "server.js"). What an application never declares is
        # what gets published: an exports map, types, a files allowlist.
        if any(field in package_json for field in ('"exports"', '"module"', '"types"', '"typings"',
                                                   '"publishConfig"', '"peerDependencies"')):
            return True, 0.8
        # `bin` is installed by `npm install -g` — only published packages have one.
        if '"main"' in package_json and ('"files"' in package_json or '"bin"' in package_json):
            return True, 0.75
        # No explicit entry point declared — Node defaults to `index.js`, which
        # older and simpler packages (express among them) rely on instead of
        # naming it. A `"files"` allowlist is what actually goes to the npm
        # registry on publish, and is not something an application declares.
        if '"files"' in package_json and client.exists('index.js'):
            return True, 0.6

    return False, 0.0


def _declares_a_cli(client):
    """
    Is there an explicit "this installs a command, and nothing importable"
    marker? Returns (bool, confidence).

    Deliberately narrower than `_declares_a_library`'s reach: Python is not
    checked here at all (see that function's docstring — pyproject.toml gives
    no reliable way to tell "only a CLI" from "a library with a CLI wrapper"),
    and Rust/Node.js/Go are only claimed when there is no sign of an
    importable API sitting next to the binary.
    """
    package_json = _reads(client, 'package.json')
    if package_json and '"bin"' in package_json:
        if not any(f in package_json for f in ('"main"', '"exports"', '"module"')):
            return True, 0.9

    cargo = _reads(client, 'Cargo.toml')
    if ('[[bin]]' in cargo or client.exists('src/main.rs')) and '[lib]' not in cargo and not client.exists('src/lib.rs'):
        return True, 0.85

    # Go: an importable library has no `main` package; a CLI's entry points
    # live under cmd/<name>/main.go — the idiomatic layout for a Go binary.
    # A repository that is both (a CLI with an importable client library
    # alongside it, e.g. an SDK with its own `cmd/`) is filed as the library:
    # a top-level Go file outside `cmd/` that is not itself `package main` is
    # what an importable API looks like.
    if client.exists('go.mod'):
        cmd_mains = [p for p in client.files
                     if p.startswith('cmd/') and p.endswith('main.go')]
        top_level_go = [p for p in client.files
                        if p.endswith('.go') and '/' not in p]
        if cmd_mains and not top_level_go:
            return True, 0.85

    return False, 0.0


def _root_is_private(client):
    return '"private":true' in _reads(client, 'package.json').replace(' ', '')


def _deploys_something(client):
    if client.any_exists(DEPLOY_ARTEFACTS):
        return True
    for path in client.files:
        if path.startswith(DEPLOY_DIR_PREFIXES):
            return True
    return False


def _infrastructure_share(client):
    """(infrastructure files, application source files) in the repository."""
    iac = code = 0
    for path in client.files:
        if path.endswith(IAC_SUFFIXES) or any(h in path for h in IAC_DIR_HINTS):
            iac += 1
        elif path.endswith(CODE_SUFFIXES):
            code += 1
    return iac, code


def _is_monorepo(client):
    """
    Several independently-versioned packages in one repository. Returns (bool, confidence).

    A workspace tool config is unambiguous. Without one, several manifests in
    different top-level directories is suggestive but not certain — a project
    that just vendors a couple of dependencies as subtrees would look the same,
    so that path is scored lower.
    """
    if client.any_exists(MONOREPO_MARKERS):
        return True, 0.9
    # Without a workspace tool, nested manifests under a root that has its
    # own are helpers of that one project (gitlab-org/gitlab-runner keeps
    # small Go modules in helpers/ and scripts/), not sibling projects.
    if client.any_exists(PACKAGE_MANIFESTS + ('requirements.txt',)):
        return False, 0.0

    # The immediate parent directory of each nested manifest — not just its
    # top-level segment, or `services/api/go.mod` and `services/worker/go.mod`
    # collapse into the one bucket "services" and look like a single package.
    manifest_dirs = set()
    for path in client.files:
        name = path.rsplit('/', 1)[-1]
        if name in PACKAGE_MANIFESTS and '/' in path:
            manifest_dirs.add(path.rsplit('/', 1)[0])
    if len(manifest_dirs) >= 2:
        return True, 0.6

    return False, 0.0


def _is_docs_only(client, code_files, iac_files):
    """
    A documentation site rather than a piece of software. Returns (bool, confidence).

    `.tf` is not a `CODE_SUFFIXES` extension, so `code_files == 0` alone is
    true of any Terraform module — caught on terraform-aws-modules/
    terraform-aws-vpc, a pure infrastructure module with the thorough
    `README.md` any well-kept module has, which is five-plus markdown files
    for free. `iac_files` rules that case out explicitly rather than by
    accident of check ordering.
    """
    if iac_files > 0:
        return False, 0.0

    has_marker = client.any_exists(DOCS_SITE_MARKERS)
    doc_files = sum(1 for p in client.files if p.endswith(DOC_SUFFIXES))

    if has_marker and code_files == 0:
        return True, 0.85
    if code_files == 0 and doc_files >= 5:
        return True, 0.55
    return False, 0.0


def _monorepo_skip(client):
    """Which deps.* checks a monorepo's root genuinely has nothing to answer for."""
    has_root_manifest = client.any_exists(PACKAGE_MANIFESTS + ('requirements.txt',))
    if has_root_manifest:
        return set(MONOREPO_SKIPPED_CHECKS_WITH_ROOT_MANIFEST)
    return set(MONOREPO_SKIPPED_CHECKS_NO_ROOT_MANIFEST)


#: `(extra_skipped_check_ids, reason)` per kind, layered on top of what the
#: engine already marks not-applicable per-file (e.g. `docker.healthcheck`
#: with no Dockerfile and no compose file — that path is unconditional and
#: does not need a `kind` to explain it).
SKIPPED_BY_KIND = {
    LIBRARY: (
        set(DEPLOYMENT_CHECKS),
        'A published package rather than a deployed service: it has no image '
        'to build and no runtime to instrument.',
    ),
    CLI: (
        set(DEPLOYMENT_CHECKS),
        'A command-line tool run on someone else’s machine, not a deployed '
        'service: it has no image to build and no runtime to instrument.',
    ),
    INFRASTRUCTURE: (
        set(DEPLOYMENT_CHECKS) | set(APPLICATION_CHECKS),
        'Infrastructure definitions, not an application: the container and '
        'dependency checks have nothing to read.',
    ),
    DOCS: (
        # Nothing to test and nothing released in versions: a list or a
        # handbook is edited in place (sindresorhus/awesome).
        set(DEPLOYMENT_CHECKS) | set(APPLICATION_CHECKS) | {'ci.tests', 'docs.changelog'},
        'A documentation site, not a deployed application: there is no container, '
        'no dependencies, no test suite and no versioned release to check.',
    ),
    # Placeholder — `detect()` overwrites this with one of the two
    # MONOREPO_SKIPPED_CHECKS_* sets once it knows whether a root manifest
    # exists, for both the heuristic path and a repository-declared
    # `kind: monorepo`. Present here only so MONOREPO is a valid key.
    MONOREPO: (
        set(MONOREPO_SKIPPED_CHECKS_NO_ROOT_MANIFEST),
        'Several independently-versioned packages in one repository: version '
        'pinning is a property of each package’s own manifest, not of one '
        'file at the root.',
    ),
    SERVICE: (set(), ''),
    UNKNOWN: (set(), ''),
}


def detect(client, forced_kind=''):
    """
    Return `(kind, skipped_check_ids, reason, confidence)`.

    `forced_kind` comes from `kind:` in the repository's own `.devopsaudit.yml`.
    The repository knows what it is better than a file-tree heuristic does, and
    a heuristic nobody can correct is one people work around instead of using —
    forcing it also means confidence is 1.0, the ceiling every heuristic path
    below is deliberately kept under.

    `reason` is shown to the reader — a check that vanishes without explanation
    reads as a check that was quietly failed.

    `confidence` is 0.0-1.0. It is a property of the *classification*, not of
    the checks that follow from it, and it is what a caller reads before
    deciding whether a public page is worth Google's trust (see `repo_kind`
    module docstring).
    """
    if forced_kind in SKIPPED_BY_KIND:
        skipped, reason = SKIPPED_BY_KIND[forced_kind]
        if forced_kind == MONOREPO:
            skipped = _monorepo_skip(client)
        if reason:
            reason = f'{reason} Declared as `kind: {forced_kind}` in .devopsaudit.yml.'
        return forced_kind, set(skipped), reason, 1.0

    iac_files, code_files = _infrastructure_share(client)
    from app.detectors import find_dockerfiles
    has_dockerfile = bool(client.any_exists(DOCKERFILES) or find_dockerfiles(client, limit=1))
    deploys = _deploys_something(client)
    is_monorepo, monorepo_conf = _is_monorepo(client)
    is_docs, docs_conf = _is_docs_only(client, code_files, iac_files)
    is_cli, cli_conf = _declares_a_cli(client)
    is_library, library_conf = _declares_a_library(client)

    # Order matters: each branch below assumes every earlier one has already
    # ruled itself out, so the strongest, least ambiguous signal goes first.
    charts = sum(1 for p in client.files if p.rsplit('/', 1)[-1] == 'Chart.yaml')
    root_dockerfile = client.any_exists(DOCKERFILES)
    if is_docs and not has_dockerfile:
        kind, confidence = DOCS, docs_conf
    elif charts >= 2 and not has_dockerfile and code_files <= charts * 3:
        # A repository of Helm charts: it packages other people's images,
        # it does not build or run one of its own.
        kind, confidence = INFRASTRUCTURE, 0.85
    elif is_monorepo and root_dockerfile:
        # A workspace whose root builds one image ships one service
        # (grafana/grafana: go.work + nx + lerna, and a root Dockerfile).
        kind, confidence = SERVICE, 0.8
    elif is_monorepo and is_library and not _root_is_private(client):
        # The root package is the product and the workspace holds its
        # plugins (TryGhost/Ghost-CLI: pnpm workspace of extensions/).
        kind, confidence = LIBRARY, 0.75
    elif is_monorepo:
        kind, confidence = MONOREPO, monorepo_conf
    elif not deploys and iac_files >= 3 and code_files <= iac_files:
        ratio = iac_files / max(1, iac_files + code_files)
        kind, confidence = INFRASTRUCTURE, round(min(0.95, 0.55 + 0.3 * ratio), 2)
    elif not deploys and is_cli:
        kind, confidence = CLI, cli_conf
    elif not deploys and is_library:
        kind, confidence = LIBRARY, library_conf
    elif not deploys and code_files == 0 and iac_files == 0:
        # Nothing here says application, library, CLI or infra — sometimes
        # because the repository is genuinely empty, sometimes because it
        # holds only things this heuristic has no opinion on (docs below the
        # docs-only bar, plain config, data). Kept at SERVICE's default skip
        # set — see the module docstring on why an unclear repository is never
        # quietly forgiven a check — but flagged with low confidence so a
        # public page built on this guess is not handed to Google as if it
        # were certain.
        kind, confidence = UNKNOWN, 0.3
    else:
        kind, confidence = SERVICE, (0.9 if has_dockerfile else 0.6)

    skipped, reason = SKIPPED_BY_KIND[kind]
    if kind == MONOREPO:
        skipped = _monorepo_skip(client)
    skipped = set(skipped)
    if kind in (LIBRARY, CLI) and _publishes_without_lockfile(client):
        skipped.add('deps.lockfile')
    return kind, skipped, reason, confidence


LOCKFILE_REASON = ('A published npm or Python package: its lock file is not shipped to the '
                   'people who install it, so committing one changes nothing for them.')


def _publishes_without_lockfile(client):
    """
    An npm or Python package: the lock file never reaches its users (npm does
    not publish it, pip ignores it), so its absence changes nothing they
    install. Rust and Go libraries are not in this set — go.sum is part of
    the module, and a committed Cargo.lock is harmless and common.
    """
    return bool(client.any_exists(('package.json', 'pyproject.toml', 'setup.py', 'setup.cfg'))) \
        and not client.any_exists(('go.mod', 'Cargo.toml'))


def apply(checks, client, forced_kind=''):
    """
    Mark the checks that do not apply to this repository and say why.

    Nothing is removed — a reader who disagrees with the classification needs to
    see what was set aside, and a check that reappears when the repository grows
    a Dockerfile should not look like a regression.
    """
    kind, skipped, reason, confidence = detect(client, forced_kind=forced_kind)
    for check in checks:
        if check['check_id'] in skipped:
            check['applicable'] = False
            check['not_applicable_reason'] = (
                LOCKFILE_REASON if check['check_id'] == 'deps.lockfile' and kind in (LIBRARY, CLI)
                else reason)
    count = sum(1 for c in checks if not c.get('applicable', True))
    logger.info('Repository kind for %s: %s confidence=%.2f (%d check(s) not applicable)',
                getattr(client, 'full_name', '?'), kind, confidence, count)
    return kind, count, reason, confidence
