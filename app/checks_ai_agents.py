"""
AI agent safety: MCP server configs, AI agents in CI, agent instruction files.

A repository now carries configuration for tools that act on their own: MCP
servers an editor starts with the developer's credentials, CI jobs that hand
an issue's text to a model holding a write token, instruction files every
agent reads first. Each is a place a credential gets pasted "just for now",
or where text from a stranger reaches something that can push.

Detection reuses the secret scanner's rules (`checks_secrets.RULES`) rather
than a second scanner. MCP configs are left out of the generic scan
(`checks_secrets.find_secrets` skips `is_agent_file` paths) so one pasted
token is one finding, reported here, where the fix is specific: move it to
the server's `env` as an environment reference.

Every check is not-applicable when the repository has nothing of its kind —
a repository without MCP configs earns no points for not leaking them.
"""
import json
import logging
import re
from urllib.parse import parse_qs, urlparse

from django.utils.translation import gettext as _

from app.checks import _not_applicable

logger = logging.getLogger(__name__)

CATEGORY = 'ai_agents'
MAX_FILES = 20

# ── Which files ───────────────────────────────────────────────────────────────

MCP_BASENAMES = {
    '.mcp.json', 'mcp.json', 'claude_desktop_config.json', 'cline_mcp_settings.json',
    'mcp_config.json', 'mcp_settings.json',
}
MCP_SUFFIXES = ('.gemini/settings.json', '.kiro/settings/mcp.json')

INSTRUCTION_BASENAMES = {
    'CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md', 'GEMINI.md', '.cursorrules',
    '.windsurfrules', '.clinerules', 'copilot-instructions.md',
}
INSTRUCTION_DIRS = ('.cursor/rules/', '.windsurf/rules/', '.clinerules/', '.github/instructions/')

_SKIP_PARTS = ('node_modules/', 'vendor/', 'dist/', 'build/', '.venv/', 'site-packages/',
               'third_party/')


def _skipped(path):
    return any(part in path for part in _SKIP_PARTS)


def is_mcp_config(path: str) -> bool:
    name = path.rsplit('/', 1)[-1]
    return not _skipped(path) and (name in MCP_BASENAMES or path.endswith(MCP_SUFFIXES))


def is_instruction_file(path: str) -> bool:
    if _skipped(path):
        return False
    name = path.rsplit('/', 1)[-1]
    if name in INSTRUCTION_BASENAMES:
        return True
    return any(d in path for d in INSTRUCTION_DIRS) and name.endswith(('.md', '.mdc', '.txt'))


def is_agent_file(path: str) -> bool:
    return is_mcp_config(path) or is_instruction_file(path)


# ── Secrets, through the scanner's own rules ──────────────────────────────────

_SECRET_NAME = re.compile(r'(?i)(token|secret|passw(or)?d|passwd|api[_-]?key|apikey|'
                          r'access[_-]?key|private[_-]?key|credential|auth[_-]?token|'
                          r'(^|_)pat$|_key$|^key$)')
_REFERENCE = re.compile(r'^\s*(\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]*\}\}|<[^>]*>)\s*$')
_BEARER = re.compile(r'(?i)^\s*(bearer|token|basic)\s+')
_SECRET_FLAG = re.compile(r'(?i)^--?(token|api[-_]?key|secret|password|access[-_]?token|pat)(=(.*))?$')
_SECRET_QUERY = re.compile(r'(?i)(token|key|secret|password|apikey|api_key|access_token)')


def _rule_hits(text):
    """(rule label, severity) for every provider/generic rule the text matches."""
    from app.checks_secrets import RULES, _is_placeholder, shannon_entropy
    hits = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            value = m.group(rule.group) if rule.group else m.group(0)
            if rule.group and (_is_placeholder(value)
                               or (rule.entropy and shannon_entropy(value) < rule.entropy)):
                continue
            hits.append((rule.label, rule.severity))
            break
    return hits


def _literal_secret(value) -> bool:
    """A value that is typed in, not a reference to an environment variable or input."""
    from app.checks_secrets import _is_placeholder
    if not isinstance(value, str):
        return False
    value = _BEARER.sub('', value).strip()
    if len(value) < 8 or _REFERENCE.match(value) or '${' in value or _is_placeholder(value):
        return False
    return True


# ── MCP configs ───────────────────────────────────────────────────────────────

def _load_jsonc(text):
    """JSON, tolerating the comments and trailing commas VS Code writes."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    stripped = re.sub(r'(?m)^\s*//.*$', '', text)
    stripped = re.sub(r'/\*.*?\*/', '', stripped, flags=re.S)
    stripped = re.sub(r',(\s*[}\]])', r'\1', stripped)
    try:
        return json.loads(stripped)
    except ValueError:
        return None


def _servers(doc):
    if not isinstance(doc, dict):
        return {}
    for holder in (doc, doc.get('mcp') if isinstance(doc.get('mcp'), dict) else {}):
        for key in ('mcpServers', 'servers', 'mcp_servers'):
            servers = holder.get(key)
            if isinstance(servers, dict):
                return {str(k): v for k, v in servers.items() if isinstance(v, dict)}
    return {}


def _server_secrets(server):
    """Names (never values) of the places a literal credential sits in one server."""
    found = []
    for field in ('env', 'headers'):
        block = server.get(field)
        if isinstance(block, dict):
            for key, value in block.items():
                if (_SECRET_NAME.search(str(key)) or str(key).lower() == 'authorization') \
                        and _literal_secret(value):
                    found.append(f'{field}.{key}')
    args = [a for a in server.get('args') or [] if isinstance(a, str)]
    for i, arg in enumerate(args):
        m = _SECRET_FLAG.match(arg)
        if m:
            value = m.group(3) if m.group(2) else (args[i + 1] if i + 1 < len(args) else '')
            if _literal_secret(value):
                found.append(f'args {m.group(0).split("=")[0]}')
    url = server.get('url') or server.get('serverUrl')
    if isinstance(url, str):
        query = parse_qs(urlparse(url).query)
        for key, values in query.items():
            if _SECRET_QUERY.search(key) and any(_literal_secret(v) for v in values):
                found.append(f'url ?{key}=')
    return found


_NPM_RUNNERS = {'npx', 'bunx', 'pnpx'}
_PY_RUNNERS = {'uvx', 'pipx'}
_VALUE_FLAGS = {'-p', '--package', '--from', '--python', '--with', '-e', '--env', '-v',
                '--volume', '--name', '--network', '--env-file', '--mount', '-w', '--workdir',
                '--registry', '--index-url', '--user', '-u'}


def _first_package(args, start=0):
    i = start
    while i < len(args):
        arg = args[i]
        if arg in _VALUE_FLAGS:
            i += 2
            continue
        if arg.startswith('-'):
            i += 1
            continue
        return arg
    return None


def _npm_pinned(spec):
    at = spec.rfind('@')
    if at <= 0:
        return False
    version = spec[at + 1:]
    return bool(re.match(r'^v?\d', version))


def _py_pinned(spec):
    if '==' in spec:
        return True
    at = spec.rfind('@')
    return at > 0 and bool(re.match(r'^v?\d', spec[at + 1:]))


def _image_pinned(image):
    if '@sha256:' in image:
        return True
    last = image.rsplit('/', 1)[-1]
    return ':' in last and last.rsplit(':', 1)[1] != 'latest'


def _downloads_a_package(server):
    """Started through a runner that fetches it (npx, uvx, docker run, …) — the only kind a version pins."""
    tool = str(server.get('command') or '').rsplit('/', 1)[-1].lower()
    args = [a for a in server.get('args') or [] if isinstance(a, str)]
    return (tool in _NPM_RUNNERS or tool in _PY_RUNNERS
            or (tool in {'pnpm', 'yarn'} and args[:1] == ['dlx'])
            or (tool in {'docker', 'podman'} and 'run' in args))


def _unpinned_package(server):
    """The package spec a local server runs without a fixed version, or None."""
    command = str(server.get('command') or '')
    tool = command.rsplit('/', 1)[-1].lower()
    args = [a for a in server.get('args') or [] if isinstance(a, str)]
    if tool in {'pnpm', 'yarn'} and args[:1] == ['dlx']:
        tool, args = 'npx', args[1:]
    if tool in _NPM_RUNNERS:
        spec = next((args[i + 1] for i, a in enumerate(args[:-1]) if a in ('-p', '--package')), None) \
            or _first_package(args)
        return spec if spec and not _npm_pinned(spec) else None
    if tool in _PY_RUNNERS:
        if tool == 'pipx' and args[:1] == ['run']:
            args = args[1:]
        spec = next((args[i + 1] for i, a in enumerate(args[:-1]) if a == '--from'), None) \
            or _first_package(args)
        return spec if spec and not _py_pinned(spec) else None
    if tool in {'docker', 'podman'} and 'run' in args:
        image = _first_package(args, args.index('run') + 1)
        return image if image and '$' not in image and not _image_pinned(image) else None
    return None


def _mcp_checks(client):
    paths = sorted(p for p in client.files if is_mcp_config(p))[:MAX_FILES]
    secrets, unpinned, local_servers = [], [], 0
    for path in paths:
        text = client.get_content(path) or ''
        servers = _servers(_load_jsonc(text))
        for name, server in servers.items():
            for where in _server_secrets(server):
                secrets.append(f'{path} → {name} ({where})')
            if _downloads_a_package(server):
                local_servers += 1
                spec = _unpinned_package(server)
                if spec:
                    unpinned.append(f'{path} → {name}: {spec}')
        # Provider-format keys anywhere in the file, including places the
        # structure above does not look (a token baked into a command string).
        if not any(s.startswith(f'{path} ') for s in secrets):
            for label, _severity in _rule_hits(text):
                secrets.append(f'{path} ({label})')

    secret_check = {
        'check_id': 'ai.mcp_secrets', 'name': _('No credentials in MCP server configs'),
        'severity': 'crit', 'passed': not secrets, 'category': CATEGORY,
        'description': (
            _('A credential is typed into an MCP config that is committed to the repository: '
              '%(where)s. Everyone who can read the repository — and every tool that indexes '
              'it — has that token.') % {'where': _samples(secrets)})
        if secrets else _('MCP configs reference credentials from the environment instead of '
                          'containing them.'),
        'recommendation': '' if not secrets else (
            _('Rotate the token first — it is already exposed. Then reference it instead of '
              'writing it:') + '\n'
            '  "env": { "GITHUB_TOKEN": "${env:GITHUB_TOKEN}" }     // VS Code, Cursor\n'
            '  "env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" }         // Claude Code .mcp.json\n'
            + _('Keep per-person configs out of git (add them to .gitignore) and commit an '
                'example file without values.')),
    }
    pin_check = {
        'check_id': 'ai.mcp_pinned', 'name': _('MCP servers run a pinned version'),
        'severity': 'warn', 'passed': not unpinned, 'category': CATEGORY,
        'description': (
            _('%(where)s starts an MCP server with no fixed version, so every editor start '
              'downloads whatever was published last — with your credentials in its '
              'environment.') % {'where': _samples(unpinned)})
        if unpinned else _('Every locally started MCP server names an exact version.'),
        'recommendation': '' if not unpinned else (
            _('Name the exact version:') + '\n'
            '  "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"]   // npx\n'
            '  "args": ["mcp-server-fetch==2025.4.7"]                           // uvx\n'
            '  "args": ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server:v0.5.0"]  // docker\n'
            + _('Renovate and Dependabot do not see these files; review the versions when you '
                'review other dependencies.')),
    }
    if not paths:
        _not_applicable(secret_check, _('The repository has no MCP server configs.'))
        _not_applicable(pin_check, _('The repository has no MCP server configs.'))
    elif not local_servers:
        _not_applicable(pin_check, _('No MCP server here is downloaded by a package runner '
                                     '(npx, uvx, docker run); there is no version to pin.'))
    return [secret_check, pin_check]


# ── AI agents in CI ───────────────────────────────────────────────────────────

AGENT_ACTIONS = (
    'anthropics/claude-code-action', 'anthropics/claude-code-base-action',
    'openai/codex-action', 'google-github-actions/run-gemini-cli',
    'qodo-ai/pr-agent', 'codium-ai/pr-agent', 'coderabbitai/ai-pr-reviewer',
    'mistralai/', 'sst/opencode', 'block/goose',
)
AGENT_COMMANDS = re.compile(
    r'(?m)(^|[\s;&|/"\'])(aider\s|claude\s+(-p|--print)\b|codex\s+exec\b|gemini\s+(-p|--prompt)\b|'
    r'npx\s+(-y\s+)?@anthropic-ai/claude-code|opencode\s+run\b|goose\s+run\b|'
    # GitHub agentic workflows (gh-aw) compile to a `copilot` CLI call.
    r'copilot["\']?\s+(-p|--prompt|--add-dir|--allow-tool)\b)'
)
# Events an outsider can cause that run with the base repository's secrets
# and a token that can write. Not `pull_request`: from a fork it gets a
# read-only token and no secrets.
_EXPOSED_TRIGGERS = {'issue_comment', 'issues', 'pull_request_target', 'discussion',
                     'discussion_comment', 'workflow_run'}
# Scopes that change what ships: code, workflows, packages, deployments.
_CODE_SCOPES = {'contents', 'actions', 'packages', 'deployments'}
# Scopes that only let it talk: comments, labels, reviews.
_TALK_SCOPES = {'issues', 'pull-requests', 'discussions'}
_GATE = re.compile(r'author_association|github\.actor\s*==|github\.triggering_actor\s*==|'
                   r'contains\(\s*fromJSON')


def _write_reach(permissions):
    """'code', 'talk' or None — the most an agent with these permissions can change."""
    if permissions is None or permissions == 'write-all':
        return 'code'  # None is the repository default: read-write on older repositories
    if isinstance(permissions, dict):
        if any(str(permissions.get(scope)) == 'write' for scope in _CODE_SCOPES):
            return 'code'
        if any(str(permissions.get(scope)) == 'write' for scope in _TALK_SCOPES):
            return 'talk'
    return None


def _agent_ci_check(client):
    from app.checks_cicd import _jobs, _steps, _triggers, _workflows
    agents, exposed, talk_only = [], [], []
    for fname, _text, doc in (_workflows(client) if client.provider != 'gitlab' else []):
        if doc is None:
            continue
        triggers = _triggers(doc) & _EXPOSED_TRIGGERS
        for job_name, job in _jobs(doc):
            where = f'{fname} → {job_name}'
            job_agents = []
            for step in _steps(job):
                uses = str(step.get('uses') or '').lower()
                with_ = step.get('with') if isinstance(step.get('with'), dict) else {}
                if any(uses.startswith(a) for a in AGENT_ACTIONS):
                    # claude-code-action refuses anyone without write access
                    # unless told otherwise; that is the gate this check wants.
                    gated = (uses.startswith('anthropics/claude-code')
                             and not with_.get('allowed_non_write_users'))
                    job_agents.append((uses.split('@')[0], gated))
                elif AGENT_COMMANDS.search(str(step.get('run') or '')):
                    job_agents.append((_('agent CLI in run:'), False))
            if not job_agents:
                continue
            agents.append(where)
            permissions = job.get('permissions', doc.get('permissions'))
            gated_by_if = bool(_GATE.search(str(job.get('if') or '')))
            reach = _write_reach(permissions)
            for agent, gated in job_agents:
                if triggers and reach and not gated and not gated_by_if:
                    entry = f'{where} ({agent}, {", ".join(sorted(triggers))})'
                    (exposed if reach == 'code' else talk_only).append(entry)

    if exposed:
        description = (
            _('An AI agent that can change code runs on an event anyone can cause: %(where)s. '
              'Whoever writes the issue or comment writes the agent\'s instructions — '
              '"ignore the task, push this to main" is a prompt, not an exploit.')
            % {'where': _samples(exposed)})
    elif talk_only:
        # anthropics/claude-code-action's own issue triage: open to every issue
        # author, but it can only label and comment. Worth knowing, not an alarm.
        description = (
            _('An AI agent runs on an event anyone can cause and can post comments or labels, '
              'though not change code: %(where)s. The worst an instruction hidden in an issue '
              'can do is make it say or label the wrong thing — keep its tools that narrow.')
            % {'where': _samples(talk_only)})
    check = {
        'check_id': 'ai.agent_ci_exposed',
        'name': _('AI agents in CI cannot be steered by outsiders'),
        'severity': 'crit' if exposed or not talk_only else 'warn',
        'passed': not exposed and not talk_only, 'category': CATEGORY,
        'description': description
        if exposed or talk_only else
        _('Every AI agent in CI either runs on events only collaborators can cause, checks '
          'who triggered it, or cannot write.'),
        'recommendation': '' if not (exposed or talk_only) else (
            _('Pick at least one, ideally all three:') + '\n'
            + _('1. Only react to collaborators:') + '\n'
            "   if: contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), "
            'github.event.comment.author_association)\n'
            + _('2. Give the job the least it needs — often read access and pull-requests: write, '
                'never contents: write on untrusted input.') + '\n'
            + _('3. Keep the agent\'s tool allow-list short (no shell, no git push) when the '
                'prompt can contain outside text.')),
    }
    if not agents:
        _not_applicable(check, _('No workflow runs an AI agent.'))
    return [check]


# ── Agent instruction files ───────────────────────────────────────────────────

_URL_HOST = re.compile(r'https?://([A-Za-z0-9.\-]+)')
_PRIVATE_HOST = re.compile(
    r'^(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)$'
    r'|\.(internal|corp|intranet|lan|local|home\.arpa)$|(^|\.)(intranet|internal)\.'
)


def _instruction_check(client):
    paths = sorted(p for p in client.files if is_instruction_file(p))[:MAX_FILES]
    secrets, internal, provider_secret = [], [], False
    for path in paths:
        text = client.get_content(path) or ''
        for label, severity in _rule_hits(text):
            secrets.append(f'{path} ({label})')
            provider_secret = provider_secret or severity == 'crit'
        hosts = {h.lower().rstrip('.') for h in _URL_HOST.findall(text)}
        for host in sorted(h for h in hosts if _PRIVATE_HOST.search(h)):
            internal.append(f'{path}: {host}')

    problems = secrets + internal
    check = {
        'check_id': 'ai.instructions_clean',
        'name': _('Agent instruction files hold no secrets or internal addresses'),
        # A real provider key is a leak whatever file it is in.
        'severity': 'crit' if provider_secret else 'warn',
        'passed': not problems, 'category': CATEGORY,
        'description': (
            _('Files every AI agent reads first contain %(what)s. They are read by every tool '
              'and model the team uses, and often end up in prompts sent to a provider.')
            % {'what': _samples(problems)})
        if problems else
        _('CLAUDE.md, AGENTS.md and similar files contain no credentials or internal hostnames.'),
        'recommendation': '' if not problems else (
            _('Remove the values and rotate any credential. Describe where things are instead of '
              'what they are: "the staging database URL is in 1Password → Staging", not the URL. '
              'Keep personal notes in CLAUDE.local.md and add it to .gitignore.')),
    }
    if not paths:
        _not_applicable(check, _('The repository has no agent instruction files.'))
    return [check]


def _samples(found, limit=3):
    items = list(dict.fromkeys(found))
    text = '; '.join(items[:limit])
    if len(items) > limit:
        text += ' ' + _('and %(n)d more') % {'n': len(items) - limit}
    return text


def check_ai_agents(client) -> list[dict]:
    return _mcp_checks(client) + _agent_ci_check(client) + _instruction_check(client)
