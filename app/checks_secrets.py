"""
Secret scanning across the whole repository tree.

The previous implementation matched one generic regex against twenty hardcoded
file paths, so it missed anything in an unusual location and flagged ordinary
config lines as leaks. This version walks the real file tree, applies
provider-specific patterns (which have almost no false-positive rate) plus one
entropy-gated generic rule, and reports which file and which kind of credential.
"""
import base64
import logging
import math
import re

from app.detectors import is_documented_example

from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)

# Files worth reading. Binaries, vendored code and lock files are skipped —
# they are large, and a match inside them is almost always noise.
SCANNABLE_SUFFIXES = (
    '.py', '.js', '.ts', '.jsx', '.tsx', '.go', '.rb', '.php', '.java', '.kt', '.cs',
    '.rs', '.sh', '.bash', '.zsh', '.yml', '.yaml', '.json', '.toml', '.ini', '.cfg',
    '.conf', '.env', '.properties', '.tf', '.tfvars', '.pem', '.key', '.xml', '.gradle',
)
SCANNABLE_NAMES = (
    '.env', 'Dockerfile', 'docker-compose.yml', 'Makefile', 'Procfile', '.npmrc', '.netrc',
    # Private keys are routinely committed under an extensionless name.
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'privkey', 'server.key', 'client.key',
)
# Any file whose name hints at credentials is worth reading regardless of extension.
CREDENTIAL_NAME_HINTS = ('secret', 'credential', 'token', 'password', '_rsa', '_key', 'keyfile')
SKIP_PATH_PARTS = (
    'node_modules/', 'vendor/', 'dist/', 'build/', '.venv/', 'venv/', 'site-packages/',
    'third_party/', 'fixtures/', 'testdata/', '__snapshots__/', '.min.', 'migrations/',
)
SKIP_EXACT = {
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock', 'Cargo.lock',
    'composer.lock', 'Gemfile.lock', 'go.sum', 'uv.lock',
}
MAX_FILES = 45

# A private key under one of these is a test fixture, not a leaked credential.
# Any TLS library commits key material to exercise its own handshake code, and
# calling that a critical breach is the fastest way to lose a reader's trust.
FIXTURE_PATH_PARTS = (
    'test/', 'tests/', '/test_', 'example/', 'examples/', 'sample/', 'samples/',
    'demo/', 'mock/', 'mocks/', 'docs/', 'doc/', 'certs/', 'certificates/',
)
# Rules whose material is routinely committed on purpose for tests. A live API
# key in a test directory is still a live API key, so only these are softened:
# key material, and the entropy-gated generic rule, which cannot tell
# `AccessToken: "oauth2-access-token"` in a Go test (gitlab-org/cli) from a
# real one. Provider rules — AWS, Stripe, GitHub, … — match the provider's own
# format and stay findings wherever they are.
FIXTURE_SAFE_RULES = ('private_key', 'generic_secret')

# Test files named by their language's convention rather than kept in a
# test directory: Go keeps `_test.go` beside the code it tests, JS/TS its
# `.test.ts`/`.spec.ts`, and so on.
_TEST_FILE = re.compile(
    r'(?:_test\.(?:go|py|rb|exs?)|_spec\.rb|\.(?:test|spec)\.[cm]?[jt]sx?|Tests?\.(?:java|kt|cs|swift))$'
    r'|(?:^|/)test_[^/]*\.py$'
)


def _is_fixture(path: str) -> bool:
    lower = '/' + path.lower()
    return any(part in lower for part in FIXTURE_PATH_PARTS) or bool(_TEST_FILE.search(path))

# Placeholder values that appear in every example file ever written.
PLACEHOLDER = re.compile(
    r'^(?:x{3,}|\.{3,}|<[^>]+>|\$\{[^}]+\}|\$[A-Z_]+|%\([a-z_]+\)s|\{\{[^}]+\}\}|'
    r'your[-_ ]?\w*|change[-_]?me|placeholder|example|sample|dummy|test|secret|password|'
    r'todo|none|null|true|false|localhost|redacted|xxx+|abc123|s3cr3t)$',
    re.IGNORECASE,
)


class Rule:
    def __init__(self, rule_id, label, pattern, severity='crit', entropy=0.0, group=0):
        self.rule_id = rule_id
        self.label = label
        self.pattern = re.compile(pattern)
        self.severity = severity
        self.entropy = entropy
        self.group = group


# Provider-specific patterns first: a match on any of these is essentially certain.
RULES = [
    Rule('aws_access_key',   'AWS access key ID',      r'\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b', group=1),
    Rule('aws_secret_key',   'AWS secret access key',
         r'(?i)aws[_\-.]?(?:secret|sk)[_\-.]?(?:access)?[_\-.]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
         group=1, entropy=4.0),
    Rule('github_pat',       'GitHub token',           r'\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,})\b', group=1),
    Rule('gitlab_pat',       'GitLab token',           r'\b(glpat-[A-Za-z0-9_\-]{20,})\b', group=1),
    Rule('slack_token',      'Slack token',            r'\b(xox[baprs]-[A-Za-z0-9-]{10,})\b', group=1),
    Rule('stripe_key',       'Stripe secret key',      r'\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b', group=1),
    Rule('google_api_key',   'Google API key',         r'\b(AIza[0-9A-Za-z_\-]{35})\b', group=1),
    Rule('openai_key',       'OpenAI API key',         r'\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b', group=1),
    Rule('anthropic_key',    'Anthropic API key',      r'\b(sk-ant-[A-Za-z0-9_\-]{20,})\b', group=1),
    Rule('sendgrid_key',     'SendGrid API key',       r'\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b', group=1),
    Rule('twilio_sid',       'Twilio account SID',     r'\b(AC[a-f0-9]{32})\b', severity='warn', group=1),
    Rule('npm_token',        'npm token',              r'\b(npm_[A-Za-z0-9]{36})\b', group=1),
    Rule('telegram_bot_token', 'Telegram bot token',   r'\b([0-9]{8,10}:AA[A-Za-z0-9_\-]{33})\b', group=1),
    Rule('private_key',      'Private key block',      r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----'),
    Rule('jwt',              'Hardcoded JWT',          r'\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b',
         severity='warn', group=1),
    Rule('db_url',           'Database URL with password',
         r'\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s\'"]+:[^@\s\'"]{4,}@[^\s\'"/]+)',
         group=1),
    # Generic assignment — gated on entropy so that ordinary config lines pass.
    Rule('generic_secret',   'Hardcoded credential',
         r'(?i)\b(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|'
         r'private[_\-]?key|client[_\-]?secret)\s*[=:]\s*["\']([^"\'\s]{12,})["\']',
         severity='warn', entropy=3.4, group=1),
]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_placeholder(value: str) -> bool:
    if PLACEHOLDER.match(value.strip()):
        return True
    stripped = value.strip()
    # Reads straight from the environment or a template, not a literal secret.
    if stripped.startswith(('os.environ', 'process.env', 'ENV[', '${', '{{', '$(')):
        return True
    # A single repeated character, e.g. "aaaaaaaaaaaa".
    return len(set(stripped)) <= 2


def _should_scan(path: str) -> bool:
    name = path.rsplit('/', 1)[-1]
    if name in SKIP_EXACT:
        return False
    if any(part in path for part in SKIP_PATH_PARTS):
        return False
    if path.endswith(SCANNABLE_SUFFIXES) or name in SCANNABLE_NAMES:
        return True
    lower = name.lower()
    return any(hint in lower for hint in CREDENTIAL_NAME_HINTS)


def _priority(path: str) -> int:
    """Lower sorts first. Credentials cluster in config and in shallow files."""
    name = path.rsplit('/', 1)[-1].lower()
    if name.startswith('.env') or any(h in name for h in CREDENTIAL_NAME_HINTS):
        return 0
    if name in SCANNABLE_NAMES or 'config' in name or 'setting' in name:
        return 1
    depth = path.count('/')
    if depth == 0:
        return 2
    if depth <= 2:
        return 3
    return 4


def find_secrets(client, max_files: int = MAX_FILES, allow_paths=()) -> list[dict]:
    """
    Return a list of {file, rule, label, severity} for every credential found.

    `allow_paths` comes from `allow_secrets:` in the repository's own config —
    the fixture directories a team has already looked at and signed off. A
    scanner that keeps reporting a finding somebody has decided about is a
    scanner that gets muted wholesale.
    """
    allow_paths = tuple(p for p in allow_paths if p)
    # MCP configs and agent instruction files belong to checks_ai_agents,
    # which reads them with these same rules plus their structure; scanning
    # them here too would count one pasted token twice.
    from app.checks_ai_agents import is_agent_file
    candidates = sorted(
        (p for p in client.files
         if _should_scan(p) and not is_agent_file(p)
         and not (allow_paths and p.startswith(allow_paths))),
        key=lambda p: (_priority(p), p),
    )[:max_files]

    # One parallel read instead of one blocking request per file.
    client.prefetch(candidates)

    findings = []
    for path in candidates:
        content = client.get_content(path)
        if not content or len(content) > 400_000:
            continue
        findings += scan_text(path, content)
    return findings


def scan_text(path: str, content: str) -> list[dict]:
    """
    Every credential in one file's text, at most one per rule.

    `value` is the matched credential itself. It exists only so the liveness
    check can ask the provider about it, and must never be logged, stored or
    rendered — everything user-facing is built from `label` and `file`.
    """
    findings = []
    seen = set()
    for rule in RULES:
        for match in rule.pattern.finditer(content):
            value = match.group(rule.group) if rule.group else match.group(0)
            if is_documented_example(value) or is_documented_example(match.group(0)):
                continue
            if rule.group and (_is_placeholder(value) or
                               (rule.entropy and shannon_entropy(value) < rule.entropy)):
                continue
            if rule.rule_id in seen:
                continue
            seen.add(rule.rule_id)
            findings.append({
                'file': path,
                'rule': rule.rule_id,
                'label': rule.label,
                'severity': rule.severity,
                'value': value,
                'line': content.count('\n', 0, match.start()) + 1,
            })
    return findings


def _is_fixture_finding(f) -> bool:
    return f['rule'] in FIXTURE_SAFE_RULES and _is_fixture(f['file'])


def scan_secrets(client, config=None, deep=False) -> list[dict]:
    """
    The `security.no_secrets` check, plus a committed-.env check.

    `deep` is for repositories their owner connected: it adds the git-history
    scan (`security.no_secrets_in_history`) and asks each provider whether
    what was found still works (`security.secret_active`). The public scanner
    never runs either — see `secret_history` and `secret_liveness`.
    """
    from app.checks import _c

    allow_paths = tuple(getattr(config, 'allow_secrets', ()) or ())
    all_findings = find_secrets(client, allow_paths=allow_paths)
    fixtures = [f for f in all_findings if _is_fixture_finding(f)]
    findings = [f for f in all_findings if f not in fixtures]
    logger.info('Secret scan [%s]: %d finding(s), %d test fixture(s)',
                client.full_name, len(findings), len(fixtures))

    deep = deep and getattr(client, 'supports_deep_scan', False)
    history = None
    history_findings = []
    if deep:
        from app.secret_history import scan_history
        from app.secret_liveness import verify_findings
        history = scan_history(client, allow_paths=allow_paths)
        # What the tree scan already reported is not reported twice; history
        # adds what was deleted since, and what sits past the tree scan's cap.
        known = {(f['rule'], f['value']) for f in all_findings}
        history_findings = [f for f in history.findings
                            if (f['rule'], f['value']) not in known
                            and not _is_fixture_finding(f)]
        verify_findings(findings + history_findings, client)
        for f in findings:
            f['in_head'] = True
        # Handed to secret_incidents.sync() by the audit task, in memory only:
        # these carry the values, which are never stored.
        client.secret_findings = findings + history_findings

    if findings:
        crit = [f for f in findings if f['severity'] == 'crit']
        sample = ', '.join(sorted({f"{f['label']} in {f['file']}" for f in findings})[:3])
        extra = len({(f['file'], f['rule']) for f in findings}) - 3
        description = _('Found %(count)d credential(s) committed to the repository: %(sample)s') % {
            'count': len(findings), 'sample': sample,
        }
        if extra > 0:
            description += _(' and %(n)d more.') % {'n': extra}
        recommendation = _(
            'Treat every value found as compromised and rotate it now — removing the line is not enough, '
            'it stays in git history.\n'
            '1. Rotate the credential at the provider.\n'
            '2. Move it to an environment variable or a secret manager.\n'
            '3. Purge it from history with git-filter-repo or BFG.\n'
            '4. Add a pre-commit hook (gitleaks or detect-secrets) so the next one never lands.'
        )
    elif fixtures:
        sample = ', '.join(sorted({f['file'] for f in fixtures})[:3])
        description = _(
            'No credentials found in the repository source. %(count)d key file(s) sit under a '
            'test or example path and are read as fixtures: %(sample)s'
        ) % {'count': len(fixtures), 'sample': sample}
        recommendation = _(
            'Nothing to do if these are throwaway test keys. If any of them is also used '
            'outside the test suite, rotate it and move it to a secret manager.'
        )
        crit = []
    else:
        description = _('No credentials found in the repository source.')
        recommendation = ''
        crit = []

    if deep and findings:
        description += ' ' + _liveness_summary(findings)

    checks = [_c(
        'security.no_secrets',
        _('No secrets committed to the repository'),
        description,
        'crit' if crit else ('warn' if findings else 'crit'),
        not findings,
        'security',
        recommendation,
    )]

    if deep:
        checks.append(_history_check(history, history_findings))
        active = [f for f in findings + history_findings if f.get('liveness') == 'active']
        if active:
            checks.append(_active_check(active))

    # A .env inside examples, tests or docs is deliberate sample material, not a
    # leak, so it is not counted here.
    _sample_dirs = ('example', 'sample', 'test', 'fixture', 'docs/', 'template')
    env_files = [
        p for p in client.files
        if (p == '.env' or p.endswith('/.env'))
        and not any(part in p.lower() for part in _sample_dirs)
    ]
    env_committed = bool(env_files)
    checks.append(_c(
        'security.env_not_committed',
        _('.env file is not committed'),
        _('%(path)s is tracked in git — every value it holds is exposed to anyone with '
          'repository access.') % {'path': env_files[0]}
        if env_committed else _('No .env file is tracked in the repository.'),
        'crit', not env_committed, 'security',
        _('Delete the file from the repository (`git rm --cached .env`), rotate every value it contained, '
          'and add `.env` to .gitignore.'),
    ))

    return checks


def _where(f) -> str:
    """'GitHub token in config.py (commit abc1234, 2024-03-01)' — never the value."""
    where = _('%(label)s in %(file)s') % {'label': f['label'], 'file': f['file']}
    if f.get('commit'):
        where += ' ' + _('(commit %(commit)s, %(date)s)') % {'commit': f['commit'], 'date': f['date']}
    return where


def _liveness_summary(findings) -> str:
    counts = {'active': 0, 'inactive': 0, 'unknown': 0}
    for f in findings:
        counts[f.get('liveness', 'unknown')] += 1
    return _('Checked with the provider: %(active)d still working, %(inactive)d rejected, '
             '%(unknown)d could not be checked.') % counts


HISTORY_SKIP_REASONS = {
    'too_large': lambda: _('The repository is too large to scan its full git history.'),
    'unsupported': lambda: _('Git history cannot be read for this connection '
                             '(a GitLab instance behind a custom DNS server).'),
    'timeout': lambda: _('Reading the git history took too long and was stopped.'),
    'failed': lambda: _('The git history could not be downloaded this time.'),
    'unavailable': lambda: _('The git history could not be downloaded this time.'),
}


def _history_check(history, findings):
    from app.checks import _c, _not_applicable

    if not history.scanned:
        reason = HISTORY_SKIP_REASONS.get(history.reason, HISTORY_SKIP_REASONS['failed'])()
        return _not_applicable(_c('security.no_secrets_in_history', _('No secrets in git history'),
                                  reason, 'crit', True, 'security'), reason)
    if not findings:
        return _c('security.no_secrets_in_history', _('No secrets in git history'),
                  _('No credentials found anywhere in the git history (%(n)d file versions read).')
                  % {'n': history.blobs}, 'crit', True, 'security')

    removed = [f for f in findings if not f.get('in_head')]
    sample = ', '.join(_where(f) for f in findings[:3])
    description = _('Found %(count)d credential(s) in the git history: %(sample)s') % {
        'count': len(findings), 'sample': sample}
    if len(findings) > 3:
        description += _(' and %(n)d more.') % {'n': len(findings) - 3}
    if removed:
        description += ' ' + _('%(n)d of them were deleted from the code later, but every clone '
                               'of the repository still contains them.') % {'n': len(removed)}
    description += ' ' + _liveness_summary(findings)
    crit = any(f['severity'] == 'crit' for f in findings)
    return _c(
        'security.no_secrets_in_history',
        _('No secrets in git history'),
        description,
        'crit' if crit else 'warn',
        False,
        'security',
        _('Deleting the line does not remove the secret: the commit that added it is still in '
          'every clone and fork.\n'
          '1. Rotate each credential at the provider — this is the step that matters.\n'
          '2. Only then rewrite history (git-filter-repo --replace-text, or BFG) and force-push, '
          'and ask collaborators to re-clone.\n'
          '3. Add a pre-commit hook (gitleaks or detect-secrets) so the next one never lands.'),
    )


def _active_check(active):
    from app.checks import _c

    sample = ', '.join(_where(f) for f in active[:3])
    description = _('%(count)d credential(s) found in this repository still work — the provider '
                    'accepted them just now: %(sample)s') % {'count': len(active), 'sample': sample}
    if len(active) > 3:
        description += _(' and %(n)d more.') % {'n': len(active) - 3}
    return _c(
        'security.secret_active',
        _('No live credentials in the repository'),
        description,
        'crit',
        False,
        'security',
        _('Anyone who has ever cloned this repository can use these keys today.\n'
          '1. Revoke or rotate each one at the provider now, before anything else.\n'
          '2. Check the provider\'s access logs for use you do not recognise.\n'
          '3. Put the new value in a secret manager or CI secret, never in the repository.\n'
          'We checked with one read-only request per key (for example GitHub GET /user, '
          'AWS sts:GetCallerIdentity) and stored only the result, never the key.'),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Redaction
# ─────────────────────────────────────────────────────────────────────────────

REDACTION = '«REDACTED:{label}»'


def redact(text: str) -> str:
    """
    Mask anything in `text` that the scanner would call a credential.

    Used on every piece of repository content that leaves for a third-party
    model. The AI suggestion feature sends the file a failed check is about —
    and for the "no secrets in code" check the candidate files were
    `settings.py`, `config.py`, `app.py`, `main.py`: exactly where the secret it
    had just found would be. Telling a customer they have a hardcoded
    credential and shipping that credential to an LLM in the same breath is not
    a trade anyone agreed to.

    The same rules the scanner reports on are the rules that mask here, so
    anything the product is willing to call a secret is something it will never
    forward.
    """
    if not text:
        return text

    # A PEM block first, as a whole span. The rule that finds one matches only
    # its BEGIN line, which would have masked the header and forwarded the key.
    text = re.sub(
        r'-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----.*?-----END (?:[A-Z ]+)?PRIVATE KEY-----',
        REDACTION.format(label='Private key block'), text, flags=re.S,
    )

    for rule in RULES:
        def _mask(match, label=rule.label, group=rule.group):
            whole = match.group(0)
            if not group:
                return REDACTION.format(label=label)
            value = match.group(group)
            if not value:
                return whole
            # Keep the surrounding line intact so the model still sees the shape
            # of the code — `API_KEY = "«REDACTED:…»"` is as useful for advice
            # as the real value, and safe to send.
            return whole.replace(value, REDACTION.format(label=label))
        text = rule.pattern.sub(_mask, text)
    return text
