"""
`.devopsaudit.yml` — the repository's own say in how it is audited.

Every scanner that cannot be argued with gets ignored. Teams stop reading a
tool the moment it insists on a finding they have already decided about, and a
score they cannot influence is a score they will not publish. This file is how
a repository answers back:

    # .devopsaudit.yml
    kind: library            # service | library | infrastructure

    fail_under: 70           # the CI gate

    ignore:
      - id: docker.nonroot
        reason: the base image already runs as nobody

    severity:
      deps.lockfile: info    # crit | warn | info

    allow_secrets:
      - tests/fixtures/

Two rules keep this from becoming a way to fake a score:

1. **An ignore needs a reason.** A bare id is refused and reported as a config
   error. Someone reading the audit six months from now — an auditor, the next
   engineer — must be able to see why the check was set aside.
2. **Nothing is hidden.** An ignored check stays in the report under "does not
   apply here" with the reason the repository gave, exactly like a check the
   engine set aside itself. The evidence trail is the product.

Severity may be lowered but never raised past `crit`, and `security.no_secrets`
cannot be ignored at all — a tool that lets you switch off the secret scanner
and still print a score is not evidence of anything.
"""
import logging

logger = logging.getLogger(__name__)

CONFIG_PATHS = ('.devopsaudit.yml', '.devopsaudit.yaml', '.github/devopsaudit.yml',
                '.devopscheck.yml', '.devopscheck.yaml')

VALID_KINDS = ('service', 'library', 'infrastructure', 'cli', 'monorepo', 'docs')
# The accuracy spec's names for the same kinds (`type: iac`).
KIND_ALIASES = {'iac': 'infrastructure'}
VALID_SEVERITIES = ('crit', 'warn', 'info')

#: Ignoring these would make the report worthless as evidence.
UNIGNORABLE = ('security.no_secrets', 'security.env_not_committed',
               'security.no_secrets_in_history', 'security.secret_active')

MAX_IGNORES = 40
MAX_ALLOW_PATHS = 60


class AuditConfig:
    """A parsed `.devopsaudit.yml`, plus whatever was wrong with it."""

    def __init__(self):
        self.present = False
        self.kind = ''
        self.fail_under = None
        self.ignores = {}          # check_id -> reason
        self.severities = {}       # check_id -> severity
        self.allow_secrets = []    # path prefixes
        self.errors = []           # human-readable problems with the file

    def __bool__(self):
        return self.present

    def as_dict(self):
        return {
            'present': self.present,
            'kind': self.kind,
            'fail_under': self.fail_under,
            'ignores': self.ignores,
            'severities': self.severities,
            'allow_secrets': self.allow_secrets,
            'errors': self.errors,
        }


def load(client) -> AuditConfig:
    """Read and validate the config a repository ships, if it ships one."""
    config = AuditConfig()

    path = client.any_exists(CONFIG_PATHS)
    if not path:
        return config

    raw = client.get_content(path)
    if not raw:
        return config

    try:
        import yaml
        data = yaml.safe_load(raw)
    except Exception as exc:
        config.present = True
        config.errors.append(f'{path} could not be parsed: {exc}'[:300])
        return config

    if not isinstance(data, dict):
        config.present = True
        config.errors.append(f'{path} must be a mapping at the top level.')
        return config

    config.present = True
    _read_kind(config, data)
    _read_fail_under(config, data)
    _read_ignores(config, data)
    _read_severities(config, data)
    _read_allow_secrets(config, data)

    logger.info(
        'audit config [%s]: kind=%s fail_under=%s ignores=%d severities=%d errors=%d',
        getattr(client, 'full_name', '?'), config.kind or '-', config.fail_under,
        len(config.ignores), len(config.severities), len(config.errors),
    )
    return config


# ── field readers ────────────────────────────────────────────────────────────

def _read_kind(config, data):
    kind = data.get('kind', data.get('type'))
    if kind is None:
        return
    if isinstance(kind, str):
        kind = KIND_ALIASES.get(kind.strip().lower(), kind)
    if not isinstance(kind, str) or kind.strip().lower() not in VALID_KINDS:
        config.errors.append(f'kind must be one of {", ".join(VALID_KINDS)}.')
        return
    config.kind = kind.strip().lower()


def _read_fail_under(config, data):
    value = data.get('fail_under')
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        config.errors.append('fail_under must be a number between 0 and 100.')
        return
    if not 0 <= value <= 100:
        config.errors.append('fail_under must be between 0 and 100.')
        return
    config.fail_under = int(value)


def _read_ignores(config, data):
    entries = data.get('ignore')
    if entries is None:
        return
    if not isinstance(entries, list):
        config.errors.append('ignore must be a list of {id, reason} entries.')
        return
    if len(entries) > MAX_IGNORES:
        config.errors.append(f'ignore holds more than {MAX_IGNORES} entries; only the first are read.')
        entries = entries[:MAX_IGNORES]

    for entry in entries:
        if isinstance(entry, str):
            check_id, reason = entry.strip(), ''
        elif isinstance(entry, dict):
            check_id = str(entry.get('id') or '').strip()
            reason = str(entry.get('reason') or '').strip()
        else:
            config.errors.append('each ignore entry must be a mapping with id and reason.')
            continue

        if not check_id:
            config.errors.append('an ignore entry has no id.')
            continue
        # Checked before the missing-reason message, so the answer to "why is my
        # ignore not working" is the real one rather than a red herring.
        if check_id in UNIGNORABLE:
            config.errors.append(
                f'{check_id} cannot be ignored — a report that can switch off the '
                f'secret scanner is not evidence of anything.'
            )
            continue
        if not reason:
            config.errors.append(
                f'{check_id} is ignored without a reason, so it is still being checked. '
                f'Write "- id: {check_id}" with a "reason:" beneath it.'
            )
            continue
        config.ignores[check_id] = reason[:300]


def _read_severities(config, data):
    entries = data.get('severity')
    if entries is None:
        return
    if not isinstance(entries, dict):
        config.errors.append('severity must be a mapping of check id to crit, warn or info.')
        return
    for check_id, severity in entries.items():
        severity = str(severity or '').strip().lower()
        if severity not in VALID_SEVERITIES:
            config.errors.append(f'severity for {check_id} must be one of {", ".join(VALID_SEVERITIES)}.')
            continue
        config.severities[str(check_id).strip()] = severity


def _read_allow_secrets(config, data):
    entries = data.get('allow_secrets')
    if entries is None:
        return
    if not isinstance(entries, list):
        config.errors.append('allow_secrets must be a list of path prefixes.')
        return
    paths = [str(p).strip().lstrip('/') for p in entries[:MAX_ALLOW_PATHS] if str(p).strip()]
    config.allow_secrets = paths


# ── application ──────────────────────────────────────────────────────────────

def apply(checks, config):
    """
    Fold the repository's own decisions into the results.

    Returns the number of checks the repository set aside. Severity is applied
    first so an ignore reads against the severity the repository actually meant.
    """
    if not config or not config.present:
        return 0

    for check in checks:
        check_id = check.get('check_id', '')

        wanted = config.severities.get(check_id)
        if wanted and wanted != check['severity']:
            check['severity'] = wanted

        reason = config.ignores.get(check_id)
        if reason:
            check['applicable'] = False
            check['not_applicable_reason'] = f'Set aside in .devopsaudit.yml: {reason}'
            check['recommendation'] = ''

    return sum(1 for c in checks if c.get('check_id') in config.ignores)
