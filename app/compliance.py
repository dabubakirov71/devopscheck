"""
Mapping from audit checks to compliance controls.

This is the same engine wearing a different jacket. An engineer buys "your
Dockerfile runs as root"; a Head of Security with an audit date buys "control
CC6.6 has no supporting evidence". The checks do not change — the framing,
the report, and the price do.

Frameworks covered:
  • SOC 2 (AICPA Trust Services Criteria, 2017 with 2022 points of focus)
  • ISO/IEC 27001:2022 Annex A
"""
from django.utils.translation import gettext_lazy as _

FRAMEWORKS = {
    'soc2': {
        'name': 'SOC 2',
        'long_name': 'SOC 2 — Trust Services Criteria',
        'authority': 'AICPA',
    },
    'iso27001': {
        'name': 'ISO 27001',
        'long_name': 'ISO/IEC 27001:2022 Annex A',
        'authority': 'ISO/IEC',
    },
}

CONTROL_TITLES = {
    # SOC 2 Trust Services Criteria
    'CC6.1': _('Logical access security — restrict access to protected information assets'),
    'CC6.3': _('Access is granted, modified and removed based on roles and least privilege'),
    'CC6.6': _('Logical access controls protect against threats from outside the system boundary'),
    'CC6.7': _('Transmission and storage of data is restricted and protected'),
    'CC6.8': _('Controls prevent or detect unauthorised or malicious software'),
    'CC7.1': _('Configuration standards are defined and deviations are detected'),
    'CC7.2': _('The system is monitored to detect anomalies and security events'),
    'CC8.1': _('Changes to infrastructure and software are authorised, designed, tested and approved'),
    'CC2.1': _('Relevant, quality information is generated and used to support internal control'),
    'A1.2': _('Environmental and recovery controls maintain processing capacity and availability'),
    # ISO/IEC 27001:2022 Annex A
    'A.5.15': _('Access control'),
    'A.5.23': _('Information security for use of cloud services'),
    'A.8.2':  _('Privileged access rights'),
    'A.8.8':  _('Management of technical vulnerabilities'),
    'A.8.9':  _('Configuration management'),
    'A.8.16': _('Monitoring activities'),
    'A.8.24': _('Use of cryptography'),
    'A.8.25': _('Secure development life cycle'),
    'A.8.28': _('Secure coding'),
    'A.8.31': _('Separation of development, test and production environments'),
    'A.8.32': _('Change management'),
}

# check_id → {framework: [control ids]}
CONTROL_MAP = {
    'security.no_secrets':          {'soc2': ['CC6.1', 'CC6.7'], 'iso27001': ['A.8.24', 'A.8.28']},
    'security.no_secrets_in_history': {'soc2': ['CC6.1', 'CC6.7'], 'iso27001': ['A.8.24', 'A.8.28']},
    'security.secret_active':       {'soc2': ['CC6.1', 'CC6.7'], 'iso27001': ['A.5.17', 'A.8.24']},
    'security.env_not_committed':   {'soc2': ['CC6.1', 'CC6.7'], 'iso27001': ['A.8.24', 'A.8.28']},
    'security.env_gitignored':      {'soc2': ['CC6.1'],          'iso27001': ['A.8.28']},
    'security.dependency_updates':  {'soc2': ['CC7.1', 'CC6.8'], 'iso27001': ['A.8.8']},
    'security.security_policy':     {'soc2': ['CC2.1'],          'iso27001': ['A.8.8']},
    'security.codeowners':          {'soc2': ['CC6.3', 'CC8.1'], 'iso27001': ['A.5.15', 'A.8.32']},
    'deps.cve':                     {'soc2': ['CC7.1', 'CC6.8'], 'iso27001': ['A.8.8']},
    'deps.manifest':                {'soc2': ['CC7.1'],          'iso27001': ['A.8.9']},
    'deps.lockfile':                {'soc2': ['CC7.1', 'CC8.1'], 'iso27001': ['A.8.9', 'A.8.32']},
    'deps.pinned':                  {'soc2': ['CC7.1', 'CC8.1'], 'iso27001': ['A.8.9']},
    'ci.pipeline':                  {'soc2': ['CC8.1'],          'iso27001': ['A.8.25', 'A.8.32']},
    'ci.tests':                     {'soc2': ['CC8.1'],          'iso27001': ['A.8.25', 'A.8.32']},
    'ci.branch_protection':         {'soc2': ['CC8.1', 'CC6.3'], 'iso27001': ['A.8.32', 'A.5.15']},
    'ci.linter':                    {'soc2': ['CC8.1'],          'iso27001': ['A.8.28']},
    'ci.security_scan':             {'soc2': ['CC7.1', 'CC6.8'], 'iso27001': ['A.8.8', 'A.8.25']},
    'actions.pinned_sha':           {'soc2': ['CC6.8', 'CC8.1'], 'iso27001': ['A.8.9', 'A.8.32']},
    'actions.pull_request_target':  {'soc2': ['CC6.6', 'CC6.8'], 'iso27001': ['A.8.25', 'A.8.31']},
    'actions.broad_permissions':    {'soc2': ['CC6.3'],          'iso27001': ['A.8.2', 'A.5.15']},
    'actions.script_injection':     {'soc2': ['CC6.6', 'CC8.1'], 'iso27001': ['A.8.25', 'A.8.28']},
    'actions.self_hosted_public':   {'soc2': ['CC6.6', 'CC6.8'], 'iso27001': ['A.8.20', 'A.8.31']},
    'actions.cloud_oidc':           {'soc2': ['CC6.1'],          'iso27001': ['A.5.17', 'A.8.5']},
    'gitlab_ci.pinned_includes':    {'soc2': ['CC6.8', 'CC8.1'], 'iso27001': ['A.8.9', 'A.8.32']},
    'gitlab_ci.pinned_images':      {'soc2': ['CC6.8', 'CC8.1'], 'iso27001': ['A.8.9', 'A.8.32']},
    'gitlab_ci.cloud_oidc':         {'soc2': ['CC6.1'],          'iso27001': ['A.5.17', 'A.8.5']},
    'ai.mcp_secrets':               {'soc2': ['CC6.1', 'CC6.7'], 'iso27001': ['A.5.17', 'A.8.12']},
    'ai.mcp_pinned':                {'soc2': ['CC6.8', 'CC8.1'], 'iso27001': ['A.8.9', 'A.8.32']},
    'ai.agent_ci_exposed':          {'soc2': ['CC6.6', 'CC8.1'], 'iso27001': ['A.8.25', 'A.8.28']},
    'ai.instructions_clean':        {'soc2': ['CC6.1', 'CC6.7'], 'iso27001': ['A.5.17', 'A.8.12']},
    'docker.dockerfile':            {'soc2': ['CC7.1'],          'iso27001': ['A.8.9']},
    'docker.nonroot':               {'soc2': ['CC6.3', 'CC6.6'], 'iso27001': ['A.8.2']},
    'docker.pinned_base':           {'soc2': ['CC7.1', 'CC8.1'], 'iso27001': ['A.8.9']},
    'docker.multistage':            {'soc2': ['CC6.8'],          'iso27001': ['A.8.25']},
    'docker.healthcheck':           {'soc2': ['A1.2', 'CC7.2'],  'iso27001': ['A.8.16']},
    'docker.resource_limits':       {'soc2': ['A1.2'],           'iso27001': ['A.8.16']},
    'docker.dockerignore':          {'soc2': ['CC6.7'],          'iso27001': ['A.8.28']},
    'k8s.resource_limits':          {'soc2': ['A1.2'],           'iso27001': ['A.8.16']},
    'k8s.nonroot':                  {'soc2': ['CC6.3', 'CC6.6'], 'iso27001': ['A.8.2']},
    'k8s.probes':                   {'soc2': ['A1.2', 'CC7.2'],  'iso27001': ['A.8.16']},
    'ops.observability':            {'soc2': ['CC7.2'],          'iso27001': ['A.8.16']},
    'ops.gitignore':                {'soc2': ['CC6.1'],          'iso27001': ['A.8.28']},
    'ops.env_example':              {'soc2': ['CC2.1'],          'iso27001': ['A.8.9']},
    'ops.license':                  {'soc2': ['CC2.1'],          'iso27001': []},
    'ops.activity':                 {'soc2': ['CC7.1'],          'iso27001': ['A.8.8']},
    'docs.readme':                  {'soc2': ['CC2.1'],          'iso27001': ['A.8.25']},
    'docs.readme_quality':          {'soc2': ['CC2.1'],          'iso27001': ['A.8.25']},
    'docs.changelog':               {'soc2': ['CC8.1'],          'iso27001': ['A.8.32']},
    'docs.contributing':            {'soc2': ['CC2.1'],          'iso27001': ['A.8.25']},
    'docs.templates':               {'soc2': ['CC8.1'],          'iso27001': ['A.8.32']},
    'iac.remote_state':             {'soc2': ['CC8.1', 'CC6.1'], 'iso27001': ['A.8.9', 'A.5.23']},
    'iac.open_ingress':             {'soc2': ['CC6.6'],          'iso27001': ['A.5.15', 'A.5.23']},
    'iac.encryption_at_rest':       {'soc2': ['CC6.7'],          'iso27001': ['A.8.24']},
    'iac.private_database':         {'soc2': ['CC6.6'],          'iso27001': ['A.5.23']},
    'iac.no_public_buckets':        {'soc2': ['CC6.1', 'CC6.6'], 'iso27001': ['A.5.23']},
    'iac.no_hardcoded_credentials': {'soc2': ['CC6.1'],          'iso27001': ['A.8.24']},
    'iac.pinned_providers':         {'soc2': ['CC7.1'],          'iso27001': ['A.8.9']},
    'iac.scanning':                 {'soc2': ['CC7.1'],          'iso27001': ['A.8.8']},
}

# Older audits stored before check_id existed.
_LEGACY = {
    'Нет секретов в коде': 'security.no_secrets',
    'CI/CD пайплайн настроен': 'ci.pipeline',
    'Тесты запускаются в CI': 'ci.tests',
    'Защита основной ветки': 'ci.branch_protection',
    'Non-root пользователь в Dockerfile': 'docker.nonroot',
    'Lock-файл присутствует': 'deps.lockfile',
    'CVE: уязвимости в зависимостях': 'deps.cve',
}


def check_id_for(check) -> str:
    cid = getattr(check, 'check_id', '') or ''
    return cid or _LEGACY.get(getattr(check, 'name', ''), '')


def controls_for(check, framework: str) -> list[str]:
    return CONTROL_MAP.get(check_id_for(check), {}).get(framework, [])


def build_report(checks, framework: str = 'soc2') -> dict:
    """
    Group an audit's checks by control.

    A control is only satisfied when every check mapped to it passes — an
    auditor does not accept partial evidence, and neither should the report.

    Checks the repository cannot act on are left out entirely. Counting a
    library's missing container hardening as a SOC 2 gap would put a finding in
    front of an auditor that nobody can ever close.
    """
    controls: dict[str, dict] = {}
    for check in checks:
        if not getattr(check, 'applicable', True):
            continue
        for control in controls_for(check, framework):
            entry = controls.setdefault(control, {
                'id': control,
                'title': str(CONTROL_TITLES.get(control, control)),
                'passed': [],
                'failed': [],
            })
            (entry['passed'] if check.passed else entry['failed']).append(check)

    ordered = [controls[k] for k in sorted(controls)]
    for entry in ordered:
        entry['status'] = 'satisfied' if not entry['failed'] else 'gap'
        entry['evidence_count'] = len(entry['passed']) + len(entry['failed'])

    satisfied = sum(1 for c in ordered if c['status'] == 'satisfied')
    total = len(ordered)
    return {
        'framework': framework,
        'framework_name': FRAMEWORKS[framework]['name'],
        'framework_long_name': FRAMEWORKS[framework]['long_name'],
        'controls': ordered,
        'satisfied': satisfied,
        'gaps': total - satisfied,
        'total': total,
        'coverage_pct': round(satisfied / total * 100) if total else 0,
    }


def unmapped_checks(checks, framework: str = 'soc2') -> list:
    return [c for c in checks if not controls_for(c, framework)]
