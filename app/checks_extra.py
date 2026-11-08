"""
Extra checks: CVE data (OSV.dev), GitHub Actions security, Kubernetes, Observability.

Each public function takes callables for reading the repository and returns a
list of dicts in the same shape as checks.py:
{check_id, name, description, severity, passed, category, recommendation}.
"""
import json
import logging
import re

import requests
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)


# ── CVE scanning via OSV.dev ──────────────────────────────────────────────────

def _parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    pkgs = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line[0] in ('#', '-', '.') or line.startswith('git+'):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*[=~]=\s*([^\s,;#]+)', line)
        if m:
            pkgs.append((m.group(1), m.group(2).strip()))
    return pkgs


def _parse_package_json(content: str) -> list[tuple[str, str]]:
    pkgs = []
    try:
        data = json.loads(content)
        for section in ('dependencies', 'devDependencies'):
            for name, ver in data.get(section, {}).items():
                clean = re.sub(r'^[\^~>=<]+', '', str(ver)).split()[0]
                if clean and re.match(r'^\d', clean):
                    pkgs.append((name, clean))
    except Exception:
        pass
    return pkgs


def _parse_go_mod(content: str) -> list[tuple[str, str]]:
    pkgs = []
    in_block = False
    for line in content.splitlines():
        s = line.strip()
        if s.startswith('require ('):
            in_block = True
            continue
        if in_block and s == ')':
            in_block = False
            continue
        if s.startswith('require ') or in_block:
            target = s[len('require '):] if s.startswith('require ') else s
            parts = target.split()
            if len(parts) >= 2 and parts[1].startswith('v'):
                pkgs.append((parts[0], parts[1].lstrip('v')))
    return pkgs


def _parse_cargo_toml(content: str) -> list[tuple[str, str]]:
    pkgs = []
    in_deps = False
    for line in content.splitlines():
        s = line.strip()
        if s == '[dependencies]':
            in_deps = True
            continue
        if s.startswith('[') and s != '[dependencies]':
            in_deps = False
        if in_deps and '=' in s and not s.startswith('#'):
            name, _, rest = s.partition('=')
            m = re.search(r'"(\d[^"]*)"', rest)
            if m:
                pkgs.append((name.strip(), m.group(1).strip()))
    return pkgs


_DEP_SOURCES = [
    ('requirements.txt', _parse_requirements_txt, 'PyPI'),
    ('package.json',     _parse_package_json,     'npm'),
    ('go.mod',           _parse_go_mod,           'Go'),
    ('Cargo.toml',       _parse_cargo_toml,       'crates.io'),
]

_SEV_ORDER = {'CRITICAL': 3, 'HIGH': 2, 'MODERATE': 1}


def _osv_max_severity(vuln: dict) -> str:
    for s in vuln.get('severity', []):
        score = s.get('score', '').upper()
        if 'CRITICAL' in score:
            return 'CRITICAL'
        if 'HIGH' in score:
            return 'HIGH'
    for alias in vuln.get('aliases', []):
        if alias.startswith('CVE-'):
            return 'HIGH'
    return 'MODERATE'


def check_cve_vulnerabilities(get_content_fn, client=None) -> list[dict]:
    """
    Scan dependency files against OSV.dev for known CVEs (free API, no key needed).

    With `client`, each vulnerable Python or JS/TS package is also marked
    imported / not imported by `reachability`, and one the code never refers
    to counts one step lower. Without it — or when the source is not all in
    memory — nothing is lowered.
    """
    logger.info("CVE scan: starting OSV.dev vulnerability check")
    all_vulns = []
    scanned = 0

    for filename, parser, ecosystem in _DEP_SOURCES:
        content = get_content_fn(filename)
        if not content:
            continue
        pkgs = parser(content)
        if not pkgs:
            continue
        pkgs = pkgs[:100]
        scanned += len(pkgs)
        logger.info("CVE scan: querying %d packages from %s (%s)", len(pkgs), filename, ecosystem)

        queries = [
            {'version': ver, 'package': {'name': name, 'ecosystem': ecosystem}}
            for name, ver in pkgs
        ]
        try:
            resp = requests.post(
                'https://api.osv.dev/v1/querybatch',
                json={'queries': queries},
                timeout=20,
            )
            if resp.status_code != 200:
                logger.warning("CVE scan: OSV.dev returned HTTP %s for %s", resp.status_code, ecosystem)
                continue
            results = resp.json().get('results', [])
            for i, result in enumerate(results):
                vulns = result.get('vulns', [])
                if vulns and i < len(pkgs):
                    name, ver = pkgs[i]
                    sev = max(
                        (_osv_max_severity(v) for v in vulns),
                        key=lambda x: _SEV_ORDER.get(x, 0),
                    )
                    all_vulns.append({
                        'package': name,
                        'ecosystem': ecosystem,
                        'version': ver,
                        'count': len(vulns),
                        'severity': sev,
                        'ids': [v.get('id', '') for v in vulns[:3]],
                    })
        except requests.exceptions.Timeout:
            logger.warning("CVE scan: OSV.dev timed out for %s", ecosystem)
        except Exception as exc:
            logger.error("CVE scan: request failed for %s: %s", filename, exc)

    if scanned == 0:
        logger.info("CVE scan: no recognized dependency files found")
        return []

    from app import reachability
    for ecosystem in {v['ecosystem'] for v in all_vulns}:
        pkgs_here = [v['package'] for v in all_vulns if v['ecosystem'] == ecosystem]
        reach = reachability.analyse(client, ecosystem, pkgs_here)
        for v in all_vulns:
            if v['ecosystem'] == ecosystem:
                v['reach'] = reach.get(v['package'], reachability.UNKNOWN)

    crit = sum(1 for v in all_vulns if v['severity'] == 'CRITICAL')
    high = sum(1 for v in all_vulns if v['severity'] == 'HIGH')
    unused = [v for v in all_vulns if v.get('reach') == reachability.NOT_IMPORTED]
    used = [v for v in all_vulns if v.get('reach') != reachability.NOT_IMPORTED]
    logger.info("CVE scan: done — %d vulnerable packages (critical=%d, high=%d, not imported=%d) of %d scanned",
                len(all_vulns), crit, high, len(unused), scanned)

    if not all_vulns:
        return [{
            'check_id': 'deps.cve',
            'name': _('Known vulnerabilities in dependencies'),
            'description': _('Checked %(n)d dependencies against OSV.dev — no known vulnerabilities.')
                           % {'n': scanned},
            'severity': 'info', 'passed': True, 'category': 'deps',
            'recommendation': '',
        }]

    # What the code uses comes first: that is the upgrade that cannot wait.
    ordered = used + unused
    pkg_names = ', '.join(f"{v['package']} {v['version']}" for v in ordered[:5])
    if len(ordered) > 5:
        pkg_names += _(' and %(n)d more') % {'n': len(ordered) - 5}
    cve_ids = ', '.join(sorted({i for v in ordered for i in v['ids'] if i})[:5])

    description = (
        _('%(vuln)d of %(scanned)d dependencies have known vulnerabilities '
          '(%(crit)d critical, %(high)d high) according to OSV.dev.')
        % {'vuln': len(all_vulns), 'scanned': scanned, 'crit': crit, 'high': high}
        + (_(' Examples: %(ids)s.') % {'ids': cve_ids} if cve_ids else '')
    )
    if unused:
        description += ' ' + _(
            '%(n)d of them are not imported anywhere in the code and count one level lower: '
            '%(pkgs)s. This is a heuristic — we read import statements and tool configs, not '
            'the call graph, and a package another dependency loads can still run.'
        ) % {'n': len(unused), 'pkgs': ', '.join(v['package'] for v in unused[:5])}

    # A package the code never refers to is lowered one step: a critical one
    # still warns, the rest become informational. Never cleared — see
    # `reachability` for why the heuristic cannot be trusted that far.
    if any(v['severity'] == 'CRITICAL' for v in used):
        severity = 'crit'
    elif used or any(v['severity'] == 'CRITICAL' for v in unused):
        severity = 'warn'
    else:
        severity = 'info'

    return [{
        'check_id': 'deps.cve',
        'name': _('Known vulnerabilities in dependencies'),
        'description': description,
        'severity': severity,
        'passed': False,
        'category': 'deps',
        'recommendation': (
            _('Upgrade the affected packages: %(pkgs)s.') % {'pkgs': pkg_names} + '\n'
            + _('Get the full list locally:') + '\n'
            '  pip-audit                  # Python\n'
            '  npm audit --fix            # Node.js\n'
            '  cargo audit                # Rust\n'
            '  govulncheck ./...          # Go\n'
            + _('Then turn on Dependabot or Renovate so the next patch arrives as a pull request.')
        ),
    }]


# ── GitHub Actions security ───────────────────────────────────────────────────

class _FunctionClient:
    """The two callables the old signature took, dressed as the client `checks_cicd` reads."""
    is_private = True  # unknown here — never claim a repository is public

    def __init__(self, get_content_fn, list_dir_fn):
        self.get_content = get_content_fn
        self.list_dir = list_dir_fn


def check_github_actions_security(get_content_fn, list_dir_fn) -> list[dict]:
    """Moved to `checks_cicd.check_github_actions`; kept for callers of the old signature."""
    from app.checks_cicd import check_github_actions
    return check_github_actions(_FunctionClient(get_content_fn, list_dir_fn))


# ── Kubernetes security ───────────────────────────────────────────────────────

_K8S_DIRS = ['k8s', 'kubernetes', 'deploy', 'manifests', '.k8s', 'kube', 'helm', 'charts']
_K8S_KINDS = re.compile(
    r'kind:\s*(Deployment|Pod|StatefulSet|DaemonSet|Job|CronJob)', re.IGNORECASE
)


def _collect_k8s_content(get_content_fn, list_dir_fn) -> str:
    parts = []
    for d in _K8S_DIRS:
        files = list_dir_fn(d)
        for f in files:
            if f.endswith(('.yaml', '.yml')):
                c = get_content_fn(f'{d}/{f}')
                if c:
                    parts.append(c)
    return '\n'.join(parts)


def check_kubernetes_security(get_content_fn, list_dir_fn) -> list[dict]:
    """Security checks for Kubernetes workload manifests (if any detected)."""
    logger.info("Kubernetes: scanning for manifests")
    combined = _collect_k8s_content(get_content_fn, list_dir_fn)

    if not combined or not _K8S_KINDS.search(combined):
        logger.info("Kubernetes: no workload manifests found, skipping")
        return []

    logger.info("Kubernetes: found manifests, running security checks")
    checks = []

    # Resource limits
    has_limits = bool(re.search(r'resources:\s*\n(?:\s+.*\n)*?\s+limits:', combined))
    checks.append({
        'check_id': 'k8s.resource_limits',
        'name': _('Kubernetes: pods declare resource limits'),
        'description': (
            _('Pods without resource limits can exhaust the node and take neighbouring services down.')
            if not has_limits else _('Resource limits are declared on the workloads.')
        ),
        'severity': 'warn', 'passed': has_limits, 'category': 'ops',
        'recommendation': _(
            'Add to every container spec:\n'
            'resources:\n'
            '  requests:\n'
            '    memory: "128Mi"\n'
            '    cpu: "100m"\n'
            '  limits:\n'
            '    memory: "256Mi"\n'
            '    cpu: "500m"'
        ) if not has_limits else '',
    })

    # Non-root / privileged
    has_nonroot = bool(re.search(r'runAsNonRoot:\s*true', combined))
    is_privileged = bool(re.search(r'privileged:\s*true', combined))
    root_issue = not has_nonroot or is_privileged
    checks.append({
        'check_id': 'k8s.nonroot',
        'name': _('Kubernetes: containers run without root privileges'),
        'description': (
            (_('privileged: true found — the container has full access to the node. ') if is_privileged else '')
            + (_('runAsNonRoot is not set.') if not has_nonroot else '')
            if root_issue else
            _('securityContext is set for non-root execution.')
        ),
        'severity': 'crit' if is_privileged else 'warn',
        'passed': not root_issue,
        'category': 'ops',
        'recommendation': _(
            'In the pod and container securityContext:\n'
            'securityContext:\n'
            '  runAsNonRoot: true\n'
            '  runAsUser: 1000\n'
            '  allowPrivilegeEscalation: false\n'
            '  readOnlyRootFilesystem: true'
        ) if root_issue else '',
    })

    # Liveness + Readiness probes
    has_liveness  = bool(re.search(r'livenessProbe:', combined))
    has_readiness = bool(re.search(r'readinessProbe:', combined))
    has_probes = has_liveness and has_readiness
    checks.append({
        'check_id': 'k8s.probes',
        'name': _('Kubernetes: liveness and readiness probes'),
        'description': (
            (_('livenessProbe is missing — a hung pod will never be restarted. ') if not has_liveness else '')
            + (_('readinessProbe is missing — traffic will reach a pod that is not ready.') if not has_readiness else '')
            if not has_probes else
            _('Liveness and readiness probes are configured.')
        ),
        'severity': 'warn', 'passed': has_probes, 'category': 'ops',
        'recommendation': _(
            'Add to the container spec:\n'
            'readinessProbe:\n'
            '  httpGet:\n'
            '    path: /health\n'
            '    port: 8080\n'
            '  initialDelaySeconds: 5\n'
            '  periodSeconds: 10\n'
            'livenessProbe:\n'
            '  httpGet:\n'
            '    path: /health\n'
            '    port: 8080\n'
            '  initialDelaySeconds: 15\n'
            '  periodSeconds: 30'
        ) if not has_probes else '',
    })

    return checks


# ── Observability ─────────────────────────────────────────────────────────────

_MONITORING_LIBS = {
    'sentry-sdk':        'Sentry',
    'sentry_sdk':        'Sentry',
    '@sentry/':          'Sentry',
    'prometheus-client': 'Prometheus',
    'prometheus_client': 'Prometheus',
    'prom-client':       'Prometheus',
    'datadog':           'Datadog',
    'ddtrace':           'Datadog',
    'newrelic':          'New Relic',
    'opentelemetry':     'OpenTelemetry',
    'elastic-apm':       'Elastic APM',
    'rollbar':           'Rollbar',
    'loguru':            'Loguru',
    'structlog':         'structlog',
    'pino':              'pino',
    'winston':           'winston',
    'zerolog':           'zerolog',
}


def check_observability(get_content_fn) -> list[dict]:
    """Detect monitoring/observability libraries in dependency files."""
    logger.info("Observability: checking for monitoring libraries")

    combined = ' '.join(filter(None, [
        get_content_fn('requirements.txt') or '',
        get_content_fn('pyproject.toml') or '',
        get_content_fn('package.json') or '',
        get_content_fn('go.mod') or '',
        get_content_fn('Cargo.toml') or '',
    ])).lower()

    found = list(dict.fromkeys(
        label for lib, label in _MONITORING_LIBS.items() if lib in combined
    ))

    logger.info("Observability: found=%s", found)

    if found:
        return [{
            'check_id': 'ops.observability',
            'name': _('Observability tooling is wired in'),
            'description': _('Found: %(tools)s.') % {'tools': ', '.join(found)},
            'severity': 'info', 'passed': True, 'category': 'ops',
            'recommendation': '',
        }]

    return [{
        'check_id': 'ops.observability',
        'name': _('Observability tooling is wired in'),
        'description': _(
            'No monitoring library found. Without one, you learn about incidents from your users.'
        ),
        'severity': 'info', 'passed': False, 'category': 'ops',
        'recommendation': _(
            'Add the three signals:\n'
            '\u2022 Errors:  sentry-sdk\n'
            '\u2022 Metrics: prometheus-client plus a /metrics endpoint\n'
            '\u2022 Traces:  opentelemetry-sdk\n'
            '\u2022 Logs:    structlog or loguru for structured JSON output'
        ),
    }]
