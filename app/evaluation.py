"""
Measuring the checks against repositories whose right answers are known
(accuracy spec, stage 1).

Two sets:

- **synthetic** — `tests/fixtures/repos/<name>/` with `expected.yaml`
  (+ `metadata.yaml`): tiny deterministic repositories, one situation each.
  No network. Run on every change by the test suite.
- **live** — `tests/golden/golden-set.yaml`: real repositories pinned to a
  commit SHA. The snapshot at that SHA is downloaded once and cached under
  `.eval-cache/`; after that the run needs no network either.

For every asserted (repository, check) pair the harness compares the
expected status with what the engine produced, and reports per check a
confusion matrix, precision and recall of FAIL, the list of disagreements
with the engine's own words as evidence, and the difference against the
previous run saved in `eval-baseline.json`.

Statuses: `pass`, `fail`, `na` (applicable=False, or the check did not run
at all — the module returned nothing because its object is absent),
`unknown` (not produced by the engine yet — spec stage 2).
"""
import json
import logging
import os
import tarfile
from collections import defaultdict
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import yaml
from django.conf import settings

logger = logging.getLogger(__name__)

ROOT = settings.BASE_DIR if hasattr(settings, 'BASE_DIR') else os.getcwd()
SYNTHETIC_DIR = os.path.join(str(ROOT), 'tests', 'fixtures', 'repos')
LIVE_SET = os.path.join(str(ROOT), 'tests', 'golden', 'golden-set.yaml')
CACHE_DIR = os.path.join(str(ROOT), '.eval-cache')
BASELINE = os.path.join(str(ROOT), 'eval-baseline.json')

STATUSES = ('pass', 'fail', 'na', 'unknown')

#: Spec names (docs/accuracy/spec.md) → check_id. See docs/checks-inventory.md §1.
ALIASES = {
    'tests_in_ci': 'ci.tests', 'dockerfile_present': 'docker.dockerfile',
    'container_nonroot': 'docker.nonroot', 'dockerfile_multistage': 'docker.multistage',
    'base_image_pinned': 'docker.pinned_base', 'dockerignore': 'docker.dockerignore',
    'healthcheck': 'docker.healthcheck', 'compose_resource_limits': 'docker.resource_limits',
    'observability': 'ops.observability', 'lockfile_present': 'deps.lockfile',
    'dependency_manifest': 'deps.manifest', 'changelog': 'docs.changelog',
    'security_policy': 'security.security_policy', 'contributing': 'docs.contributing',
    'codeowners': 'security.codeowners', 'readme': 'docs.readme', 'license': 'ops.license',
    'secrets_in_code': 'security.no_secrets', 'workflow_permissions': 'actions.broad_permissions',
    'actions_pinned_sha': 'actions.pinned_sha', 'branch_protection': 'ci.branch_protection',
}
#: The spec's type names → repo_kind's. A CLI is the spec's "library".
TYPE_ALIASES = {'iac': 'infrastructure', 'infrastructure': 'infrastructure', 'library': 'library',
                'cli': 'library', 'service': 'service', 'docs': 'docs', 'monorepo': 'monorepo'}


def check_id(name: str) -> str:
    return ALIASES.get(name, name)


def status_of(check) -> str:
    if check is None:
        return 'na'
    if check.get('status') in STATUSES:        # stage 2 will set this directly
        return check['status']
    if not check.get('applicable', True):
        return 'na'
    return 'pass' if check.get('passed') else 'fail'


def evidence_of(check) -> str:
    if check is None:
        return 'the check did not run (its module found nothing to inspect)'
    return (check.get('evidence') or check.get('not_applicable_reason')
            or check.get('description') or '')[:300]


@contextmanager
def _offline():
    """No network during a run: OSV answers "no vulnerabilities"."""
    resp = MagicMock(status_code=200)
    resp.json.side_effect = lambda: {'results': [{'vulns': []} for _ in range(100)]}
    with patch('app.checks_extra.requests.post', return_value=resp):
        yield


def run_repo(client) -> dict:
    """{kind, checks: {check_id: check dict}, error} for a loaded-or-loadable client."""
    from app.checks import run_all_checks
    from app.repo_client import RepoAccessError
    from app.repo_kind import detect
    try:
        client.load()
    except RepoAccessError as exc:
        return {'kind': None, 'checks': {}, 'error': 'empty' if 'empty' in str(exc).lower() else str(exc)}
    with _offline():
        checks = run_all_checks(client)
    kind = detect(client)[0]
    return {'kind': kind, 'checks': {c['check_id']: c for c in checks}, 'error': None}


# ── The two sets ──────────────────────────────────────────────────────────────

def synthetic_cases():
    from app.repo_client import LocalDirClient
    for name in sorted(os.listdir(SYNTHETIC_DIR)):
        d = os.path.join(SYNTHETIC_DIR, name)
        with open(os.path.join(d, 'expected.yaml'), encoding='utf-8') as fh:
            expected = yaml.safe_load(fh) or {}
        yield name, expected, (lambda d=d, name=name: LocalDirClient(d, full_name=f'fixture/{name}')), True


def archive_name(entry) -> str:
    """Where a snapshot tarball is expected: .eval-cache/<platform>/<owner>__<repo>@<sha>.tar.gz"""
    platform = entry.get('platform', 'github')
    return os.path.join(CACHE_DIR, platform, f"{entry['repo'].replace('/', '__')}@{entry['ref']}.tar.gz")


def archive_url(entry) -> str:
    repo, ref = entry['repo'], entry['ref']
    if entry.get('platform', 'github') == 'gitlab':
        return (f"https://gitlab.com/api/v4/projects/{repo.replace('/', '%2F')}"
                f"/repository/archive.tar.gz?sha={ref}")
    return f'https://api.github.com/repos/{repo}/tarball/{ref}'


def _commit_date(entry, headers):
    import requests
    repo, ref = entry['repo'], entry['ref']
    try:
        if entry.get('platform', 'github') == 'gitlab':
            data = requests.get(f"https://gitlab.com/api/v4/projects/{repo.replace('/', '%2F')}"
                                f"/repository/commits/{ref}", timeout=60).json()
            return data.get('committed_date')
        data = requests.get(f'https://api.github.com/repos/{repo}/commits/{ref}',
                            headers=headers, timeout=60).json()
        return ((data.get('commit') or {}).get('committer') or {}).get('date')
    except (requests.RequestException, ValueError):
        return None


def _snapshot(entry) -> str:
    """
    Directory holding the repository at entry['ref'].

    Uses a tarball already placed at `archive_name(entry)` (scripts/eval-fetch.sh
    downloads them on a host with a fast link and copies them here), and only
    downloads it itself when there is none.
    """
    import requests
    target = archive_name(entry)[:-len('.tar.gz')]
    if os.path.isdir(target):
        return target
    headers = {}
    token = getattr(settings, 'PUBLIC_SCAN_GITHUB_TOKEN', '') or os.environ.get('GITHUB_TOKEN', '')
    if token and entry.get('platform', 'github') == 'github':
        headers['Authorization'] = f'token {token}'
    archive = archive_name(entry)
    os.makedirs(os.path.dirname(archive), exist_ok=True)
    if not os.path.exists(archive):
        resp = requests.get(archive_url(entry), headers=headers, timeout=900, stream=True)
        resp.raise_for_status()
        with open(archive + '.part', 'wb') as fh:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                fh.write(chunk)
        os.replace(archive + '.part', archive)
    tmp = target + '.tmp'
    os.makedirs(tmp, exist_ok=True)
    with tarfile.open(archive, mode='r:gz') as tar:
        for member in tar:
            parts = member.name.split('/', 1)
            if len(parts) < 2 or not parts[1] or not (member.isfile() or member.isdir()):
                continue
            if member.isfile() and member.size > 2 * 1024 * 1024:
                continue
            member.name = parts[1]
            tar.extract(member, tmp, filter='data')
    # Metadata as of that commit: the "last push" is the commit date, so a
    # check that depends on age reads the same every time the set is run.
    with open(os.path.join(tmp, 'metadata.yaml'), 'w', encoding='utf-8') as fh:
        yaml.safe_dump({'provider': entry.get('platform', 'github'), 'default_branch': 'main',
                        'pushed_at': _commit_date(entry, headers), 'private': False,
                        'ref': entry['ref'], 'branch_protected': None}, fh)
    os.replace(tmp, target)
    os.remove(archive)
    return target


def fetch_list() -> list[tuple[str, str]]:
    """(url, archive path relative to .eval-cache) for every live entry without a snapshot."""
    with open(LIVE_SET, encoding='utf-8') as fh:
        data = yaml.safe_load(fh) or {}
    out = []
    for entry in data.get('repos', []):
        if not entry.get('ref') or entry['ref'] == 'TODO':
            continue
        archive = archive_name(entry)
        if not os.path.isdir(archive[:-len('.tar.gz')]) and not os.path.exists(archive):
            out.append((archive_url(entry), os.path.relpath(archive, CACHE_DIR)))
    return out


def live_cases(only=None):
    from app.repo_client import LocalDirClient
    with open(LIVE_SET, encoding='utf-8') as fh:
        data = yaml.safe_load(fh) or {}
    for entry in data.get('repos', []):
        if only and entry['repo'] not in only:
            continue
        if not entry.get('ref') or entry['ref'] == 'TODO':
            logger.warning('Live set: %s has no ref, skipped', entry['repo'])
            continue
        expected = {'expected_type': entry.get('expected_type'), 'checks': entry.get('checks') or {}}
        d = _snapshot(entry)
        yield (entry['repo'], expected,
               (lambda d=d, e=entry: LocalDirClient(d, full_name=e['repo'])), bool(entry.get('verified')))


# ── Comparison and metrics ────────────────────────────────────────────────────

def evaluate(cases) -> dict:
    pairs, types, errors = [], [], []
    for name, expected, make_client, verified in cases:
        result = run_repo(make_client())
        exp_error = expected.get('expected_error')
        if exp_error or result['error']:
            errors.append({'repo': name, 'expected': exp_error, 'actual': result['error'],
                           'ok': exp_error == result['error']})
            continue
        if expected.get('expected_type'):
            want = TYPE_ALIASES.get(expected['expected_type'], expected['expected_type'])
            got = TYPE_ALIASES.get(result['kind'], result['kind'])
            types.append({'repo': name, 'expected': want, 'actual': got, 'ok': want == got,
                          'verified': verified})
        for spec_name, want in (expected.get('checks') or {}).items():
            cid = check_id(spec_name)
            check = result['checks'].get(cid)
            got = status_of(check)
            pairs.append({'repo': name, 'check': cid, 'expected': str(want), 'actual': got,
                          'ok': str(want) == got, 'verified': verified, 'evidence': evidence_of(check)})
    return {'pairs': pairs, 'types': types, 'errors': errors, 'metrics': metrics(pairs, types, errors)}


def metrics(pairs, types, errors) -> dict:
    per_check = defaultdict(lambda: {'matrix': defaultdict(int), 'tp': 0, 'fp': 0, 'fn': 0, 'n': 0, 'ok': 0})
    for p in pairs:
        m = per_check[p['check']]
        m['matrix'][f"{p['expected']}>{p['actual']}"] += 1
        m['n'] += 1
        m['ok'] += p['ok']
        if p['actual'] == 'fail' and p['expected'] == 'fail':
            m['tp'] += 1
        elif p['actual'] == 'fail':
            m['fp'] += 1
        elif p['expected'] == 'fail':
            m['fn'] += 1
    out = {}
    for cid, m in sorted(per_check.items()):
        out[cid] = {
            'n': m['n'], 'correct': m['ok'], 'matrix': dict(m['matrix']),
            'fail_precision': round(m['tp'] / (m['tp'] + m['fp']), 3) if (m['tp'] + m['fp']) else None,
            'fail_recall': round(m['tp'] / (m['tp'] + m['fn']), 3) if (m['tp'] + m['fn']) else None,
            'false_fail': m['fp'],
        }
    fails = sum(1 for p in pairs if p['actual'] == 'fail')
    false_fails = sum(1 for p in pairs if p['actual'] == 'fail' and p['expected'] != 'fail')
    return {
        'pairs': len(pairs), 'correct': sum(p['ok'] for p in pairs),
        'accuracy': round(sum(p['ok'] for p in pairs) / len(pairs), 3) if pairs else None,
        'actual_fails': fails, 'false_fails': false_fails,
        # Share of reported FAILs that are wrong — the spec's "≤ 3%".
        'false_fail_rate': round(false_fails / fails, 3) if fails else 0.0,
        'type_accuracy': round(sum(t['ok'] for t in types) / len(types), 3) if types else None,
        'errors_ok': all(e['ok'] for e in errors),
        'per_check': out,
    }


def pair_key(p) -> str:
    return f"{p['repo']}::{p['check']}"


def compare(result: dict, baseline: dict | None) -> dict:
    """Pairs that got right or wrong since the baseline."""
    if not baseline:
        return {'fixed': [], 'broken': []}
    before = {k: v for k, v in (baseline.get('pairs_ok') or {}).items()}
    now = {pair_key(p): p['ok'] for p in result['pairs']}
    fixed = sorted(k for k, ok in now.items() if ok and before.get(k) is False)
    broken = sorted(k for k, ok in now.items() if not ok and before.get(k) is True)
    return {'fixed': fixed, 'broken': broken}


def baseline_payload(results: dict) -> dict:
    return {name: {'metrics': {k: v for k, v in r['metrics'].items() if k != 'per_check'},
                   'per_check': r['metrics']['per_check'],
                   'pairs_ok': {pair_key(p): p['ok'] for p in r['pairs']},
                   'types_ok': {t['repo']: t['ok'] for t in r['types']}}
            for name, r in results.items()}


def load_baseline() -> dict:
    if os.path.exists(BASELINE):
        with open(BASELINE, encoding='utf-8') as fh:
            return json.load(fh)
    return {}


def write_baseline(results: dict) -> None:
    with open(BASELINE, 'w', encoding='utf-8') as fh:
        json.dump(baseline_payload(results), fh, indent=1, sort_keys=True)
        fh.write('\n')


def render(name: str, result: dict, diff: dict) -> str:
    m = result['metrics']
    lines = [f'=== {name} ===',
             f"pairs {m['pairs']}, correct {m['correct']} ({m['accuracy']}), "
             f"FAIL reported {m['actual_fails']}, false FAIL {m['false_fails']} "
             f"(rate {m['false_fail_rate']}), type accuracy {m['type_accuracy']}, "
             f"error cases ok: {m['errors_ok']}", '',
             f"{'check':32} {'n':>3} {'ok':>3} {'P(fail)':>8} {'R(fail)':>8}  matrix expected>actual"]
    for cid, c in m['per_check'].items():
        p = '—' if c['fail_precision'] is None else f"{c['fail_precision']:.2f}"
        r = '—' if c['fail_recall'] is None else f"{c['fail_recall']:.2f}"
        matrix = ' '.join(f'{k}:{v}' for k, v in sorted(c['matrix'].items()))
        lines.append(f"{cid:32} {c['n']:>3} {c['correct']:>3} {p:>8} {r:>8}  {matrix}")
    wrong = [p for p in result['pairs'] if not p['ok']]
    if wrong:
        lines += ['', 'Disagreements:']
        for p in wrong:
            mark = '' if p['verified'] else ' [unverified]'
            lines.append(f"  {p['repo']} · {p['check']}: expected {p['expected']}, got {p['actual']}{mark}"
                         f"\n      evidence: {p['evidence']}")
    bad_types = [t for t in result['types'] if not t['ok']]
    if bad_types:
        lines += ['', 'Type disagreements:'] + [
            f"  {t['repo']}: expected {t['expected']}, got {t['actual']}" for t in bad_types]
    bad_errors = [e for e in result['errors'] if not e['ok']]
    if bad_errors:
        lines += ['', 'Error cases:'] + [
            f"  {e['repo']}: expected {e['expected']}, got {e['actual']}" for e in bad_errors]
    if diff['fixed'] or diff['broken']:
        lines += ['', f"Since baseline: fixed {len(diff['fixed'])}, broken {len(diff['broken'])}"]
        lines += [f'  + {k}' for k in diff['fixed']] + [f'  - {k}' for k in diff['broken']]
    return '\n'.join(lines)
