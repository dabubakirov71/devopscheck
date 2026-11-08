"""
Golden-corpus regression check.

Loads every fixture in tests/golden/fixtures/ (recorded network responses,
not live calls — see record_fixture.py), runs the real check engine and
classifier against each, and compares against the checked-in expectation in
tests/golden/expected/. Prints a diff and exits non-zero on any mismatch.

    make golden
    # or directly:
    docker compose -f docker/docker-compose.yml exec web python tests/golden/run_golden.py

`--write` regenerates tests/golden/expected/ from the current engine output —
use it once, by hand, after a change you have reviewed and intend, never to
silence a failure you have not looked at.
"""
import json
import os
import sys

import django

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from app.checks import run_all_checks, calculate_score, get_category_scores  # noqa: E402
from app.repo_client import StaticRepoClient  # noqa: E402
from app.repo_kind import detect  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE_DIR = os.path.join(HERE, 'fixtures')
EXPECTED_DIR = os.path.join(HERE, 'expected')


def run_one(fixture_path):
    fx = json.load(open(fixture_path))
    client = StaticRepoClient(fx['files'], full_name=fx['full_name'],
                              provider=fx.get('provider', 'github'))
    # Every corpus repository is public — that is how it could be recorded
    # without credentials — and checks such as actions.self_hosted_public
    # only mean anything when the client knows it.
    client.is_private = fx.get('is_private', False)
    # A fixture keeps the content of the files the checks read and records
    # every other path as ''. CVE reachability reads all source, so it must see
    # those as unread (None, -> "unknown"), not as empty files that import
    # nothing — which would lower a CVE on evidence the fixture never kept.
    client.local_text = lambda path: fx['files'].get(path.strip('/')) or None

    kind, _skipped, _reason, confidence = detect(client)
    checks = run_all_checks(client)

    return {
        'full_name': fx['full_name'],
        'kind': kind,
        'confidence': confidence,
        'score': calculate_score(checks),
        'category_scores': get_category_scores(checks),
        # id -> passed, for every check the repository could act on. Not
        # applicable checks are excluded — their presence and reason are a
        # `repo_kind` concern (covered by RepoKindTest), not a scoring one,
        # and including them here would make every kind change touch every
        # fixture's expectation regardless of whether a real check outcome
        # moved.
        'checks': {
            c['check_id']: c['passed']
            for c in sorted(checks, key=lambda c: c['check_id'])
            if c.get('applicable', True)
        },
    }


def diff(expected, actual):
    lines = []
    for key in ('kind', 'confidence', 'score'):
        if expected.get(key) != actual.get(key):
            lines.append(f'  {key}: expected {expected.get(key)!r}, got {actual.get(key)!r}')

    exp_checks, act_checks = expected.get('checks', {}), actual.get('checks', {})
    for check_id in sorted(set(exp_checks) | set(act_checks)):
        e, a = exp_checks.get(check_id, '<missing>'), act_checks.get(check_id, '<missing>')
        if e != a:
            lines.append(f'  check {check_id}: expected passed={e}, got passed={a}')
    return lines


def main():
    write = '--write' in sys.argv
    os.makedirs(EXPECTED_DIR, exist_ok=True)

    fixtures = sorted(f for f in os.listdir(FIXTURE_DIR) if f.endswith('.json'))
    if not fixtures:
        print('No fixtures in tests/golden/fixtures/ — nothing to check.', file=sys.stderr)
        return 1

    failures = 0
    for name in fixtures:
        actual = run_one(os.path.join(FIXTURE_DIR, name))
        expected_path = os.path.join(EXPECTED_DIR, name)

        if write:
            with open(expected_path, 'w') as f:
                json.dump(actual, f, indent=1, sort_keys=True)
            print(f'wrote {expected_path}')
            continue

        if not os.path.exists(expected_path):
            print(f'FAIL {actual["full_name"]}: no expected/{name} yet — run with --write once you '
                  f'have reviewed this result.')
            failures += 1
            continue

        expected = json.load(open(expected_path))
        problems = diff(expected, actual)
        if problems:
            failures += 1
            print(f'FAIL {actual["full_name"]}:')
            for line in problems:
                print(line)
        else:
            print(f'ok   {actual["full_name"]} (kind={actual["kind"]}, score={actual["score"]})')

    if write:
        return 0

    print(f'\n{len(fixtures) - failures}/{len(fixtures)} fixtures match the golden expectation.')
    if failures:
        print(
            'A mismatch here means a check or the classifier changed behaviour on a real, '
            'well-known repository — confirm the new reading is correct, then regenerate the '
            'expectation deliberately with --write. It is never a reason to loosen the check '
            'that moved without looking at why.'
        )
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
