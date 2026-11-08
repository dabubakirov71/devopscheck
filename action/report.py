#!/usr/bin/env python3
"""
Turn an audit result into the two things a CI run has to produce: a job summary
somebody will actually read, and a pull request comment body.

Kept separate from audit.sh because formatting a table in bash is how you get a
report that breaks on a backtick in a recommendation.
"""
import json
import os
import sys

ICON = {'crit': '🔴', 'warn': '🟡', 'info': '🔵'}
SUMMARY_PATH = os.environ.get('GITHUB_STEP_SUMMARY', '')
COMMENT_PATH = '/tmp/devops-audit-comment.md'
MAX_ROWS = 10


def first_line(text, limit=110):
    line = (text or '').split('\n')[0].strip()
    return (line[:limit] + '…') if len(line) > limit else line


def table(rows):
    out = ['| | Finding | What to do |', '|---|---|---|']
    for check in rows[:MAX_ROWS]:
        name = (check.get('name') or check.get('check_id') or '').replace('|', '\\|')
        fix = first_line(check.get('recommendation')).replace('|', '\\|')
        out.append(f"| {ICON.get(check.get('severity'), '•')} | {name} | {fix} |")
    if len(rows) > MAX_ROWS:
        out.append(f'| | _and {len(rows) - MAX_ROWS} more_ | |')
    return out


def build(data):
    score = data.get('score')
    delta = data.get('score_delta')
    gate = data.get('gate')
    fail_under = data.get('fail_under')
    url = data.get('url', '')
    repo = data.get('repo', '')
    ref = data.get('ref') or 'default branch'

    checks = data.get('checks') or []
    # Hygiene (README, CODEOWNERS, …) is shown on the report but is not a
    # finding: it is out of the score, and it must not be out of a build either.
    open_findings = [c for c in checks if not c.get('passed') and c.get('applicable', True)
                     and c.get('category') != 'hygiene']
    set_aside = [c for c in checks if not c.get('applicable', True)]
    new_ids = set(data.get('new_findings') or [])
    appeared = [c for c in open_findings if c.get('check_id') in new_ids]
    standing = [c for c in open_findings if c.get('check_id') not in new_ids]
    resolved = data.get('resolved_findings') or []

    crit = sum(1 for c in open_findings if c.get('severity') == 'crit')
    warn = sum(1 for c in open_findings if c.get('severity') == 'warn')

    if delta is None:
        headline = f'**{score}/100**'
    elif delta > 0:
        headline = f'**{score}/100** (▲ +{delta})'
    elif delta < 0:
        headline = f'**{score}/100** (▼ {delta})'
    else:
        headline = f'**{score}/100** (no change)'

    lines = [f'## DevOpsCheck — `{repo}` @ `{ref}`', '']

    if appeared:
        lines.append(f'**{len(appeared)} new** since the last run. Score: {headline}')
    elif resolved:
        lines.append(f'Nothing new, and **{len(resolved)} fixed**. Score: {headline}')
    else:
        lines.append(f'Nothing new. Score: {headline}')

    if gate is False:
        lines += ['', f'⛔ **Below the threshold of {fail_under}.**']
    elif gate is True:
        lines += ['', f'✅ Clears the threshold of {fail_under}.']

    if appeared:
        lines += ['', '### New in this run', ''] + table(appeared)

    if standing:
        label = 'Already open' if appeared else 'Open findings'
        lines += ['', f'<details><summary>{label} — {crit} critical, {warn} warnings</summary>', '']
        lines += table(standing)
        lines += ['', '</details>']
    elif not appeared:
        lines += ['', 'No findings. ✅']

    if set_aside:
        reason = next((c.get('not_applicable_reason') for c in set_aside
                       if c.get('not_applicable_reason')), '')
        lines += ['', f'<details><summary>{len(set_aside)} check(s) do not apply here</summary>', '']
        if reason:
            lines += [reason, '']
        lines += [f"- `{c.get('check_id')}` — {c.get('name')}" for c in set_aside]
        lines += ['', '</details>']

    config_errors = data.get('config_errors') or []
    if config_errors:
        lines += ['', '<details><summary>⚠️ `.devopsaudit.yml` needs attention</summary>', '']
        lines += [f'- {e}' for e in config_errors]
        lines += ['', '</details>']

    if url:
        lines += ['', f'[Full report]({url})']

    return '\n'.join(lines), score, crit, warn, len(appeared)


def main():
    with open(sys.argv[1]) as fh:
        data = json.load(fh)

    body, score, crit, warn, new_count = build(data)

    if SUMMARY_PATH:
        with open(SUMMARY_PATH, 'a') as fh:
            fh.write(body + '\n')

    with open(COMMENT_PATH, 'w') as fh:
        fh.write(body)

    print(f'Score {score}/100 — {crit} critical, {warn} warnings, {new_count} new')


if __name__ == '__main__':
    main()
