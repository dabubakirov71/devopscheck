"""
Write the audit's open findings as SARIF 2.1.0, so github/codeql-action/upload-sarif
shows them under Security → Code scanning.

    python3 sarif.py result.json devopscheck.sarif

Every failed, applicable check becomes one result. Its location is the file
the check's evidence names when that file exists in the checkout; otherwise the
repository's README (code scanning needs a file to hang a result on).
"""
import json
import os
import re
import sys

LEVEL = {'crit': 'error', 'warn': 'warning', 'info': 'note'}
SECURITY_SEVERITY = {'crit': '8.0', 'warn': '5.0', 'info': '2.0'}
_PATH = re.compile(r'^([\w./-]+\.[\w-]+|[\w./-]*Dockerfile[\w.-]*)(?=[:\s,]|$)')


def _location(evidence, workspace):
    match = _PATH.match((evidence or '').strip())
    if match and os.path.isfile(os.path.join(workspace, match.group(1))):
        return match.group(1)
    for name in ('README.md', 'README.rst', 'README', 'readme.md'):
        if os.path.isfile(os.path.join(workspace, name)):
            return name
    return 'README.md'


def build(data, workspace='.'):
    base = (data.get('url') or 'https://devopscheck.com').split('/scan/')[0].split('/audit/')[0]
    rules, results, seen = [], [], set()
    for check in data.get('checks') or []:
        if check.get('passed') or not check.get('applicable', True) or check.get('category') == 'hygiene':
            continue
        cid = check.get('check_id') or 'devopscheck'
        sev = check.get('severity') or 'warn'
        if cid not in seen:
            seen.add(cid)
            rules.append({
                'id': cid,
                'name': cid.replace('.', '_'),
                'shortDescription': {'text': check.get('name') or cid},
                'helpUri': f'{base}/checks/{cid}/',
                'help': {'text': check.get('recommendation') or check.get('name') or cid},
                'properties': {'security-severity': SECURITY_SEVERITY.get(sev, '5.0'),
                               'tags': ['devops', check.get('category') or 'general']},
            })
        text = check.get('name') or cid
        if check.get('recommendation'):
            text += ' — ' + check['recommendation'].split('\n')[0]
        results.append({
            'ruleId': cid,
            'level': LEVEL.get(sev, 'warning'),
            'message': {'text': text},
            'locations': [{'physicalLocation': {
                'artifactLocation': {'uri': _location(check.get('evidence'), workspace)},
                'region': {'startLine': 1}}}],
        })
    return {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {'name': 'DevOpsCheck', 'informationUri': base, 'rules': rules}},
            'results': results,
        }],
    }


if __name__ == '__main__':
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
    with open(sys.argv[2], 'w') as fh:
        json.dump(build(data, os.environ.get('GITHUB_WORKSPACE', '.')), fh, indent=1)
