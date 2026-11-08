#!/usr/bin/env bash
#
# Run a DevOpsCheck against the commit under test and decide whether the
# build passes.
#
# The point of this file is the exit code. A report that can only be read on a
# website is a report people close; a check that fails a build is one the team
# has to talk about before merging. Everything else here — the job summary, the
# pull request comment — exists so that when it does fail, the reason is on
# screen and nobody has to go looking for it.
#
# Written in bash against curl and python3, both of which every GitHub runner
# already has. A Docker action would cost a build on every run, and a
# JavaScript one would mean shipping node_modules to the marketplace.
set -euo pipefail

API_URL="${INPUT_API_URL%/}"
REPO="${INPUT_REPOSITORY}"
TIMEOUT="${INPUT_TIMEOUT:-300}"

# No token: the free CI scanner, public repositories only. With a token: the
# account's own audit, which also works for private repositories.
if [[ -n "${DEVOPS_AUDIT_TOKEN:-}" ]]; then
  START_URL="${API_URL}/api/v1/audit/start/"
  AUTH=(-H "Authorization: Bearer ${DEVOPS_AUDIT_TOKEN}")
  MODE="account"
else
  START_URL="${API_URL}/api/v1/ci-scan/"
  AUTH=()
  MODE="free"
fi

# The commit under test. On a pull request GITHUB_SHA is the merge commit, which
# does not exist on the remote for us to read, so prefer the head sha.
REF="${INPUT_REF}"
if [[ -z "$REF" ]]; then
  if [[ -n "${GITHUB_HEAD_REF:-}" ]]; then
    REF="$GITHUB_HEAD_REF"
  else
    REF="${GITHUB_SHA:-}"
  fi
fi

PR_NUMBER=""
if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" || "${GITHUB_EVENT_NAME:-}" == "pull_request_target" ]]; then
  PR_NUMBER="$(python3 -c "
import json, os
path = os.environ.get('GITHUB_EVENT_PATH', '')
try:
    with open(path) as fh:
        print(json.load(fh).get('pull_request', {}).get('number', '') or '')
except Exception:
    print('')
")"
fi

say() { echo "$*"; }
fail() { echo "::error::$*"; exit 1; }

# ── start ────────────────────────────────────────────────────────────────────

say "Auditing ${REPO} at ${REF:-default branch}"

start_payload="$(AUDIT_REPO="$REPO" AUDIT_REF="$REF" AUDIT_PR="$PR_NUMBER" python3 -c "
import json, os
payload = {'repo': os.environ['AUDIT_REPO']}
if os.environ.get('AUDIT_REF'):
    payload['ref'] = os.environ['AUDIT_REF']
if os.environ.get('GITHUB_SHA'):
    payload['commit_sha'] = os.environ['GITHUB_SHA']
if os.environ.get('AUDIT_PR'):
    payload['pr_number'] = os.environ['AUDIT_PR']
print(json.dumps(payload))
")"

start_body="$(mktemp)"
start_code="$(curl -sS -o "$start_body" -w '%{http_code}' \
  -X POST "$START_URL" \
  "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  --data "$start_payload" || echo 000)"

if [[ "$start_code" == "401" || "$start_code" == "403" ]]; then
  detail="$(python3 -c "
import json,sys
try: print(json.load(open(sys.argv[1])).get('error',''))
except Exception: print('')
" "$start_body")"
  fail "The API refused the request (HTTP ${start_code}). ${detail:-Check that the token is valid and the plan allows this repository.}"
fi
if [[ "$start_code" != "201" && "$start_code" != "200" ]]; then
  fail "Could not start the audit (HTTP ${start_code}). $(head -c 300 "$start_body")"
fi

AUDIT_ID="$(python3 -c "
import json,sys; d = json.load(open(sys.argv[1])); print(d.get('audit_id') or d.get('id'))
" "$start_body")"
if [[ "$MODE" == "free" ]]; then
  DETAIL_URL="${API_URL}/api/v1/ci-scan/${AUDIT_ID}/"
  say "Free scan ${AUDIT_ID} queued (public repository, no token)"
else
  DETAIL_URL="${API_URL}/api/v1/audit/${AUDIT_ID}/"
  say "Audit ${AUDIT_ID} queued"
fi

# ── wait ─────────────────────────────────────────────────────────────────────

result="$(mktemp)"
deadline=$(( SECONDS + TIMEOUT ))
status="pending"

while (( SECONDS < deadline )); do
  sleep 4
  code="$(curl -sS -o "$result" -w '%{http_code}' \
    "$DETAIL_URL" "${AUTH[@]}" || echo 000)"
  [[ "$code" == "200" ]] || continue
  status="$(python3 -c "
import json,sys; print(json.load(open(sys.argv[1])).get('status',''))
" "$result")"
  [[ "$status" == "done" || "$status" == "failed" ]] && break
done

if [[ "$status" == "failed" ]]; then
  reason="$(python3 -c "
import json,sys; print(json.load(open(sys.argv[1])).get('error_message','') or 'no reason recorded')
" "$result")"
  fail "The audit could not finish: ${reason}"
fi
if [[ "$status" != "done" ]]; then
  fail "The audit did not finish within ${TIMEOUT}s. Raise the 'timeout' input, or check ${API_URL}/audit/${AUDIT_ID}/"
fi

# ── report ───────────────────────────────────────────────────────────────────

# One pass over the result: writes the outputs, the job summary and the PR
# comment body, and prints the verdict for the shell to act on.
verdict="$(python3 "${BASH_SOURCE%/*}/report.py" "$result")"
say "$verdict"

score="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('score') or 0)" "$result")"
gate="$(python3 -c "
import json,sys
g = json.load(open(sys.argv[1])).get('gate')
print('' if g is None else str(g).lower())
" "$result")"
new_count="$(python3 -c "
import json,sys; print(len(json.load(open(sys.argv[1])).get('new_findings') or []))
" "$result")"
report_url="$(python3 -c "
import json,sys; print(json.load(open(sys.argv[1])).get('url',''))
" "$result")"

{
  echo "score=${score}"
  echo "gate=${gate}"
  echo "new_findings=${new_count}"
  echo "report_url=${report_url}"
  echo "audit_id=${AUDIT_ID}"
} >> "${GITHUB_OUTPUT:-/dev/null}"

# ── SARIF ────────────────────────────────────────────────────────────────────

if [[ -n "${INPUT_SARIF:-}" ]]; then
  python3 "${BASH_SOURCE%/*}/sarif.py" "$result" "${INPUT_SARIF}" \
    && echo "sarif_file=${INPUT_SARIF}" >> "${GITHUB_OUTPUT:-/dev/null}" \
    || echo "::warning::Could not write SARIF to ${INPUT_SARIF}."
fi

# ── comment ──────────────────────────────────────────────────────────────────

if [[ "${INPUT_COMMENT}" == "true" && -n "$PR_NUMBER" && -f /tmp/devops-audit-comment.md ]]; then
  if ! curl -sS -o /dev/null -w '' -X POST \
      "${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H 'Accept: application/vnd.github+json' \
      --data "$(python3 -c "
import json
print(json.dumps({'body': open('/tmp/devops-audit-comment.md').read()}))
")"; then
    echo "::warning::Could not post the pull request comment. The job needs 'permissions: pull-requests: write'."
  fi
fi

# ── verdict ──────────────────────────────────────────────────────────────────

# An explicit fail-under input beats whatever the repository declares, so a
# pipeline can be stricter than the file without editing it.
threshold="${INPUT_FAIL_UNDER}"
if [[ -n "$threshold" ]]; then
  if (( score < threshold )); then
    fail "Score ${score} is below the fail-under of ${threshold}. ${report_url}"
  fi
elif [[ "$gate" == "false" ]]; then
  declared="$(python3 -c "
import json,sys; print(json.load(open(sys.argv[1])).get('fail_under') or '')
" "$result")"
  fail "Score ${score} is below the fail_under of ${declared} set in .devopsaudit.yml. ${report_url}"
fi

if [[ "${INPUT_FAIL_ON_NEW}" == "true" && "$new_count" -gt 0 ]]; then
  fail "${new_count} finding(s) appeared that the previous run did not have. ${report_url}"
fi

say "Passed."
