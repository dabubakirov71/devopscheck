"""
Pull request until green CI (roadmap phase 5).

We open a fix pull request; this module follows it. Every minute `step()`
looks at the checks on the branch head:

    ci_running ──success──▶ green
        │  └─no checks after NO_CI_GRACE──▶ no_ci
        └─failure──▶ fixing ──pushed──▶ ci_running  (at most MAX_ITERATIONS)
                         └─cannot / may not / out of budget──▶ gave_up

The rules that make it safe to let a model push to someone's branch:

1. **Only the files this pull request touched** (`FixAttempt.scope_files`).
2. **Never make CI green by making CI check less.** `guardrail()` diffs every
   proposed change and refuses it if a test, lint or scan command disappears,
   or if anything like `continue-on-error`, `allow_failure`, `|| true`,
   `if: false` or a skip marker appears. A refused change is not pushed.
3. **Bounded**: MAX_ITERATIONS pushes, MAX_LLM_CALLS model calls, TIMEOUT
   wall clock. Then it stops and says so on the pull request — what it tried,
   why it stopped, what to do by hand.
4. **The same AI gates as everything else**: the account switch, and
   privacy routing (`_get_active_provider(is_private=...)`). Logs and files
   go through `redact()`.
5. **Test repositories first**: `FIX_AGENT_REPOS` lists the repositories the
   agent may act on ("*" for all). Everything else gets the plain PR.

GitHub only for now; GitLab pipelines are the same loop over a different API.
"""
import json
import logging
import re
from datetime import datetime, timedelta

import requests
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

API = 'https://api.github.com'
TIMEOUT_HTTP = 20
MAX_ITERATIONS = 3
MAX_LLM_CALLS = 6
TIMEOUT = timedelta(hours=2)
NO_CI_GRACE = timedelta(minutes=10)
MAX_LOG_CHARS = 5000
MAX_FAILED_JOBS = 3
MAX_FILE_CHARS = 20000
FAILED = ('failure', 'timed_out', 'startup_failure', 'action_required')

# Commands that check something. The count of these in a file may not go down.
CHECK_COMMAND = re.compile(
    r'\b(?:pytest|py\.test|unittest|tox|nox|npm (?:run )?test|yarn (?:run )?test|pnpm (?:run )?test|'
    r'jest|vitest|mocha|go test|go vet|cargo test|cargo clippy|mvn\b[^\n]*\btest|gradlew? [^\n]*test|'
    r'rspec|phpunit|make test|dotnet test|ruff|flake8|pylint|mypy|eslint|golangci-lint|'
    r'trivy|gitleaks|checkov|tfsec|semgrep|bandit)\b')
# Ways to make a failing check stop failing without fixing anything.
FORBIDDEN_ADDED = [
    (re.compile(r'continue-on-error:\s*true'), 'continue-on-error: true'),
    (re.compile(r'allow_failure:\s*true'), 'allow_failure: true'),
    (re.compile(r'\|\|\s*(?:true|:|exit 0)\b'), '"|| true" swallowing a failure'),
    (re.compile(r'^\s*if:\s*(?:false|\$\{\{\s*false\s*\}\})', re.M), 'a step disabled with if: false'),
    (re.compile(r'\bexit 0\b'), 'exit 0'),
    (re.compile(r'(?:pytest\.mark\.skip|unittest\.skip|\bxit\(|\bit\.skip\(|\bdescribe\.skip\(|'
                r'\btest\.skip\(|\bt\.Skip\()'), 'a skipped test'),
    (re.compile(r'(?:\s-k\s+["\']?not\b|--deselect\b|--ignore[= ])'), 'tests deselected'),
    (re.compile(r'--exit-zero\b|--no-fail\b|exit-code:\s*["\']?0'), 'a check told not to fail'),
]


def enabled_for(repo_full_name: str) -> bool:
    allowed = [r.strip().lower() for r in
               (getattr(settings, 'FIX_AGENT_REPOS', '') or '').split(',') if r.strip()]
    return '*' in allowed or repo_full_name.lower() in allowed


# ── GitHub ────────────────────────────────────────────────────────────────────

class GitHub:
    def __init__(self, token, repo):
        self.repo = repo
        self.s = requests.Session()
        self.s.headers.update({'Authorization': f'token {token}',
                               'Accept': 'application/vnd.github+json'})

    def _get(self, path, **kw):
        return self.s.get(f'{API}/repos/{self.repo}{path}', timeout=TIMEOUT_HTTP, **kw)

    def pull(self, number):
        r = self._get(f'/pulls/{number}')
        r.raise_for_status()
        return r.json()

    def check_runs(self, sha):
        r = self._get(f'/commits/{sha}/check-runs', params={'per_page': 100})
        r.raise_for_status()
        return r.json().get('check_runs', [])

    def failed_logs(self, sha):
        """[(job name, log excerpt)] for the failed Actions jobs on this commit."""
        out = []
        runs = self._get('/actions/runs', params={'head_sha': sha, 'per_page': 20})
        if runs.status_code != 200:
            return out
        for run in runs.json().get('workflow_runs', []):
            if run.get('conclusion') not in FAILED:
                continue
            jobs = self._get(f'/actions/runs/{run["id"]}/jobs')
            if jobs.status_code != 200:
                continue
            for job in jobs.json().get('jobs', []):
                if job.get('conclusion') not in FAILED:
                    continue
                log = self._get(f'/actions/jobs/{job["id"]}/logs')
                text = log.text if log.status_code == 200 else ''
                out.append((f'{run.get("name", "")} / {job.get("name", "")}', excerpt(text)))
                if len(out) >= MAX_FAILED_JOBS:
                    return out
        return out

    def read_file(self, path, ref):
        import base64
        r = self._get(f'/contents/{path}', params={'ref': ref})
        if r.status_code != 200:
            return None, None
        data = r.json()
        try:
            return base64.b64decode(data['content']).decode('utf-8'), data.get('sha')
        except (KeyError, ValueError, UnicodeDecodeError):
            return None, None

    def commit_file(self, branch, path, content, message, sha):
        import base64
        payload = {'message': message, 'branch': branch,
                   'content': base64.b64encode(content.encode()).decode()}
        if sha:
            payload['sha'] = sha
        r = self.s.put(f'{API}/repos/{self.repo}/contents/{path}', json=payload, timeout=TIMEOUT_HTTP)
        r.raise_for_status()
        return r.json().get('commit', {}).get('sha', '')

    def comment(self, number, body):
        r = self.s.post(f'{API}/repos/{self.repo}/issues/{number}/comments',
                        json={'body': body}, timeout=TIMEOUT_HTTP)
        if r.status_code >= 300:
            logger.warning('Fix agent: comment on %s#%s failed (%s)', self.repo, number, r.status_code)


# ── Pure parts ────────────────────────────────────────────────────────────────

_TS = re.compile(r'^\d{4}-\d{2}-\d{2}T[\d:.]+Z ')
_INTERESTING = re.compile(r'error|fail|traceback|exception|not found|no such file|exit code|'
                          r'assert|cannot|could not|denied', re.I)


def excerpt(log: str) -> str:
    """The part of a job log worth a model's attention: error lines with context, and the tail."""
    lines = [_TS.sub('', ln) for ln in (log or '').splitlines()]
    keep = set(range(max(0, len(lines) - 40), len(lines)))
    for i, ln in enumerate(lines):
        if _INTERESTING.search(ln):
            keep.update(range(max(0, i - 3), min(len(lines), i + 4)))
    text = '\n'.join(lines[i] for i in sorted(keep))
    return text[-MAX_LOG_CHARS:]


def ci_status(runs) -> str:
    """'none' | 'pending' | 'success' | 'failure' for a commit's check runs."""
    if not runs:
        return 'none'
    if any(r.get('status') != 'completed' for r in runs):
        return 'pending'
    if any(r.get('conclusion') in FAILED for r in runs):
        return 'failure'
    return 'success'


def guardrail(old: dict, new: dict, scope) -> list[str]:
    """Reasons to refuse a proposed change. Empty means it may be pushed."""
    problems = []
    for path, content in new.items():
        if path not in scope:
            problems.append(f'{path} is outside this pull request (allowed: {", ".join(scope)})')
            continue
        before = old.get(path) or ''
        if not content.strip():
            problems.append(f'{path} would be emptied')
            continue
        if len(CHECK_COMMAND.findall(content)) < len(CHECK_COMMAND.findall(before)):
            problems.append(f'{path}: a test, lint or scan command would be removed')
        before_lines = set(before.splitlines())
        added = '\n'.join(ln for ln in content.splitlines() if ln not in before_lines)
        for pattern, label in FORBIDDEN_ADDED:
            if pattern.search(added):
                problems.append(f'{path}: adds {label}')
    return problems


def parse_answer(text: str) -> dict:
    text = re.sub(r'^```(?:json)?\s*|\s*```$', '', (text or '').strip())
    start, end = text.find('{'), text.rfind('}')
    if start == -1 or end == -1:
        return {}
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def build_prompt(attempt, files: dict, logs, feedback='') -> str:
    from app.repo_context import host_rule
    tried = [h.get('explanation', '') for h in (attempt.history or []) if h.get('event') == 'pushed']
    body = '\n\n'.join(f'=== FILE: {p} ===\n{t}' for p, t in files.items())
    log_text = '\n\n'.join(f'=== FAILED JOB: {name} ===\n{text}' for name, text in logs) or '(no logs available)'
    return f"""You are fixing a pull request whose CI failed. {host_rule(attempt.source, 'en')}

The pull request exists to fix the check "{attempt.check_name}": {attempt.recommendation[:600]}
It changed only these files: {', '.join(attempt.scope_files)}.

{log_text}

Files you may change (current content on the branch):
{body}

{('Earlier attempts on this pull request (do not repeat them):' + chr(10) + chr(10).join('- ' + t for t in tried)) if tried else ''}
{('Your previous answer was refused: ' + feedback) if feedback else ''}

Rules — a change that breaks one is refused and never pushed:
- Change only the files listed above; return each changed file's full new content.
- Make CI pass by fixing the cause. Never remove, skip or weaken a test, lint or scan step or command,
  never add continue-on-error, allow_failure, "|| true", "exit 0", "if: false", or skip markers.
- If the failure cannot be fixed inside these files (it is in the project's own code or tests, or needs
  a secret or setting), give up instead and say why.

Answer with JSON only:
{{"explanation": "one sentence: the cause and the change", "files": [{{"path": "...", "content": "..."}}]}}
or
{{"give_up": "why it cannot be fixed within these files, and what the owner should do"}}
"""


# ── The loop ──────────────────────────────────────────────────────────────────

def _finish(attempt, state, reason=''):
    attempt.state = state
    attempt.finished_at = timezone.now()
    if reason:
        attempt.gave_up_reason = reason
    attempt.log(state, reason=reason)


def _give_up(attempt, gh, reason, logs=()):
    _finish(attempt, attempt.STATE_GAVE_UP, reason)
    pushed = [h for h in attempt.history if h.get('event') == 'pushed']
    lines = ['**DevOpsCheck could not get CI green on this pull request, and stopped.**', '',
             f'Why: {reason}', '']
    if pushed:
        lines += ['What was tried:'] + [f'{i}. `{h.get("sha", "")[:7]}` — {h.get("explanation", "")}'
                                        for i, h in enumerate(pushed, 1)] + ['']
    if logs:
        lines += ['Failing jobs: ' + ', '.join(f'`{name}`' for name, _ in logs), '']
    lines += ['What to do: open the failing job in the Checks tab, fix the cause on this branch, '
              'or close the pull request. Nothing further will be pushed here automatically.']
    gh.comment(attempt.pr_number, '\n'.join(lines))


def _fix(attempt, gh, sha):
    from app.ai_providers import PROVIDERS, _call_provider, _get_active_provider
    from app.checks_secrets import redact

    provider, api_key = _get_active_provider(attempt.user_id, is_private=attempt.audit.repo_is_private)
    logs = gh.failed_logs(sha)
    if not provider or not api_key:
        return _give_up(attempt, gh, 'no AI provider may read this repository (private repositories '
                                     'need a paid provider, or AI analysis is switched off).', logs)
    logs = [(name, redact(text)) for name, text in logs]
    current, blob_shas = {}, {}
    for path in attempt.scope_files:
        text, blob = gh.read_file(path, attempt.branch)
        current[path] = text or ''
        blob_shas[path] = blob
    files_for_prompt = {p: redact(t[:MAX_FILE_CHARS]) for p, t in current.items()}

    feedback = ''
    for _try in range(2):
        if attempt.llm_calls >= MAX_LLM_CALLS:
            return _give_up(attempt, gh, f'the model budget for one pull request ({MAX_LLM_CALLS} calls) '
                                         'is spent.', logs)
        prompt = build_prompt(attempt, files_for_prompt, logs, feedback)
        try:
            answer = _call_provider(provider, api_key, prompt, max_tokens=6000)
        except Exception as exc:
            logger.warning('Fix agent: model call failed for %s: %s', attempt, exc)
            answer = ''
        attempt.llm_calls += 1
        attempt.llm_chars += len(prompt) + len(answer or '')
        attempt.llm_provider = PROVIDERS[provider]['name']
        data = parse_answer(answer)
        if data.get('give_up'):
            return _give_up(attempt, gh, str(data['give_up'])[:600], logs)
        proposed = {f.get('path'): f.get('content', '') for f in data.get('files') or []
                    if isinstance(f, dict) and f.get('path')}
        proposed = {p: c for p, c in proposed.items() if c != current.get(p)}
        if not proposed:
            feedback = 'it changed nothing (or was not valid JSON).'
            attempt.log('refused', reason=feedback)
            continue
        problems = guardrail(current, proposed, attempt.scope_files)
        if problems:
            feedback = '; '.join(problems)
            attempt.log('refused', reason=feedback)
            logger.info('Fix agent: guardrail refused a change on %s: %s', attempt, feedback)
            continue
        explanation = str(data.get('explanation', ''))[:300]
        new_sha = ''
        for path, content in proposed.items():
            new_sha = gh.commit_file(attempt.branch, path, content,
                                     f'fix(ci): {explanation[:60] or "make CI pass"}\n\n'
                                     f'Automatic fix {attempt.iterations + 1}/{MAX_ITERATIONS} by DevOpsCheck.',
                                     blob_shas.get(path))
        attempt.iterations += 1
        attempt.head_sha = new_sha or attempt.head_sha
        attempt.state = attempt.STATE_CI_RUNNING
        attempt.log('pushed', sha=new_sha, explanation=explanation, files=sorted(proposed))
        gh.comment(attempt.pr_number,
                   f'🔧 CI failed ({", ".join(n for n, _ in logs) or "checks"}). Pushed a fix '
                   f'({attempt.iterations}/{MAX_ITERATIONS}): {explanation}')
        return
    _give_up(attempt, gh, f'every proposed change was refused by the guardrail ({feedback})', logs)


def step(attempt) -> None:
    """Advance one FixAttempt by one poll. Saves it."""
    now = timezone.now()
    attempt.last_checked_at = now
    try:
        profile = attempt.user.github_profiles.first()
        token = profile.current_token if profile else ''
        if not token:
            _finish(attempt, attempt.STATE_GAVE_UP, 'the GitHub connection is gone')
            return
        gh = GitHub(token, attempt.repo_full_name)
        pr = gh.pull(attempt.pr_number)
        if pr.get('state') == 'closed':
            attempt.merged = bool(pr.get('merged'))
            if attempt.merged:
                from app import funnel
                funnel.record('fix_pr_merged', user=attempt.user, ref=attempt.check_id)
            _finish(attempt, attempt.STATE_CLOSED)
            return
        if now - attempt.created_at > TIMEOUT:
            _give_up(attempt, gh, f'CI was not green within {int(TIMEOUT.total_seconds() // 3600)} hours.')
            return
        sha = (pr.get('head') or {}).get('sha', '')
        attempt.head_sha = sha
        status = ci_status(gh.check_runs(sha))
        if status == 'pending':
            return
        if status == 'none':
            # Checks take a moment to appear after a push; only a long silence
            # means the repository has no CI on pull requests at all.
            pushes = [datetime.fromisoformat(h['at']) for h in attempt.history
                      if h.get('event') == 'pushed']
            if now - max([attempt.created_at, *pushes]) > NO_CI_GRACE:
                _finish(attempt, attempt.STATE_NO_CI)
            return
        if status == 'success':
            _finish(attempt, attempt.STATE_GREEN)
            if attempt.iterations:
                gh.comment(attempt.pr_number, f'✅ CI is green after {attempt.iterations} automatic '
                                              f'fix{"es" if attempt.iterations > 1 else ""}.')
            return
        # failure
        attempt.log('ci_failed', sha=sha)
        if attempt.iterations >= MAX_ITERATIONS:
            _give_up(attempt, gh, f'CI still fails after {MAX_ITERATIONS} automatic fixes.',
                     gh.failed_logs(sha))
            return
        attempt.state = attempt.STATE_FIXING
        _fix(attempt, gh, sha)
    except requests.RequestException as exc:
        logger.warning('Fix agent: GitHub request failed for %s: %s', attempt, exc)
    finally:
        attempt.save()


def track(audit, check, pr: dict, filename: str) -> None:
    """Start following a fix pull request we just opened, if the agent may act on this repository."""
    from app.models import FixAttempt
    if audit.source != 'github' or not pr.get('number') or not enabled_for(audit.repo_display):
        return
    FixAttempt.objects.create(
        user=audit.user, audit=audit, check_id=check.check_id or '', check_name=check.name,
        recommendation=check.recommendation or '', source=audit.source,
        repo_full_name=audit.repo_display, branch=pr['branch'], pr_number=pr['number'],
        pr_url=pr['url'], scope_files=[filename],
    )
