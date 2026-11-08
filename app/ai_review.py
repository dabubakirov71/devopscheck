"""
AI review of the files that decide how a repository builds and runs.

The rule-based checks answer fixed questions — is the base image pinned, does
the container run as root. They cannot say "this compose file publishes the
database port to the world" or "this job runs `curl | sh` on a tagged
release". A model reading the actual Dockerfile, compose file, CI config,
Terraform and Kubernetes manifests can, and that is where it earns its place.

What keeps it honest:

- **Every finding must quote its line.** The model returns `file`, `line` and
  `evidence` (the line's text). A finding whose evidence is not in that file
  within a few lines of where it says is dropped — a model that invents a
  problem also invents where it is, and this is where that shows.
- **Not in the score.** Findings are shown as "AI review", separately, and
  never change a number someone may be graded on.
- **Same gates as every other AI call**: the account's AI switch, the plan
  allowance, and the provider routing by repository privacy
  (`ai_providers._get_active_provider`). Content goes through `redact()`.
- **One request per audit**, bounded input, at most MAX_FINDINGS results.
"""
import json
import logging
import re

logger = logging.getLogger(__name__)

MAX_FILES = 12
MAX_FILE_CHARS = 6000
MAX_TOTAL_CHARS = 28000
MAX_FINDINGS = 8
LINE_SLACK = 3
SEVERITIES = ('high', 'medium', 'low')

_DOCKERFILE = re.compile(r'(?:^|/)(?:[\w.-]*\.)?Dockerfile(?:\.[\w.-]+)?$|(?:^|/)Containerfile$')
_COMPOSE = re.compile(r'(?:^|/)(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$')
_SKIP = ('node_modules/', 'vendor/', 'test/', 'tests/', 'examples/', 'example/', 'fixtures/', 'docs/')


def _kind(path: str) -> str:
    if any(part in '/' + path for part in ('/' + s for s in _SKIP)):
        return ''
    if _DOCKERFILE.search(path):
        return 'docker'
    if _COMPOSE.search(path):
        return 'compose'
    if path.startswith('.github/workflows/') and path.endswith(('.yml', '.yaml')):
        return 'ci'
    if path == '.gitlab-ci.yml' or (path.startswith('.gitlab/ci/') and path.endswith(('.yml', '.yaml'))):
        return 'ci'
    if path.endswith('.tf'):
        return 'terraform'
    if path.endswith(('.yml', '.yaml')) and any(p in path for p in ('k8s/', 'kubernetes/', 'deploy/', 'manifests/', 'helm/', 'charts/')):
        return 'kubernetes'
    return ''


# Order of interest: what runs in production first.
_PRIORITY = {'docker': 0, 'compose': 1, 'ci': 2, 'kubernetes': 3, 'terraform': 4}


def select_files(client) -> list[tuple[str, str]]:
    """(path, redacted text) for the files worth a review, within the budget."""
    from app.checks_secrets import redact

    candidates = sorted(
        ((p, _kind(p)) for p in client.files if _kind(p)),
        key=lambda pk: (_PRIORITY[pk[1]], pk[0].count('/'), pk[0]),
    )
    picked, total = [], 0
    for path, _kind_ in candidates:
        if len(picked) >= MAX_FILES:
            break
        text = client.get_content(path)
        if not text or not text.strip():
            continue
        text = redact(text[:MAX_FILE_CHARS])
        if total + len(text) > MAX_TOTAL_CHARS:
            continue
        picked.append((path, text))
        total += len(text)
    return picked


def _numbered(text: str) -> str:
    return '\n'.join(f'{i:>4}| {line}' for i, line in enumerate(text.splitlines(), 1))


def build_prompt(files, failed_names, host: str, language: str) -> str:
    from app.repo_context import host_rule

    ru = language == 'ru'
    body = '\n\n'.join(f'=== FILE: {path} ===\n{_numbered(text)}' for path, text in files)
    known = '\n'.join(f'- {n}' for n in failed_names[:40]) or '- (none)'
    lang_rule = ('Write "title", "why" and "fix" in Russian.' if ru else
                 'Write "title", "why" and "fix" in English.')
    return f"""You are a senior DevOps and security engineer reviewing a repository's build, deploy and CI files.
{host_rule(host, 'en')}

Find concrete problems in THESE files that could cause a security incident, an outage or a broken
deploy. Examples of what counts: secrets passed as build args or printed in logs, database/admin ports
published to 0.0.0.0, `curl | sh` of unpinned scripts, privileged containers or docker.sock mounts,
CI jobs running untrusted input with write tokens, missing healthchecks on services others depend on,
state or credentials in plain Terraform, containers without resource limits in Kubernetes.

Rules:
- Only report what you can point to on a specific line. Quote that line exactly in "evidence".
- Do not report style, formatting, comments or missing documentation.
- Files meant only for local development (compose.override.yml, *.dev.*, *.local.*, docker-compose.dev.yml)
  may publish ports and use debug flags; report them only if the same setting reaches production.
- Report each problem once, on the line where it is introduced.
- Do not repeat these issues, the scanner already reported them:
{known}
- At most {MAX_FINDINGS} findings, most serious first. If nothing is wrong, return [].
- {lang_rule}
- Values shown as «REDACTED:…» were removed by us; do not report them as secrets.

Answer with a JSON array only, no prose, no code fences:
[{{"file": "path", "line": 12, "evidence": "exact text of that line", "severity": "high|medium|low",
  "title": "short problem", "why": "one sentence: what can go wrong here", "fix": "one or two sentences: the concrete change"}}]

{body}
"""


def _parse(text: str):
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*|\s*```$', '', text)
    start, end = text.find('['), text.rfind(']')
    if start == -1 or end == -1:
        return []
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def _norm(s: str) -> str:
    return re.sub(r'\s+', ' ', s or '').strip()


def verify(raw, files) -> list[dict]:
    """Keep only findings whose quoted evidence really is on (or next to) the cited line."""
    by_path = {path: text.splitlines() for path, text in files}
    kept, seen = [], set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        path = item.get('file')
        lines = by_path.get(path)
        evidence = _norm(str(item.get('evidence', '')))
        try:
            line = int(item.get('line'))
        except (TypeError, ValueError):
            continue
        if not lines or not evidence or len(evidence) < 4:
            continue
        window = range(max(1, line - LINE_SLACK), min(len(lines), line + LINE_SLACK) + 1)
        hit = next((n for n in window if evidence in _norm(lines[n - 1])
                    or (len(_norm(lines[n - 1])) >= 4 and _norm(lines[n - 1]) in evidence)), None)
        if hit is None:
            continue
        severity = str(item.get('severity', '')).lower()
        if severity not in SEVERITIES:
            severity = 'medium'
        title = _norm(str(item.get('title', '')))[:160]
        if not title or (path, hit) in seen:
            continue
        seen.add((path, hit))
        kept.append({
            'file': path, 'line': hit, 'severity': severity, 'title': title,
            'evidence': lines[hit - 1].strip()[:200],
            'why': _norm(str(item.get('why', '')))[:400],
            'fix': _norm(str(item.get('fix', '')))[:500],
        })
        if len(kept) >= MAX_FINDINGS:
            break
    order = {s: i for i, s in enumerate(SEVERITIES)}
    kept.sort(key=lambda f: order[f['severity']])
    return kept


def file_url(client, path: str, line: int) -> str:
    base = (getattr(client, 'repo_url', '') or '').rstrip('/')
    ref = getattr(client, 'head_sha', '') or getattr(client, 'ref', '') or ''
    if not base or not ref:
        return ''
    sep = '/-/blob/' if client.provider == 'gitlab' else '/blob/'
    return f'{base}{sep}{ref}/{path}#L{line}'


def review(client, checks, language='en', user_id=None, is_private=True) -> tuple[list[dict], str]:
    """
    Run the review. Returns (findings, provider display name).

    ([], '') when there is nothing to review or no model may see this
    repository — the built-in rules have no opinion to add here, so there is
    no fallback: absence is shown as absence.
    """
    from app.ai_providers import PROVIDERS, _call_provider, _get_active_provider
    from app.checks import counts

    provider, api_key = _get_active_provider(user_id, is_private=is_private)
    if not provider or not api_key:
        return [], ''
    files = select_files(client)
    if not files:
        return [], ''
    failed = [c['name'] for c in checks if counts(c) and not c['passed']]
    prompt = build_prompt(files, failed, client.provider, language)
    try:
        text = _call_provider(provider, api_key, prompt, max_tokens=4000)
    except Exception as exc:
        logger.warning('AI review failed for %s: %s', client.full_name, exc)
        return [], ''
    raw = _parse(text)
    if not raw and '[]' not in text.replace(' ', ''):
        # Not "nothing found" — an answer we could not read (cut off, or prose).
        logger.warning('AI review for %s: unreadable answer (%d chars): %r',
                       client.full_name, len(text), text[:200])
    findings = verify(raw, files)
    for f in findings:
        f['url'] = file_url(client, f['file'], f['line'])
    logger.info('AI review [%s]: %d file(s) sent, %d returned, %d verified',
                client.full_name, len(files), len(raw), len(findings))
    return findings, PROVIDERS[provider]['name']
