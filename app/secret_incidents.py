"""
Live secrets as incidents, and their rotation (roadmap phase 6).

An active key found by `checks_secrets` (with `secret_liveness` saying the
provider accepted it) becomes a `SecretIncident`: provider, file, line, the
commit that added it, and a rotation playbook for that provider. It stays
open until an audit *confirms* the old key no longer works — the key is in
git history for good, so every later audit finds it again and asks the
provider. That, not a button, is what closes an incident.

Nothing here stores a key. `fingerprint()` is an HMAC keyed with the
server's secret: enough to recognise the same key next time, useless for
recovering it. The env-var pull request re-finds the literal in the file by
rule and fingerprint rather than remembering it.

The agent never rewrites history. It explains how (git filter-repo) and says
plainly that rotating the key is what actually matters.
"""
import hashlib
import hmac
import logging
import re

from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy

logger = logging.getLogger(__name__)


def fingerprint(rule: str, value: str) -> str:
    key = hashlib.sha256(('secret-incident:' + settings.SECRET_KEY).encode()).digest()
    return hmac.new(key, f'{rule}:{value}'.encode(), hashlib.sha256).hexdigest()


# ── Playbooks ─────────────────────────────────────────────────────────────────

PLAYBOOKS = {
    'github_pat': {
        'provider': 'GitHub', 'env': 'GITHUB_TOKEN',
        'revoke_url': 'https://github.com/settings/tokens',
        'steps': [
            gettext_lazy('Open GitHub → Settings → Developer settings → Personal access tokens (classic and fine-grained) and delete this token. An OAuth or App token (gho_/ghu_/ghs_) is revoked from the app that issued it.'),
            gettext_lazy('Create a replacement with only the scopes and repositories the job needs, and a short expiry.'),
            gettext_lazy('Store it as a repository or organisation secret (Actions → Secrets) or in your secret manager, never in the code.'),
            gettext_lazy('Check the security log (Settings → Security log) for use you do not recognise since the commit that added it.'),
        ],
    },
    'gitlab_pat': {
        'provider': 'GitLab', 'env': 'GITLAB_TOKEN',
        'revoke_url': 'https://gitlab.com/-/user_settings/personal_access_tokens',
        'steps': [
            gettext_lazy('Open GitLab → User settings → Access tokens (or the project/group Access tokens page) and revoke this token.'),
            gettext_lazy('Create a replacement with the narrowest scope and an expiry date.'),
            gettext_lazy('Store it as a masked, protected CI/CD variable (Settings → CI/CD → Variables), never in the code.'),
            gettext_lazy('Review the audit events for the account or project since the commit that added it.'),
        ],
    },
    'aws_access_key': {
        'provider': 'AWS', 'env': 'AWS_ACCESS_KEY_ID',
        'revoke_url': 'https://console.aws.amazon.com/iam/home#/security_credentials',
        'steps': [
            gettext_lazy('In IAM, find the user that owns this access key, create a new key, then deactivate and delete the old one.'),
            gettext_lazy('Prefer no long-lived key at all: an IAM role, or OIDC federation for CI (GitHub/GitLab → AWS).'),
            gettext_lazy('Search CloudTrail for the old key ID since the commit that added it; look for unfamiliar regions and IAM, EC2 or S3 activity.'),
            gettext_lazy('Put the new credentials in a secret manager or CI secret, never in the code.'),
        ],
    },
    'slack_token': {
        'provider': 'Slack', 'env': 'SLACK_TOKEN',
        'revoke_url': 'https://api.slack.com/apps',
        'steps': [
            gettext_lazy('In api.slack.com/apps open the app → OAuth & Permissions and rotate (or revoke) the token; for a webhook, delete it and create a new one.'),
            gettext_lazy('Review the workspace access logs for unfamiliar use.'),
            gettext_lazy('Store the new token in a secret manager or CI secret.'),
        ],
    },
    'stripe_key': {
        'provider': 'Stripe', 'env': 'STRIPE_SECRET_KEY',
        'revoke_url': 'https://dashboard.stripe.com/apikeys',
        'steps': [
            gettext_lazy('Dashboard → Developers → API keys → "Roll key" on this secret or restricted key; set the old one to expire now.'),
            gettext_lazy('Check Developers → Logs and recent payouts, refunds and customers for anything you did not do.'),
            gettext_lazy('Prefer a restricted key with only the permissions the service uses.'),
        ],
    },
    'openai_key': {
        'provider': 'OpenAI', 'env': 'OPENAI_API_KEY',
        'revoke_url': 'https://platform.openai.com/api-keys',
        'steps': [
            gettext_lazy('Delete this key at platform.openai.com/api-keys and create a new one scoped to the project.'),
            gettext_lazy('Check Usage for spend you do not recognise, and set a monthly budget limit.'),
        ],
    },
    'anthropic_key': {
        'provider': 'Anthropic', 'env': 'ANTHROPIC_API_KEY',
        'revoke_url': 'https://console.anthropic.com/settings/keys',
        'steps': [
            gettext_lazy('Disable and delete this key in the Anthropic Console → API keys, and create a new one.'),
            gettext_lazy('Check Usage for spend you do not recognise, and set a spend limit on the workspace.'),
        ],
    },
    'telegram_bot_token': {
        'provider': 'Telegram', 'env': 'TELEGRAM_BOT_TOKEN',
        'revoke_url': 'https://t.me/BotFather',
        'steps': [
            gettext_lazy('In @BotFather send /revoke, choose the bot, and take the new token it gives you.'),
            gettext_lazy('Anyone with the old token could read the bot\'s messages and act as the bot — check the bot\'s chats and webhook (getWebhookInfo) for changes.'),
        ],
    },
    'google_api_key': {
        'provider': 'Google Cloud', 'env': 'GOOGLE_API_KEY',
        'revoke_url': 'https://console.cloud.google.com/apis/credentials',
        'steps': [
            gettext_lazy('APIs & Services → Credentials: regenerate or delete this key.'),
            gettext_lazy('Restrict the new key to the APIs and the HTTP referrers / IPs that use it.'),
        ],
    },
    'sendgrid_key': {
        'provider': 'SendGrid', 'env': 'SENDGRID_API_KEY',
        'revoke_url': 'https://app.sendgrid.com/settings/api_keys',
        'steps': [
            gettext_lazy('Settings → API Keys: delete this key and create one with only "Mail Send".'),
            gettext_lazy('Check Activity for mail you did not send — a leaked mail key is a phishing tool.'),
        ],
    },
    'npm_token': {
        'provider': 'npm', 'env': 'NPM_TOKEN',
        'revoke_url': 'https://www.npmjs.com/settings/~/tokens',
        'steps': [
            gettext_lazy('npmjs.com → Access Tokens: delete this token; create a granular one limited to the packages it publishes.'),
            gettext_lazy('Check your packages\' recent versions for releases you did not publish.'),
        ],
    },
}
GENERIC_PLAYBOOK = {
    'provider': '', 'env': 'SECRET_VALUE', 'revoke_url': '',
    'steps': [
        gettext_lazy('Revoke or change this credential where it was issued — treat it as known to anyone who could read the repository.'),
        gettext_lazy('Check that system\'s logs for access you do not recognise since the commit that added it.'),
        gettext_lazy('Store the new value in a secret manager or CI secret, never in the code.'),
    ],
}
ENV_NAMES = {'aws_secret_key': 'AWS_SECRET_ACCESS_KEY', 'db_url': 'DATABASE_URL',
             'twilio_sid': 'TWILIO_ACCOUNT_SID', 'jwt': 'JWT_TOKEN'}

HISTORY_CLEANUP = """# Rotate the key first. Then, if you also want it out of the history:
pip install git-filter-repo
git clone --mirror <repository-url> repo.git && cd repo.git
echo 'PASTE-THE-OLD-KEY-HERE==>REMOVED' > ../replacements.txt
git filter-repo --replace-text ../replacements.txt
git push --force --mirror
# Everyone re-clones afterwards. Forks, open pull requests and caches keep the
# old commits — which is why rotation, not this, is what protects you."""


def playbook(rule: str) -> dict:
    return PLAYBOOKS.get(rule) or {**GENERIC_PLAYBOOK, 'env': ENV_NAMES.get(rule, 'SECRET_VALUE')}


# ── Keeping incidents in step with audits ─────────────────────────────────────

def sync(audit, findings) -> None:
    """
    Update incidents from one audit's secret findings (with `liveness` set).

    A live key opens an incident (or refreshes one); a key the provider now
    rejects closes its open incident as rotated — confirmed.
    """
    from app.models import SecretIncident

    now = timezone.now()
    repo = audit.repo_display
    seen = set()
    for f in findings:
        fp = fingerprint(f['rule'], f['value'])
        if fp in seen:
            continue
        seen.add(fp)
        status = f.get('liveness', 'unknown')
        incident = SecretIncident.objects.filter(user=audit.user, repo_full_name=repo,
                                                 fingerprint=fp).first()
        if incident is None:
            if status != 'active':
                continue
            incident = SecretIncident(user=audit.user, first_audit=audit, source=audit.source,
                                      repo_full_name=repo, fingerprint=fp, rule=f['rule'],
                                      label=f['label'][:80])
            logger.warning('Secret incident opened: %s %s in %s', f['label'], f['file'], repo)
        elif status == 'active' and incident.status != SecretIncident.STATUS_OPEN:
            # Marked rotated by hand, but the provider still accepts it.
            incident.status = SecretIncident.STATUS_OPEN
            incident.resolved_at = None
        incident.last_audit = audit
        incident.file = f['file'][:500]
        incident.line = f.get('line') if f.get('in_head') else None
        incident.in_head = bool(f.get('in_head'))
        if f.get('commit'):
            incident.commit, incident.commit_date = f['commit'][:40], f.get('date', '')[:20]
        incident.last_seen_at = now
        if status != 'unknown':
            incident.liveness = status
            incident.last_checked_at = now
        if status == 'inactive' and incident.status != SecretIncident.STATUS_ROTATED:
            incident.status = SecretIncident.STATUS_ROTATED
            incident.resolved_at = now
            logger.info('Secret incident confirmed rotated: %s', incident)
        incident.save()


# ── The env-var pull request ──────────────────────────────────────────────────

_ASSIGNED = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)["\']?\s*[:=]')


def env_var_name(line_text: str, value_start: int, rule: str) -> str:
    """The variable name the code already uses for it (`API_KEY = "..."`), else the provider's usual one."""
    names = _ASSIGNED.findall(line_text[:value_start])
    if names:
        name = re.sub(r'[^A-Za-z0-9_]', '_', names[-1]).upper()
        if len(name) >= 3:
            return name
    return playbook(rule)['env']


def _kind(path: str, host: str) -> str:
    name = path.rsplit('/', 1)[-1]
    if path.endswith('.py'):
        return 'python'
    if path.endswith(('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs')):
        return 'js'
    if path.startswith('.github/workflows/') and path.endswith(('.yml', '.yaml')):
        return 'gha'
    if name == '.gitlab-ci.yml':
        return 'gitlab_ci'
    if re.match(r'(?:docker-)?compose[\w.-]*\.ya?ml$', name):
        return 'compose'
    return ''


def can_rewrite(incident) -> bool:
    return bool(incident.in_head and incident.line and _kind(incident.file, incident.source))


def _reference(kind: str, var: str) -> str:
    return {'python': f'os.environ["{var}"]', 'js': f'process.env.{var}',
            'gha': f'${{{{ secrets.{var} }}}}', 'gitlab_ci': f'${var}', 'compose': f'${{{var}}}'}[kind]


def rewrite(text: str, incident):
    """
    (new text, env var name) with the incident's literal replaced by an
    environment reference, or None when that cannot be done safely.

    The literal is re-found on (or within five lines of) the recorded line by
    the incident's own rule, and only a match whose fingerprint equals the
    incident's is touched.
    """
    from app.checks_secrets import RULES

    kind = _kind(incident.file, incident.source)
    rule = next((r for r in RULES if r.rule_id == incident.rule), None)
    if not kind or rule is None or not incident.line:
        return None
    lines = text.split('\n')
    for idx in sorted(range(max(0, incident.line - 6), min(len(lines), incident.line + 5)),
                      key=lambda i: abs(i - (incident.line - 1))):
        line = lines[idx]
        for m in rule.pattern.finditer(line):
            value = m.group(rule.group) if rule.group else m.group(0)
            if fingerprint(incident.rule, value) != incident.fingerprint:
                continue
            start = m.start(rule.group) if rule.group else m.start()
            var = env_var_name(line, start, incident.rule)
            ref = _reference(kind, var)
            for quote in ('"', "'"):
                quoted = f'{quote}{value}{quote}'
                if quoted in line:
                    lines[idx] = line.replace(quoted, ref, 1)
                    break
            else:
                if kind in ('python', 'js'):
                    return None   # inside a larger string: not a safe mechanical edit
                lines[idx] = line.replace(value, ref, 1)
            new = '\n'.join(lines)
            if kind == 'python' and not re.search(r'^\s*(?:import os\b|from os import|import os,)', new, re.M):
                new = _add_import_os(new)
            return new, var
    return None


def _add_import_os(text: str) -> str:
    lines = text.split('\n')
    at = 0
    while at < len(lines) and (lines[at].startswith('#!') or lines[at].startswith('# -*-')
                               or lines[at].startswith('from __future__')):
        at += 1
    lines.insert(at, 'import os')
    return '\n'.join(lines)


def env_example(existing: str | None, var: str) -> str | None:
    """.env.example with `var=` listed, or None if it already is."""
    if existing and re.search(rf'^\s*{re.escape(var)}\s*=', existing, re.M):
        return None
    head = existing if existing is not None else '# Copy to .env and fill in. Never commit .env.\n'
    if head and not head.endswith('\n'):
        head += '\n'
    return f'{head}{var}=\n'


def pr_body(incident, var: str, kind: str) -> str:
    pb = playbook(incident.rule)
    where = {'gha': f'Add `{var}` under Settings → Secrets and variables → Actions.',
             'gitlab_ci': f'Add `{var}` as a masked, protected variable under Settings → CI/CD → Variables.',
             'compose': f'Set `{var}` in the environment or an untracked `.env` next to the compose file.'}.get(
        kind, f'Set `{var}` in the environment where this runs (see `.env.example`).')
    lines = [
        f'Moves the {incident.label} out of `{incident.file}` and reads it from `{var}` instead.',
        '',
        '> **Merging this does not make the leaked key safe.** It is in the git history and in every '
        'clone. Revoke it first' + (f' ({pb["revoke_url"]})' if pb['revoke_url'] else '') + ', then put '
        'the new value where this change reads it from.',
        '',
        f'**Before merging:** {where}',
        '',
        'Opened by DevOpsCheck from a secret incident. The key was never stored by us — only a '
        'fingerprint to recognise it on the next audit, which is also how rotation gets confirmed.',
    ]
    return '\n'.join(lines)


class CannotRewrite(Exception):
    """The literal could not be moved to an environment variable mechanically."""


def open_env_pr(incident, user) -> str:
    """
    Open a PR (GitHub) or MR (GitLab) that replaces the literal with an
    environment reference and lists the variable in `.env.example`.
    Returns its URL. Raises CannotRewrite, or the writer's own error.
    """
    kind = _kind(incident.file, incident.source)
    title = f'security: read the {incident.label} from the environment'
    if incident.source == 'gitlab':
        from app.gitlab_writer import _Project
        profile = user.gitlab_profile
        project_id = int(incident.first_audit.repo_full_name.split('::')[1])
        repo = _Project(profile.current_token, project_id, profile.gitlab_url,
                        profile.verify_ssl, profile.custom_dns)
        repo.require_push_access()
        repo.require_write_scope()

        def read(path):
            return repo.read_file(path, repo.default_branch), None
    else:
        from app.github_writer import _Repo
        repo = _Repo(user.github_profiles.first().current_token, incident.repo_full_name)
        repo.require_push_access()

        def read(path):
            return repo.read_file(path)

    text, sha = read(incident.file)
    result = rewrite(text or '', incident)
    if result is None:
        raise CannotRewrite(str(gettext_lazy('The key is no longer where it was found, or sits inside a larger '
                                   'string — move it to an environment variable by hand.')))
    new_text, var = result
    changes = [(incident.file, new_text, sha)]
    if kind in ('python', 'js', 'compose'):
        example, example_sha = read('.env.example')
        updated = env_example(example, var)
        if updated is not None:
            changes.append(('.env.example', updated, example_sha))

    branch = repo.branch_from_default(f'env-{var.lower()}')
    for path, content, blob in changes:
        message = f'security: read {var} from the environment\n\nOpened by DevOpsCheck.'
        if incident.source == 'gitlab':
            repo.commit_file(branch, path, content, message)
        else:
            repo.commit_file(branch, path, content, message, sha=blob)
    body = pr_body(incident, var, kind)
    if incident.source == 'gitlab':
        url = repo.open_merge_request(branch, title, body)
    else:
        url = repo.open_pull_request(branch, title, body)
    incident.fix_pr_url = url or ''
    incident.save(update_fields=['fix_pr_url'])
    return url
