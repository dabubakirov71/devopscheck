"""
Is a leaked credential still live?

A key that was revoked last year and a key that opens production today are
both "a secret in git", and a report that cannot tell them apart makes the
reader do the triage. This module asks the provider, with one read-only call
that identifies the caller and changes nothing:

    AWS        sts:GetCallerIdentity (needs the key ID and the secret together)
    GitHub     GET /user
    GitLab     GET /api/v4/user
    Slack      auth.test
    Stripe     GET /v1/balance
    OpenAI     GET /v1/models
    Anthropic  GET /v1/models
    Telegram   getMe

Result: `active` (the provider accepted it), `inactive` (the provider
rejected it as invalid or revoked) or `unknown` (no checker for this kind of
credential, or the provider did not give a clear answer).

Runs only for repositories their owner connected — never for the public
scanner, where the repository and whatever is in it belong to someone who
did not ask. The credential is sent only to the provider that issued it,
over HTTPS, and is never logged or stored; only the status is kept.
"""
import datetime
import hashlib
import hmac
import logging
from concurrent.futures import ThreadPoolExecutor

import requests

logger = logging.getLogger(__name__)

ACTIVE, INACTIVE, UNKNOWN = 'active', 'inactive', 'unknown'
TIMEOUT = 6
MAX_CHECKS = 12
USER_AGENT = 'devopscheck-secret-liveness/1.0 (+https://devopscheck.com/trust/)'


def _status_by_code(resp, active=(200,), inactive=(401,)):
    if resp is None:
        return UNKNOWN
    if resp.status_code in active:
        return ACTIVE
    if resp.status_code in inactive:
        return INACTIVE
    return UNKNOWN


def _get(url, **kw):
    headers = {'User-Agent': USER_AGENT, **kw.pop('headers', {})}
    try:
        return requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=False, **kw)
    except requests.RequestException:
        return None


def _post(url, **kw):
    headers = {'User-Agent': USER_AGENT, **kw.pop('headers', {})}
    try:
        return requests.post(url, headers=headers, timeout=TIMEOUT, allow_redirects=False, **kw)
    except requests.RequestException:
        return None


def check_github(token, **_ctx):
    resp = _get('https://api.github.com/user',
                headers={'Authorization': f'token {token}', 'Accept': 'application/vnd.github+json'})
    return _status_by_code(resp)


def check_gitlab(token, gitlab_url='https://gitlab.com', verify_ssl=True, **_ctx):
    # A glpat- token does not say which instance issued it. The instance the
    # audited project lives on is the best guess, and gitlab.com otherwise.
    resp = _get(f'{gitlab_url.rstrip("/")}/api/v4/user',
                headers={'PRIVATE-TOKEN': token}, verify=verify_ssl)
    return _status_by_code(resp)


def check_slack(token, **_ctx):
    resp = _post('https://slack.com/api/auth.test', headers={'Authorization': f'Bearer {token}'})
    if resp is None or resp.status_code != 200:
        return UNKNOWN
    try:
        data = resp.json()
    except ValueError:
        return UNKNOWN
    if data.get('ok'):
        return ACTIVE
    if data.get('error') in ('invalid_auth', 'token_revoked', 'account_inactive',
                             'not_authed', 'token_expired', 'org_login_required'):
        return INACTIVE
    return UNKNOWN


def check_stripe(key, **_ctx):
    # A restricted key without balance access answers 403 — it is still live.
    resp = _get('https://api.stripe.com/v1/balance', auth=(key, ''))
    return _status_by_code(resp, active=(200, 403))


def check_openai(key, **_ctx):
    # 429 is "out of quota" or "slow down": the key itself was accepted.
    resp = _get('https://api.openai.com/v1/models', headers={'Authorization': f'Bearer {key}'})
    return _status_by_code(resp, active=(200, 429))


def check_anthropic(key, **_ctx):
    resp = _get('https://api.anthropic.com/v1/models',
                headers={'x-api-key': key, 'anthropic-version': '2023-06-01'})
    return _status_by_code(resp, active=(200, 429))


def check_telegram(token, **_ctx):
    resp = _get(f'https://api.telegram.org/bot{token}/getMe')
    return _status_by_code(resp, inactive=(401, 404))


def check_aws(access_key_id, secret_key=None, **_ctx):
    """sts:GetCallerIdentity, signed with SigV4. Needs no IAM permission at all."""
    if not secret_key:
        return UNKNOWN
    host, region, service = 'sts.amazonaws.com', 'us-east-1', 'sts'
    body = 'Action=GetCallerIdentity&Version=2011-06-15'
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    day = now.strftime('%Y%m%d')
    content_type = 'application/x-www-form-urlencoded; charset=utf-8'
    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canonical = '\n'.join([
        'POST', '/', '',
        f'content-type:{content_type}', f'host:{host}', f'x-amz-date:{amz_date}', '',
        'content-type;host;x-amz-date', payload_hash,
    ])
    scope = f'{day}/{region}/{service}/aws4_request'
    to_sign = '\n'.join(['AWS4-HMAC-SHA256', amz_date, scope,
                         hashlib.sha256(canonical.encode()).hexdigest()])

    def _hmac(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k = _hmac(('AWS4' + secret_key).encode(), day)
    for part in (region, service, 'aws4_request'):
        k = _hmac(k, part)
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    resp = _post(f'https://{host}/', data=body, headers={
        'Content-Type': content_type,
        'X-Amz-Date': amz_date,
        'Authorization': (f'AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, '
                          'SignedHeaders=content-type;host;x-amz-date, '
                          f'Signature={signature}'),
    })
    # STS answers 403 for both an unknown key ID and a bad signature.
    return _status_by_code(resp, inactive=(403,))


CHECKERS = {
    'github_pat': check_github,
    'gitlab_pat': check_gitlab,
    'slack_token': check_slack,
    'stripe_key': check_stripe,
    'openai_key': check_openai,
    'anthropic_key': check_anthropic,
    'telegram_bot_token': check_telegram,
    'aws_access_key': check_aws,
}


def _gitlab_context(client):
    if getattr(client, 'provider', '') == 'gitlab':
        return {'gitlab_url': client.gitlab_url, 'verify_ssl': client.verify_ssl}
    return {}


def verify_findings(findings, client=None) -> None:
    """
    Set `liveness` on every finding, in place.

    An AWS key ID is checked together with a secret key found in the same
    file; alone it cannot be checked and stays `unknown`. The same value found
    twice is asked about once. At most MAX_CHECKS provider calls are made per
    audit; anything past that stays `unknown`.
    """
    ctx = _gitlab_context(client)
    secrets_by_file = {}
    for f in findings:
        f['liveness'] = UNKNOWN
        if f['rule'] == 'aws_secret_key':
            secrets_by_file.setdefault(f['file'], f['value'])

    jobs = {}
    for f in findings:
        rule = f['rule']
        if rule not in CHECKERS:
            continue
        if rule == 'aws_access_key':
            secret = secrets_by_file.get(f['file'])
            if not secret:
                continue
            key = (rule, f['value'], secret)
        else:
            key = (rule, f['value'], None)
        jobs.setdefault(key, []).append(f)

    keys = list(jobs)[:MAX_CHECKS]

    def _run(key):
        rule, value, extra = key
        try:
            if rule == 'aws_access_key':
                return CHECKERS[rule](value, secret_key=extra)
            return CHECKERS[rule](value, **ctx)
        except Exception:
            logger.warning('Liveness check crashed for rule %s', rule, exc_info=True)
            return UNKNOWN

    if not keys:
        return
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = dict(zip(keys, pool.map(_run, keys)))
    for key, status in results.items():
        for f in jobs[key]:
            f['liveness'] = status
        # The secret half of an AWS pair is exactly as live as its key ID.
        if key[0] == 'aws_access_key':
            for f in findings:
                if f['rule'] == 'aws_secret_key' and f['value'] == key[2]:
                    f['liveness'] = status
    logger.info('Liveness: %d checked, %d active',
                len(results), sum(1 for s in results.values() if s == ACTIVE))
