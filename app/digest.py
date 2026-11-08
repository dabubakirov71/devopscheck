"""
The weekly digest for a CTO (roadmap phase 7).

One email a week for Team-plan accounts: what got worse, the three things to
do this week, fix pull requests that are green and waiting for a merge, open
secret incidents, and — on the Compliance plan — SOC 2 control coverage.

Everything in it is computed from stored audits (`build()`); a model only
writes the two-sentence opening from those numbers, and a plain template
writes it when no model may or can (`summary()`). The numbers never come
from the model.
"""
import logging
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext as _

from app.funnel import tagged  # noqa: E402

logger = logging.getLogger(__name__)

WINDOW = timedelta(days=7)


def _baseline(audit, since):
    from app.models import Audit
    return (Audit.objects.filter(user=audit.user, source=audit.source, repo_full_name=audit.repo_full_name,
                                 status=Audit.STATUS_DONE, score__isnull=False, created_at__lt=since)
            .order_by('-created_at').first())


def build(user, now=None) -> dict:
    from app.compliance import build_report
    from app.models import Audit, FixAttempt, SecretIncident, UserSubscription

    now = now or timezone.now()
    since = now - WINDOW
    sub, _c = UserSubscription.objects.get_or_create(user=user)
    base_url = getattr(settings, 'BASE_URL', '')

    repos = []
    for audit in Audit.objects.filter(user=user, status=Audit.STATUS_DONE,
                                      score__isnull=False).latest_per_repo():
        before = _baseline(audit, since)
        new = []
        if before is not None:
            appeared = audit._failed_ids() - before._failed_ids()
            new = list(audit.checks.counted().filter(check_id__in=appeared)
                       .order_by('severity_rank').values_list('name', flat=True)[:3])
        coverage = None
        if sub.is_compliance:
            coverage = build_report(list(audit.checks.all()), 'soc2')['coverage_pct']
        repos.append({
            'name': audit.repo_display, 'score': audit.score, 'audit': audit,
            'before': before.score if before else None,
            'delta': audit.score - before.score if before else None,
            'new_findings': new, 'coverage': coverage,
            'private': audit.repo_is_private,
            'url': tagged(f'{base_url}/audit/{audit.id}/', 'digest', 'email'),
        })

    worsened = sorted([r for r in repos if (r['delta'] or 0) < 0 or r['new_findings']],
                      key=lambda r: (r['delta'] or 0))

    incidents = list(SecretIncident.objects.filter(user=user, status=SecretIncident.STATUS_OPEN))

    # Three actions: a live key beats everything; then the worst failing
    # checks, critical first, in the weakest repositories first.
    actions = []
    for inc in incidents:
        actions.append({'repo': inc.repo_full_name, 'kind': 'incident',
                        'text': _('Rotate the %(label)s found in %(file)s — it still works.')
                        % {'label': inc.label, 'file': inc.file},
                        'url': f'{base_url}/audit/{inc.last_audit_id or inc.first_audit_id}/#section-incidents'})
    candidates = []
    for r in repos:
        for check in r['audit'].checks.counted().filter(passed=False).order_by('severity_rank')[:5]:
            candidates.append((check.severity_rank, r['score'], r['name'], check.name, r['url']))
    for _rank, _score, repo, name, url in sorted(candidates):
        actions.append({'repo': repo, 'kind': 'check', 'text': name, 'url': url})
    top_actions = actions[:3]

    ready = [{'repo': a.repo_full_name, 'title': a.check_name, 'url': a.pr_url}
             for a in FixAttempt.objects.filter(user=user, state=FixAttempt.STATE_GREEN, merged__isnull=True)]
    ready += [{'repo': i.repo_full_name, 'title': _('Read the %(label)s from the environment') % {'label': i.label},
               'url': i.fix_pr_url} for i in incidents if i.fix_pr_url]

    scores = [r['score'] for r in repos]
    befores = [r['before'] for r in repos if r['before'] is not None]
    coverages = [r['coverage'] for r in repos if r['coverage'] is not None]
    return {
        'user': user,
        'since': since, 'now': now,
        'repos': repos,
        'repo_count': len(repos),
        'avg_score': round(sum(scores) / len(scores)) if scores else None,
        'avg_before': round(sum(befores) / len(befores)) if befores else None,
        'worsened': worsened[:5],
        'top_actions': top_actions,
        'ready_prs': ready[:5],
        'incidents': incidents,
        'compliance_pct': round(sum(coverages) / len(coverages)) if coverages else None,
        'is_compliance': sub.is_compliance,
        'any_private': any(r['private'] for r in repos),
        'dashboard_url': tagged(f'{base_url}/organization/', 'digest', 'email'),
    }


def _template_summary(d) -> str:
    parts = []
    if d['avg_score'] is not None:
        if d['avg_before'] is not None and d['avg_before'] != d['avg_score']:
            parts.append(_('Average score across %(n)d repositories: %(before)d → %(now)d.')
                         % {'n': d['repo_count'], 'before': d['avg_before'], 'now': d['avg_score']})
        else:
            parts.append(_('Average score across %(n)d repositories: %(now)d.')
                         % {'n': d['repo_count'], 'now': d['avg_score']})
    if d['incidents']:
        parts.append(_('%(n)d leaked key(s) still work and need rotating first.') % {'n': len(d['incidents'])})
    elif d['worsened']:
        parts.append(_('%(n)d repositories got worse this week.') % {'n': len(d['worsened'])})
    else:
        parts.append(_('Nothing got worse this week.'))
    return ' '.join(parts)


def summary(d, language='en') -> str:
    """Two sentences for a CTO, from the numbers in `d` — a model if one may, else the template."""
    from app.ai_providers import _call_provider, _get_active_provider

    provider, key = _get_active_provider(d['user'].id, is_private=d['any_private'])
    if not provider or not key:
        return _template_summary(d)
    facts = [
        f"repositories: {d['repo_count']}; average score now {d['avg_score']}, a week ago {d['avg_before']}",
        f"open leaked-and-still-working keys: {len(d['incidents'])}",
        'got worse: ' + ('; '.join(f"{r['name']} {r['before']}→{r['score']}"
                                   + (f" new: {', '.join(r['new_findings'])}" if r['new_findings'] else '')
                                   for r in d['worsened']) or 'none'),
        'top actions: ' + '; '.join(f"{a['repo']}: {a['text']}" for a in d['top_actions']),
        f"fix pull requests green and waiting for merge: {len(d['ready_prs'])}",
    ]
    if d['compliance_pct'] is not None:
        facts.append(f"SOC 2 control coverage: {d['compliance_pct']}%")
    lang = 'Russian' if language == 'ru' else 'English'
    prompt = (
        f"Write two sentences in {lang} for a CTO's weekly engineering-risk email. Business language: "
        "risk, exposure, what needs a decision — no tool names, no jargon, no lists, no greeting. Use only "
        "these facts and do not add numbers that are not here:\n- " + '\n- '.join(facts)
    )
    try:
        text = (_call_provider(provider, key, prompt, max_tokens=400) or '').strip()
    except Exception as exc:
        logger.warning('Digest summary model call failed: %s', exc)
        text = ''
    return text or _template_summary(d)


def render(user, digest_settings, now=None, use_model=True) -> tuple[str, str, dict]:
    """(subject, html, data) for this user's digest, in the digest's language."""
    from django.template.loader import render_to_string
    from django.utils import translation

    lang = digest_settings.language if digest_settings.language in ('en', 'ru') else 'en'
    prev = translation.get_language()
    translation.activate(lang)
    try:
        d = build(user, now)
        # The preview page renders on every visit; it does not spend a model call.
        d['summary'] = summary(d, lang) if use_model else _template_summary(d)
        base_url = getattr(settings, 'BASE_URL', '')
        d['unsubscribe_url'] = f'{base_url}/digest/stop/{digest_settings.unsubscribe_token}/'
        d['settings_url'] = f'{base_url}/digest/'
        html = render_to_string('app/email/weekly_digest.html', d)
        subject = _('[DevOpsCheck] Weekly: %(n)d repositories, %(inc)d open incident(s)') % {
            'n': d['repo_count'], 'inc': len(d['incidents'])}
        return subject, html, d
    finally:
        translation.activate(prev) if prev else translation.deactivate()


def send(user, digest_settings, now=None, test=False) -> bool:
    from django.core.mail import EmailMultiAlternatives

    recipients = digest_settings.recipient_list()
    if not recipients:
        return False
    subject, html, d = render(user, digest_settings, now)
    if not d['repo_count']:
        return False
    msg = EmailMultiAlternatives(
        subject=subject, body=d['summary'] + '\n\n' + d['dashboard_url'],
        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@devopscheck.com'), to=recipients,
        headers={'List-Unsubscribe': f"<{d['unsubscribe_url']}>",
                 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click'},
    )
    msg.attach_alternative(html, 'text/html')
    msg.send()
    if test:
        return True
    digest_settings.last_sent_at = now or timezone.now()
    digest_settings.save(update_fields=['last_sent_at'])
    return True
