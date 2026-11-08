import logging

from celery import shared_task
from django.conf import settings
from django.utils import timezone, translation
from app.checks import counts as _counts  # noqa: E402

from app.funnel import tagged  # noqa: E402

logger = logging.getLogger(__name__)


def _audit_language(audit) -> str:
    return audit.language if audit.language in ('en', 'ru') else 'en'


def _apply_checks(audit, checks_data):
    """Replace the audit's check rows with a fresh run and recompute the scores."""
    from app.models import AuditCheck
    from app.checks import SCORE_VERSION, calculate_score, get_category_scores

    AuditCheck.objects.filter(audit=audit).delete()
    AuditCheck.objects.bulk_create([
        AuditCheck(
            audit=audit,
            check_id=c.get('check_id', ''),
            name=c['name'],
            description=c['description'],
            severity=c['severity'],
            passed=c['passed'],
            recommendation=c.get('recommendation', ''),
            category=c.get('category', 'ops'),
            severity_rank=AuditCheck.SEVERITY_RANK.get(c['severity'], 3),
            applicable=c.get('applicable', True),
            not_applicable_reason=c.get('not_applicable_reason', '')[:300],
            status=c.get('status', ''),
            evidence=c.get('evidence', '')[:500],
        )
        for c in checks_data
    ])
    audit.score = calculate_score(checks_data)
    audit.category_scores = get_category_scores(checks_data)
    audit.score_version = SCORE_VERSION
    return audit.score


def _ai_allowance(audit):
    """
    Whether this audit gets AI analysis, and whether using it consumes a free credit.

    Paid plans always get it. Free users get a set number of full AI reports per
    calendar month — seeing the feature is what sells it.
    """
    from app.models import MonthlyUsage, UserSubscription

    sub, _created = UserSubscription.objects.get_or_create(user=audit.user)
    if sub.is_pro:
        return True, False
    usage = MonthlyUsage.for_user(audit.user)
    if usage.ai_reports < settings.FREE_AI_REPORTS_PER_MONTH:
        return True, True
    return False, False


def _run_ai(audit, checks_data, client, consume_free_credit=False):
    """Generate the AI summary and per-check suggestions. Returns (summary, provider)."""
    from app.models import AuditCheck, MonthlyUsage
    from app.ai_providers import get_ai_summary, get_ai_code_suggestions
    from app.repo_context import with_host

    language = _audit_language(audit)
    user_id = audit.user_id
    repo_display = audit.repo_display

    logger.info('AI analysis starting: audit_id=%s', audit.id)

    # The file review first: its findings feed the "fix first" list below.
    # Only against the commit this audit graded — a re-run of the AI step on
    # an old audit must not attach findings from today's code to it.
    if client is not None and (not audit.commit_sha
                               or (client.head_sha or '')[:40] == audit.commit_sha):
        from app.ai_review import review
        findings, _provider = review(client, checks_data, language, user_id=user_id,
                                     is_private=audit.repo_is_private)
        audit.ai_findings = findings
        audit.save(update_fields=['ai_findings'])

    ai_summary, ai_provider = get_ai_summary(
        repo_display, checks_data, audit.score or 0, language,
        user_id=user_id, repo_context=with_host(audit.repo_context, audit.source),
        is_private=audit.repo_is_private, ai_findings=audit.ai_findings,
    )

    # Only findings the repository can actually act on get a code suggestion.
    failed = [c for c in checks_data if not c['passed'] and _counts(c)]
    if failed and client is not None:
        suggestions = get_ai_code_suggestions(failed, client.get_content, language, user_id=user_id,
                                              is_private=audit.repo_is_private, host=audit.source)
        if suggestions:
            for check_obj in AuditCheck.objects.filter(audit=audit, passed=False):
                suggestion = suggestions.get(check_obj.name, '')
                if suggestion:
                    check_obj.ai_suggestion = suggestion
                    check_obj.save(update_fields=['ai_suggestion'])

    if consume_free_credit and ai_summary:
        MonthlyUsage.for_user(audit.user).consume('ai_reports')

    return ai_summary, ai_provider


@shared_task(bind=True)
def run_audit_task(self, audit_id: int):
    from app.models import Audit
    from app.checks import run_all_checks
    from app.repo_client import build_client_for_audit, RepoAccessError

    try:
        audit = Audit.objects.get(id=audit_id)
    except Audit.DoesNotExist:
        return

    logger.info('run_audit_task started: audit_id=%s repo=%s', audit_id, audit.repo_full_name)
    audit.status = Audit.STATUS_RUNNING
    audit.celery_task_id = self.request.id or ''
    audit.error_message = ''
    audit.save(update_fields=['status', 'celery_task_id', 'error_message'])

    prev_lang = translation.get_language()
    translation.activate(_audit_language(audit))
    try:
        client = build_client_for_audit(audit)
        if not audit.commit_sha and client.head_sha:
            audit.commit_sha = client.head_sha[:40]
        audit.repo_is_private = client.is_private

        from app import audit_config
        config = audit_config.load(client)
        checks_data = run_all_checks(client, config=config, deep=True)
        score = _apply_checks(audit, checks_data)

        # Phase 6: live keys become incidents; a key the provider now rejects
        # closes its incident. The findings carry the values — used here, in
        # memory, and dropped.
        found = getattr(client, 'secret_findings', None)
        client.secret_findings = None
        if found:
            try:
                from app.secret_incidents import sync
                sync(audit, found)
            except Exception:
                logger.error('secret incident sync failed: audit_id=%s', audit_id, exc_info=True)
        from app.repo_kind import detect as detect_repo_kind
        audit.repo_kind, _skipped, _reason, audit.kind_confidence = detect_repo_kind(
            client, forced_kind=config.kind)
        audit.fail_under = config.fail_under
        audit.config_errors = config.errors

        # Captured now so the SBOM export works later without repository access.
        from app.sbom import collect_components
        audit.sbom_components = collect_components(client.get_content)

        # And what the repository actually is, for the same reason: the AI step
        # runs next and the fix view runs much later, and neither should have to
        # read the repository again. Credentials are redacted before storing.
        from app.repo_context import build as build_repo_context
        try:
            audit.repo_context = build_repo_context(client)
        except Exception:
            logger.warning('repo_context failed: audit_id=%s', audit_id, exc_info=True)
            audit.repo_context = {}
        logger.info('run_audit_task checks complete: audit_id=%s count=%d score=%s api_calls=%d',
                    audit_id, len(checks_data), score, client.api_calls)

        ai_summary, ai_provider = '', ''
        allow_ai, consume = _ai_allowance(audit)
        if allow_ai:
            ai_summary, ai_provider = _run_ai(audit, checks_data, client, consume_free_credit=consume)

        audit.ai_summary = ai_summary
        audit.ai_provider = ai_provider
        audit.status = Audit.STATUS_DONE
        audit.completed_at = timezone.now()
        audit.save(update_fields=[
            'score', 'category_scores', 'ai_summary', 'ai_provider',
            'status', 'completed_at', 'commit_sha', 'sbom_components', 'repo_kind',
            'kind_confidence', 'fail_under', 'config_errors', 'repo_context', 'score_version',
            'repo_is_private',
        ])
        logger.info('run_audit_task completed: audit_id=%s score=%s', audit_id, score)

        if audit.trigger == Audit.TRIGGER_PR and audit.pr_number:
            post_pr_comment.delay(audit.id)
        else:
            _send_audit_email(audit)

    except RepoAccessError as exc:
        logger.warning('run_audit_task cannot read repo: audit_id=%s %s', audit_id, exc)
        audit.status = Audit.STATUS_FAILED
        audit.error_message = str(exc)
        audit.save(update_fields=['status', 'error_message'])
    except Exception as exc:
        logger.error('run_audit_task failed: audit_id=%s', audit_id, exc_info=True)
        audit.status = Audit.STATUS_FAILED
        audit.error_message = str(exc)[:500]
        audit.save(update_fields=['status', 'error_message'])
        raise exc
    finally:
        translation.activate(prev_lang) if prev_lang else translation.deactivate()


@shared_task(bind=True)
def regenerate_ai_task(self, audit_id: int):
    """Re-run AI analysis on existing check results without re-fetching the repository."""
    from app.models import Audit, AuditCheck, UserSubscription

    try:
        audit = Audit.objects.get(id=audit_id)
    except Audit.DoesNotExist:
        return

    logger.info('regenerate_ai_task started: audit_id=%s', audit_id)
    sub, _created = UserSubscription.objects.get_or_create(user=audit.user)
    if not sub.is_pro:
        audit.status = Audit.STATUS_DONE
        audit.save(update_fields=['status'])
        return

    audit.status = Audit.STATUS_RUNNING
    audit.celery_task_id = self.request.id or ''
    audit.save(update_fields=['status', 'celery_task_id'])

    prev_lang = translation.get_language()
    translation.activate(_audit_language(audit))
    try:
        checks_data = [
            {
                'check_id': c.check_id, 'name': c.name, 'description': c.description,
                'severity': c.severity, 'passed': c.passed,
                'recommendation': c.recommendation, 'category': c.category,
            }
            for c in AuditCheck.objects.filter(audit=audit)
        ]

        from app.repo_client import build_client_for_audit
        try:
            client = build_client_for_audit(audit)
        except Exception:
            client = None

        ai_summary, ai_provider = _run_ai(audit, checks_data, client)
        audit.ai_summary = ai_summary
        audit.ai_provider = ai_provider
        audit.status = Audit.STATUS_DONE
        audit.save(update_fields=['ai_summary', 'ai_provider', 'status'])
    except Exception:
        logger.error('regenerate_ai_task error: audit_id=%s', audit_id, exc_info=True)
        audit.status = Audit.STATUS_DONE  # the checks themselves are still valid
        audit.save(update_fields=['status'])
        raise
    finally:
        translation.activate(prev_lang) if prev_lang else translation.deactivate()


# ── Pull request feedback ─────────────────────────────────────────────────────

@shared_task
def post_pr_comment(audit_id: int):
    """
    Comment the audit result on the pull request that triggered it.

    This is what puts the product in the engineer's day: the score and what
    changed since the base branch show up where the work already happens.
    """
    import requests
    from app.models import Audit

    try:
        audit = Audit.objects.get(id=audit_id)
    except Audit.DoesNotExist:
        return
    if audit.source != Audit.SOURCE_GITHUB or not audit.pr_number:
        return

    profile = audit.user.github_profiles.first()
    if not profile:
        return

    previous = audit.previous_run()
    delta = audit.score_delta
    appeared, resolved = audit.changed_findings()
    crit = audit.checks.counted().filter(passed=False, severity='crit').count()
    warn = audit.checks.counted().filter(passed=False, severity='warn').count()

    if delta is None:
        trend = f'**{audit.score}/100**'
    elif delta > 0:
        trend = f'**{audit.score}/100** (▲ +{delta} from {previous.score})'
    elif delta < 0:
        trend = f'**{audit.score}/100** (▼ {delta} from {previous.score})'
    else:
        trend = f'**{audit.score}/100** (no change)'

    icon = {'crit': '🔴', 'warn': '🟡', 'info': '🔵'}

    # A reviewer is looking at one change, not at the repository. What this push
    # broke goes first; the standing total is context underneath it.
    if previous is None:
        headline = f'First audit of this repository. Score: {trend}'
    elif appeared:
        headline = f'**{len(appeared)} new** since the last run. Score: {trend}'
    elif resolved:
        headline = f'Nothing new, and **{len(resolved)} fixed**. Score: {trend}'
    else:
        headline = f'Nothing new. Score: {trend}'

    lines = ['### DevOpsCheck', '', headline]

    gate = audit.gate
    if gate is False:
        lines += ['', f'⛔ Below the `fail_under: {audit.fail_under}` set in `.devopsaudit.yml`.']
    elif gate is True:
        lines += ['', f'✅ Clears the `fail_under: {audit.fail_under}` set in `.devopsaudit.yml`.']

    if appeared:
        lines += ['', '**New in this run**', '', '| | Issue | Fix |', '|---|---|---|']
        for c in appeared[:5]:
            rec = (c.recommendation or '').split('\n')[0][:120]
            lines.append(f'| {icon.get(c.severity, "•")} | {c.name} | {rec} |')
        if len(appeared) > 5:
            lines.append(f'| | _and {len(appeared) - 5} more_ | |')

    standing = list(
        audit.checks.counted().filter(passed=False)
        .exclude(check_id__in=[c.check_id for c in appeared])
        .order_by('severity_rank')[:5]
    )
    if standing:
        label = 'Already open' if appeared else 'Open findings'
        lines += ['', f'<details><summary>{label} — {crit} critical, {warn} warnings</summary>', '',
                  '| | Issue | Fix |', '|---|---|---|']
        for c in standing:
            rec = (c.recommendation or '').split('\n')[0][:120]
            lines.append(f'| {icon.get(c.severity, "•")} | {c.name} | {rec} |')
        lines += ['', '</details>']
    elif not appeared:
        lines += ['', 'No issues found. ✅']

    if audit.config_errors:
        lines += ['', '<details><summary>⚠️ `.devopsaudit.yml` needs attention</summary>', '']
        lines += [f'- {e}' for e in audit.config_errors[:5]]
        lines += ['', '</details>']

    lines += [
        '',
        f'[Full report]({tagged(f"{settings.BASE_URL}/audit/{audit.id}/", "pr-comment", "github")})',
    ]
    body = '\n'.join(lines)

    url = f'https://api.github.com/repos/{audit.repo_display}/issues/{audit.pr_number}/comments'
    try:
        resp = requests.post(
            url,
            headers={
                'Authorization': f'token {profile.current_token}',
                'Accept': 'application/vnd.github.v3+json',
            },
            json={'body': body},
            timeout=15,
        )
        if resp.status_code >= 300:
            logger.warning('PR comment failed for audit %s: HTTP %s', audit_id, resp.status_code)
        else:
            logger.info('PR comment posted for audit %s on PR #%s', audit_id, audit.pr_number)
    except Exception:
        logger.error('PR comment request failed for audit %s', audit_id, exc_info=True)


# ── Public (no-account) scans ─────────────────────────────────────────────────

@shared_task
def run_public_scan_task(scan_id: int):
    """Audit a public repository for the no-signup demo at /scan/<owner>/<repo>/."""
    from app.models import Audit, PublicScan
    from app.checks import run_all_checks, calculate_score, get_category_scores
    from app.repo_client import GithubRepoClient, RepoAccessError

    try:
        scan = PublicScan.objects.get(id=scan_id)
    except PublicScan.DoesNotExist:
        return

    scan.status = Audit.STATUS_RUNNING
    scan.save(update_fields=['status'])

    prev_lang = translation.get_language()
    translation.activate('en')
    try:
        token = getattr(settings, 'PUBLIC_SCAN_GITHUB_TOKEN', '') or ''
        client = GithubRepoClient(scan.repo_full_name, token).load()
        if client.is_private:
            raise RepoAccessError('Repository is not public')

        checks_data = run_all_checks(client)
        scan.repo_url = client.repo_url
        scan.description = (client.description or '')[:500]
        scan.stars = client.stars
        scan.primary_language = client.primary_language or ''
        scan.score = calculate_score(checks_data)
        scan.category_scores = get_category_scores(checks_data)
        scan.results = checks_data
        from app.checks import SCORE_VERSION
        scan.score_version = SCORE_VERSION
        from app.repo_kind import detect as detect_repo_kind
        scan.repo_kind, _skipped, _reason, scan.kind_confidence = detect_repo_kind(client)
        scan.status = Audit.STATUS_DONE
        # A re-scan that succeeds has to drop the previous failure's message,
        # or the row keeps claiming an error it no longer has.
        scan.error_message = ''
        scan.save()
        logger.info('public scan done: %s score=%s', scan.repo_full_name, scan.score)
        from app import funnel
        funnel.record('scan_completed', ref=scan.repo_full_name)
    except RepoAccessError as exc:
        logger.info('public scan rejected %s: %s', scan.repo_full_name, exc)
        scan.status = Audit.STATUS_FAILED
        scan.error_message = str(exc)[:300]
        scan.save(update_fields=['status', 'error_message'])
    except Exception as exc:
        logger.error('public scan failed: %s', scan.repo_full_name, exc_info=True)
        scan.status = Audit.STATUS_FAILED
        scan.error_message = str(exc)[:300]
        scan.save(update_fields=['status', 'error_message'])
    finally:
        translation.activate(prev_lang) if prev_lang else translation.deactivate()


# ── Subscription lifecycle ────────────────────────────────────────────────────

@shared_task
def send_expiry_reminders(days_before: int = 3):
    """
    Warn people whose access is about to lapse.

    Crypto payments are one-off: without this, access simply stops and the
    customer never had a chance to renew.
    """
    from django.core.mail import send_mail
    from django.template.loader import render_to_string
    from app.models import UserSubscription

    now = timezone.now()
    horizon = now + timezone.timedelta(days=days_before)
    due = UserSubscription.objects.select_related('user').filter(
        plan__in=UserSubscription.PAID_PLANS,
        current_period_end__gt=now,
        current_period_end__lte=horizon,
        cancel_at_period_end=False,
    )

    sent = 0
    for sub in due:
        if sub.expiry_notified_at and sub.expiry_notified_at > now - timezone.timedelta(days=30):
            continue
        if not sub.user.email:
            continue
        try:
            html = render_to_string('app/email/subscription_expiring.html', {
                'user': sub.user,
                'subscription': sub,
                'days_left': sub.days_left,
                'billing_url': f'{settings.BASE_URL}/billing/',
                'base_url': settings.BASE_URL,
            })
            send_mail(
                subject=f'Your DevOpsCheck {sub.plan_label} access ends in {sub.days_left} days',
                message=(
                    f'Your {sub.plan_label} access ends on '
                    f'{sub.current_period_end:%d %b %Y}. Renew at {settings.BASE_URL}/billing/'
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[sub.user.email],
                html_message=html,
                fail_silently=True,
            )
            sub.expiry_notified_at = now
            sub.save(update_fields=['expiry_notified_at'])
            sent += 1
        except Exception:
            logger.error('expiry reminder failed for user %s', sub.user_id, exc_info=True)
    logger.info('send_expiry_reminders: %d reminder(s) sent', sent)
    return sent


# ── Email ─────────────────────────────────────────────────────────────────────

def _send_audit_email(audit):
    """Email the audit result if the user has an address and notifications on."""
    from django.core.mail import send_mail
    from django.template.loader import render_to_string
    from app.models import UserProfile

    user = audit.user
    if not user.email:
        return
    try:
        profile = UserProfile.objects.get(user=user)
        if not profile.email_notifications:
            return
    except UserProfile.DoesNotExist:
        return

    base_url = getattr(settings, 'BASE_URL', 'http://localhost:8000')
    # The email is the only view of the audit some people ever open. It has to
    # report the same counts the report page does.
    top_issues = list(
        audit.checks.counted().filter(passed=False).order_by('severity_rank')[:3]
        .values('name', 'severity', 'recommendation')
    )
    passed_count = audit.checks.counted().filter(passed=True).count()
    failed_count = audit.checks.counted().filter(passed=False).count()

    lang = _audit_language(audit)
    prev_lang = translation.get_language()
    translation.activate(lang)
    try:
        html = render_to_string('app/email/audit_complete.html', {
            'user': user,
            'audit': audit,
            'repo_display': audit.repo_display,
            'top_issues': top_issues,
            'audit_url': tagged(f'{base_url}/audit/{audit.id}/', 'audit-email', 'email'),
            'base_url': base_url,
            'passed_count': passed_count,
            'failed_count': failed_count,
            'score_delta': audit.score_delta,
        })
        send_mail(
            subject=f'[DevOpsCheck] {audit.repo_display} — score {audit.score}/100',
            message=f'Your audit for {audit.repo_display} is complete. Score: {audit.score}/100',
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@devopscheck.com'),
            recipient_list=[user.email],
            html_message=html,
            fail_silently=True,
        )
        logger.info('_send_audit_email sent: audit_id=%s', audit.id)
    except Exception:
        logger.error('_send_audit_email failed: audit_id=%s', audit.id, exc_info=True)
    finally:
        translation.activate(prev_lang) if prev_lang else translation.deactivate()


@shared_task
def refresh_stale_public_scans(limit: int = 40):
    """
    Re-scan the public repositories people actually look at.

    Every public scan is an indexable page; a page showing a score from three
    months ago is worth less to a visitor and less to a search engine.
    """
    from app.models import Audit, PublicScan

    from django.db.models import Q
    from app.checks import SCORE_VERSION

    cutoff = timezone.now() - timezone.timedelta(days=7)
    # A page scored under an older methodology is stale whatever its age:
    # it shows findings the current engine no longer believes.
    stale = (PublicScan.objects
             .filter(status=Audit.STATUS_DONE)
             .filter(Q(updated_at__lt=cutoff) | ~Q(score_version=SCORE_VERSION) | Q(score_version__isnull=True))
             .order_by('-view_count')[:limit])
    queued = 0
    seen = set()
    for scan in stale:
        run_public_scan_task.delay(scan.id)
        seen.add(scan.repo_full_name.lower())
        queued += 1

    # The landing page's showcase is the only place the product proves it works.
    # Leaving it to chance means the section reads "no score yet" until a visitor
    # happens to scan one of those repositories — which is exactly backwards.
    from app.views import LANDING_DEMO_REPOS

    for full_name in LANDING_DEMO_REPOS:
        if full_name.lower() in seen:
            continue
        scan = PublicScan.objects.filter(repo_full_name__iexact=full_name).first()
        if scan is None:
            scan = PublicScan.objects.create(
                repo_full_name=full_name,
                repo_url=f'https://github.com/{full_name}',
                status=Audit.STATUS_PENDING,
            )
        elif scan.status == Audit.STATUS_DONE and not scan.is_stale:
            continue
        run_public_scan_task.delay(scan.id)
        queued += 1

    logger.info('refresh_stale_public_scans: queued %d rescans', queued)
    return queued


@shared_task
def scan_pending_public_repos(limit: int = 0):
    """
    Work through the backlog `seed_public_scans` recorded, at a rate the API
    budget can carry.

    An audit costs three calls and an authenticated token allows 5000 an hour,
    so a few hundred an hour leaves room for the visitors who came to scan
    something themselves — they are the point, the corpus is the by-product.
    Best-known repositories go first: they are what a reader recognises on a
    leaderboard, and what the score distribution needs to be credible.
    """
    from app.models import Audit, PublicScan

    limit = limit or getattr(settings, 'PUBLIC_SCAN_BATCH', 400)
    pending = (PublicScan.objects
               .filter(queued_at__isnull=True, status=Audit.STATUS_PENDING)
               .order_by('-stars', 'id')[:limit])

    queued = 0
    for scan in pending:
        # Claim the row first: a second beat tick must not queue it again.
        claimed = PublicScan.objects.filter(pk=scan.pk, queued_at__isnull=True).update(
            queued_at=timezone.now())
        if not claimed:
            continue
        run_public_scan_task.delay(scan.id)
        queued += 1

    if queued:
        # The batch before this one has landed by now; let the page recompute.
        from app import rankings
        rankings.invalidate()
    logger.info('scan_pending_public_repos: queued %d', queued)
    return queued


@shared_task
def expire_stuck_public_scans(older_than_minutes: int = 10):
    """
    Close out scans the queue never finished.

    A repository that does not exist, or a worker that died, would otherwise
    leave a row queued forever and its page spinning for every visitor.
    """
    from app.models import Audit, PublicScan

    cutoff = timezone.now() - timezone.timedelta(minutes=older_than_minutes)
    stuck = PublicScan.objects.filter(
        status__in=[Audit.STATUS_PENDING, Audit.STATUS_RUNNING], updated_at__lt=cutoff,
        # A seeded row that has not been handed to a worker yet is waiting its
        # turn, not dying. Without this the whole backlog would be closed out
        # as failed fifteen minutes after it was recorded.
        queued_at__isnull=False,
    )
    count = stuck.update(
        status=Audit.STATUS_FAILED, error_message='The scan did not complete in time.',
    )
    if count:
        logger.info('expire_stuck_public_scans: closed %d stuck scan(s)', count)
    return count


# ── Keeping the visitor ───────────────────────────────────────────────────────

def _scan_summary(scan):
    """The numbers a message about a scan has to agree with the page on."""
    results = scan.results or []
    applicable = [c for c in results if _counts(c)]
    failed = [c for c in applicable if not c.get('passed')]
    order = {'crit': 0, 'warn': 1, 'info': 2}
    failed.sort(key=lambda c: order.get(c.get('severity'), 3))
    return {
        'failed': failed,
        'top_issues': failed[:3],
        'failed_count': len(failed),
        'passed_count': len(applicable) - len(failed),
        'crit_count': sum(1 for c in failed if c.get('severity') == 'crit'),
        'warn_count': sum(1 for c in failed if c.get('severity') == 'warn'),
    }


def _send_watch_email(watch, template, subject, context):
    """
    Render and send one message to a watcher, in the language they read the
    page in, with the unsubscribe link every message must carry.
    """
    from django.core.mail import send_mail
    from django.template.loader import render_to_string

    base_url = getattr(settings, 'BASE_URL', 'http://localhost:8000')
    prev_lang = translation.get_language()
    translation.activate(watch.language if watch.language in ('en', 'ru') else 'en')
    try:
        ctx = {
            'watch': watch,
            'base_url': base_url,
            'repo': watch.repo_full_name,
            'scan_url': tagged(f'{base_url}/scan/{watch.repo_full_name}/', 'watch-email', 'email'),
            'confirm_url': f'{base_url}/watch/confirm/{watch.token}/',
            'unsubscribe_url': f'{base_url}/watch/stop/{watch.token}/',
            **context,
        }
        html = render_to_string(template, ctx)
        send_mail(
            subject=subject,
            message=ctx['scan_url'],
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@devopscheck.com'),
            recipient_list=[watch.email],
            html_message=html,
            fail_silently=False,
        )
        return True
    finally:
        translation.activate(prev_lang) if prev_lang else translation.deactivate()


@shared_task
def send_watch_confirmation(watch_id: int):
    """
    The first message: the report they asked for, and an offer to hear more.

    One report to an address someone typed into a form is ordinary. A standing
    subscription is not, so this message carries the confirm link and nothing
    recurring is sent until it is followed.
    """
    from app.models import Audit, PublicScan, RepoWatch

    watch = RepoWatch.objects.filter(id=watch_id).first()
    if watch is None or watch.unsubscribed_at:
        return False
    scan = PublicScan.objects.filter(repo_full_name__iexact=watch.repo_full_name).first()
    if scan is None or scan.status != Audit.STATUS_DONE:
        return False

    summary = _scan_summary(scan)
    try:
        _send_watch_email(
            watch,
            'app/email/watch_report.html',
            f'[DevOpsCheck] {scan.repo_full_name} — {scan.score}/100',
            {'scan': scan, **summary},
        )
    except Exception:
        logger.error('send_watch_confirmation failed: watch_id=%s', watch_id, exc_info=True)
        return False

    # The score they were told, so the first change is measured from here even
    # if they never confirm and later do.
    RepoWatch.objects.filter(pk=watch.pk).update(
        last_score=scan.score, last_notified_at=timezone.now(),
    )
    logger.info('send_watch_confirmation sent: watch_id=%s repo=%s', watch_id, scan.repo_full_name)
    return True


@shared_task
def refresh_watched_public_scans(older_than_days: int = 3):
    """
    Keep watched repositories fresh enough for a change to be worth reporting.

    A repository someone asked to hear about is by definition one worth
    re-reading, and on a shorter cycle than the weekly sweep — a score change
    reported eleven days late is not news.
    """
    from app.models import Audit, PublicScan, RepoWatch

    watched = set(
        RepoWatch.objects
        .filter(confirmed_at__isnull=False, unsubscribed_at__isnull=True)
        .values_list('repo_full_name', flat=True)
    )
    if not watched:
        return 0

    cutoff = timezone.now() - timezone.timedelta(days=older_than_days)
    queued = 0
    for scan in PublicScan.objects.filter(
        repo_full_name__in=watched, status=Audit.STATUS_DONE, updated_at__lt=cutoff,
    ):
        run_public_scan_task.delay(scan.id)
        queued += 1
    logger.info('refresh_watched_public_scans: queued %d', queued)
    return queued


@shared_task
def notify_watched_score_changes():
    """
    Mail the watchers whose repository moved since they were last told.

    Compared against `last_score` — what the reader was actually told — not
    against the previous scan. A score that dips and recovers between two
    messages is not a change the reader ever saw, and mailing them about it
    would be mailing them about nothing.
    """
    from app.models import Audit, PublicScan, RepoWatch

    active = (RepoWatch.objects
              .filter(confirmed_at__isnull=False, unsubscribed_at__isnull=True)
              .exclude(last_score__isnull=True))
    if not active.exists():
        return 0

    names = set(active.values_list('repo_full_name', flat=True))
    scores = {
        s.repo_full_name: s
        for s in PublicScan.objects.filter(
            repo_full_name__in=names, status=Audit.STATUS_DONE, score__isnull=False,
        )
    }

    sent = 0
    for watch in active:
        scan = scores.get(watch.repo_full_name)
        if scan is None or scan.score == watch.last_score:
            continue
        delta = scan.score - watch.last_score
        summary = _scan_summary(scan)
        try:
            _send_watch_email(
                watch,
                'app/email/watch_changed.html',
                f'[DevOpsCheck] {scan.repo_full_name}: {watch.last_score} → {scan.score}/100',
                {'scan': scan, 'previous_score': watch.last_score,
                 'delta': delta, 'improved': delta > 0, **summary},
            )
        except Exception:
            logger.error('notify_watched_score_changes failed: watch_id=%s',
                         watch.id, exc_info=True)
            continue
        RepoWatch.objects.filter(pk=watch.pk).update(
            last_score=scan.score, last_notified_at=timezone.now(),
        )
        sent += 1

    logger.info('notify_watched_score_changes: sent %d', sent)
    return sent


@shared_task
def check_provider_connections():
    """
    Notice a dead connection before the customer does, and say so once.

    A personal access token expires and every audit for that account silently
    stops. The only symptom used to be the dashboard link appearing to do
    nothing — which reads as the product being broken, not the token. A tool
    that tells you it stopped working is worth keeping; one that dies quietly
    gets cancelled.

    One email per outage, not per run: `token_notified_at` is cleared only when
    the connection comes back.
    """
    import requests
    from django.core.mail import send_mail
    from django.template.loader import render_to_string
    from app.models import GithubProfile, GitlabProfile, UserProfile

    now = timezone.now()
    newly_broken = {}          # user -> [ {label, message, since} ]

    def record(profile, label):
        if profile.is_healthy or profile.token_notified_at:
            return
        newly_broken.setdefault(profile.user, []).append({
            'label': label,
            'message': profile.status_message,
            'since': profile.token_broken_since,
        })

    for profile in GithubProfile.objects.select_related('user'):
        try:
            resp = requests.get(
                'https://api.github.com/user',
                headers={'Authorization': f'token {profile.current_token}',
                         'Accept': 'application/vnd.github.v3+json'},
                timeout=15,
            )
            if resp.status_code == 200:
                profile.mark_working()
            elif resp.status_code == 401:
                profile.mark_broken(GithubProfile.EXPIRED)
            elif resp.status_code == 403:
                profile.mark_broken(GithubProfile.FORBIDDEN)
        except Exception:
            profile.mark_broken(GithubProfile.UNREACHABLE)
        record(profile, f'GitHub — {profile.github_login}')

    for profile in GitlabProfile.objects.select_related('user'):
        try:
            from app.views import custom_dns_server
            with custom_dns_server(profile.custom_dns):
                resp = requests.get(
                    f'{profile.gitlab_url}/api/v4/user',
                    headers={'Authorization': f'Bearer {profile.current_token}'},
                    timeout=15, verify=profile.verify_ssl,
                )
            if resp.status_code == 200:
                profile.mark_working()
            elif resp.status_code == 401:
                profile.mark_broken(GitlabProfile.EXPIRED)
            elif resp.status_code == 403:
                profile.mark_broken(GitlabProfile.FORBIDDEN)
        except Exception:
            profile.mark_broken(GitlabProfile.UNREACHABLE)
        record(profile, f'GitLab — {profile.gitlab_username}')

    sent = 0
    for user, connections in newly_broken.items():
        if not user.email:
            continue
        prefs = UserProfile.objects.filter(user=user).first()
        if prefs and not prefs.email_notifications:
            continue
        try:
            html = render_to_string('app/email/connection_broken.html', {
                'connections': connections,
                'profile_url': f'{settings.BASE_URL}/profile/',
                'base_url': settings.BASE_URL,
            })
            send_mail(
                subject='A DevOpsCheck connection stopped working',
                message='\n'.join(f"{c['label']}: {c['message']}" for c in connections)
                        + f'\n\nReconnect at {settings.BASE_URL}/profile/',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html,
                fail_silently=True,
            )
            sent += 1
        except Exception:
            logger.error('connection alert failed for user %s', user.id, exc_info=True)
            continue

        for profile in list(GithubProfile.objects.filter(user=user)) + \
                list(GitlabProfile.objects.filter(user=user)):
            if not profile.is_healthy:
                profile.token_notified_at = now
                profile.save(update_fields=['token_notified_at'])

    logger.info('check_provider_connections: %d user(s) notified', sent)
    return sent


# ── Fix pull requests, followed until CI is green (roadmap phase 5) ──────────

@shared_task
def poll_fix_attempts():
    """Advance every active FixAttempt by one step. Runs every minute."""
    from django.core.cache import cache
    from app import fix_agent
    from app.models import FixAttempt

    for attempt in FixAttempt.objects.filter(state__in=FixAttempt.ACTIVE_STATES).select_related('audit', 'user'):
        # One worker per attempt: a slow model call must not let the next
        # minute's poll push a second fix on top of the first.
        lock = f'fix-attempt-lock:{attempt.pk}'
        if not cache.add(lock, 1, timeout=600):
            continue
        try:
            fix_agent.step(attempt)
        except Exception:
            logger.error('Fix agent step failed for attempt %s', attempt.pk, exc_info=True)
        finally:
            cache.delete(lock)


# ── Weekly digest (roadmap phase 7) ──────────────────────────────────────────

@shared_task
def send_weekly_digests():
    """
    Runs daily at 08:00 UTC; sends to Team-plan accounts whose chosen day is
    today. Settings are created on first run with the digest on, in the
    language of the account's latest audit.
    """
    from app import digest
    from app.models import Audit, DigestSettings, UserSubscription

    now = timezone.now()
    sent = 0
    for sub in UserSubscription.objects.exclude(plan='free').select_related('user'):
        if not sub.is_team:
            continue
        user = sub.user
        latest = Audit.objects.filter(user=user).order_by('-created_at').first()
        ds, _created = DigestSettings.objects.get_or_create(
            user=user, defaults={'language': (latest.language if latest and latest.language in ('en', 'ru') else 'en')})
        if not ds.enabled or ds.weekday != now.weekday():
            continue
        if ds.last_sent_at and now - ds.last_sent_at < timezone.timedelta(days=6):
            continue
        try:
            sent += bool(digest.send(user, ds, now))
        except Exception:
            logger.error('Weekly digest failed for user %s', user.pk, exc_info=True)
    logger.info('Weekly digests sent: %d', sent)


@shared_task
def run_ci_scan_task(scan_id: int):
    """Scan one commit of a public repository for the keyless GitHub Action."""
    from app.models import CIScan
    from app.checks import calculate_score, run_all_checks
    from app.repo_client import GithubRepoClient, RepoAccessError
    from app import audit_config

    scan = CIScan.objects.filter(id=scan_id).first()
    if scan is None:
        return
    scan.status = 'running'
    scan.save(update_fields=['status'])
    prev_lang = translation.get_language()
    translation.activate('en')
    try:
        token = getattr(settings, 'PUBLIC_SCAN_GITHUB_TOKEN', '') or ''
        client = GithubRepoClient(scan.repo_full_name, token, ref=scan.ref or scan.commit_sha).load()
        if client.is_private:
            raise RepoAccessError('This repository is private. Pass an API token to audit it.')
        config = audit_config.load(client)
        checks = run_all_checks(client, config=config)
        from app.repo_kind import detect
        scan.repo_kind = detect(client, forced_kind=config.kind)[0]
        scan.score = calculate_score(checks)
        scan.results = [{k: c.get(k) for k in ('check_id', 'name', 'passed', 'severity', 'category',
                                                 'recommendation', 'applicable', 'not_applicable_reason',
                                                 'status', 'evidence')} for c in checks]
        scan.fail_under = config.fail_under
        scan.config_errors = config.errors
        scan.status = 'done'
        scan.completed_at = timezone.now()
        scan.save()
    except RepoAccessError as exc:
        scan.status = 'failed'
        scan.error_message = str(exc)[:300]
        scan.save(update_fields=['status', 'error_message'])
    except Exception as exc:
        logger.error('ci scan failed: %s', scan.repo_full_name, exc_info=True)
        scan.status = 'failed'
        scan.error_message = str(exc)[:300]
        scan.save(update_fields=['status', 'error_message'])
    finally:
        translation.activate(prev_lang) if prev_lang else translation.deactivate()


@shared_task
def run_org_scan_task(org_scan_id: int):
    """
    List an organisation's public repositories and scan the most starred ones.

    Runs the repository scans inline, one after another, rather than queueing
    thirty jobs: a visitor's own scan must not wait behind an organisation.
    """
    import requests as _requests
    from app.models import Audit, OrgScan, PublicScan

    org_scan = OrgScan.objects.filter(id=org_scan_id).first()
    if org_scan is None:
        return
    org_scan.status = 'running'
    org_scan.save(update_fields=['status'])
    token = getattr(settings, 'PUBLIC_SCAN_GITHUB_TOKEN', '') or ''
    headers = {'Accept': 'application/vnd.github+json'}
    if token:
        headers['Authorization'] = f'token {token}'
    try:
        repos = []
        for kind in ('orgs', 'users'):
            r = _requests.get(f'https://api.github.com/{kind}/{org_scan.org}/repos',
                              params={'type': 'public', 'per_page': 100, 'sort': 'pushed'},
                              headers=headers, timeout=20)
            if r.status_code == 200:
                repos = r.json()
                break
        else:
            raise ValueError('No public GitHub organisation or user by that name.')
        live = [r for r in repos if not r.get('fork') and not r.get('archived') and not r.get('private')]
        live.sort(key=lambda r: r.get('stargazers_count', 0), reverse=True)
        picked = [r['full_name'] for r in live[:OrgScan.MAX_REPOS]]
        org_scan.repos = picked
        org_scan.total_public = len(live)
        org_scan.save(update_fields=['repos', 'total_public'])
        for full_name in picked:
            scan = PublicScan.objects.filter(repo_full_name__iexact=full_name).first()
            if scan is None:
                scan = PublicScan.objects.create(repo_full_name=full_name,
                                                 repo_url=f'https://github.com/{full_name}',
                                                 status=Audit.STATUS_PENDING)
            elif scan.status == Audit.STATUS_DONE and not scan.is_stale:
                continue
            scan.queued_at = timezone.now()
            scan.save(update_fields=['queued_at'])
            run_public_scan_task(scan.id)
        org_scan.status = 'done'
        org_scan.error_message = ''
        org_scan.save(update_fields=['status', 'error_message', 'updated_at'])
    except Exception as exc:
        logger.info('org scan failed for %s: %s', org_scan.org, exc)
        org_scan.status = 'failed'
        org_scan.error_message = str(exc)[:300]
        org_scan.save(update_fields=['status', 'error_message'])
