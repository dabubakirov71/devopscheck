"""
Surfaces that work without an account.

Anyone can audit any public repository at /scan/<owner>/<repo>/ — no signup, no
token. It is the demo, the top of the funnel, and the SEO surface all at once:
every scanned repository becomes an indexable page, and the score card is what
gets pasted into Slack.
"""
import logging
import re

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from app.models import Audit, PublicScan, RepoWatch
from app.checks import counts as _counts  # noqa: E402

logger = logging.getLogger(__name__)

from django.utils.translation import gettext_lazy as _lazy  # noqa: E402

#: How the report names the repository kind it detected (repo_kind.detect).
KIND_LABELS = {
    'service': _lazy('service'), 'library': _lazy('library'), 'cli': _lazy('command-line tool'),
    'infrastructure': _lazy('infrastructure as code'), 'monorepo': _lazy('monorepo'),
    'docs': _lazy('documentation'),
}

REPO_RE = re.compile(r'^[A-Za-z0-9_.\-]{1,100}$')
NEW_SCANS_PER_HOUR = 10

# Seeded so the index is never empty and there is always something to look at.
FEATURED = [
    'django/django', 'pallets/flask', 'fastapi/fastapi', 'expressjs/express',
    'gin-gonic/gin', 'rails/rails', 'laravel/laravel', 'spring-projects/spring-boot',
]


def _client_ip(request):
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def _rate_limited(request) -> bool:
    key = f'pubscan:{_client_ip(request)}'
    try:
        count = cache.get(key, 0)
        if count >= NEW_SCANS_PER_HOUR:
            return True
        cache.set(key, count + 1, 3600)
    except Exception:
        pass  # never block a scan because the cache is unavailable
    return False


def _normalise(raw: str):
    """Accept 'owner/repo', a full GitHub URL, or 'github.com/owner/repo'."""
    text = (raw or '').strip()
    text = re.sub(r'^https?://', '', text)
    text = re.sub(r'^(www\.)?github\.com/', '', text)
    text = text.rstrip('/')
    text = re.sub(r'\.git$', '', text)
    parts = [p for p in text.split('/') if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if not REPO_RE.match(owner) or not REPO_RE.match(repo):
        return None
    # A segment made only of dots would be a path-traversal attempt, never a name.
    if set(owner) == {'.'} or set(repo) == {'.'}:
        return None
    return f'{owner}/{repo}'


def scan_index(request):
    """Landing page for the no-signup scanner."""
    done = PublicScan.objects.filter(status=Audit.STATUS_DONE)
    popular = list(done.order_by('-view_count')[:8])
    seen = {s.repo_full_name.lower() for s in popular}

    # The two lists used to be drawn from the same rows, so on a young install
    # the page showed the same three cards twice and called them different
    # things. Recent means recent *and not already above*.
    recent = [s for s in done.order_by('-updated_at')[:24]
              if s.repo_full_name.lower() not in seen][:12]
    seen.update(s.repo_full_name.lower() for s in recent)

    # Recognisable names to start from. This only rendered when there were no
    # scans at all, which meant it never rendered once the site had any traffic
    # — and a visitor with nothing to type stared at a blank input.
    featured = [r for r in FEATURED if r.lower() not in seen][:8]

    from app import rankings as rank

    return render(request, 'app/scan_index.html', {
        'recent': recent,
        'popular': popular,
        'featured': featured,
        'total_scanned': done.count(),
        # Only offered once the rankings page has enough to say.
        'corpus_size': rank.corpus_size() if rank.corpus_size() >= rank.MIN_SAMPLE else 0,
    })


@require_POST
def scan_submit(request):
    repo = _normalise(request.POST.get('repo', ''))
    if not repo:
        return render(request, 'app/scan_index.html', {
            'error': 'Enter a repository as owner/name, for example django/django.',
            'recent': PublicScan.objects.filter(status=Audit.STATUS_DONE).order_by('-updated_at')[:12],
            'popular': PublicScan.objects.filter(status=Audit.STATUS_DONE).order_by('-view_count')[:8],
            'featured': FEATURED,
        }, status=400)
    owner, name = repo.split('/', 1)
    return redirect('public_scan', owner=owner, repo=name)


def public_scan(request, owner, repo):
    """Show a public repository's audit, starting one if it is missing or stale."""
    full_name = _normalise(f'{owner}/{repo}')
    if not full_name:
        return redirect('scan_index')

    scan = PublicScan.objects.filter(repo_full_name__iexact=full_name).first()
    started = False

    # A queue that never picked the job up used to leave the page spinning
    # forever. Time it out and say what happened instead.
    if scan is not None and scan.is_stuck:
        scan.status = Audit.STATUS_FAILED
        scan.error_message = 'The scan did not complete in time.'
        scan.save(update_fields=['status', 'error_message'])

    needs_run = (
        scan is None
        or scan.status == Audit.STATUS_FAILED
        or (scan.status == Audit.STATUS_DONE and scan.is_stale)
    )
    if needs_run:
        if scan is not None and scan.status == Audit.STATUS_FAILED and not scan.is_stale:
            # A repo that just failed (private, missing) is not retried on every view.
            needs_run = False
        elif _rate_limited(request):
            return render(request, 'app/scan_result.html', {
                'repo_full_name': full_name,
                'rate_limited': True,
            }, status=429)

    if needs_run:
        if scan is None:
            scan = PublicScan.objects.create(
                repo_full_name=full_name,
                repo_url=f'https://github.com/{full_name}',
                status=Audit.STATUS_PENDING,
            )
        else:
            scan.status = Audit.STATUS_PENDING
            scan.save(update_fields=['status'])
        # Stamped on the way to the worker, so the stuck-scan sweep can tell a
        # job that died from a seeded row that is still waiting its turn.
        scan.queued_at = timezone.now()
        scan.save(update_fields=['queued_at'])
        from app.tasks import run_public_scan_task
        run_public_scan_task.delay(scan.id)
        started = True
        from app import funnel
        funnel.record('scan_started', request, ref=scan.repo_full_name)

    PublicScan.objects.filter(pk=scan.pk).update(view_count=scan.view_count + 1)

    results = scan.results or []
    # A check the repository cannot act on is neither a pass nor a failure. It
    # is shown on its own with the reason — a check that simply disappeared
    # would read as one that was quietly failed.
    applicable = [c for c in results if _counts(c)]
    not_applicable = [c for c in results if not c.get('applicable', True) and c.get('status') != 'unknown']
    unknown = [c for c in results if c.get('status') == 'unknown']
    failed = [c for c in applicable if not c.get('passed')]
    passed = [c for c in applicable if c.get('passed')]
    order = {'crit': 0, 'warn': 1, 'info': 2}
    failed.sort(key=lambda c: order.get(c.get('severity'), 3))

    from app import rankings

    return render(request, 'app/scan_result.html', {
        'scan': scan,
        # Where this repository stands against everything else scanned. None
        # until the corpus is big enough for the comparison to mean anything.
        'standing': rankings.standing(scan.score, scan.primary_language),
        'repo_full_name': full_name,
        # The normalised halves, not the raw URL segments: the watch form posts
        # them back and a differently-cased path would miss the row.
        'owner': full_name.split('/')[0],
        'scan_repo_name': full_name.split('/')[1],
        'watch_state': request.GET.get('watch', ''),
        # The badge markdown the copy button shows is the same string the pull
        # request commits — built once, in badge_markdown().
        'badge_markdown': badge_markdown(full_name, scan.score),
        'badge_state': request.GET.get('badge', ''),
        'badge_pr_url': request.session.pop('badge_pr_url', ''),
        'badge_pr_error': request.session.pop('badge_pr_error', ''),
        'can_open_badge_pr': (request.user.is_authenticated
                              and request.user.github_profiles.exists()),
        'started': started,
        'failed': failed,
        'passed': passed,
        'hygiene': sorted((c for c in results if c.get('applicable', True)
                           and c.get('category') == 'hygiene'),
                          key=lambda c: (c.get('passed', False), c.get('name', ''))),
        'not_applicable': not_applicable,
        'not_applicable_reason': (not_applicable[0].get('not_applicable_reason', '')
                                  if not_applicable else ''),
        'unknown': unknown,
        'guide_ids': _guide_ids(),
        'fp_state': request.GET.get('fp', ''),
        'kind_label': KIND_LABELS.get(scan.repo_kind or '', ''),
        'crit_count': sum(1 for c in failed if c.get('severity') == 'crit'),
        'warn_count': sum(1 for c in failed if c.get('severity') == 'warn'),
        'og_image': f'{settings.BASE_URL}/og/scan/{full_name}.png',
        'canonical': f'{settings.BASE_URL}/scan/{full_name}/',
        'status_url': f'/scan/{full_name}/status/',
    })


# ── Keeping the visitor ───────────────────────────────────────────────────────
#
# The scan result is the one moment this product has someone's full attention.
# Everything below exists to turn that moment into a returning reader without
# asking for an account: an address, one report, and mail when the score moves.

WATCH_SIGNUPS_PER_HOUR = 5


def _watch_rate_limited(request) -> bool:
    """
    A cap per address per hour, so the form cannot be used to mail strangers.

    Separate from the scan limit: scanning is cheap and public, sending mail on
    someone else's behalf is neither.
    """
    key = f'repowatch:{_client_ip(request)}'
    try:
        count = cache.get(key, 0)
        if count >= WATCH_SIGNUPS_PER_HOUR:
            return True
        cache.set(key, count + 1, 3600)
    except Exception:
        # A cache outage must not open the mailer up; a scan still runs without
        # the cache, but this one fails closed.
        return False
    return False


@require_POST
def watch_subscribe(request, owner, repo):
    """
    Take an address and send the report, plus an offer to hear about changes.

    Answers the same way whether the address is new, already pending or already
    watching. Telling a stranger "that address is already subscribed" turns the
    form into a way to test whether someone uses this product.
    """
    full_name = _normalise(f'{owner}/{repo}')
    if not full_name:
        return redirect('scan_index')

    back = f'/scan/{full_name}/'
    email = (request.POST.get('email') or '').strip().lower()

    try:
        validate_email(email)
    except ValidationError:
        return redirect(f'{back}?watch=invalid#watch')

    if _watch_rate_limited(request):
        return redirect(f'{back}?watch=throttled#watch')

    scan = PublicScan.objects.filter(repo_full_name__iexact=full_name).first()
    if scan is None or scan.status != Audit.STATUS_DONE:
        return redirect(f'{back}?watch=notready#watch')

    watch, created = RepoWatch.objects.get_or_create(
        email=email,
        repo_full_name=scan.repo_full_name,
        defaults={'language': getattr(request, 'LANGUAGE_CODE', 'en') or 'en'},
    )
    if created:
        from app import funnel
        funnel.record('report_email_submitted', request, ref=scan.repo_full_name)
    # An address that unsubscribed and came back through the form is asking
    # again, in the only place that proves it is them. Reopen it as pending.
    if watch.unsubscribed_at:
        watch.unsubscribed_at = None
        watch.confirmed_at = None
        watch.save(update_fields=['unsubscribed_at', 'confirmed_at'])

    from app.tasks import send_watch_confirmation
    send_watch_confirmation.delay(watch.id)

    return redirect(f'{back}?watch=sent#watch')


def watch_confirm(request, token):
    """Confirm a watch. The link is in the first email and nowhere else."""
    watch = RepoWatch.objects.filter(token=token).first()
    if watch is None:
        return render(request, 'app/watch_status.html', {'state': 'unknown'}, status=404)
    confirmed = watch.confirm()
    return render(request, 'app/watch_status.html', {
        'state': 'confirmed' if confirmed else watch.state,
        'watch': watch,
        'scan_url': f'/scan/{watch.repo_full_name}/',
    })


def watch_unsubscribe(request, token):
    """
    One click, no login, no confirmation step.

    An unsubscribe that asks the reader to do anything else is the reason people
    press the spam button instead, and that costs the sending domain far more
    than the subscriber was worth.
    """
    watch = RepoWatch.objects.filter(token=token).first()
    if watch is None:
        return render(request, 'app/watch_status.html', {'state': 'unknown'}, status=404)
    watch.unsubscribe()
    return render(request, 'app/watch_status.html', {
        'state': 'unsubscribed',
        'watch': watch,
        'scan_url': f'/scan/{watch.repo_full_name}/',
    })


# ── The badge, as a pull request ──────────────────────────────────────────────
#
# A badge in a README is a backlink, an impression on every visitor to that
# repository, and an entry point for the next reader — the loop shields.io,
# Codecov and Snyk all grew on. Offering it as text to copy by hand is where
# that loop stopped.

def badge_markdown(full_name, score, base_url=None):
    """
    The badge, in one place.

    The scan page renders it to copy, and the pull request commits it. Built in
    two places they would drift, and the pull request would start adding a badge
    the page never showed.
    """
    base = base_url or settings.BASE_URL
    if score is None:
        colour = '9aa5b1'
        value = 'pending'
    else:
        colour = ('00cc6a' if score >= 80 else
                  '4488ff' if score >= 60 else
                  'ffaa00' if score >= 40 else 'ff4466')
        value = f'{score}%2F100'
    from app.funnel import tagged
    return (f'[![DevOps Score](https://img.shields.io/badge/DevOps_Score-{value}-{colour})]'
            f'({tagged(f"{base}/scan/{full_name}/", "badge", "readme")})')


@require_POST
def badge_pull_request(request, owner, repo):
    """
    Open the pull request that puts the badge in the repository's README.

    Anonymous visitors never reach this: the page sends them to sign up first,
    because opening a pull request needs a credential for the repository. That
    is the strongest reason this product has to offer for making an account —
    not "track your score over time", but "we will open the pull request".
    """
    full_name = _normalise(f'{owner}/{repo}')
    if not full_name:
        return redirect('scan_index')
    back = f'/scan/{full_name}/'

    if not request.user.is_authenticated:
        return redirect(f'/register/?next={back}%3Fbadge%3D1')

    profile = request.user.github_profiles.first()
    if profile is None:
        return redirect(f'/profile/?next={back}')

    scan = PublicScan.objects.filter(repo_full_name__iexact=full_name).first()
    if scan is None or scan.status != Audit.STATUS_DONE:
        return redirect(f'{back}?badge=notready#badge')

    from app.github_writer import (
        open_badge_pull_request, GitHubWriteError, NothingToChange,
    )
    try:
        pr_url = open_badge_pull_request(
            token=profile.current_token,
            repo_full_name=scan.repo_full_name,
            badge=badge_markdown(scan.repo_full_name, scan.score),
            report_url=f'{settings.BASE_URL}/scan/{scan.repo_full_name}/',
        )
    except NothingToChange:
        return redirect(f'{back}?badge=already#badge')
    except GitHubWriteError as exc:
        # These are almost all permission problems the reader can fix, so the
        # message is worth carrying rather than replacing with "failed".
        request.session['badge_pr_error'] = str(exc)
        return redirect(f'{back}?badge=error#badge')
    except Exception:
        logger.error('badge_pull_request failed for %s', full_name, exc_info=True)
        return redirect(f'{back}?badge=error#badge')

    request.session['badge_pr_url'] = pr_url
    return redirect(f'{back}?badge=opened#badge')


def public_scan_status(request, owner, repo):
    full_name = _normalise(f'{owner}/{repo}')
    scan = PublicScan.objects.filter(repo_full_name__iexact=full_name).first()
    if scan is None:
        return JsonResponse({'status': 'unknown'}, status=404)
    return JsonResponse({
        'status': scan.status,
        'score': scan.score,
        'checks': len(scan.results or []),
    })


# ── Rankings: what the corpus knows ───────────────────────────────────────────

def rankings(request, slug: str = ''):
    """
    The scanned corpus, as a public reference.

    Two audiences share one page. Somebody who just scanned their repository
    wants to know whether 76 is good — the distribution answers that. Everybody
    else wants the finding: how many of the best-known repositories on GitHub
    ship without a lockfile, without tests in CI, with a container running as
    root. A scanner is a tool; that is a story.
    """
    from app import rankings as rank

    language = rank.language_from_slug(slug) if slug else ''
    if slug and not language:
        return redirect('rankings')

    summary = rank.summary()
    counts, scoped_total = rank._histogram(language) if language else (None, 0)

    return render(request, 'app/rankings.html', {
        'language': language,
        'language_slug': rank.language_slug(language) if language else '',
        'summary': summary,
        'scoped_total': scoped_total,
        'languages': rank.languages(),
        # Equal lengths: two columns of different heights read as one list
        # having run out rather than as a deliberate pair.
        'best': rank.leaderboard(language, limit=12),
        'worst': rank.leaderboard(language, limit=12, worst=True),
        'prevalence': rank.check_prevalence(),
        'min_sample': rank.MIN_SAMPLE,
        'canonical': (f'{settings.BASE_URL}/rankings/{rank.language_slug(language)}/'
                      if language else f'{settings.BASE_URL}/rankings/'),
    })


# ── Social preview cards ──────────────────────────────────────────────────────

def _png(data, etag):
    return HttpResponse(data, content_type='image/png', headers={
        'Cache-Control': 'public, max-age=3600',
        'ETag': etag,
    })


def og_scan_image(request, owner, repo):
    from app.og_image import render_card

    full_name = _normalise(f'{owner}/{repo}') or f'{owner}/{repo}'
    scan = PublicScan.objects.filter(repo_full_name__iexact=full_name).first()
    if scan is None:
        data = render_card(full_name, None)
        return _png(data, f'og-none-{full_name}')

    # Set-aside checks are neither passed nor failed, so they belong in neither
    # number on the card.
    results = [c for c in (scan.results or []) if _counts(c)]
    failed = sum(1 for c in results if not c.get('passed'))
    data = render_card(
        scan.repo_full_name, scan.score, scan.category_scores or {},
        failed=failed, passed=len(results) - failed,
    )
    return _png(data, f'og-scan-{scan.id}-{scan.score}')


def og_audit_image(request, token):
    from app.og_image import render_card

    audit = Audit.objects.filter(public_token=token, is_public=True).first()
    if audit is None:
        return HttpResponse(status=404)
    failed = audit.checks.counted().filter(passed=False).count()
    passed = audit.checks.counted().filter(passed=True).count()
    data = render_card(
        audit.repo_display, audit.score, audit.category_scores or {},
        failed=failed, passed=passed,
    )
    return _png(data, f'og-audit-{audit.id}-{audit.score}')


# ── "This FAIL is wrong" ─────────────────────────────────────────────────────

FALSE_POSITIVE_REPORTS_PER_HOUR = 20


@require_POST
def report_false_positive(request):
    """
    Record a reader's claim that a failed check is wrong (accuracy spec, stage 7).

    Only a check that actually failed in that report can be reported, and the
    evidence stored is the engine's own, not whatever the form sent — the row
    must say what the product claimed, so a human can judge it.
    """
    from django.utils.http import url_has_allowed_host_and_scheme
    from app.models import FalsePositiveReport

    back = request.POST.get('next', '/')
    if not url_has_allowed_host_and_scheme(back, {request.get_host()}, request.is_secure()):
        back = '/'
    back = back.split('#')[0].split('?')[0]
    check_id = (request.POST.get('check_id') or '')[:60]
    comment = (request.POST.get('comment') or '').strip()[:2000]

    key = f'falsepositive:{_client_ip(request)}'
    try:
        count = cache.get(key, 0)
        if count >= FALSE_POSITIVE_REPORTS_PER_HOUR:
            return redirect(f'{back}?fp=throttled')
        cache.set(key, count + 1, 3600)
    except Exception:
        pass

    report = None
    audit_id = request.POST.get('audit_id')
    if audit_id:
        audit = Audit.objects.filter(id=audit_id).first() if str(audit_id).isdigit() else None
        allowed = audit is not None and (audit.is_public or (request.user.is_authenticated
                                                             and audit.user_id == request.user.id))
        check = audit.checks.filter(check_id=check_id, passed=False).first() if allowed else None
        if check:
            report = FalsePositiveReport(repo_full_name=audit.repo_display, source='audit',
                                         commit_sha=audit.commit_sha or '', score_version=audit.score_version,
                                         check_id=check_id, evidence=check.evidence)
    else:
        full_name = _normalise(request.POST.get('repo', '')) or ''
        scan = PublicScan.objects.filter(repo_full_name__iexact=full_name).first() if full_name else None
        check = next((c for c in (scan.results or []) if c.get('check_id') == check_id
                      and not c.get('passed') and c.get('applicable', True)), None) if scan else None
        if check:
            report = FalsePositiveReport(repo_full_name=scan.repo_full_name, source='public',
                                         score_version=scan.score_version, check_id=check_id,
                                         evidence=(check.get('evidence') or '')[:500])
    if report is None:
        return redirect(f'{back}?fp=invalid')
    report.comment = comment
    report.user = request.user if request.user.is_authenticated else None
    report.save()
    logger.info('false positive reported: %s %s', report.repo_full_name, check_id)
    return redirect(f'{back}?fp=sent#chk-{check_id}')


# ── Check guides (/checks/) ──────────────────────────────────────────────────

def _guide_ids():
    from app.check_guides import GUIDES
    return set(GUIDES)


def checks_index(request):
    """Every check as a guide — the search-facing side of the rule set."""
    from django.utils.translation import get_language
    from app import check_guides
    guides = check_guides.all_guides(get_language())
    groups = {}
    for g in guides:
        groups.setdefault(g['category'], []).append(g)
    from app.checks import CATEGORIES
    return render(request, 'app/checks_index.html', {
        'groups': [(CATEGORIES.get(cat, cat) if cat != 'hygiene' else 'Hygiene', items)
                   for cat, items in groups.items()],
        'total': len(guides),
        'canonical': f'{settings.BASE_URL}/checks/',
    })


def check_guide(request, check_id):
    from django.http import Http404
    from django.utils.translation import get_language
    from app import check_guides
    g = check_guides.guide(check_id, get_language())
    if g is None:
        raise Http404
    # Real public repositories this check fails on: the page's proof, and the
    # internal links that make every scan page reachable from a guide.
    failing = list(PublicScan.objects
                   .filter(status=Audit.STATUS_DONE,
                           results__contains=[{'check_id': check_id, 'passed': False, 'applicable': True}])
                   .order_by('-stars')
                   .values_list('repo_full_name', flat=True)[:8])
    related = [r for r in check_guides.all_guides(get_language())
               if r['category'] == g['category'] and r['check_id'] != check_id][:6]
    return render(request, 'app/check_guide.html', {
        'g': g,
        'failing': failing,
        'related': related,
        'canonical': f'{settings.BASE_URL}/checks/{check_id}/',
    })


def og_page_image(request, page):
    from django.http import Http404
    from app.og_image import PAGE_CARDS, render_page_card
    if page not in PAGE_CARDS:
        raise Http404
    return _png(render_page_card(page), f'og-page-{page}-2')


@require_POST
def public_rescan(request, owner, repo):
    """
    "Rescan now" on a report. At most once per RESCAN_INTERVAL_MINUTES per
    repository, and inside the visitor's own scan rate limit — a public
    button must not be a way to spend the API budget.
    """
    full_name = _normalise(f'{owner}/{repo}')
    scan = PublicScan.objects.filter(repo_full_name__iexact=full_name).first() if full_name else None
    if scan is None:
        return redirect('scan_index')
    if scan.can_rescan and not _rate_limited(request):
        scan.status = Audit.STATUS_PENDING
        scan.queued_at = timezone.now()
        scan.save(update_fields=['status', 'queued_at'])
        from app.tasks import run_public_scan_task
        run_public_scan_task.delay(scan.id)
    owner, name = scan.repo_full_name.split('/', 1)
    return redirect('public_scan', owner=owner, repo=name)


def compare(request):
    """B1.8: an honest comparison table. Cells: (css class, text)."""
    from django.utils.translation import gettext as _
    Y, N, P = ('y', _('Yes')), ('n', '—'), ('p', _('Partly'))
    U = ('n', _('see vendor docs'))   # not sure — do not claim a competitor lacks it
    rows = [
        (_('Free for public repositories'), [Y, Y, Y, P, Y]),
        (_('Opens fix pull requests'), [('y', _('Config and CI fixes')), N, ('p', _('Dependencies')), ('p', _('Dependencies')), N]),
        (_('Known CVEs in dependencies'), [Y, Y, Y, Y, Y]),
        (_('Secrets committed to the repository'), [Y, N, Y, U, Y]),
        (_('GitHub Actions supply chain (pinning, token permissions, dangerous triggers)'), [Y, Y, P, U, N]),
        (_('Dockerfile and Kubernetes misconfiguration'), [Y, N, N, Y, Y]),
        (_('Terraform misconfiguration'), [Y, N, N, Y, Y]),
        (_('Code analysis (SAST)'), [N, N, Y, Y, N]),
        (_('One score for the whole repository'), [('y', '0–100'), ('y', '0–10'), N, N, N]),
        (_('Self-hosted GitLab'), [Y, P, N, Y, Y]),
        (_('Runs offline on your machine (CLI)'), [N, Y, N, Y, Y]),
    ]
    return render(request, 'app/compare.html', {'rows': rows, 'support_email': settings.SUPPORT_EMAIL})


def llms_txt(request):
    """B6.6: a plain map of the site for AI assistants (llmstxt.org)."""
    from app.check_guides import all_guides
    base = settings.BASE_URL
    lines = [
        f'# {settings.PRODUCT_NAME}',
        '',
        '> Automated DevOps and security audit for GitHub and GitLab repositories: committed secrets, '
        'known CVEs in dependencies (OSV.dev), GitHub Actions supply chain, Docker, Kubernetes and '
        'Terraform. One 0–100 score; where a fix can be written it is opened as a pull request. '
        'Public repositories are free to scan without an account.',
        '',
        '## Main pages',
        f'- [Free scanner]({base}/scan/): scan any public GitHub repository',
        f'- [Checks]({base}/checks/): every check, why it matters and how to fix it',
        f'- [Comparison]({base}/compare/): versus OpenSSF Scorecard, GitHub Advanced Security, Snyk, Trivy',
        f'- [Trust]({base}/trust/): what is read, what is sent to an AI provider, how tokens are stored',
        f'- [Pricing]({base}/pricing/)',
        '',
        '## Check guides',
    ]
    lines += [f"- [{g['title']}]({base}/checks/{g['check_id']}/)" for g in all_guides('en')]
    return HttpResponse('\n'.join(lines) + '\n', content_type='text/plain; charset=utf-8')


#: Google Search Console ownership file, served byte-for-byte at the site root.
GOOGLE_VERIFICATION = 'google9c61ce115925089c.html'


def google_site_verification(request):
    return HttpResponse(f'google-site-verification: {GOOGLE_VERIFICATION}',
                        content_type='text/html; charset=utf-8')


# ── Keyless CI scans for public repositories (growth plan B4) ────────────────

CI_SCANS_PER_REPO_PER_HOUR = 20
CI_SCANS_PER_HOUR = 300          # all repositories together: the API budget is shared


def _ci_payload(scan):
    from app.funnel import tagged
    payload = {
        'id': scan.id, 'repo': scan.repo_full_name, 'ref': scan.ref, 'commit_sha': scan.commit_sha,
        'status': scan.status, 'score': scan.score, 'repo_kind': scan.repo_kind,
        'checks': scan.results, 'fail_under': scan.fail_under, 'gate': scan.gate,
        'config_errors': scan.config_errors, 'error_message': scan.error_message,
        'score_delta': None, 'new_findings': [], 'resolved_findings': [],
        'url': tagged(f'{settings.BASE_URL}/scan/{scan.repo_full_name}/', 'action', 'ci'),
    }
    if scan.status == 'done':
        prev = scan.previous()
        if prev is not None and prev.score is not None:
            failing = {c['check_id'] for c in scan.results if not c.get('passed') and c.get('applicable', True)}
            before = {c['check_id'] for c in prev.results if not c.get('passed') and c.get('applicable', True)}
            payload.update(score_delta=scan.score - prev.score,
                           new_findings=sorted(failing - before), resolved_findings=sorted(before - failing))
    return payload


@csrf_exempt
@require_POST
def api_ci_scan_start(request):
    """
    POST /api/v1/ci-scan/ {"repo": "owner/name", "ref": "...", "commit_sha": "...", "pr_number": 1}

    No account and no token: public GitHub repositories only, bounded per
    repository and in total. A private repository gets a clear 403 from the
    worker, not a silent pass.
    """
    import json
    from app.models import CIScan
    try:
        body = json.loads(request.body or b'{}')
    except ValueError:
        return JsonResponse({'error': 'Body must be JSON.'}, status=400)
    repo = _normalise(str(body.get('repo', '')))
    if not repo:
        return JsonResponse({'error': 'repo must be "owner/name" of a public GitHub repository.'}, status=400)
    hour = timezone.now() - timezone.timedelta(hours=1)
    recent = CIScan.objects.filter(created_at__gte=hour)
    if recent.filter(repo_full_name__iexact=repo).count() >= CI_SCANS_PER_REPO_PER_HOUR:
        return JsonResponse({'error': f'At most {CI_SCANS_PER_REPO_PER_HOUR} keyless scans per repository '
                                      'per hour. Pass an API token for more.'}, status=429)
    if recent.count() >= CI_SCANS_PER_HOUR:
        return JsonResponse({'error': 'The free CI scanner is busy. Retry in a few minutes, '
                                      'or pass an API token.'}, status=429)
    pr = body.get('pr_number')
    scan = CIScan.objects.create(
        repo_full_name=repo, ref=str(body.get('ref') or '')[:255],
        commit_sha=str(body.get('commit_sha') or '')[:64],
        pr_number=int(pr) if str(pr or '').isdigit() else None,
    )
    from app.tasks import run_ci_scan_task
    run_ci_scan_task.delay(scan.id)
    from app import funnel
    funnel.record('scan_started', ref=repo, source='action')
    return JsonResponse({'id': scan.id, 'status': scan.status}, status=201)


def api_ci_scan_detail(request, scan_id):
    from app.models import CIScan
    scan = CIScan.objects.filter(id=scan_id).first()
    if scan is None:
        return JsonResponse({'error': 'not found'}, status=404)
    return JsonResponse(_ci_payload(scan))


# ── Organisation scan (growth plan B7) ───────────────────────────────────────

_ORG_NAME = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$')


def org_scan_submit(request):
    org = (request.POST.get('org') or request.GET.get('org') or '').strip()
    org = re.sub(r'^https?://(www\.)?github\.com/', '', org).strip('/').split('/')[0]
    if not _ORG_NAME.match(org):
        return redirect('scan_index')
    return redirect('org_scan', org=org)


def org_scan(request, org):
    """
    /scan/org/<org>/ — an organisation's public repositories at a glance.

    Deliberately a summary, not thirty reports: the average, the weakest
    repositories and the findings that repeat across them. That is the page an
    engineer forwards to their CTO — and the CTA is the private half.
    """
    from collections import Counter
    from app.models import OrgScan
    if not _ORG_NAME.match(org):
        return redirect('scan_index')
    row = OrgScan.objects.filter(org__iexact=org).first()
    stale = row is None or (row.status in ('done', 'failed') and row.is_stale)
    if stale:
        if _rate_limited(request):
            return render(request, 'app/scan_result.html', {'repo_full_name': org, 'rate_limited': True},
                          status=429)
        if row is None:
            row = OrgScan.objects.create(org=org)
        else:
            row.status = 'pending'
            row.save(update_fields=['status'])
        from app.tasks import run_org_scan_task
        run_org_scan_task.delay(row.id)
        from app import funnel
        funnel.record('scan_started', request, ref=f'org:{org}')
    OrgScan.objects.filter(pk=row.pk).update(view_count=row.view_count + 1)

    scans = list(PublicScan.objects.filter(repo_full_name__in=row.repos, status=Audit.STATUS_DONE))
    scans.sort(key=lambda s: s.score if s.score is not None else 101)
    scored = [s.score for s in scans if s.score is not None]
    problems = Counter()
    names = {}
    secrets = 0
    for s in scans:
        for c in s.results or []:
            if not c.get('passed') and _counts(c):
                problems[c['check_id']] += 1
                names.setdefault(c['check_id'], c.get('name', c['check_id']))
                if c['check_id'] in ('security.no_secrets', 'security.env_not_committed'):
                    secrets += 1
    from app.check_guides import GUIDES
    return render(request, 'app/org_scan.html', {
        'row': row,
        'org': row.org,
        'scans': scans,
        'done': len(scans),
        'pending': max(0, len(row.repos) - len(scans)),
        'running': row.status in ('pending', 'running'),
        'average': round(sum(scored) / len(scored)) if scored else None,
        'worst': scans[:5],
        'common': [(cid, names[cid], n, cid in GUIDES) for cid, n in problems.most_common(8)],
        'secrets': secrets,
        'canonical': f'{settings.BASE_URL}/scan/org/{row.org}/',
    })
