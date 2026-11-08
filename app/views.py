import base64
import hashlib
import hmac
import json
import logging

import requests
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from datetime import timedelta
from functools import wraps

from app.models import (
    Audit, AuditCheck, GithubProfile, GitlabProfile, MonthlyUsage,
    PublicScan, UserSubscription, UserAISettings, UserProfile,
)
from app.dns_utils import custom_dns_server
from app.checks import counts as _counts  # noqa: E402

logger = logging.getLogger(__name__)

FREE_REPO_LIMIT = settings.FREE_REPO_LIMIT


def _repo_quota_exceeded(user, source, repo_key):
    """
    True when a free user is trying to audit a repository beyond their allowance.

    Re-auditing a repository they have already used never counts against the
    limit — the limit is on how many repositories they watch, not how often.
    """
    sub = _get_subscription(user)
    if sub.is_pro:
        return False
    used = _tracked_repo_count(user, source)
    already_used = Audit.objects.filter(
        user=user, source=source, repo_full_name=repo_key,
    ).active().exists()
    return used >= FREE_REPO_LIMIT and not already_used


def _tracked_repo_count(user, source=None):
    """
    Repositories occupying the user's quota right now.

    Removed repositories do not count — that is the whole point of being able to
    remove one. Every surface that shows "x of 3" reads it from here so the
    dashboard, the profile page and the billing page cannot disagree.
    """
    qs = Audit.objects.filter(user=user)
    if source:
        qs = qs.filter(source=source)
    return qs.tracked_repo_count()


def _start_audit(user, repo_full_name, repo_url, source, language='en',
                 trigger=Audit.TRIGGER_MANUAL, pr_number=None, commit_sha='', ref=''):
    """
    Create a new audit run and queue it.

    Every run is its own row. The previous implementation reused one row per
    repository and wiped it, which made the score history permanently one point
    long and the trend chart impossible.
    """
    from app.tasks import run_audit_task

    # Auditing a repository the user had removed puts it back, history and all.
    # Leaving the old rows archived would give the repository two disjoint
    # histories and a trend chart that starts again from nothing.
    Audit.restore_repo(user, source, repo_full_name)

    audit = Audit.objects.create(
        user=user,
        repo_full_name=repo_full_name,
        repo_url=repo_url,
        source=source,
        language=language if language in ('en', 'ru') else 'en',
        trigger=trigger,
        pr_number=pr_number,
        commit_sha=commit_sha or '',
        ref=(ref or '')[:255],
    )
    task = run_audit_task.delay(audit.id)
    audit.celery_task_id = task.id
    audit.save(update_fields=['celery_task_id'])
    MonthlyUsage.for_user(user).consume('audits')
    from app import funnel
    funnel.record('first_private_scan', user=user, ref=repo_full_name, once_per_user=True)
    return audit


def _lang(request):
    return getattr(request, 'LANGUAGE_CODE', 'en') or 'en'


def _get_subscription(user):
    sub, _ = UserSubscription.objects.get_or_create(user=user)
    return sub


def _get_profile(user):
    profile, _ = UserProfile.objects.get_or_create(user=user)
    return profile


def _bearer_auth(view_func):
    """Decorator: authenticate via Bearer token for API endpoints."""
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        auth = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth.startswith('Bearer '):
            return JsonResponse({'error': 'Authorization required'}, status=401)
        token = auth[7:]
        try:
            profile = UserProfile.objects.select_related('user').get(api_token=token)
            request.api_user = profile.user
        except UserProfile.DoesNotExist:
            return JsonResponse({'error': 'Invalid token'}, status=401)
        return view_func(request, *args, **kwargs)
    return _wrapped


# ── Helpers ───────────────────────────────────────────────────────────────────

def _oauth_ctx():
    from app import github_app
    return {
        'github_app_enabled': github_app.is_configured() and bool(settings.GITHUB_APP_SLUG),
        'github_enabled': bool(getattr(settings, 'GITHUB_CLIENT_ID', '')),
        'gitlab_enabled': bool(getattr(settings, 'GITLAB_APP_ID', '')),
        'google_enabled': bool(getattr(settings, 'GOOGLE_CLIENT_ID', '')),
    }


# ── Landing ───────────────────────────────────────────────────────────────────

LANDING_DEMO_REPOS = ['django/django', 'fastapi/fastapi', 'expressjs/express']
LANDING_DEMO_SLOTS = 3


def landing(request):
    if request.user.is_authenticated:
        return redirect('connect')

    # Real scans of real repositories, in place of the invented testimonials
    # that used to sit here.
    #
    # This is the only section on the page that proves the product works, so it
    # is never allowed to prove nothing. The pinned repositories come first when
    # they have a finished scan; any empty slot is filled from the public scans
    # that already exist, most-viewed first. A card without a score is a last
    # resort, shown only when the database has nothing to show at all.
    def _card(scan, repo=None):
        if scan is None:
            return {'repo': repo, 'score': None, 'color': 'gray', 'issues': 0, 'crit': 0}
        applicable = [c for c in (scan.results or []) if _counts(c)]
        failed = [c for c in applicable if not c.get('passed')]
        return {
            'repo': scan.repo_full_name,
            'score': scan.score,
            'color': scan.score_color,
            'issues': len(failed),
            # A critical counts thirty points and an info counts five, so a card
            # reading "11 issues · 84" next to "2 issues · 76" looks like the
            # counter is broken. Naming the criticals is what explains the gap.
            'crit': sum(1 for c in failed if c.get('severity') == 'crit'),
        }

    done = PublicScan.objects.filter(status=Audit.STATUS_DONE, score__isnull=False)
    pinned = {s.repo_full_name.lower(): s for s in
              done.filter(repo_full_name__in=LANDING_DEMO_REPOS)}

    demo_scans = [_card(pinned[r.lower()]) for r in LANDING_DEMO_REPOS
                  if r.lower() in pinned]

    if len(demo_scans) < LANDING_DEMO_SLOTS:
        taken = {c['repo'].lower() for c in demo_scans}
        for scan in done.order_by('-view_count', '-updated_at')[:LANDING_DEMO_SLOTS * 4]:
            if len(demo_scans) >= LANDING_DEMO_SLOTS:
                break
            if scan.repo_full_name.lower() in taken:
                continue
            demo_scans.append(_card(scan))
            taken.add(scan.repo_full_name.lower())

    # Still short: fall back to the pinned names, which at least link through
    # and start a real scan when clicked.
    for repo in LANDING_DEMO_REPOS:
        if len(demo_scans) >= LANDING_DEMO_SLOTS:
            break
        if repo.lower() not in {c['repo'].lower() for c in demo_scans}:
            demo_scans.append(_card(None, repo))

    # The hero used to show a mocked terminal session for a command-line tool
    # that does not exist. Show the actual report instead, with real data from a
    # real repository — people buy what they can see.
    hero = (PublicScan.objects
            .filter(status=Audit.STATUS_DONE, score__isnull=False)
            .exclude(results=[])
            .order_by('-view_count')
            .first())
    hero_ctx = None
    if hero:
        results = [c for c in (hero.results or []) if _counts(c)]
        failed = [c for c in results if not c.get('passed')]
        order = {'crit': 0, 'warn': 1, 'info': 2}
        failed.sort(key=lambda c: order.get(c.get('severity'), 3))
        cats = list((hero.category_scores or {}).items())[:5]
        hero_ctx = {
            'repo': hero.repo_full_name,
            'score': hero.score,
            'color': hero.score_color,
            'label': hero.primary_language or 'repository',
            'categories': [{'name': k, 'value': v} for k, v in cats],
            'findings': failed[:4],
            'passed': len(results) - len(failed),
            'failed': len(failed),
            'total': len(results),
        }

    from app import funnel
    fresh = not request.COOKIES.get('dvl')
    if fresh:
        funnel.record('visit_landing', request)
    response = render(request, 'app/landing.html', {
        'base_url': settings.BASE_URL,
        'og_repo': LANDING_DEMO_REPOS[0],
        'demo_scans': demo_scans,
        'hero_scan': hero_ctx,
        # Same rows the pricing page builds, so the landing cannot advertise a
        # price the pricing page contradicts.
        'plans': {row['key']: row for row in _plan_rows('monthly')},
        'annual_discount': settings.ANNUAL_DISCOUNT_PCT,
        'free_limit': FREE_REPO_LIMIT,
        'support_email': settings.SUPPORT_EMAIL,
    })
    if fresh:
        # One landing visit per browser per 12 hours, not one per reload.
        response.set_cookie('dvl', '1', max_age=12 * 3600, httponly=True, samesite='Lax')
    return response


# ── Auth ──────────────────────────────────────────────────────────────────────

def register_view(request):
    if request.user.is_authenticated:
        return redirect('connect')

    if request.method == 'POST':
        username  = request.POST.get('username', '').strip()
        email     = request.POST.get('email', '').strip()
        password  = request.POST.get('password', '')
        password2 = request.POST.get('password2', '')

        ctx = {'mode': 'register', 'username': username, 'email': email, **_oauth_ctx()}

        if not username:
            return render(request, 'app/auth.html', {**ctx, 'error': _('Enter a username')})
        if len(username) < 3:
            return render(request, 'app/auth.html', {**ctx, 'error': _('Username must be at least 3 characters')})
        if not username.replace('_', '').replace('-', '').isalnum():
            return render(request, 'app/auth.html', {**ctx, 'error': _('Username: letters, numbers, _ and - only')})
        if User.objects.filter(username=username).exists():
            return render(request, 'app/auth.html', {**ctx, 'error': _('User already exists')})
        if email and User.objects.filter(email=email).exists():
            return render(request, 'app/auth.html', {**ctx, 'error': _('This email is already registered.')})
        if len(password) < 6:
            return render(request, 'app/auth.html', {**ctx, 'error': _('Password must be at least 6 characters')})
        if password != password2:
            return render(request, 'app/auth.html', {**ctx, 'error': _('Passwords do not match')})

        user = User.objects.create_user(username=username, email=email, password=password)
        UserProfile.objects.get_or_create(user=user)
        from app import funnel
        funnel.record('signup', request, user=user)
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        next_url = request.GET.get('next', '')
        if next_url and next_url.startswith('/') and not next_url.startswith('//'):
            return redirect(next_url)
        return redirect('onboarding')

    return render(request, 'app/auth.html', {'mode': 'register', **_oauth_ctx()})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('connect')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        if not username or not password:
            return render(request, 'app/auth.html', {
                'mode': 'login', 'error': _('Enter username and password'), **_oauth_ctx()
            })

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', '')
            if next_url and next_url.startswith('/') and not next_url.startswith('//'):
                return redirect(next_url)
            return redirect('connect')

        # Проверяем существует ли пользователь вообще
        if User.objects.filter(username=username).exists():
            error = _('Incorrect password. Please try again.')
        else:
            error = _('Enter username and password')

        return render(request, 'app/auth.html', {
            'mode': 'login', 'error': error, 'username': username, **_oauth_ctx()
        })

    return render(request, 'app/auth.html', {'mode': 'login', **_oauth_ctx()})


def logout_view(request):
    logout(request)
    request.session.flush()
    return redirect('landing')


# ── PAT Connect ───────────────────────────────────────────────────────────────

@login_required
def connect(request):
    ctx = _connect_context(request)
    ctx['settings_success'] = request.GET.get('settings_success')
    ctx['settings_error']   = request.GET.get('settings_error')
    ctx['pwd_success']      = request.GET.get('pwd_success')
    ctx['pwd_error']        = request.GET.get('pwd_error')
    return render(request, 'app/connect.html', ctx)


@login_required
@require_POST
def connect_token(request):
    provider = request.POST.get('provider', '')
    token    = request.POST.get('token', '').strip()

    if not token:
        return _pat_error(request, provider, _('Enter token'))

    if provider == 'github':
        return _connect_github_pat(request, token)
    elif provider == 'gitlab':
        gitlab_url = request.POST.get('gitlab_url', 'https://gitlab.com').rstrip('/')
        verify_ssl = request.POST.get('verify_ssl') != 'off'
        custom_dns = request.POST.get('custom_dns', '').strip()
        return _connect_gitlab_pat(request, token, gitlab_url, verify_ssl, custom_dns)

    return redirect('connect')


def _connect_github_pat(request, token):
    try:
        resp = requests.get(
            'https://api.github.com/user',
            headers={'Authorization': f'token {token}', 'Accept': 'application/vnd.github.v3+json'},
            timeout=10,
        )
        if resp.status_code == 401:
            return _pat_error(request, 'github', _('Invalid token. Required scopes: repo, read:user'))
        if resp.status_code != 200:
            return _pat_error(request, 'github', f'GitHub вернул ошибку {resp.status_code}. Попробуйте снова.')

        gh = resp.json()
        # Remove any profile for this github_id that belongs to another user (allow re-linking)
        GithubProfile.objects.filter(github_id=gh['id']).exclude(user=request.user).delete()
        # Get or create for this user + github_id pair
        profile, created = GithubProfile.objects.get_or_create(
            user=request.user,
            github_id=gh['id'],
            defaults={
                'github_login': gh['login'],
                'access_token': token,
                'avatar_url':   gh.get('avatar_url', ''),
            }
        )
        if not created:
            profile.github_login = gh['login']
            profile.access_token = token
            profile.avatar_url   = gh.get('avatar_url', '')
            profile.save()

        # Name the account. GitHub issues a token to whichever account the
        # browser is signed in as, which is not always the one the reader had in
        # mind — and saying nothing made a token for the account they already
        # had look like the product connecting the wrong one.
        if created:
            messages.success(request, _('GitHub account @%(login)s connected.')
                             % {'login': gh['login']})
        else:
            messages.info(request, _(
                'That token belongs to @%(login)s, which is already connected — '
                'its token has been refreshed. To add a different account, create '
                'the token while signed in to GitHub as that account.'
            ) % {'login': gh['login']})
        return redirect('dashboard')

    except requests.exceptions.Timeout:
        return _pat_error(request, 'github', 'GitHub не отвечает. Проверьте соединение.')
    except Exception as e:
        return _pat_error(request, 'github', f'Ошибка подключения: {e}')


def _connect_gitlab_pat(request, token, gitlab_url, verify_ssl=True, custom_dns=''):
    try:
        with custom_dns_server(custom_dns):
            resp = requests.get(
                f'{gitlab_url}/api/v4/user',
                headers={'Authorization': f'Bearer {token}'},
                timeout=10,
                verify=verify_ssl,
            )
        if resp.status_code == 401:
            return _pat_error(request, 'gitlab', _('Invalid token. Required scopes: read_user, read_api'))
        if resp.status_code == 404:
            return _pat_error(request, 'gitlab', f'Сервер не найден: {gitlab_url}. Проверьте URL.')
        if resp.status_code != 200:
            return _pat_error(request, 'gitlab', f'GitLab вернул ошибку {resp.status_code}.')

        gl = resp.json()

        # Verify the token also has read_api scope (needed to list projects)
        with custom_dns_server(custom_dns):
            scope_check = requests.get(
                f'{gitlab_url}/api/v4/projects',
                headers={'Authorization': f'Bearer {token}'},
                params={'membership': True, 'per_page': 1},
                timeout=10,
                verify=verify_ssl,
            )
        if scope_check.status_code == 403:
            return _pat_error(
                request, 'gitlab',
                _("Token doesn't have the required permissions. Add scope: read_api (or api) when creating the token.")
            )

        GitlabProfile.objects.filter(gitlab_id=gl['id']).exclude(user=request.user).delete()
        _profile, created = GitlabProfile.objects.update_or_create(
            user=request.user, gitlab_id=gl['id'],
            defaults={
                'gitlab_username': gl['username'],
                'access_token':    token,
                # A PAT replacing an earlier OAuth connection must drop the
                # OAuth refresh state, or current_token would see the old
                # expiry, "refresh", and overwrite this PAT with a new OAuth
                # token — silently undoing the reconnect.
                'refresh_token':    '',
                'token_expires_at': None,
                'avatar_url':      gl.get('avatar_url', ''),
                'gitlab_url':      gitlab_url,
                'verify_ssl':      verify_ssl,
                'custom_dns':      custom_dns,
            }
        )
        # Same reason as GitHub: name the account, so a refreshed token is not
        # mistaken for the wrong account being connected.
        if created:
            messages.success(request, _('GitLab account @%(login)s connected.')
                             % {'login': gl['username']})
        else:
            messages.info(request, _(
                'That token belongs to @%(login)s, which is already connected — '
                'its token has been refreshed.'
            ) % {'login': gl['username']})
        return redirect('gitlab_dashboard')

    except requests.exceptions.SSLError:
        return _pat_error(
            request, 'gitlab',
            f'Ошибка SSL-сертификата: {gitlab_url}. '
            'Если сервер использует самоподписанный сертификат, '
            'отключите проверку SSL в форме ниже.'
        )
    except requests.exceptions.ConnectionError as e:
        err = str(e)
        if 'NameResolutionError' in err or 'Name or service not known' in err or 'nodename nor servname' in err:
            return _pat_error(
                request, 'gitlab',
                f'Не удалось разрешить DNS для {gitlab_url}. '
                'Это может быть внутренний адрес, недоступный с сервера приложения. '
                'Убедитесь, что GitLab доступен из сети, где развёрнут сервис, '
                'или укажите IP-адрес сервера напрямую (например, https://192.168.1.10).'
            )
        return _pat_error(request, 'gitlab', f'Не удалось подключиться к {gitlab_url}. Проверьте URL и доступность сервера.')
    except requests.exceptions.Timeout:
        return _pat_error(request, 'gitlab', f'{gitlab_url} не отвечает. Сервер недоступен.')
    except Exception as e:
        return _pat_error(request, 'gitlab', f'Ошибка: {e}')


def _connect_context(request):
    github_profiles = GithubProfile.objects.filter(user=request.user)
    sub = _get_subscription(request.user)
    raw_audits = Audit.objects.filter(user=request.user).active().order_by('-created_at')[:30]
    audits = []
    for a in raw_audits:
        name = a.repo_full_name.split('::')[0] if '::' in a.repo_full_name else a.repo_full_name
        audits.append({
            'id': a.id, 'name': name, 'source': a.source, 'status': a.status,
            'score': a.score, 'score_label': a.score_label, 'score_color': a.score_color,
            'completed_at': a.completed_at,
        })
    gh_count = _tracked_repo_count(request.user, Audit.SOURCE_GITHUB)
    gl_count = _tracked_repo_count(request.user, Audit.SOURCE_GITLAB)
    ai_cfg = None
    try:
        ai_cfg = request.user.ai_settings
    except Exception:
        pass
    user_profile = _get_profile(request.user)
    user_profile.ensure_webhook_secret()
    user_profile.ensure_api_token()
    webhook_url = f"{settings.BASE_URL}/webhook/github/{user_profile.webhook_secret}/"
    gitlab_profiles = GitlabProfile.objects.filter(user=request.user)
    # A connection that stopped working is the first thing the owner needs to
    # see. Until this existed, an expired token showed up as the dashboard
    # link doing nothing at all.
    broken = [p for p in list(github_profiles) + list(gitlab_profiles) if not p.is_healthy]
    return {
        'github_profiles': github_profiles,
        'gitlab_profiles': gitlab_profiles,
        'broken_connections': broken,
        'github_needs_token': any(not p.is_healthy for p in github_profiles),
        'gitlab_needs_token': any(not p.is_healthy for p in gitlab_profiles),
        'subscription':    sub,
        'repo_count':      gh_count + gl_count,
        'free_limit':      FREE_REPO_LIMIT,
        'audits':          audits,
        'ai_cfg':          ai_cfg,
        'user_profile':    user_profile,
        'webhook_url':     webhook_url,
        'api_token':       user_profile.api_token,
        # The template has always checked github_app_enabled, but only the
        # login page was given it — so the one-click App install on this
        # page never rendered, and GitLab had no OAuth button at all.
        **_oauth_ctx(),
    }


def _pat_error(request, provider, msg):
    ctx = _connect_context(request)
    ctx[f'{provider}_error'] = msg
    return render(request, 'app/connect.html', ctx)


@login_required
@require_POST
def disconnect_provider(request, provider, provider_id):
    if provider == 'github':
        try:
            GithubProfile.objects.filter(user=request.user, id=int(provider_id)).delete()
        except (ValueError, TypeError):
            GithubProfile.objects.filter(user=request.user).delete()
    elif provider == 'gitlab':
        try:
            GitlabProfile.objects.filter(user=request.user, id=int(provider_id)).delete()
        except (ValueError, TypeError):
            GitlabProfile.objects.filter(user=request.user).delete()
    return redirect('connect')


@login_required
@require_POST
def remove_repo(request):
    """
    Take a repository off the user's list and give the quota slot back.

    Nothing is deleted. The runs are kept and the repository can be restored
    from the billing page with its score history intact — a free user who has
    filled three slots needs a way out that is not "delete your reports".
    """
    source = request.POST.get('source', '')
    repo = request.POST.get('repo', '').strip()
    if source in (Audit.SOURCE_GITHUB, Audit.SOURCE_GITLAB) and repo:
        Audit.archive_repo(request.user, source, repo)
    return redirect(request.POST.get('next') or 'dashboard')


@login_required
@require_POST
def restore_repo(request):
    """Put a removed repository back, if there is a slot free for it."""
    source = request.POST.get('source', '')
    repo = request.POST.get('repo', '').strip()
    if source not in (Audit.SOURCE_GITHUB, Audit.SOURCE_GITLAB) or not repo:
        return redirect('billing')

    # The quota is checked on the way back in, not only on the way out.
    # Otherwise removing three repositories and restoring them all would be a
    # free upgrade to unlimited.
    if _repo_quota_exceeded(request.user, source, repo):
        return redirect(f"{reverse('billing')}?repo_limit=1")

    Audit.restore_repo(request.user, source, repo)
    return redirect(request.POST.get('next') or 'billing')


# ── GitHub / GitLab OAuth ─────────────────────────────────────────────────────
#
# Handled by django-allauth. `/accounts/<provider>/login/` and its callback are
# allauth's views, and `{% url 'github_login' %}` resolves to them.
#
# Hand-written `github_login`, `github_callback`, `gitlab_login` and
# `gitlab_callback` used to sit here, routed by nothing. They were removed
# because the callback was a sign-in flow wearing a connect flow's name: it
# ignored `request.user` entirely, so a signed-in customer who ever reached it
# would have been logged into whichever account already owned that GitHub id —
# or into a brand-new user created on the spot, losing the session they arrived
# with. Dead code that dangerous is worth deleting rather than leaving to be
# wired up by someone in a hurry.
#
# Adding a second account goes through the GitHub App install or a personal
# access token (`_connect_github_pat`), both of which key on
# `(request.user, github_id)` and hold as many accounts as the customer has.


# ── GitHub App ────────────────────────────────────────────────────────────────


def github_app_install(request):
    """Send the user to GitHub to install the App on their account or organisation."""
    from app import github_app
    if not github_app.is_configured() or not settings.GITHUB_APP_SLUG:
        messages.error(request, _('One-click GitHub install is not configured on this deployment. '
                                  'Connect with a personal access token instead.'))
        return redirect('connect')
    return redirect(github_app.install_url(state=str(request.user.id) if request.user.is_authenticated else ''))


@login_required
def github_app_callback(request):
    """
    GitHub sends the user back here after installing the App.

    The installation id is what identifies the account from now on; access
    tokens are minted per request and never stored.
    """
    from app import github_app

    installation_id = request.GET.get('installation_id')
    if not installation_id:
        messages.error(request, _('GitHub did not return an installation. Please try again.'))
        return redirect('connect')

    try:
        installation_id = int(installation_id)
        account = github_app.installation_account(installation_id)
        token, _expires = github_app.installation_token(installation_id)
    except Exception:
        logger.exception('GitHub App callback failed')
        messages.error(request, _('Could not complete the GitHub installation. Please try again.'))
        return redirect('connect')

    login_name = account.get('login', '') or 'github'
    account_id = account.get('id') or installation_id

    profile, _created = GithubProfile.objects.update_or_create(
        user=request.user, github_id=account_id,
        defaults={
            'github_login': login_name,
            'access_token': token,
            'avatar_url': account.get('avatar_url', '') or '',
            'installation_id': installation_id,
        },
    )
    messages.success(request, _('GitHub connected — %(name)s') % {'name': login_name})
    from app import funnel
    funnel.record('app_installed', request, once_per_user=True)
    return redirect('dashboard')


@login_required
def dashboard(request):
    github_profiles = GithubProfile.objects.filter(user=request.user)
    if not github_profiles.exists():
        return redirect('connect')

    repos = []
    expired_ids = []
    for gh_profile in github_profiles:
        try:
            resp = requests.get(
                'https://api.github.com/user/repos?sort=pushed&per_page=30&type=owner',
                headers={'Authorization': f'token {gh_profile.current_token}', 'Accept': 'application/vnd.github.v3+json'},
                timeout=10,
            )
            if resp.status_code == 200:
                gh_profile.mark_working()
                for repo in resp.json():
                    repo['account_login'] = gh_profile.github_login
                    repos.append(repo)
            elif resp.status_code == 401:
                # Deleting the connection on a single 401 loses the installation
                # id with it, turning a token refresh into a full re-install.
                gh_profile.mark_broken(GithubProfile.EXPIRED)
                expired_ids.append(gh_profile.id)
            elif resp.status_code == 403:
                gh_profile.mark_broken(GithubProfile.FORBIDDEN)
        except Exception:
            gh_profile.mark_broken(GithubProfile.UNREACHABLE)

    # A dead token used to bounce the customer to the connect page. Their audits
    # are still in the database and still readable — sending them away means a
    # paying customer opens the product and finds nothing they paid for. Show the
    # dashboard, say what is wrong, and keep the finished reports reachable.
    connection_broken = bool(expired_ids) and not repos

    seen = set()
    unique_repos = []
    for repo in repos:
        if repo['id'] not in seen:
            seen.add(repo['id'])
            unique_repos.append(repo)

    latest = list(Audit.objects.filter(user=request.user, source=Audit.SOURCE_GITHUB).latest_per_repo())

    # Repositories that hold a quota slot but are not in the list above: the
    # token is dead, or the repository was deleted, renamed or transferred on
    # GitHub. They used to be shown only when the whole list failed to load, so
    # a slot could be occupied by something the customer could not see anywhere
    # — and therefore could not remove.
    live = {r['full_name'] for r in unique_repos}
    orphans = [a for a in latest if a.repo_full_name not in live]

    return render(request, 'app/dashboard.html', {
        'repos':             unique_repos,
        'audits_by_repo':    {a.repo_full_name: a for a in latest},
        'past_audits':       orphans,
        'connection_broken': connection_broken,
        'profile':           github_profiles.first(),
        'github_profiles':   github_profiles,
        # The template used to carry its own hardcoded 3, which is how a
        # settings change would have moved the limit everywhere but here.
        'repos_used':        len(latest),
        'free_limit':        FREE_REPO_LIMIT,
        'removed_repos':     Audit.removed_repos(request.user, Audit.SOURCE_GITHUB),
    })


@login_required
@require_POST
def start_audit_for_repo(request):
    repo_full_name = request.POST.get('repo', '').strip()
    repo_url       = request.POST.get('repo_url', '') or f'https://github.com/{repo_full_name}'

    if not repo_full_name:
        return redirect('dashboard')

    if _repo_quota_exceeded(request.user, Audit.SOURCE_GITHUB, repo_full_name):
        return redirect('billing')

    audit = _start_audit(
        request.user, repo_full_name, repo_url,
        Audit.SOURCE_GITHUB, language=_lang(request),
    )
    return redirect('audit_detail', audit_id=audit.id)


@login_required
def gitlab_dashboard(request):
    gitlab_profiles = GitlabProfile.objects.filter(user=request.user)
    if not gitlab_profiles.exists():
        return redirect('connect')

    profile       = gitlab_profiles.first()
    projects      = []
    projects_error = None
    try:
        with custom_dns_server(profile.custom_dns):
            resp = requests.get(
                f'{profile.gitlab_url}/api/v4/projects',
                headers={'Authorization': f'Bearer {profile.current_token}'},
                params={'membership': True, 'order_by': 'last_activity_at', 'per_page': 30},
                timeout=10,
                verify=profile.verify_ssl,
            )
        if resp.status_code == 200:
            projects = resp.json()
            profile.mark_working()
        elif resp.status_code == 401:
            # Bouncing back to the profile page reads as the page refusing to
            # load. Say what happened and keep the connection so reconnecting
            # is one step rather than a re-setup.
            profile.mark_broken(GitlabProfile.EXPIRED)
            return redirect('connect')
        elif resp.status_code == 403:
            profile.mark_broken(GitlabProfile.FORBIDDEN)
            projects_error = _("Token doesn't have permission to read projects. Recreate the token with scope: read_api")
        else:
            projects_error = _('GitLab returned error %(code)s. Try reconnecting your account.') % {'code': resp.status_code}
    except requests.exceptions.Timeout:
        profile.mark_broken(GitlabProfile.UNREACHABLE)
        projects_error = _('GitLab is not responding. Check server availability.')
    except Exception:
        profile.mark_broken(GitlabProfile.UNREACHABLE)
        projects_error = _('Failed to load projects. Check your connection.')

    audits_by_id = {}
    for a in Audit.objects.filter(user=request.user, source=Audit.SOURCE_GITLAB).latest_per_repo():
        parts = a.repo_full_name.split('::')
        if len(parts) > 1:
            try:
                audits_by_id[int(parts[1])] = a
            except ValueError:
                pass

    return render(request, 'app/gitlab_dashboard.html', {
        'projects':        projects,
        'projects_error':  projects_error,
        'audits_by_id':    audits_by_id,
        'profile':         profile,
        'gitlab_profiles': gitlab_profiles,
        'repos_used':      _tracked_repo_count(request.user, Audit.SOURCE_GITLAB),
        'free_limit':      FREE_REPO_LIMIT,
        'removed_repos':   Audit.removed_repos(request.user, Audit.SOURCE_GITLAB),
    })


@login_required
@require_POST
def start_gitlab_audit(request):
    project_id   = request.POST.get('project_id', '').strip()
    project_name = request.POST.get('project_name', '')
    project_url  = request.POST.get('project_url', '')

    if not project_id:
        return redirect('gitlab_dashboard')

    repo_key = f'{project_name}::{project_id}'
    if _repo_quota_exceeded(request.user, Audit.SOURCE_GITLAB, repo_key):
        return redirect('billing')

    audit = _start_audit(
        request.user, repo_key, project_url,
        Audit.SOURCE_GITLAB, language=_lang(request),
    )
    return redirect('audit_detail', audit_id=audit.id)


# ── Audit ─────────────────────────────────────────────────────────────────────

@login_required
def audit_detail(request, audit_id):
    audit  = get_object_or_404(Audit, id=audit_id, user=request.user)
    checks = audit.checks.all()
    sub = _get_subscription(request.user)

    # Score over time for this repository. Audits are append-only, so this is a
    # real series rather than the single point the old one-row-per-repo model
    # could ever produce.
    history = list(
        Audit.objects.filter(
            user=request.user,
            source=audit.source,
            repo_full_name=audit.repo_full_name,
            status=Audit.STATUS_DONE,
            score__isnull=False,
        ).order_by('created_at').values('id', 'score', 'created_at', 'trigger', 'score_version')[:30]
    )
    # A run scored under a different methodology than the one before it: the
    # jump is the ruler moving, not the repository — say so on the chart.
    for prev, run in zip(history, history[1:]):
        run['method_changed'] = bool(prev['score_version'] and run['score_version']
                                     and prev['score_version'] != run['score_version'])
    from app.charts import series, color_for
    spark = series([h['score'] for h in history])
    method_marks = []
    if spark:
        for coord, point in zip(spark['coords'], history):
            coord['label'] = point['created_at'].strftime('%d %b')
            if point.get('method_changed'):
                method_marks.append(coord['x'])

    public_url = badge_url = ''
    if audit.is_public and audit.public_token:
        public_url = f"{settings.BASE_URL}/audit/public/{audit.public_token}/"
        badge_url = f"{settings.BASE_URL}/badge/{audit.public_token}/"

    # "Start here" — the three moves worth making first, and what they are worth.
    from app.action_plan import build as build_action_plan
    plan = build_action_plan(checks) if audit.status == Audit.STATUS_DONE else None
    if plan:
        # Use the plan's own arithmetic for both ends so the projection is always
        # self-consistent, even for older rows whose stored score predates a
        # scoring change.
        plan['projected_display'] = plan['projected_score']

    usage = MonthlyUsage.for_user(request.user)
    # Checks the repository cannot act on are kept out of the two working lists
    # and shown on their own, with the reason. A check that simply vanished
    # would read as one that was quietly failed.
    not_applicable = checks.filter(applicable=False)
    return render(request, 'app/audit_detail.html', {
        'plan':         plan,
        'audit':        audit,
        'checks':       checks,
        'passed':       checks.counted().filter(passed=True),
        'failed':       checks.counted().filter(passed=False),
        'hygiene':      checks.hygiene().order_by('passed', 'name'),
        'not_applicable': not_applicable,
        'not_applicable_reason': (not_applicable.first().not_applicable_reason
                                  if not_applicable.exists() else ''),
        'subscription': sub,
        'incidents':    _incidents_for(audit),
        'repo_display': audit.repo_display,
        'history':      json.dumps(history, cls=DjangoJSONEncoder),
        'method_marks': method_marks,
        'history_rows': history,
        'history_count': len(history),
        'spark':        spark,
        'spark_color':  color_for(audit.score),
        'score_delta':  audit.score_delta,
        'public_url':   public_url,
        'badge_url':    badge_url,
        'base_url':     settings.BASE_URL,
        'pdf_credits_left': max(0, settings.FREE_PDF_PER_MONTH - usage.pdf_exports),
        'can_export_compliance': sub.is_compliance,
    })


@login_required
@require_POST
def run_audit(request, audit_id):
    """Re-run the audit. Creates a new run so the score history keeps growing."""
    audit = get_object_or_404(Audit, id=audit_id, user=request.user)
    if Audit.objects.filter(
        user=request.user, source=audit.source, repo_full_name=audit.repo_full_name,
        status__in=[Audit.STATUS_PENDING, Audit.STATUS_RUNNING],
    ).exists():
        return JsonResponse({'error': _('An audit for this repository is already running')}, status=400)

    if _repo_quota_exceeded(request.user, audit.source, audit.repo_full_name):
        return JsonResponse({'error': _('Free plan limit reached'), 'upgrade_url': '/billing/'}, status=403)

    new_audit = _start_audit(
        request.user, audit.repo_full_name, audit.repo_url,
        audit.source, language=_lang(request),
    )
    return JsonResponse({
        'status': 'started',
        'audit_id': new_audit.id,
        'redirect': f'/audit/{new_audit.id}/',
    })


@login_required
@require_POST
def regenerate_ai(request, audit_id):
    audit = get_object_or_404(Audit, id=audit_id, user=request.user)
    sub = _get_subscription(request.user)
    if not sub.is_pro:
        return JsonResponse({'error': 'PRO required'}, status=403)
    if audit.status == Audit.STATUS_RUNNING:
        return JsonResponse({'error': 'Audit is already running'}, status=400)
    if audit.status != Audit.STATUS_DONE:
        return JsonResponse({'error': 'Audit must be completed first'}, status=400)
    audit.status = Audit.STATUS_PENDING
    audit.save(update_fields=['status'])
    from app.tasks import regenerate_ai_task
    task = regenerate_ai_task.delay(audit.id)
    audit.celery_task_id = task.id
    audit.save(update_fields=['celery_task_id'])
    return JsonResponse({'status': 'started'})


@login_required
def audit_status(request, audit_id):
    audit = get_object_or_404(Audit, id=audit_id, user=request.user)
    return JsonResponse({
        'status':      audit.status,
        'score':       audit.score,
        'score_label': audit.score_label,
        'score_color': audit.score_color,
        # The reason a run failed is captured — say it out loud rather than
        # leaving the user to guess between an expired token, a renamed repo
        # and a spent API quota.
        'error':       audit.error_message,
        'can_retry':   audit.status == Audit.STATUS_FAILED,
    })


# ── Profile edit ─────────────────────────────────────────────────────────────

@login_required
@require_POST
def update_profile(request):
    username = request.POST.get('username', '').strip()
    email    = request.POST.get('email', '').strip()
    user     = request.user

    if username and username != user.username:
        if len(username) < 3:
            return redirect('/profile/?settings_error=username_short')
        if not username.replace('_', '').replace('-', '').isalnum():
            return redirect('/profile/?settings_error=username_invalid')
        if User.objects.filter(username=username).exclude(pk=user.pk).exists():
            return redirect('/profile/?settings_error=username_taken')
        user.username = username

    if email != user.email:
        if email and User.objects.filter(email=email).exclude(pk=user.pk).exists():
            return redirect('/profile/?settings_error=email_taken')
        user.email = email

    user.save()
    return redirect('/profile/?settings_success=1')


@login_required
@require_POST
def change_password(request):
    current_pw = request.POST.get('current_password', '')
    new_pw     = request.POST.get('new_password', '')
    confirm_pw = request.POST.get('confirm_password', '')

    if not request.user.check_password(current_pw):
        return redirect('/profile/?pwd_error=wrong')
    if len(new_pw) < 6:
        return redirect('/profile/?pwd_error=short')
    if new_pw != confirm_pw:
        return redirect('/profile/?pwd_error=mismatch')

    request.user.set_password(new_pw)
    request.user.save()
    login(request, request.user, backend='django.contrib.auth.backends.ModelBackend')
    return redirect('/profile/?pwd_success=1')


# ── Billing ───────────────────────────────────────────────────────────────────

def card_variant_for(plan, period):
    """
    The Lemon Squeezy variant that sells this (plan, period), or '' if none.

    LEMONSQUEEZY_VARIANT_ID predates plans and periods: it is one monthly Pro
    subscription. Serving any other combination from it charges the Pro monthly
    amount and still grants the larger plan or the longer period — so it only
    ever answers for (pro, monthly). Everything else needs its own
    LS_VARIANT_<PLAN>_<PERIOD>, and without one the billing page offers to
    invoice instead of showing a button that charges the wrong amount.
    """
    variant = settings.LS_VARIANTS.get((plan, period))
    if variant:
        return variant
    if (plan, period) == (UserSubscription.PLAN_PRO, 'monthly'):
        return settings.LEMONSQUEEZY_VARIANT_ID
    return ''


def crypto_enabled():
    return bool(settings.CRYPTOMUS_MERCHANT_ID and settings.CRYPTOMUS_API_KEY)


def _plan_rows(period='annual'):
    """Plan cards for the pricing tables. Shared by the public page and billing."""
    card_ok = bool(settings.LEMONSQUEEZY_API_KEY)
    rows = []
    for key in ('pro', 'team', 'compliance'):
        prices = settings.PLAN_PRICES[key]
        rows.append({
            'key': key,
            'monthly': prices['monthly'],
            'annual': prices['annual'],
            'annual_per_month': round(prices['annual'] / 12),
            'price': prices[period],
            'saving': prices['monthly'] * 12 - prices['annual'],
            # Card needs its own Lemon Squeezy variant per (plan, period) —
            # one variant cannot sell six different prices, and custom_price
            # only overrides the first charge, not what renews.
            'card_available': card_ok and bool(card_variant_for(key, period)),
            # Cryptomus is a one-off payment for the exact amount, so it sells
            # every plan and every period as soon as the keys are set. Card
            # needs a variant per (plan, period); check_payments reports which
            # are missing, and the checkout says so if one is clicked.
            'crypto_available': crypto_enabled(),
        })
    return rows


def pricing_page(request):
    """
    Public pricing. Deliberately not behind a login.

    /pricing/ used to point straight at billing_view, which is @login_required —
    so every visitor who clicked "Pricing" hit a sign-in wall, and robots.txt
    invited search engines to index that redirect.
    """
    if request.user.is_authenticated:
        return redirect('billing')

    period = request.GET.get('period', 'annual')
    if period not in ('monthly', 'annual'):
        period = 'annual'

    return render(request, 'app/pricing.html', {
        'plans': _plan_rows(period),
        'period': period,
        'annual_discount': settings.ANNUAL_DISCOUNT_PCT,
        'free_limit': FREE_REPO_LIMIT,
        'free_ai': settings.FREE_AI_REPORTS_PER_MONTH,
        'free_pdf': settings.FREE_PDF_PER_MONTH,
        'base_url': settings.BASE_URL,
        'support_email': settings.SUPPORT_EMAIL,
        'crypto_enabled': crypto_enabled(),
    })


@login_required
def billing_view(request):
    sub = _get_subscription(request.user)
    gh_count = _tracked_repo_count(request.user, Audit.SOURCE_GITHUB)
    gl_count = _tracked_repo_count(request.user, Audit.SOURCE_GITLAB)
    usage = MonthlyUsage.for_user(request.user)
    period = request.GET.get('period', 'annual')
    if period not in ('monthly', 'annual'):
        period = 'annual'

    plans = _plan_rows(period)
    # Buying the plan you are already subscribed to on Lemon Squeezy opens a
    # second subscription and charges the card again. A Cryptomus payment is a
    # one-off, so repeating it genuinely extends access — only the recurring
    # case has its purchase buttons closed off.
    recurring = (sub.stripe_subscription_id or '').startswith('ls_') and not sub.cancel_at_period_end
    for plan in plans:
        plan['current'] = sub.plan == plan['key'] and sub.is_active
        plan['renews'] = plan['current'] and recurring
        plan['extendable'] = plan['current'] and not recurring

    return render(request, 'app/billing.html', {
        'subscription':  sub,
        'plans':         plans,
        'period':        period,
        'annual_discount': settings.ANNUAL_DISCOUNT_PCT,
        'pro_price':     settings.PLAN_PRICES['pro']['monthly'],
        # The quota is enforced per provider, so a single "6 / 3" bar summing the
        # two was reporting a number the product does not actually apply. Each
        # provider gets its own row, and only the ones in use are shown.
        'repo_quota':    [
            row for row in (
                {'label': 'GitHub', 'used': gh_count, 'limit': FREE_REPO_LIMIT,
                 'url': reverse('dashboard')},
                {'label': 'GitLab', 'used': gl_count, 'limit': FREE_REPO_LIMIT,
                 'url': reverse('gitlab_dashboard')},
            ) if row['used'] or row['label'] == 'GitHub'
        ],
        'repo_count':    gh_count + gl_count,
        'free_limit':    FREE_REPO_LIMIT,
        'removed_repos': Audit.removed_repos(request.user),
        'repo_limit_hit': request.GET.get('repo_limit') == '1',
        'payment_mode':  settings.PAYMENT_MODE,
        'early_access':  not can_checkout(request.user),
        'crypto_enabled': crypto_enabled(),
        'support_email': settings.SUPPORT_EMAIL,
        'ai_credits_left':  max(0, settings.FREE_AI_REPORTS_PER_MONTH - usage.ai_reports),
        'pdf_credits_left': max(0, settings.FREE_PDF_PER_MONTH - usage.pdf_exports),
    })


def _response_body(resp):
    """Short provider response body for the log — checkout failures are silent otherwise."""
    return (getattr(resp, 'text', '') or '')[:500]


def _requested_plan(request):
    """(plan, period) from the checkout form, validated against what we sell."""
    plan = request.POST.get('plan', UserSubscription.PLAN_PRO)
    if plan not in settings.PLAN_PRICES:
        plan = UserSubscription.PLAN_PRO
    period = request.POST.get('period', 'monthly')
    if period not in ('monthly', 'annual'):
        period = 'monthly'
    return plan, period


def _period_days(period):
    return settings.ANNUAL_PERIOD_DAYS if period == 'annual' else settings.PRO_PERIOD_DAYS


def _activate_plan(sub, plan, period, provider='', subscription_id=''):
    sub.plan = plan
    sub.billing_period = period
    sub.payment_provider = provider or sub.payment_provider
    sub.current_period_end = timezone.now() + timedelta(days=_period_days(period))
    sub.cancel_at_period_end = False
    sub.expiry_notified_at = None
    if subscription_id:
        sub.stripe_subscription_id = subscription_id
    sub.save()
    from app import funnel
    funnel.record('paid', user=sub.user, ref=f'{plan}/{period}')
    return sub


@login_required
@require_POST
def cancel_subscription(request):
    sub = _get_subscription(request.user)

    if sub.stripe_subscription_id and sub.stripe_subscription_id.startswith('ls_'):
        ls_sub_id = sub.stripe_subscription_id[3:]
        try:
            requests.delete(
                f'https://api.lemonsqueezy.com/v1/subscriptions/{ls_sub_id}',
                headers={
                    'Authorization': f'Bearer {settings.LEMONSQUEEZY_API_KEY}',
                    'Accept': 'application/vnd.api+json',
                },
                timeout=10,
            )
        except Exception:
            pass
        sub.cancel_at_period_end = True
        sub.save(update_fields=['cancel_at_period_end'])
    else:
        # Crypto payments are one-off: there is nothing to cancel, access simply
        # runs to the end of the paid period.
        messages.info(request, _(
            'Crypto payments are one-off — nothing is charged again. '
            'Your access stays active until the end of the paid period.'
        ))

    return redirect('billing')


def can_checkout(user) -> bool:
    """Real checkout once payments are live; before that, staff only (to test it)."""
    return settings.PAYMENTS_LIVE or bool(getattr(user, 'is_staff', False))


@login_required
@require_POST
def early_access(request):
    """
    Record interest in a plan while payments are not live.

    Answers "you are on the list" and nothing else: no plan is granted, no
    charge is attempted. The owner gets one line by mail so demand is visible
    the day it happens.
    """
    from app.models import PlanInterest
    plan, period = _requested_plan(request)
    email = request.user.email or ''
    from app import funnel
    funnel.record('early_access', request, ref=f'{plan}/{period}')
    if not PlanInterest.objects.filter(user=request.user, plan=plan, period=period).exists():
        PlanInterest.objects.create(user=request.user, email=email, plan=plan, period=period)
        try:
            from django.core.mail import mail_admins, send_mail
            send_mail(f'[DevOpsCheck] early access: {plan}/{period}',
                      f'{email or "user #%s" % request.user.id} asked for {plan} ({period}).',
                      settings.DEFAULT_FROM_EMAIL, [settings.SUPPORT_EMAIL], fail_silently=True)
        except Exception:
            logger.warning('early access notification failed', exc_info=True)
    messages.success(request, _("You're on the early-access list for %(plan)s. We'll email you the day "
                                "paid plans open — at the launch price shown here.") % {'plan': plan.title()})
    return redirect(f"{reverse('billing')}?period={period}")


@login_required
@require_POST
def create_crypto_checkout(request):
    """Redirect to the Cryptomus hosted invoice for a one-off crypto payment."""
    if not can_checkout(request.user):
        return redirect('billing')
    from app import funnel
    funnel.record('checkout_started', request, ref=request.POST.get('plan', ''))
    if not settings.CRYPTOMUS_MERCHANT_ID or not settings.CRYPTOMUS_API_KEY:
        messages.error(request, _('Crypto payments are not configured yet. Please pay by card or contact support.'))
        return redirect('billing')

    plan, period = _requested_plan(request)
    amount = settings.PLAN_PRICES[plan][period]

    try:
        # order_id carries what was bought; the IPN has no other way to know.
        order_id = f'{request.user.id}-{plan}-{period}-{int(timezone.now().timestamp())}'
        payload = {
            'amount': str(amount),
            'currency': 'USD',
            'order_id': order_id,
            'url_callback': settings.BASE_URL + '/billing/webhooks/crypto/',
            'url_success': settings.BASE_URL + '/billing/success/',
            'url_return': settings.BASE_URL + '/billing/cancel/',
        }
        body = json.dumps(payload)
        sign = hashlib.md5(
            (base64.b64encode(body.encode()).decode() + settings.CRYPTOMUS_API_KEY).encode()
        ).hexdigest()
        resp = requests.post(
            'https://api.cryptomus.com/v1/payment',
            headers={
                'merchant': settings.CRYPTOMUS_MERCHANT_ID,
                'sign': sign,
                'Content-Type': 'application/json',
            },
            data=body,
            timeout=15,
        )
        resp.raise_for_status()
        return redirect(resp.json()['result']['url'])
    except Exception:
        logger.exception(
            'Cryptomus checkout failed (plan=%s period=%s): %s',
            plan, period, _response_body(locals().get('resp')),
        )
        messages.error(request, _('Crypto checkout is temporarily unavailable. Please try paying by card.'))
        return redirect('billing')


@login_required
@require_POST
def create_ls_checkout(request):
    """Create a Lemon Squeezy checkout for the requested plan and billing period."""
    if not can_checkout(request.user):
        return redirect('billing')
    from app import funnel
    funnel.record('checkout_started', request, ref=request.POST.get('plan', ''))
    if not settings.LEMONSQUEEZY_API_KEY:
        messages.error(request, _('Payments are not configured.'))
        return redirect('billing')

    plan, period = _requested_plan(request)
    variant = card_variant_for(plan, period)
    if not variant:
        messages.error(request, _('This plan is not available for card payment yet. Please pay with crypto or contact support.'))
        return redirect('billing')

    # Lemon Squeezy rejects an empty email with a 422, and registration does not
    # require one — so omit the key entirely and let the checkout page ask.
    checkout_data = {'custom': {
        'user_id': str(request.user.id),
        'plan': plan,
        'period': period,
    }}
    if request.user.email:
        checkout_data['email'] = request.user.email

    try:
        resp = requests.post(
            'https://api.lemonsqueezy.com/v1/checkouts',
            headers={
                'Authorization': f'Bearer {settings.LEMONSQUEEZY_API_KEY}',
                'Accept': 'application/vnd.api+json',
                'Content-Type': 'application/vnd.api+json',
            },
            json={
                'data': {
                    'type': 'checkouts',
                    'attributes': {
                        'checkout_data': checkout_data,
                        'product_options': {
                            'redirect_url': settings.BASE_URL + '/billing/success/',
                        },
                    },
                    'relationships': {
                        'store': {
                            'data': {'type': 'stores', 'id': str(settings.LEMONSQUEEZY_STORE_ID)},
                        },
                        'variant': {
                            'data': {'type': 'variants', 'id': str(variant)},
                        },
                    },
                }
            },
            timeout=15,
        )
        resp.raise_for_status()
        return redirect(resp.json()['data']['attributes']['url'])
    except Exception:
        logger.exception(
            'Lemon Squeezy checkout failed (plan=%s period=%s variant=%s): %s',
            plan, period, variant, _response_body(locals().get('resp')),
        )
        messages.error(request, _('Checkout is unavailable right now. Please try again.'))
        return redirect('billing')


@csrf_exempt
@require_POST
def ls_webhook(request):
    """Lemon Squeezy IPN — grants and revokes paid access."""
    secret = settings.LEMONSQUEEZY_WEBHOOK_SECRET
    sig    = request.META.get('HTTP_X_SIGNATURE', '')
    body   = request.body

    if secret:
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return HttpResponse(status=400)

    try:
        data = json.loads(body)
    except Exception:
        return HttpResponse(status=400)

    event   = request.META.get('HTTP_X_EVENT_NAME', '')
    custom  = data.get('meta', {}).get('custom_data', {})
    user_id = custom.get('user_id')
    plan    = custom.get('plan') or UserSubscription.PLAN_PRO
    period  = custom.get('period') or 'monthly'
    if plan not in settings.PLAN_PRICES:
        plan = UserSubscription.PLAN_PRO
    if period not in ('monthly', 'annual'):
        period = 'monthly'

    if event in ('subscription_created', 'order_created', 'subscription_payment_success'):
        if user_id:
            try:
                sub, _created = UserSubscription.objects.get_or_create(user_id=int(user_id))
                ls_sub_id = (
                    data.get('data', {})
                        .get('relationships', {})
                        .get('subscription', {})
                        .get('data', {})
                        .get('id', '')
                )
                _activate_plan(
                    sub, plan, period, provider='lemonsqueezy',
                    subscription_id=f'ls_{ls_sub_id}' if ls_sub_id else '',
                )
            except Exception:
                pass

    elif event in ('subscription_cancelled', 'subscription_expired'):
        if user_id:
            try:
                sub = UserSubscription.objects.get(user_id=int(user_id))
                if event == 'subscription_expired':
                    sub.plan = UserSubscription.PLAN_FREE
                    sub.current_period_end = None
                else:
                    sub.cancel_at_period_end = True
                sub.save()
            except UserSubscription.DoesNotExist:
                pass

    return HttpResponse(status=200)


def _parse_crypto_order_id(order_id):
    """
    (user_id, plan, period) from a Cryptomus order_id.

    Invoices created before plans existed carry a bare user id; those are read
    as a monthly Pro purchase.
    """
    raw = str(order_id or '')
    if raw.isdigit():
        return int(raw), UserSubscription.PLAN_PRO, 'monthly'
    parts = raw.split('-')
    if len(parts) >= 3 and parts[0].isdigit():
        plan = parts[1] if parts[1] in settings.PLAN_PRICES else UserSubscription.PLAN_PRO
        period = parts[2] if parts[2] in ('monthly', 'annual') else 'monthly'
        return int(parts[0]), plan, period
    return None, UserSubscription.PLAN_PRO, 'monthly'


@csrf_exempt
@require_POST
def cryptomus_webhook(request):
    """IPN from Cryptomus: grants access once the payment is confirmed."""
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return HttpResponse(status=400)

    api_key = settings.CRYPTOMUS_API_KEY
    if api_key:
        received_sign = data.get('sign', '')
        data['sign'] = None
        body_for_verify = json.dumps(data)
        expected = hashlib.md5(
            (base64.b64encode(body_for_verify.encode()).decode() + api_key).encode()
        ).hexdigest()
        if not hmac.compare_digest(received_sign.lower(), expected.lower()):
            return HttpResponse(status=400)

    if data.get('status', '') in ('paid', 'paid_over'):
        user_id, plan, period = _parse_crypto_order_id(data.get('order_id'))
        if user_id:
            try:
                user = User.objects.get(id=user_id)
                sub, _created = UserSubscription.objects.get_or_create(user=user)
                _activate_plan(sub, plan, period, provider='cryptomus')
            except (ValueError, User.DoesNotExist):
                pass

    return HttpResponse(status=200)


@login_required
def payment_success(request):
    sub = _get_subscription(request.user)
    has_provider = (
        GithubProfile.objects.filter(user=request.user).exists()
        or GitlabProfile.objects.filter(user=request.user).exists()
    )
    return render(request, 'app/payment_success.html', {
        'subscription':  sub,
        'has_provider':  has_provider,
        'support_email': settings.SUPPORT_EMAIL,
    })


def payment_cancel(request):
    return render(request, 'app/payment_cancel.html')



@login_required
def audit_pdf_download(request, audit_id):
    audit = get_object_or_404(Audit, id=audit_id, user=request.user)
    if audit.status != Audit.STATUS_DONE:
        return HttpResponse(_('The audit has not finished yet.'), status=400)

    sub = _get_subscription(request.user)
    usage = MonthlyUsage.for_user(request.user)
    consume = False
    if not sub.is_pro:
        if usage.pdf_exports >= settings.FREE_PDF_PER_MONTH:
            return redirect('billing')
        consume = True

    from app.pdf_report import generate_audit_pdf
    language = _lang(request) or audit.language or 'en'
    framework = request.GET.get('framework', 'soc2')
    if framework not in ('soc2', 'iso27001'):
        framework = 'soc2'
    buf = generate_audit_pdf(
        audit, audit.checks.all(), language=language,
        # The control-coverage section is what makes the PDF an audit artefact
        # rather than a summary, so it belongs to the Compliance plan.
        include_compliance=sub.is_compliance,
        framework=framework,
    )
    if consume:
        usage.consume('pdf_exports')

    safe_name = audit.repo_display.replace('/', '_')
    response = HttpResponse(buf.read(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="audit_{safe_name}_{audit.id}.pdf"'
    return response


@login_required
@require_POST
def save_ai_settings(request):
    provider = request.POST.get('provider', '').strip()
    api_key  = request.POST.get('api_key', '').strip()

    if provider not in ('anthropic', 'openai', 'gemini', ''):
        provider = ''

    ai_cfg, _ = UserAISettings.objects.get_or_create(user=request.user)
    ai_cfg.provider = provider
    ai_cfg.api_key  = api_key
    ai_cfg.save()
    return redirect('/profile/?settings_success=1&tab=settings')


def health_check(request):
    """Simple liveness probe for load balancers and docker health checks."""
    from django.db import connection
    try:
        connection.ensure_connection()
        db_ok = True
    except Exception:
        db_ok = False
    status = 'ok' if db_ok else 'degraded'
    code = 200 if db_ok else 503
    return JsonResponse({'status': status, 'db': db_ok}, status=code)


# ── Custom Error Handlers ─────────────────────────────────────────────────────

def error_404(request, exception=None):
    return render(request, '404.html', status=404)


def error_500(request):
    return render(request, '500.html', status=500)


def error_403(request, exception=None):
    return render(request, '403.html', status=403)


def error_429(request, exception=None):
    return render(request, '429.html', status=429)


# ── Public Report Sharing ────────────────────────────────────────────────────

@login_required
@require_POST
def toggle_public(request, audit_id):
    audit = get_object_or_404(Audit, id=audit_id, user=request.user)
    if audit.is_public:
        audit.is_public = False
        audit.save(update_fields=['is_public'])
        return JsonResponse({'public': False, 'url': ''})
    else:
        token = audit.generate_public_token()
        url = f"{settings.BASE_URL}/audit/public/{token}/"
        return JsonResponse({'public': True, 'url': url, 'token': token})


def public_audit_detail(request, token):
    audit = get_object_or_404(Audit, public_token=token, is_public=True, status=Audit.STATUS_DONE)
    checks = audit.checks.all()
    repo_display = audit.repo_full_name.split('::')[0]
    badge_url = f"{settings.BASE_URL}/badge/{token}/"
    public_url = f"{settings.BASE_URL}/audit/public/{token}/"
    failed = checks.counted().filter(passed=False)
    not_applicable = checks.filter(applicable=False)
    return render(request, 'app/public_audit.html', {
        'hygiene':      checks.hygiene().order_by('passed', 'name'),
        'not_applicable': not_applicable,
        'not_applicable_reason': (not_applicable.first().not_applicable_reason
                                  if not_applicable.exists() else ''),
        'audit':        audit,
        'checks':       checks,
        'passed':       checks.counted().filter(passed=True),
        'failed':       failed,
        'crit_count':   failed.filter(severity='crit').count(),
        'warn_count':   failed.filter(severity='warn').count(),
        'repo_display': repo_display,
        'badge_url':    badge_url,
        'public_url':   public_url,
        'og_image':     f'{settings.BASE_URL}/og/audit/{token}.png',
        'base_url':     settings.BASE_URL,
    })


# ── README Badge SVG ─────────────────────────────────────────────────────────

def badge_svg(request, token):
    audit = get_object_or_404(Audit, public_token=token, is_public=True)
    score = audit.score if audit.score is not None else 0
    if score >= 80:
        color = '#00cc6a'
    elif score >= 60:
        color = '#4488ff'
    elif score >= 40:
        color = '#ffaa00'
    else:
        color = '#ff4466'
    label = 'DevOps Score'
    value = f'{score}/100'
    label_w = 90
    value_w = 54
    total_w = label_w + value_w
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total_w}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_w}" height="20" fill="#555"/>
    <rect x="{label_w}" width="{value_w}" height="20" fill="{color}"/>
    <rect width="{total_w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{label_w//2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_w//2}" y="14">{label}</text>
    <text x="{label_w + value_w//2}" y="15" fill="#010101" fill-opacity=".3">{value}</text>
    <text x="{label_w + value_w//2}" y="14">{value}</text>
  </g>
</svg>'''
    return HttpResponse(svg, content_type='image/svg+xml', headers={
        'Cache-Control': 'no-cache, max-age=0',
        'ETag': f'badge-{audit.id}-{score}',
    })


# ── Onboarding ────────────────────────────────────────────────────────────────

@login_required
def onboarding(request):
    profile = _get_profile(request.user)
    if profile.onboarding_done:
        return redirect('connect')
    has_github = GithubProfile.objects.filter(user=request.user).exists()
    has_gitlab = GitlabProfile.objects.filter(user=request.user).exists()
    return render(request, 'app/onboarding.html', {
        'has_github': has_github,
        'has_gitlab': has_gitlab,
    })


@login_required
@require_POST
def onboarding_complete(request):
    profile = _get_profile(request.user)
    profile.onboarding_done = True
    profile.save(update_fields=['onboarding_done'])
    return redirect('connect')


# ── Profile: email notifications + delete account ───────────────────────────

@login_required
@require_POST
def dismiss_guide_step(request):
    """Wave away one step of the guide, or the guide entirely."""
    from app.guide import STEP_KEYS

    profile = _get_profile(request.user)
    key = request.POST.get('step', '')
    dismissed = list(profile.guide_dismissed or [])
    if key == 'all':
        dismissed = list(STEP_KEYS)
    elif key in STEP_KEYS and key not in dismissed:
        dismissed.append(key)
    profile.guide_dismissed = dismissed
    profile.save(update_fields=['guide_dismissed'])
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'ok': True})
    return redirect(request.POST.get('next') or 'dashboard')


@login_required
@require_POST
def restore_guide(request):
    """Bring the guide back for someone who dismissed it and wants it again."""
    profile = _get_profile(request.user)
    profile.guide_dismissed = []
    profile.save(update_fields=['guide_dismissed'])
    return redirect(request.POST.get('next') or 'dashboard')


@login_required
@require_POST
def update_ai_consent(request):
    """
    Turn AI analysis on or off for this account.

    Not gated on a plan. Whether repository content is sent to a third party is
    not a paid feature — it is a decision the account owner is entitled to make,
    and before this there was no way to make it: if the deployment held a key,
    every customer's repositories were sent.
    """
    profile = _get_profile(request.user)
    profile.ai_analysis_enabled = request.POST.get('ai_analysis_enabled') in ('1', 'true', 'on', 'True')
    profile.save(update_fields=['ai_analysis_enabled'])
    messages.success(request, _('AI analysis is on. Reports are written by the model.')
                     if profile.ai_analysis_enabled else
                     _('AI analysis is off. Nothing from your repositories is sent anywhere, '
                       'and reports are written by our own rules.'))
    return redirect('/profile/?tab=settings#ai-privacy')


@login_required
@require_POST
def update_notifications(request):
    profile = _get_profile(request.user)
    val = request.POST.get('email_notifications', '0')
    profile.email_notifications = val in ('1', 'true', 'on', 'True')
    profile.save(update_fields=['email_notifications'])
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'ok': True})
    return redirect('/profile/?settings_success=1#notifications')


@login_required
@require_POST
def delete_account(request):
    confirm = request.POST.get('confirm_delete', '').strip()
    if confirm != request.user.username:
        return redirect('/profile/?settings_error=delete_mismatch')
    user = request.user
    logout(request)
    user.delete()
    return redirect('landing')


@login_required
def regenerate_api_token(request):
    if request.method != 'POST':
        return redirect('/profile/#notifications')
    import secrets
    profile = _get_profile(request.user)
    profile.api_token = secrets.token_urlsafe(32)
    profile.save(update_fields=['api_token'])
    return JsonResponse({'token': profile.api_token})


# ── Audit History (JSON for Chart.js) ────────────────────────────────────────

@login_required
def audit_history_json(request, audit_id):
    audit = get_object_or_404(Audit, id=audit_id, user=request.user)
    history = list(
        Audit.objects.filter(
            user=request.user,
            source=audit.source,
            repo_full_name=audit.repo_full_name,
            status=Audit.STATUS_DONE,
            score__isnull=False,
        ).order_by('created_at').values('id', 'score', 'created_at', 'trigger')[:30]
    )
    return JsonResponse({'history': [
        {
            'id': h['id'],
            'score': h['score'],
            'trigger': h['trigger'],
            'date': h['created_at'].strftime('%Y-%m-%d'),
            'iso': h['created_at'].isoformat(),
        }
        for h in history
    ]})


# ── GitHub Push Webhook ───────────────────────────────────────────────────────

@csrf_exempt
@require_POST
def github_webhook_auto(request, secret):
    """
    Auto-audit on GitHub events. Set up under Profile → Notifications & API.

    `push` to the default branch re-audits the repository. `pull_request`
    (opened / synchronize / reopened) audits the PR and posts the score as a
    comment, which is where an engineer actually sees it.
    """
    try:
        profile = UserProfile.objects.select_related('user').get(webhook_secret=secret)
    except UserProfile.DoesNotExist:
        return HttpResponse(status=404)

    # HMAC-SHA256 verification is mandatory — reject unsigned requests outright.
    sig = request.META.get('HTTP_X_HUB_SIGNATURE_256', '')
    if not sig:
        return HttpResponse(status=403)
    expected = 'sha256=' + hmac.new(
        secret.encode(), request.body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return HttpResponse(status=403)

    event = request.META.get('HTTP_X_GITHUB_EVENT', '')
    if event not in ('push', 'pull_request'):
        return HttpResponse(status=200)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return HttpResponse(status=400)

    repo = data.get('repository', {}) or {}
    repo_full_name = repo.get('full_name', '')
    repo_url = repo.get('html_url', '')
    if not repo_full_name:
        return HttpResponse(status=200)

    user = profile.user
    sub = _get_subscription(user)

    if event == 'push':
        # Automatic re-audits are a paid feature.
        if not sub.is_pro:
            return HttpResponse(status=403)
        ref = data.get('ref', '')
        default_branch = repo.get('default_branch', 'main')
        if ref != f'refs/heads/{default_branch}':
            return HttpResponse(status=200)
        if Audit.objects.filter(
            user=user, source=Audit.SOURCE_GITHUB, repo_full_name=repo_full_name,
            status__in=[Audit.STATUS_PENDING, Audit.STATUS_RUNNING],
        ).exists():
            return HttpResponse(status=200)
        _start_audit(
            user, repo_full_name, repo_url, Audit.SOURCE_GITHUB,
            language='en',
            trigger=Audit.TRIGGER_WEBHOOK,
            commit_sha=(data.get('after') or '')[:40],
        )
        return HttpResponse(status=200)

    # pull_request
    #
    # Gated on Pro, not Team. This is the most visible surface the product has —
    # every engineer on the team reads it on every pull request — and behind the
    # $99 tier almost nobody ever saw it. Exposure on the cheapest paid plan is
    # worth more than the handful of upgrades the gate was buying. The
    # organisation dashboard, weekly trends and org-wide `fail_under` stay on
    # Team; the comment itself does not.
    if not sub.is_pro:
        return HttpResponse(status=403)
    if not profile.pr_comments_enabled:
        return HttpResponse(status=200)
    if data.get('action') not in ('opened', 'synchronize', 'reopened'):
        return HttpResponse(status=200)
    pr = data.get('pull_request', {}) or {}
    pr_number = data.get('number') or pr.get('number')
    if not pr_number:
        return HttpResponse(status=200)
    _start_audit(
        user, repo_full_name, repo_url, Audit.SOURCE_GITHUB,
        language='en', trigger=Audit.TRIGGER_PR, pr_number=int(pr_number),
        commit_sha=((pr.get('head') or {}).get('sha') or '')[:40],
    )
    return HttpResponse(status=200)


# ── GitHub App webhook ───────────────────────────────────────────────────────

@csrf_exempt
@require_POST
def github_app_webhook(request):
    """
    One URL, configured once on the App itself — GitHub sends every event for
    every installation here, so `push` and `pull_request` auto-audit an
    App-connected repository with nothing for the customer to set up. The
    per-user webhook above (`github_webhook_auto`) exists because a PAT
    connection has no equivalent: no installation, nothing GitHub will call
    on our behalf without the customer pasting a URL into their own repo
    settings.

    Signature verification is mandatory here for the same reason it is on the
    per-user webhook, with one difference: there is exactly one secret
    (`GITHUB_APP_WEBHOOK_SECRET`, set once when the App is created), not one
    per customer, so a missing secret is a deployment that is not configured
    yet rather than an unknown caller — refused the same way, because an
    unconfigured secret cannot verify anything either.
    """
    secret = settings.GITHUB_APP_WEBHOOK_SECRET
    if not secret:
        return HttpResponse(status=503)

    sig = request.META.get('HTTP_X_HUB_SIGNATURE_256', '')
    if not sig:
        return HttpResponse(status=403)
    expected = 'sha256=' + hmac.new(
        secret.encode(), request.body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return HttpResponse(status=403)

    event = request.META.get('HTTP_X_GITHUB_EVENT', '')
    if event == 'ping':
        return HttpResponse(status=200)

    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return HttpResponse(status=400)

    installation_id = (data.get('installation') or {}).get('id')
    if not installation_id:
        return HttpResponse(status=200)

    if event == 'installation':
        # `created` is not handled here: the install-flow redirect
        # (github_app_callback) already creates the profile at the moment
        # the customer completes it on our site. An installation added
        # directly from GitHub's own App page, with no matching visit to our
        # site first, arrives here with no GithubProfile row to attach it
        # to — there is nothing to do with it until the owner signs in and
        # the callback runs; it is not lost, GitHub keeps offering the
        # installation on their next visit to /connect/.
        if data.get('action') == 'deleted':
            # mark_broken(), not a bulk .update() — it also stamps
            # token_broken_since and token_checked_at, which the broken-
            # connection email (tasks.py) and the profile page both read to
            # say *when*, not just that. A raw .update() would leave a
            # connection that reads as broken with no explanation of since when.
            for profile in GithubProfile.objects.filter(installation_id=installation_id):
                profile.mark_broken(GithubProfile.EXPIRED)
        return HttpResponse(status=200)

    if event == 'installation_repositories':
        # Nothing to update: RepoClient reads the repository list from GitHub
        # on every audit rather than caching one, so a repository added to or
        # removed from the installation is already correct next time anyone
        # asks — there is no local list for this event to keep in sync.
        return HttpResponse(status=200)

    if event not in ('push', 'pull_request'):
        return HttpResponse(status=200)

    profile = (GithubProfile.objects
               .filter(installation_id=installation_id)
               .select_related('user').first())
    if profile is None:
        return HttpResponse(status=200)

    repo = data.get('repository', {}) or {}
    repo_full_name = repo.get('full_name', '')
    repo_url = repo.get('html_url', '')
    if not repo_full_name:
        return HttpResponse(status=200)

    user = profile.user
    sub = _get_subscription(user)

    if event == 'push':
        if not sub.is_pro:
            return HttpResponse(status=403)
        ref = data.get('ref', '')
        default_branch = repo.get('default_branch', 'main')
        if ref != f'refs/heads/{default_branch}':
            return HttpResponse(status=200)
        if Audit.objects.filter(
            user=user, source=Audit.SOURCE_GITHUB, repo_full_name=repo_full_name,
            status__in=[Audit.STATUS_PENDING, Audit.STATUS_RUNNING],
        ).exists():
            return HttpResponse(status=200)
        _start_audit(
            user, repo_full_name, repo_url, Audit.SOURCE_GITHUB,
            language='en',
            trigger=Audit.TRIGGER_WEBHOOK,
            commit_sha=(data.get('after') or '')[:40],
        )
        return HttpResponse(status=200)

    # pull_request — same Pro gate and PR-comment opt-out as the per-user webhook.
    if not sub.is_pro:
        return HttpResponse(status=403)
    user_profile = _get_profile(user)
    if not user_profile.pr_comments_enabled:
        return HttpResponse(status=200)
    if data.get('action') not in ('opened', 'synchronize', 'reopened'):
        return HttpResponse(status=200)
    pr = data.get('pull_request', {}) or {}
    pr_number = data.get('number') or pr.get('number')
    if not pr_number:
        return HttpResponse(status=200)
    _start_audit(
        user, repo_full_name, repo_url, Audit.SOURCE_GITHUB,
        language='en', trigger=Audit.TRIGGER_PR, pr_number=int(pr_number),
        commit_sha=((pr.get('head') or {}).get('sha') or '')[:40],
    )
    return HttpResponse(status=200)


# ── REST API ──────────────────────────────────────────────────────────────────

@_bearer_auth
def api_audits(request):
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    user = request.api_user
    audits = Audit.objects.filter(user=user).order_by('-created_at')[:20]
    return JsonResponse({'audits': [
        {
            'id': a.id,
            'repo': a.repo_full_name.split('::')[0],
            'source': a.source,
            'status': a.status,
            'score': a.score,
            'created_at': a.created_at.isoformat(),
        }
        for a in audits
    ]})


@csrf_exempt
@_bearer_auth
def api_audit_start(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    user = request.api_user
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    repo_full_name = data.get('repo', '').strip()
    if not repo_full_name:
        return JsonResponse({'error': 'repo is required'}, status=400)

    ref = str(data.get('ref') or '').strip()[:255]
    commit_sha = str(data.get('commit_sha') or '').strip()[:40]
    pr_number = data.get('pr_number')
    try:
        pr_number = int(pr_number) if pr_number not in (None, '') else None
    except (TypeError, ValueError):
        pr_number = None

    if _repo_quota_exceeded(user, Audit.SOURCE_GITHUB, repo_full_name):
        return JsonResponse({'error': 'Free plan limit reached'}, status=403)

    # Two CI jobs on two branches of the same repository are a normal Tuesday.
    # Only an identical (repo, ref) already in flight is a duplicate; refusing
    # anything else would make the check fail for reasons the author cannot see.
    running = Audit.objects.filter(
        user=user, source=Audit.SOURCE_GITHUB, repo_full_name=repo_full_name,
        ref=ref, status__in=[Audit.STATUS_PENDING, Audit.STATUS_RUNNING],
    ).order_by('-created_at').first()
    if running:
        return JsonResponse(
            {'audit_id': running.id, 'status': running.status, 'duplicate': True},
            status=200,
        )

    audit = _start_audit(
        user, repo_full_name,
        data.get('repo_url') or f'https://github.com/{repo_full_name}',
        Audit.SOURCE_GITHUB,
        language=data.get('language', 'en'),
        trigger=Audit.TRIGGER_PR if pr_number else Audit.TRIGGER_API,
        pr_number=pr_number,
        commit_sha=commit_sha,
        ref=ref,
    )
    return JsonResponse({
        'audit_id': audit.id,
        'status': 'started',
        'ref': audit.ref,
        'url': f'{settings.BASE_URL}/audit/{audit.id}/',
    }, status=201)


@_bearer_auth
def api_audit_detail(request, audit_id):
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    user = request.api_user
    audit = get_object_or_404(Audit, id=audit_id, user=user)
    checks = list(audit.checks.values(
        'check_id', 'name', 'passed', 'severity', 'category',
        'recommendation', 'applicable', 'not_applicable_reason',
    ))
    appeared, resolved = audit.changed_findings()
    return JsonResponse({
        'id': audit.id,
        'repo': audit.repo_full_name.split('::')[0],
        'source': audit.source,
        'status': audit.status,
        'score': audit.score,
        'score_label': audit.score_label,
        'ai_summary': audit.ai_summary,
        'created_at': audit.created_at.isoformat(),
        'completed_at': audit.completed_at.isoformat() if audit.completed_at else None,
        'checks': checks,
        # Everything a CI job needs to decide whether to fail the build and to
        # say why, without a second request.
        'ref': audit.ref,
        'commit_sha': audit.commit_sha,
        'repo_kind': audit.repo_kind,
        'fail_under': audit.fail_under,
        'gate': audit.gate,
        'config_errors': audit.config_errors or [],
        'error_message': audit.error_message,
        'score_delta': audit.score_delta,
        'new_findings': [c.check_id for c in appeared],
        'resolved_findings': resolved,
        'url': f'{settings.BASE_URL}/audit/{audit.id}/',
    })


# ── One-click Fix ────────────────────────────────────────────────────────────

@login_required
def fix_generate(request, audit_id: int, check_id: int):
    """
    Return a ready-to-use file that fixes a specific failed check.
    Free users get the static template; paid plans get an AI-tailored version.
    """
    from app.fix_templates import get_fix, detect_ecosystem, is_fixable, resolve_check_id

    audit = get_object_or_404(Audit, id=audit_id, user=request.user)
    check = get_object_or_404(AuditCheck, id=check_id, audit=audit)

    key = resolve_check_id(check)
    if not is_fixable(key, host=audit.source):
        return JsonResponse({'ok': False, 'error': 'no_template'})

    from app import content_fixes
    if content_fixes.has_fixer(key, audit.source):
        # The fix edits the repository's own workflows; what it will do is the preview.
        _fixer, title, why = content_fixes.FIXERS[key]
        return JsonResponse({
            'ok': True, 'filename': '.github/workflows/*.yml',
            'content': f'# {title}\n#\n# {why}\n#\n# The pull request edits your existing workflow files in place '
                       '— only the lines this concerns — and lists every change and every file it left alone.',
            'language': 'yaml', 'is_ai': False,
            **_pr_capability(request.user, audit),
        })

    ecosystem = detect_ecosystem(audit.checks.all())
    repo_name = audit.repo_display
    sub = _get_subscription(request.user)

    if sub.is_pro:
        result = _generate_ai_fix(check, key, ecosystem, repo_name, audit.language or 'en')
        if result:
            filename, content = result
            return JsonResponse({
                'ok': True, 'filename': filename, 'content': content,
                'language': _guess_language(filename), 'is_ai': True,
                **_pr_capability(request.user, audit),
            })

    fix = get_fix(key, ecosystem, repo_name, host=audit.source)
    if fix is None:
        return JsonResponse({'ok': False, 'error': 'no_template'})

    filename, content = fix
    return JsonResponse({
        'ok': True, 'filename': filename, 'content': content,
        'language': _guess_language(filename), 'is_ai': False,
        **_pr_capability(request.user, audit),
    })


def _pr_capability(user, audit) -> dict:
    """
    Whether a pull request can be opened, and if not, what to do about it.

    The product already knew the connection was broken — `token_status` is
    recorded on every 401 — and offered the button anyway. Pressing it spent a
    round trip to GitHub to be told what the database could have said instantly,
    and left the reader looking at a failure instead of at the way out.
    """
    if audit.source == Audit.SOURCE_GITHUB:
        profile = user.github_profiles.first()
        if profile is None:
            return {
                'can_open_pr': False,
                'pr_blocked': _('Connect a GitHub account to open pull requests.'),
                'pr_blocked_url': reverse('connect'),
                'pr_blocked_cta': _('Connect GitHub'),
            }
        if not profile.is_healthy:
            return {
                'can_open_pr': False,
                'pr_blocked': _('The GitHub token for @%(login)s has stopped working, so a pull '
                                'request cannot be opened. Reconnect and try again.')
                              % {'login': profile.github_login or 'this account'},
                'pr_blocked_url': reverse('connect') + '#connect',
                'pr_blocked_cta': _('Reconnect GitHub'),
            }
        return {'can_open_pr': True}

    if audit.source == Audit.SOURCE_GITLAB:
        profile = getattr(user, 'gitlab_profile', None)
        if profile is None:
            return {
                'can_open_pr': False,
                'pr_blocked': _('Connect a GitLab account to open merge requests.'),
                'pr_blocked_url': reverse('connect'),
                'pr_blocked_cta': _('Connect GitLab'),
            }
        if not profile.is_healthy:
            return {
                'can_open_pr': False,
                'pr_blocked': _('The GitLab token for @%(login)s has stopped working, so a merge '
                                'request cannot be opened. Reconnect and try again.')
                              % {'login': profile.gitlab_username or 'this account'},
                'pr_blocked_url': reverse('connect') + '#connect',
                'pr_blocked_cta': _('Reconnect GitLab'),
            }
        return {'can_open_pr': True}

    return {'can_open_pr': False}


def _can_open_pr(user, audit) -> bool:
    return _pr_capability(user, audit)['can_open_pr']


@login_required
@require_POST
def fix_open_pr(request, audit_id: int, check_id: int):
    """
    Turn a generated fix into an actual pull request.

    Telling someone their Dockerfile runs as root is advice. Opening the pull
    request that fixes it is the product.
    """
    from app.fix_templates import get_fix, detect_ecosystem, is_fixable, resolve_check_id

    audit = get_object_or_404(Audit, id=audit_id, user=request.user)
    check = get_object_or_404(AuditCheck, id=check_id, audit=audit)

    if audit.source not in (Audit.SOURCE_GITHUB, Audit.SOURCE_GITLAB):
        return JsonResponse({'ok': False, 'error': _('Pull requests are supported for GitHub and GitLab repositories.')}, status=400)

    key = resolve_check_id(check)
    if not is_fixable(key, host=audit.source):
        return JsonResponse({'ok': False, 'error': 'no_template'}, status=400)

    if audit.source == Audit.SOURCE_GITHUB:
        profile = request.user.github_profiles.first()
        if not profile:
            return JsonResponse({'ok': False, 'error': _('Connect a GitHub account first.')}, status=400)
    else:
        profile = getattr(request.user, 'gitlab_profile', None)
        if not profile:
            return JsonResponse({'ok': False, 'error': _('Connect a GitLab account first.')}, status=400)

    # Findings fixed by editing the repository's own workflows, not by adding
    # a file (app/content_fixes.py).
    from app import content_fixes
    if content_fixes.has_fixer(key, audit.source):
        from app.github_writer import GitHubWriteError, NothingToChange
        try:
            done = content_fixes.open_pull_request(profile.current_token, audit.repo_display, key,
                                                   audit_url=f'{settings.BASE_URL}/audit/{audit.id}/')
        except NothingToChange as exc:
            return JsonResponse({'ok': False, 'error': str(exc)}, status=400)
        except content_fixes.WorkflowScopeError as exc:
            if profile.is_oauth:
                # Step-up, not a wider sign-in: `workflow` is asked for here,
                # at the moment someone wants their workflows changed.
                return JsonResponse({
                    'ok': False,
                    'error': _('Changing workflow files needs one more GitHub permission ("workflow"), '
                               'which signing in did not ask for. Nothing was changed.'),
                    'reauth_url': _github_workflow_reauth_url(audit),
                    'reauth_label': _('Allow DevOpsCheck to edit workflows on GitHub'),
                }, status=403)
            return JsonResponse({'ok': False, 'error': str(exc), 'reconnect': True}, status=400)
        except GitHubWriteError as exc:
            return JsonResponse({'ok': False, 'error': str(exc), 'reconnect': exc.reconnect}, status=400)
        from app import funnel
        funnel.record('fix_pr_opened', request, ref=key)
        return JsonResponse({'ok': True, 'pr_url': done['url'], 'filename': ', '.join(done['files'])})

    ecosystem = detect_ecosystem(audit.checks.all())
    repo_name = audit.repo_display

    content = filename = None
    sub = _get_subscription(request.user)
    if sub.is_pro:
        ai = _generate_ai_fix(check, key, ecosystem, repo_name, audit.language or 'en')
        if ai:
            filename, content = ai
    if content is None:
        fix = get_fix(key, ecosystem, repo_name, host=audit.source)
        if fix is None:
            return JsonResponse({'ok': False, 'error': 'no_template'}, status=400)
        filename, content = fix

    audit_url = f'{settings.BASE_URL}/audit/{audit.id}/'
    try:
        if audit.source == Audit.SOURCE_GITHUB:
            from app.github_app import GitHubAppError
            from app.github_writer import open_fix_pull_request_details, GitHubWriteError
            try:
                pr = open_fix_pull_request_details(
                    token=profile.current_token,
                    repo_full_name=repo_name,
                    filename=filename,
                    content=content,
                    check_name=check.name,
                    recommendation=check.recommendation,
                    audit_url=audit_url,
                )
                pr_url = pr['url']
                # Phase 5: follow it until CI is green (allowlisted repositories only).
                from app.fix_agent import track
                try:
                    track(audit, check, pr, filename)
                except Exception:
                    logger.error('Could not start tracking fix PR %s', pr_url, exc_info=True)
            except GitHubWriteError as exc:
                return JsonResponse({'ok': False, 'error': str(exc), 'reconnect': exc.reconnect},
                                    status=400)
            except GitHubAppError as exc:
                return JsonResponse({'ok': False, 'error': str(exc), 'reconnect': True}, status=400)
        else:
            from app.gitlab_writer import open_fix_merge_request, GitlabScopeError, GitlabWriteError
            from app.gitlab_oauth import GitlabOAuthError
            parts = audit.repo_full_name.split('::')
            project_id = int(parts[1]) if len(parts) > 1 else 0
            try:
                pr_url = open_fix_merge_request(
                    token=profile.current_token,
                    project_id=project_id,
                    filename=filename,
                    content=content,
                    check_name=check.name,
                    recommendation=check.recommendation,
                    audit_url=audit_url,
                    gitlab_url=profile.gitlab_url,
                    verify_ssl=profile.verify_ssl,
                    custom_dns=profile.custom_dns,
                )
            except GitlabScopeError:
                if profile.is_oauth:
                    # Signing in with GitLab asks for read_api only, so an
                    # audit never needs write access. Write is asked for here,
                    # at the moment someone wants a merge request, by sending
                    # them back through GitLab's consent screen with api added.
                    return JsonResponse({
                        'ok': False,
                        'error': _('Opening a merge request needs write access to your GitLab '
                                   'repositories, which signing in did not ask for.'),
                        'reauth_url': _gitlab_write_reauth_url(audit),
                        'reauth_label': _('Grant write access on GitLab'),
                    }, status=403)
                return JsonResponse({'ok': False, 'reconnect': True, 'error': _(
                    'This GitLab token can read but was not created with the api scope, which '
                    'opening a merge request needs. Create a new token with the api scope and '
                    'reconnect on the profile page.')}, status=400)
            except GitlabWriteError as exc:
                return JsonResponse({'ok': False, 'error': str(exc), 'reconnect': exc.reconnect},
                                    status=400)
            except GitlabOAuthError as exc:
                return JsonResponse({'ok': False, 'error': str(exc), 'reconnect': True}, status=400)
    except (ValueError, IndexError):
        return JsonResponse({'ok': False, 'error': _('This repository is missing the information needed to open a merge request. Re-run the audit and try again.')}, status=400)

    from app import funnel
    funnel.record('fix_pr_opened', request, ref=check.check_id or '')
    return JsonResponse({'ok': True, 'pr_url': pr_url, 'filename': filename})


def _github_workflow_reauth_url(audit) -> str:
    """GitHub sign-in as a connect, with `workflow` added to the configured scopes."""
    from urllib.parse import urlencode
    return reverse('github_login') + '?' + urlencode({
        'process': 'connect',
        'scope': 'workflow',
        'next': reverse('audit_detail', args=[audit.id]),
    })


def _gitlab_write_reauth_url(audit) -> str:
    """
    allauth's GitLab login, as a connect (not a new sign-in) with `api` added
    to the configured scopes, returning to this report afterwards.

    allauth appends `?scope=` to `SOCIALACCOUNT_PROVIDERS['gitlab']['SCOPE']`
    (`OAuth2Provider.get_scope_from_request`), and the account-updated signal
    stores the new token over the old one via `app.signals._link_gitlab`.
    """
    from urllib.parse import urlencode
    return reverse('gitlab_login') + '?' + urlencode({
        'process': 'connect',
        'scope': 'api',
        'next': reverse('audit_detail', args=[audit.id]),
    })


def _guess_language(filename: str) -> str:
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return {
        'yml': 'yaml', 'yaml': 'yaml',
        'sh': 'bash', 'json': 'json',
        'md': 'markdown', 'toml': 'toml',
        'py': 'python', 'js': 'javascript',
        'go': 'go', 'rs': 'rust',
    }.get(ext, 'text')


def _generate_ai_fix(check, check_key: str, ecosystem: str, repo_name: str, language: str) -> tuple[str, str] | None:
    """Call AI to generate a customized fix file for a failed check. Returns (filename, content) or None."""
    from app.fix_templates import get_fix
    from app.ai_providers import _get_active_provider, _call_anthropic, _call_openai, _call_gemini, PROVIDERS
    import logging
    logger = logging.getLogger(__name__)

    template_result = get_fix(check_key, ecosystem, repo_name, host=check.audit.source)
    if template_result is None:
        return None
    filename, template_content = template_result

    provider_name, api_key = _get_active_provider(user_id=check.audit.user_id,
                                                  is_private=check.audit.repo_is_private)
    if not provider_name or not api_key:
        return None

    # Facts read from the repository during the run. Without them "customise this
    # template for the project" asks the model to invent a project, and it does.
    from app.repo_context import to_prompt, with_host
    facts = to_prompt(with_host(check.audit.repo_context, check.audit.source), language)

    prompt = (
        f"You are a senior DevOps engineer. Generate a production-ready file to fix this issue.\n\n"
        f"Repository: {repo_name}\n"
        f"Tech stack: {ecosystem}\n"
        + (f"\n{facts}\n" if facts else "")
        + f"Failed check: {check.name}\n"
        f"Issue: {check.description}\n"
        f"Recommendation: {check.recommendation}\n\n"
        f"Target filename: {filename}\n\n"
        f"Base template (adapt it to the repository described above):\n{template_content}\n\n"
        f"Rules:\n"
        f"- Return ONLY the file content, no explanation, no markdown fences\n"
        f"- Use this repository's real stack, images, ports and commands where the facts give them\n"
        f"- Invent nothing: if a fact is not listed above, leave the template's default\n"
        f"- Keep it concise and production-ready\n"
        f"- Language for comments: {'Russian' if language == 'ru' else 'English'}"
    )

    model = PROVIDERS[provider_name].get('default_model', '')
    try:
        callers = {'anthropic': _call_anthropic, 'openai': _call_openai, 'gemini': _call_gemini}
        caller = callers.get(provider_name)
        if caller:
            content = caller(api_key, prompt, model)
            content = content.strip().lstrip('`').rstrip('`')
            if content.startswith(('yaml\n', 'bash\n', 'json\n', 'markdown\n', 'text\n', 'sh\n')):
                content = content.split('\n', 1)[1] if '\n' in content else content
            return filename, content
    except Exception as exc:
        logger.warning("AI fix generation failed (%s): %s", provider_name, exc)

    return None


# ── Trust ─────────────────────────────────────────────────────────────────────

def trust_page(request):
    """
    What actually happens to a repository's content — not behind a login,
    because whether code reaches a third party is a decision every visitor is
    entitled to see the answer to before they connect anything, not a reward
    for signing up.

    Every claim here has a corresponding switch or piece of code a reader can
    go check: the AI toggle on the profile page (`ai_analysis_enabled`,
    off by default sends nothing, on by default only ever if a provider key
    is configured), `checks_secrets.redact()` for what is masked before
    anything leaves, `crypto_utils.py` for how tokens are stored. Nothing on
    this page should say more than the code actually does.
    """
    return render(request, 'app/trust.html', {
        'support_email': settings.SUPPORT_EMAIL,
        'base_url': settings.BASE_URL,
    })


# ── SEO: robots.txt + sitemap.xml ─────────────────────────────────────────────

def security_txt(request):
    """
    RFC 9116, at /.well-known/security.txt — where a researcher who finds a
    problem looks first, before they look for a contact form.

    `Expires` is computed one year out on every request rather than hardcoded,
    so the file can never go stale the way a fixed date in source would — RFC
    9116 clients treat an expired file as absent, and nobody would notice
    until a researcher's tool silently skipped it.
    """
    base = settings.BASE_URL
    expires = (timezone.now() + timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    content = f"""Contact: mailto:{settings.SUPPORT_EMAIL}
Expires: {expires}
Preferred-Languages: en, ru
Canonical: {base}/.well-known/security.txt
Policy: {base}/trust/
"""
    return HttpResponse(content, content_type='text/plain')


def robots_txt(request):
    base = settings.BASE_URL
    content = f"""User-agent: *
Disallow: /admin/
Disallow: /billing/
Disallow: /dashboard/
Disallow: /organization/
Disallow: /gitlab/
Disallow: /profile/
Disallow: /audit/
Allow: /audit/public/
Allow: /trust/
Allow: /scan/
Allow: /rankings/
Allow: /checks/
Allow: /compare/
Allow: /llms.txt
Allow: /pricing/
Allow: /
Sitemap: {base}/sitemap.xml
"""
    return HttpResponse(content, content_type='text/plain')


def sitemap_xml(request):
    """
    Public scans are the SEO surface: every repository someone runs through the
    free scanner becomes an indexable page with real content on it.
    """
    base = settings.BASE_URL
    urls = [
        {'loc': base + '/', 'changefreq': 'weekly', 'priority': '1.0'},
        {'loc': base + '/scan/', 'changefreq': 'daily', 'priority': '0.9'},
        {'loc': base + '/rankings/', 'changefreq': 'daily', 'priority': '0.9'},
        {'loc': base + '/pricing/', 'changefreq': 'monthly', 'priority': '0.8'},
        {'loc': base + '/trust/', 'changefreq': 'monthly', 'priority': '0.6'},
        {'loc': base + '/checks/', 'changefreq': 'weekly', 'priority': '0.8'},
        {'loc': base + '/compare/', 'changefreq': 'monthly', 'priority': '0.7'},
    ]
    from app.check_guides import GUIDES
    for cid in GUIDES:
        urls.append({'loc': f'{base}/checks/{cid}/', 'changefreq': 'monthly', 'priority': '0.7'})

    # One ranking page per language the corpus can actually rank.
    from app import rankings as _rankings
    for entry in _rankings.languages(limit=60):
        urls.append({
            'loc': f"{base}/rankings/{entry['slug']}/",
            'changefreq': 'weekly',
            'priority': '0.8',
        })

    for scan in (PublicScan.objects
                 .filter(status=Audit.STATUS_DONE)
                 .order_by('-view_count')[:5000]
                 .values('repo_full_name', 'updated_at')):
        urls.append({
            'loc': f"{base}/scan/{scan['repo_full_name']}/",
            'changefreq': 'weekly',
            'priority': '0.7',
            'lastmod': scan['updated_at'].strftime('%Y-%m-%d'),
        })

    from app.models import OrgScan
    for org in OrgScan.objects.filter(status='done').order_by('-view_count')[:2000]:
        if PublicScan.objects.filter(repo_full_name__in=org.repos, status=Audit.STATUS_DONE).count() >= 3:
            urls.append({'loc': f'{base}/scan/org/{org.org}/', 'changefreq': 'weekly', 'priority': '0.7',
                         'lastmod': org.updated_at.strftime('%Y-%m-%d')})

    # The same public pages in Russian (LanguagePrefixMiddleware).
    from app.middleware import is_ru_public
    urls += [dict(u, loc=base + '/ru' + u['loc'][len(base):]) for u in list(urls)
             if is_ru_public(u['loc'][len(base):])]

    for a in (Audit.objects
              .filter(is_public=True, status=Audit.STATUS_DONE)
              .values('public_token', 'completed_at')):
        urls.append({
            'loc': f"{base}/audit/public/{a['public_token']}/",
            'changefreq': 'monthly',
            'priority': '0.5',
            'lastmod': a['completed_at'].strftime('%Y-%m-%d') if a['completed_at'] else '',
        })

    return render(request, 'app/sitemap.xml', {'urls': urls}, content_type='application/xml')


# ── Secret incidents (roadmap phase 6) ───────────────────────────────────────

def _incidents_for(audit):
    from app.models import SecretIncident
    from app.secret_incidents import HISTORY_CLEANUP, can_rewrite, playbook
    rows = list(SecretIncident.objects.filter(user=audit.user, repo_full_name=audit.repo_display))
    for inc in rows:
        inc.playbook = playbook(inc.rule)
        inc.can_rewrite = can_rewrite(inc)
        inc.history_cleanup = HISTORY_CLEANUP
    return rows


@login_required
@require_POST
def incident_open_pr(request, incident_id: int):
    """Open the PR/MR that moves a live key's literal to an environment variable."""
    from app.models import SecretIncident
    from app.secret_incidents import CannotRewrite, can_rewrite, open_env_pr
    from app.github_writer import GitHubWriteError
    from app.gitlab_writer import GitlabWriteError

    incident = get_object_or_404(SecretIncident, id=incident_id, user=request.user)
    if not can_rewrite(incident):
        return JsonResponse({'ok': False, 'error': _('This key cannot be moved automatically.')}, status=400)
    try:
        url = open_env_pr(incident, request.user)
    except CannotRewrite as exc:
        return JsonResponse({'ok': False, 'error': str(exc)}, status=400)
    except (GitHubWriteError, GitlabWriteError) as exc:
        return JsonResponse({'ok': False, 'error': str(exc),
                             'reconnect': getattr(exc, 'reconnect', False)}, status=400)
    except Exception:
        logger.error('incident_open_pr failed: incident=%s', incident_id, exc_info=True)
        return JsonResponse({'ok': False, 'error': _('Could not open the pull request.')}, status=500)
    return JsonResponse({'ok': True, 'pr_url': url})


@login_required
@require_POST
def incident_mark_rotated(request, incident_id: int):
    """
    The owner says the key is rotated. Only for a key we can no longer check —
    while it is still in the repository, the next audit asks the provider and
    decides, which is the only confirmation that counts.
    """
    from app.models import SecretIncident
    incident = get_object_or_404(SecretIncident, id=incident_id, user=request.user)
    if incident.status == SecretIncident.STATUS_OPEN:
        incident.status = SecretIncident.STATUS_MARKED
        incident.resolved_at = timezone.now()
        incident.save(update_fields=['status', 'resolved_at'])
    return redirect(request.POST.get('next') or 'dashboard')
