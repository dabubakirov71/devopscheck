"""
Server-side funnel events (growth plan B2) — no third party, no personal data.

    visit_landing → scan_started → scan_completed → report_email_submitted →
    signup → app_installed → first_private_scan → fix_pr_opened →
    fix_pr_merged → checkout_started → early_access → paid

Each event carries the visitor's *first-touch source*: the utm_source (or
?ref=) they arrived with, else the external referrer's host, else "direct".
It lives in a signed cookie, not the session, so crawlers do not create a
database row per hit. Nothing about the visitor is stored — no IP, no user
agent, no cookie value; a signed-in user's events point at their account,
which the product already holds.
"""
import logging
import re
from urllib.parse import urlencode, urlparse, urlsplit, urlunsplit, parse_qsl

from django.conf import settings

logger = logging.getLogger(__name__)

EVENTS = (
    'visit_landing', 'scan_started', 'scan_completed', 'report_email_submitted', 'signup',
    'app_installed', 'first_private_scan', 'fix_pr_opened', 'fix_pr_merged',
    'checkout_started', 'early_access', 'paid',
)
SOURCE_COOKIE = 'dsrc'
SOURCE_MAX_AGE = 90 * 24 * 3600
_BOT = re.compile(r'bot|crawl|spider|slurp|preview|fetch|monitor|curl|wget|python-requests|headless',
                  re.IGNORECASE)
_SAFE = re.compile(r'[^a-z0-9._-]')


def is_bot(request) -> bool:
    return bool(_BOT.search(request.META.get('HTTP_USER_AGENT', '') or '')) or \
        not request.META.get('HTTP_USER_AGENT')


def _clean(value: str) -> str:
    return _SAFE.sub('', (value or '').lower())[:40]


def first_touch(request) -> str:
    """Where this visit came from, for a visitor without a source cookie yet."""
    for key in ('utm_source', 'ref'):
        if request.GET.get(key):
            return _clean(request.GET[key])
    referrer = request.META.get('HTTP_REFERER', '')
    host = urlparse(referrer).hostname or ''
    own = urlparse(settings.BASE_URL).hostname or ''
    if host and host != own and not host.endswith('.' + own):
        return _clean(host.removeprefix('www.'))
    return 'direct'


def source_of(request) -> str:
    if request is None:
        return ''
    stored = request.get_signed_cookie(SOURCE_COOKIE, default='', salt='funnel') if hasattr(
        request, 'get_signed_cookie') else ''
    return stored or getattr(request, '_funnel_source', '') or first_touch(request)


class SourceMiddleware:
    """Remember the first-touch source on public pages (signed cookie, 90 days)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        has = bool(request.COOKIES.get(SOURCE_COOKIE))
        if not has and request.method == 'GET':
            request._funnel_source = first_touch(request)
        response = self.get_response(request)
        if not has and getattr(request, '_funnel_source', '') and not is_bot(request) \
                and response.status_code < 400:
            response.set_signed_cookie(SOURCE_COOKIE, request._funnel_source, salt='funnel',
                                       max_age=SOURCE_MAX_AGE, httponly=True, samesite='Lax',
                                       secure=not settings.DEBUG)
        return response


def _user_source(user) -> str:
    from app.models import FunnelEvent
    first = FunnelEvent.objects.filter(user=user).exclude(source='').order_by('created_at').first()
    return first.source if first else ''


def record(name, request=None, user=None, ref='', once_per_user=False, source=None):
    """Store one event. Never raises: measuring must not break the product."""
    try:
        from app.models import FunnelEvent
        if name not in EVENTS:
            raise ValueError(name)
        if request is not None and is_bot(request):
            return None
        if user is None and request is not None and getattr(request, 'user', None) \
                and request.user.is_authenticated:
            user = request.user
        if once_per_user and user is not None and FunnelEvent.objects.filter(name=name, user=user).exists():
            return None
        if source is None:
            source = source_of(request) if request is not None else (_user_source(user) if user else '')
        return FunnelEvent.objects.create(name=name, user=user, source=source[:40], ref=(ref or '')[:200])
    except Exception:
        logger.warning('funnel event %s not recorded', name, exc_info=True)
        return None


def tagged(url: str, source: str, medium: str = 'product') -> str:
    """The same URL with utm_source/utm_medium, so the visit it brings is attributed."""
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query))
    query.setdefault('utm_source', source)
    query.setdefault('utm_medium', medium)
    return urlunsplit(parts._replace(query=urlencode(query)))
