import time

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponse


class DefaultLanguageMiddleware:
    """
    Sets the language cookie to LANGUAGE_CODE ('en') on first visit
    if no language cookie exists. This ensures new users get English
    regardless of their browser's Accept-Language header.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        cookie_name = settings.LANGUAGE_COOKIE_NAME
        if not request.COOKIES.get(cookie_name):
            request.META['HTTP_ACCEPT_LANGUAGE'] = settings.LANGUAGE_CODE
        response = self.get_response(request)
        # /ru/ pages set the cookie themselves (LanguagePrefixMiddleware).
        if not request.COOKIES.get(cookie_name) and cookie_name not in response.cookies:
            response.set_cookie(
                cookie_name,
                settings.LANGUAGE_CODE,
                max_age=settings.LANGUAGE_COOKIE_AGE,
                path='/',
            )
        return response



#: Public, indexable pages that also exist under /ru/. Anything else — the
#: app behind the login, the API, webhooks — keeps its single URL.
RU_PUBLIC_PREFIXES = ('/scan/', '/rankings/', '/checks/', '/trust/', '/pricing/', '/compare/')


def is_ru_public(path: str) -> bool:
    return path == '/' or path.startswith(RU_PUBLIC_PREFIXES)


class LanguagePrefixMiddleware:
    """
    /ru/<public page> serves the Russian version of that page.

    The language used to live only in a cookie, so a search engine — which
    keeps no cookies — only ever saw English, and nothing Russian could rank.
    The prefix is stripped before URL resolution (request.path keeps it, so
    canonical links built from it stay on /ru/), Russian is activated for the
    request, and the cookie follows so the next click stays in Russian.
    Must run after LocaleMiddleware, which would otherwise re-activate the
    cookie's language.
    """
    PREFIX = '/ru'

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.utils import translation
        path = request.path_info
        request.lang_prefix = ''
        if path == self.PREFIX:
            from django.shortcuts import redirect
            return redirect(self.PREFIX + '/', permanent=True)
        if path.startswith(self.PREFIX + '/') and is_ru_public(path[len(self.PREFIX):]):
            request.path_info = path[len(self.PREFIX):]
            request.lang_prefix = self.PREFIX
            translation.activate('ru')
            request.LANGUAGE_CODE = 'ru'
            response = self.get_response(request)
            response.set_cookie(settings.LANGUAGE_COOKIE_NAME, 'ru',
                                max_age=settings.LANGUAGE_COOKIE_AGE, path='/')
            response.setdefault('Content-Language', 'ru')
            return response
        return self.get_response(request)


class RateLimitMiddleware:
    """Simple IP-based rate limiting for login and register endpoints."""

    LIMITS = {
        '/login/': (20, 300),     # 20 requests per 5 minutes
        '/register/': (10, 300),  # 10 requests per 5 minutes
    }

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == 'POST':
            limit_cfg = self.LIMITS.get(request.path)
            if limit_cfg:
                max_requests, window = limit_cfg
                ip = self._get_ip(request)
                key = f'rl:{request.path}:{ip}'
                try:
                    count = cache.get(key, 0)
                    if count >= max_requests:
                        return HttpResponse(
                            'Too many requests. Please wait a few minutes.',
                            status=429,
                            content_type='text/plain',
                        )
                    cache.set(key, count + 1, window)
                except Exception:
                    pass  # Don't block on cache errors

        return self.get_response(request)

    @staticmethod
    def _get_ip(request):
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '0.0.0.0')


class SecurityHeadersMiddleware:
    """
    Content-Security-Policy and Permissions-Policy.

    Django ships the other headers (nosniff, frame options, HSTS) but not these
    two, and they are exactly what corporate security questionnaires ask about —
    the questionnaires that come with the Team and Compliance plans.

    'unsafe-inline' is present because the templates carry inline <style> and
    inline event handlers. It weakens the policy against injected inline script,
    but every other CSP protection still applies: no external script origin can
    load, no plugins, no framing, no form posting anywhere but the checkouts.
    Removing 'unsafe-inline' means moving all inline handlers and styles to
    files first.

    form-action must name the payment hosts. Both checkouts are a POST to our
    own URL that answers with a redirect to the provider, and Chrome applies
    form-action to the whole redirect chain — with 'self' alone the navigation
    is aborted, the buyer stays on the billing page, and nothing at all appears
    to happen.
    """

    #: Hosts a checkout POST is allowed to end up on.
    PAYMENT_ORIGINS = (
        'https://*.lemonsqueezy.com',
        'https://lemonsqueezy.com',
        'https://api.cryptomus.com',
        'https://pay.cryptomus.com',
    )

    CSP = '; '.join([
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com data:",
        # Avatars come from the providers, README badges from shields.io.
        "img-src 'self' data: https:",
        "connect-src 'self'",
        "form-action 'self' " + ' '.join(PAYMENT_ORIGINS),
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "object-src 'none'",
        "upgrade-insecure-requests",
    ])

    PERMISSIONS = ', '.join([
        'accelerometer=()', 'camera=()', 'geolocation=()', 'gyroscope=()',
        'magnetometer=()', 'microphone=()', 'payment=()', 'usb=()',
        'interest-cohort=()',
    ])

    def __init__(self, get_response):
        self.get_response = get_response
        # Reports and social cards are embedded elsewhere on purpose.
        self.embeddable_prefixes = ('/badge/', '/og/')

    def __call__(self, request):
        response = self.get_response(request)

        csp = self.CSP
        if not request.is_secure():
            # Would otherwise break plain-HTTP local development.
            csp = csp.replace('; upgrade-insecure-requests', '')

        response.setdefault('Content-Security-Policy', csp)
        response.setdefault('Permissions-Policy', self.PERMISSIONS)
        response.setdefault('Cross-Origin-Opener-Policy', 'same-origin')

        # Badges and social cards are meant to be hot-linked from README files
        # and chat clients, so they opt out of the framing restrictions.
        if request.path.startswith(self.embeddable_prefixes):
            response['Content-Security-Policy'] = "default-src 'none'; img-src 'self' data:"
            response['X-Frame-Options'] = 'SAMEORIGIN'
            response['Access-Control-Allow-Origin'] = '*'

        return response
