from pathlib import Path
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = config('SECRET_KEY')
DEBUG = config('DEBUG', default=False, cast=bool)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost').split(',')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.sites',
    'whitenoise.runserver_nostatic',
    'django.contrib.staticfiles',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.github',
    'allauth.socialaccount.providers.gitlab',
    'allauth.socialaccount.providers.google',
    'app.apps.AppConfig_',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'app.middleware.DefaultLanguageMiddleware',       # force EN on first visit
    'django.middleware.locale.LocaleMiddleware',  # i18n — должен быть после SessionMiddleware
    'app.middleware.LanguagePrefixMiddleware',     # /ru/<public page>, after LocaleMiddleware
    'app.funnel.SourceMiddleware',                 # first-touch source cookie (growth plan B2)
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'app.middleware.RateLimitMiddleware',
    'app.middleware.SecurityHeadersMiddleware',
]

# The admin runs as its own process on its own port. `ADMIN_SITE=1` swaps the
# URL configuration for one that serves nothing but /admin/; the public process
# leaves it out entirely, so /admin/ 404s on the customer-facing domain instead
# of presenting a login form to the internet. Same code, same database, separate
# exposure — which is the part that actually needs separating.
ADMIN_SITE = config('ADMIN_SITE', default=False, cast=bool)
ROOT_URLCONF = 'config.urls_admin' if ADMIN_SITE else 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'app' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.template.context_processors.i18n',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'app.context_processors.guide',
                'app.context_processors.nav',
                'app.context_processors.site_facts',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME', default='devopsaudit'),
        'USER': config('DB_USER', default='devopsaudit'),
        'PASSWORD': config('DB_PASSWORD', default='devopsaudit'),
        'HOST': config('DB_HOST', default='db'),
        'PORT': config('DB_PORT', default='5432'),
    }
}

# ── i18n ──────────────────────────────────────────────────────────────────────
LANGUAGE_CODE = 'en'
# UTC on the server; dates are rendered in the visitor's own timezone client-side.
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

from django.utils.translation import gettext_lazy as _
LANGUAGES = [
    ('en', _('English')),
    ('ru', _('Русский')),
]

LOCALE_PATHS = [BASE_DIR / 'locale']

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

CELERY_BROKER_URL = config('CELERY_BROKER_URL', default='redis://redis:6379/0')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default='redis://redis:6379/0')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True

# Scheduled jobs. Crypto payments are one-off, so without the expiry reminder a
# customer's access simply stops one day with no warning and no chance to renew.
from celery.schedules import crontab  # noqa: E402
CELERY_BEAT_SCHEDULE = {
    'subscription-expiry-reminders': {
        'task': 'app.tasks.send_expiry_reminders',
        'schedule': crontab(hour=9, minute=0),
        'kwargs': {'days_before': 3},
    },
    'refresh-popular-public-scans': {
        'task': 'app.tasks.refresh_stale_public_scans',
        'schedule': crontab(hour=3, minute=30),
    },
    # Turns the seeded backlog into scanned repositories at a rate that leaves
    # API budget for the visitors who came to scan something themselves.
    'scan-pending-public-repos': {
        'task': 'app.tasks.scan_pending_public_repos',
        'schedule': crontab(minute=5),
    },
    'expire-stuck-public-scans': {
        'task': 'app.tasks.expire_stuck_public_scans',
        'schedule': crontab(minute='*/15'),
    },
    # An expired provider token stops every audit for that account. Without
    # this, the first symptom is the customer finding a dead dashboard link.
    'check-provider-connections': {
        'task': 'app.tasks.check_provider_connections',
        'schedule': crontab(hour=7, minute=15),
    },
    # A repository somebody asked to hear about is worth re-reading on a shorter
    # cycle than the weekly sweep: a score change reported eleven days late is
    # not news. Refresh first, then compare — in that order, an hour apart, so
    # the scans have finished before anything is sent.
    'refresh-watched-public-scans': {
        'task': 'app.tasks.refresh_watched_public_scans',
        'schedule': crontab(hour=4, minute=0),
    },
    'notify-watched-score-changes': {
        'task': 'app.tasks.notify_watched_score_changes',
        'schedule': crontab(hour=5, minute=0),
    },
    # Phase 5: fix pull requests followed until CI is green.
    # Phase 7: the weekly CTO digest, on each account's chosen weekday.
    'send-weekly-digests': {
        'task': 'app.tasks.send_weekly_digests',
        'schedule': crontab(hour=8, minute=0),
    },
    'poll-fix-attempts': {
        'task': 'app.tasks.poll_fix_attempts',
        'schedule': crontab(minute='*'),
    },
}

# Repositories the fix agent may push to ("owner/repo, owner/repo", or "*").
# Test repositories first — widen only after watching it behave.
FIX_AGENT_REPOS = config('FIX_AGENT_REPOS', default='')
CELERY_TIMEZONE = 'UTC' 

SITE_ID = 1

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

ACCOUNT_EMAIL_REQUIRED = False
ACCOUNT_USERNAME_REQUIRED = True
ACCOUNT_AUTHENTICATION_METHOD = 'username'
ACCOUNT_EMAIL_VERIFICATION = 'none'
ACCOUNT_DEFAULT_HTTP_PROTOCOL = 'https'
LOGIN_REDIRECT_URL = '/profile/'
LOGOUT_REDIRECT_URL = '/'

SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_LOGIN_ON_GET = True
SOCIALACCOUNT_QUERY_EMAIL = True
SOCIALACCOUNT_EMAIL_REQUIRED = False
SOCIALACCOUNT_EMAIL_VERIFICATION = 'none'
# allauth 0.58+ defaults this to False, and then never writes a SocialToken —
# app.signals links a sign-in to GithubProfile/GitlabProfile from that row, so
# with it off "Continue with GitHub/GitLab" logged people in and connected
# nothing. The plaintext copy is blanked by app.signals the moment our own
# encrypted copy is saved.
SOCIALACCOUNT_STORE_TOKENS = True
# Signing in with GitHub/Google whose verified email matches an account here
# signs in to that account (and connects the provider) instead of stopping at
# a "create another account" form. app.adapters narrows it to emails we have
# verified ourselves — see its docstring for why.
SOCIALACCOUNT_EMAIL_AUTHENTICATION = True
SOCIALACCOUNT_EMAIL_AUTHENTICATION_AUTO_CONNECT = True
SOCIALACCOUNT_ADAPTER = 'app.adapters.SocialAccountAdapter'
SOCIALACCOUNT_FORMS = {'signup': 'app.forms_social.SocialSignupForm'}

SOCIALACCOUNT_PROVIDERS = {
    'github': {'SCOPE': ['user', 'repo']},
    'gitlab': {'GITLAB_URL': 'https://gitlab.com', 'SCOPE': ['read_user', 'read_api']},
    'google': {'SCOPE': ['profile', 'email'], 'AUTH_PARAMS': {'access_type': 'online'}},
}

GITHUB_CLIENT_ID     = config('GITHUB_CLIENT_ID', default='')
GITHUB_CLIENT_SECRET = config('GITHUB_CLIENT_SECRET', default='')
GITLAB_APP_ID        = config('GITLAB_APP_ID', default='')
GITLAB_APP_SECRET    = config('GITLAB_APP_SECRET', default='')
GOOGLE_CLIENT_ID     = config('GOOGLE_CLIENT_ID', default='')
GOOGLE_CLIENT_SECRET = config('GOOGLE_CLIENT_SECRET', default='')

# ── Token encryption ──────────────────────────────────────────────────────────
# Provider access tokens are encrypted at rest (app/crypto_utils.py). Generate a
# dedicated key so rotating SECRET_KEY does not orphan stored tokens:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
TOKEN_ENCRYPTION_KEY = config('TOKEN_ENCRYPTION_KEY', default='')

# ── Public scanner ────────────────────────────────────────────────────────────
# The no-signup scanner reads public repositories. Unauthenticated GitHub allows
# only 60 requests an hour per IP — roughly one scan — so a token is effectively
# required in production. A classic token with no scopes is enough: it grants no
# access beyond what is already public, but raises the limit to 5000/hour.
PUBLIC_SCAN_GITHUB_TOKEN = config('PUBLIC_SCAN_GITHUB_TOKEN', default='')
# Public repositories scanned per hour from the seeded backlog. Three API
# calls each, against an authenticated budget of 5000 an hour.
PUBLIC_SCAN_BATCH = config('PUBLIC_SCAN_BATCH', default=400, cast=int)

# ── GitHub App ────────────────────────────────────────────────────────────────
# One-click install replaces the Personal Access Token flow: shorter-lived
# credentials, organisation-wide access, and permission to comment on PRs.
GITHUB_APP_ID          = config('GITHUB_APP_ID', default='')
GITHUB_APP_SLUG        = config('GITHUB_APP_SLUG', default='')
GITHUB_APP_PRIVATE_KEY = config('GITHUB_APP_PRIVATE_KEY', default='').replace('\\n', '\n')
GITHUB_APP_WEBHOOK_SECRET = config('GITHUB_APP_WEBHOOK_SECRET', default='')

DOMAIN  = config('DOMAIN', default='localhost:8000')
BASE_URL = config('BASE_URL', default='http://localhost:8000')
GITHUB_REDIRECT_URI = BASE_URL + '/auth/github/callback/'
GITLAB_REDIRECT_URI = BASE_URL + '/auth/gitlab/callback/'

# i18n cookie settings
LANGUAGE_COOKIE_NAME = 'django_language'
LANGUAGE_COOKIE_AGE = 365 * 24 * 60 * 60  # 1 год
USE_L10N = True

# ── Payments ─────────────────────────────────────────────────────────────────
# PAYMENT_MODE controls live vs sandbox for Lemon Squeezy and Cryptomus.
# Set PAYMENT_MODE=live in .env for real charges.
# The product's name, in one place (growth plan B1.1): same as the domain.
PRODUCT_NAME    = 'DevOpsCheck'

PAYMENT_MODE    = config('PAYMENT_MODE', default='test')  # 'test' | 'live'
# Until payments are live, customers see "early access" instead of a checkout
# that would either fail on a real card or hand out a plan for a test card.
# Staff still get the test checkout, to try the flow end to end.
PAYMENTS_LIVE   = PAYMENT_MODE == 'live'
PRO_PRICE_USD   = 19   # int — cast to str() only where Cryptomus's payload requires it
PRO_PERIOD_DAYS = 31   # days of access granted after a successful monthly payment
ANNUAL_PERIOD_DAYS = 366

# ── Plans ─────────────────────────────────────────────────────────────────────
# Prices are whole dollars. Annual is billed once at a 20% discount, which turns
# month-thirty-one revenue into month-one cash — the thing that matters at launch.
PLAN_PRICES = {
    'pro':        {'monthly': 19,  'annual': 182},   # 19*12 = 228 → -20%
    'team':       {'monthly': 99,  'annual': 950},   # per organisation, seats included
    'compliance': {'monthly': 299, 'annual': 2870},
}
ANNUAL_DISCOUNT_PCT = 20

# Free-plan quotas. Free users get a real taste of the paid features each month
# rather than a description of them.
FREE_REPO_LIMIT           = 3
FREE_AI_REPORTS_PER_MONTH = 1
FREE_PDF_PER_MONTH        = 1

# Lemon Squeezy variant ids per plan and period. Fill these in .env after
# creating the variants in the Lemon Squeezy dashboard.
LS_VARIANTS = {
    ('pro', 'monthly'):        config('LS_VARIANT_PRO_MONTHLY', default=''),
    ('pro', 'annual'):         config('LS_VARIANT_PRO_ANNUAL', default=''),
    ('team', 'monthly'):       config('LS_VARIANT_TEAM_MONTHLY', default=''),
    ('team', 'annual'):        config('LS_VARIANT_TEAM_ANNUAL', default=''),
    ('compliance', 'monthly'): config('LS_VARIANT_COMPLIANCE_MONTHLY', default=''),
    ('compliance', 'annual'):  config('LS_VARIANT_COMPLIANCE_ANNUAL', default=''),
}

# ── Lemon Squeezy ─────────────────────────────────────────────────────────────
LEMONSQUEEZY_API_KEY        = config('LEMONSQUEEZY_API_KEY', default='')
LEMONSQUEEZY_STORE_ID       = config('LEMONSQUEEZY_STORE_ID', default='')
LEMONSQUEEZY_PRODUCT_ID     = config('LEMONSQUEEZY_PRODUCT_ID', default='')
LEMONSQUEEZY_VARIANT_ID     = config('LEMONSQUEEZY_VARIANT_ID', default='')
LEMONSQUEEZY_WEBHOOK_SECRET = config('LEMONSQUEEZY_WEBHOOK_SECRET', default='')

# ── Cryptomus (crypto checkout) ───────────────────────────────────────────────
# Sign up at cryptomus.com → Payouts → API
# Use a separate test merchant for PAYMENT_MODE=test
CRYPTOMUS_MERCHANT_ID = config('CRYPTOMUS_MERCHANT_ID', default='')
CRYPTOMUS_API_KEY     = config('CRYPTOMUS_API_KEY',     default='')

# ── Email (SMTP) ──────────────────────────────────────────────────────────────
EMAIL_BACKEND    = config('EMAIL_BACKEND', default='django.core.mail.backends.smtp.EmailBackend')
EMAIL_HOST       = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT       = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS    = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER  = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='DevOpsCheck <noreply@devopscheck.com>')
# Where a buyer is sent when a plan has no self-serve checkout yet.
SUPPORT_EMAIL      = config('SUPPORT_EMAIL', default='support@devopscheck.com')

# ── Database connection pooling ────────────────────────────────────────────────
DATABASES['default']['CONN_MAX_AGE'] = 60

# ── Sentry (optional error tracking) ─────────────────────────────────────────
SENTRY_DSN = config('SENTRY_DSN', default='')
if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.celery import CeleryIntegration
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[DjangoIntegration(), CeleryIntegration()],
        traces_sample_rate=0.1,
        send_default_pii=False,
    )

# ── Security ─────────────────────────────────────────────────────────────────
SECURE_BROWSER_XSS_FILTER   = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS             = 'DENY'
SESSION_COOKIE_HTTPONLY      = True
CSRF_COOKIE_HTTPONLY         = True

# Proxy headers — set by Nginx before forwarding to Gunicorn
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST    = True

# HSTS — 1-year max-age, including subdomains + preload list eligibility.
# Nginx also sets Strict-Transport-Security; this is defence-in-depth at the
# Django layer (e.g. for requests that bypass Nginx in development).
SECURE_HSTS_SECONDS            = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD            = True

# SECURE_SSL_REDIRECT is intentionally off — Nginx terminates TLS and handles
# HTTP→HTTPS redirect. Enabling this here would cause a double-redirect loop
# inside the Docker/Gunicorn stack.
SECURE_SSL_REDIRECT = False

# Secure cookies — HTTPS-only transport in production
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE    = True

CSRF_TRUSTED_ORIGINS = config(
    'CSRF_TRUSTED_ORIGINS',
    default='https://devopscheck.com,https://www.devopscheck.com',
).split(',')

# ── Logging ───────────────────────────────────────────────────────────────────
# Writes django.request errors (500s, unhandled exceptions) to stderr so they
# appear in `docker logs` / `journalctl` without needing a separate log file.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['console'],
            'level': 'ERROR',
            'propagate': False,
        },
        'django': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'app': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
