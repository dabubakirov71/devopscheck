"""
Context every page needs, computed once.

The guide has to appear on whichever page the reader happens to be on, and
base.html has no view behind it — so it is assembled here rather than in each of
the dozen views that render through it.
"""
from django.conf import settings



def guide(request):
    """The current guide hint, or nothing."""
    user = getattr(request, 'user', None)
    if not user or not user.is_authenticated:
        return {}
    # Public and anonymous surfaces are not where a signed-in guide belongs.
    match = getattr(request, 'resolver_match', None)
    page = match.url_name if match else ''
    if page in ('landing', 'scan_index', 'public_scan', 'rankings', 'public_audit'):
        return {}
    try:
        from app.guide import hint_for
        return {'guide_hint': hint_for(user, page)}
    except Exception:
        # A guide is a convenience. It must never be the reason a page 500s.
        return {}


# "Repositories" covers the GitHub and GitLab pages and the audit itself, so the
# tab stays lit while the reader is anywhere inside that part of the product.
NAV_REPO_PAGES = ('dashboard', 'gitlab_dashboard', 'audit_detail',
                  'compliance_report', 'compliance_report_framework')


def nav(request):
    return {'nav_repo_pages': NAV_REPO_PAGES}


#: Which social card a page shares when it has no card of its own.
OG_PAGES = {
    'landing': 'home', 'scan_index': 'scan', 'rankings': 'rankings', 'rankings_language': 'rankings',
    'trust': 'trust', 'pricing': 'pricing', 'checks_index': 'checks', 'check_guide': 'checks',
    'compare': 'home',
}


def site_facts(request):
    """base_url and the numbers the site quotes about itself (app/site_facts.py)."""
    from django.conf import settings
    from app import site_facts as f
    match = getattr(request, 'resolver_match', None)
    return {
        'base_url': settings.BASE_URL,
        'product_name': settings.PRODUCT_NAME,
        'github_app_enabled': _github_app_enabled(),
        'check_count': f.CHECK_COUNT,
        'category_count': f.CATEGORY_COUNT,
        'scan_seconds': f.SCAN_SECONDS,
        'og_page': OG_PAGES.get(match.url_name if match else '', 'home'),
        **_alternates(request, settings.BASE_URL),
    }


def _alternates(request, base):
    """hreflang URLs for a public page, and its canonical in the current language."""
    from app.middleware import is_ru_public
    path = getattr(request, 'path_info', '/') or '/'
    prefix = getattr(request, 'lang_prefix', '')
    if not is_ru_public(path):
        return {'lang_prefix': prefix, 'hreflang': None}
    return {
        'lang_prefix': prefix,
        'hreflang': {'en': f'{base}{path}', 'ru': f'{base}/ru{path}'},
    }



def _github_app_enabled():
    try:
        from app import github_app
        return github_app.is_configured() and bool(settings.GITHUB_APP_SLUG)
    except Exception:
        return False
