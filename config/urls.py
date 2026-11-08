from django.urls import path, include
from django.conf.urls.i18n import set_language
from app import views, views_public, views_team

handler404 = 'app.views.error_404'
handler500 = 'app.views.error_500'
handler403 = 'app.views.error_403'
handler429 = 'app.views.error_429'

# The admin is deliberately absent. It is served by a separate process on its
# own port (`ADMIN_SITE=1` → `config.urls_admin`), so on the public domain
# /admin/ does not exist rather than existing behind a password.
# `AdminIsNotOnThePublicSiteTest` keeps it that way.
urlpatterns = [
    path('accounts/', include('allauth.urls')),
    path('i18n/setlang/', set_language, name='set_language'),

    path('health/', views.health_check, name='health_check'),
    path('robots.txt', views.robots_txt, name='robots_txt'),
    path('sitemap.xml', views.sitemap_xml, name='sitemap_xml'),
    path('.well-known/security.txt', views.security_txt, name='security_txt'),
    path('trust/', views.trust_page, name='trust'),
    path('', views.landing, name='landing'),
    path('pricing/', views.pricing_page, name='pricing'),

    # ── Public, no-account scanner (top of the funnel + SEO surface) ────────
    path('scan/', views_public.scan_index, name='scan_index'),

    # ── The corpus as a public reference: distribution, leaderboards, and how
    #    often each check fails across everything scanned ──────────────────────
    path('rankings/', views_public.rankings, name='rankings'),
    path('checks/', views_public.checks_index, name='checks_index'),
    path('compare/', views_public.compare, name='compare'),
    path('llms.txt', views_public.llms_txt, name='llms_txt'),
    path('google9c61ce115925089c.html', views_public.google_site_verification),
    path('checks/<str:check_id>/', views_public.check_guide, name='check_guide'),
    path('rankings/<str:slug>/', views_public.rankings, name='rankings_language'),
    path('scan/submit/', views_public.scan_submit, name='scan_submit'),
    path('scan/org/', views_public.org_scan_submit, name='org_scan_submit'),
    path('scan/org/<str:org>/', views_public.org_scan, name='org_scan'),
    path('scan/<str:owner>/<str:repo>/', views_public.public_scan, name='public_scan'),
    path('scan/<str:owner>/<str:repo>/status/', views_public.public_scan_status, name='public_scan_status'),

    # ── Keeping the visitor: an address, one report, mail when the score moves.
    #    No account, and every message carries a one-click unsubscribe. ────────
    path('scan/<str:owner>/<str:repo>/watch/', views_public.watch_subscribe, name='watch_subscribe'),
    path('scan/<str:owner>/<str:repo>/rescan/', views_public.public_rescan, name='public_rescan'),
    path('false-positive/', views_public.report_false_positive, name='report_false_positive'),
    path('scan/<str:owner>/<str:repo>/badge/pr/', views_public.badge_pull_request, name='badge_pull_request'),
    path('watch/confirm/<str:token>/', views_public.watch_confirm, name='watch_confirm'),
    path('watch/stop/<str:token>/', views_public.watch_unsubscribe, name='watch_unsubscribe'),
    path('og/scan/<str:owner>/<str:repo>.png', views_public.og_scan_image, name='og_scan'),
    path('og/audit/<str:token>.png', views_public.og_audit_image, name='og_audit'),
    path('og/page/<str:page>.png', views_public.og_page_image, name='og_page'),
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Onboarding
    path('onboarding/', views.onboarding, name='onboarding'),
    path('onboarding/complete/', views.onboarding_complete, name='onboarding_complete'),

    # Profile / connect
    path('profile/', views.connect, name='connect'),
    path('profile/token/', views.connect_token, name='connect_token'),
    path('profile/disconnect/<str:provider>/<str:provider_id>/', views.disconnect_provider, name='disconnect_provider'),
    path('repo/remove/', views.remove_repo, name='remove_repo'),
    path('repo/restore/', views.restore_repo, name='restore_repo'),
    path('profile/update/', views.update_profile, name='update_profile'),
    path('profile/password/', views.change_password, name='change_password'),
    path('profile/ai-settings/', views.save_ai_settings, name='save_ai_settings'),
    path('profile/notifications/', views.update_notifications, name='update_notifications'),
    path('profile/ai-consent/', views.update_ai_consent, name='update_ai_consent'),
    path('guide/dismiss/', views.dismiss_guide_step, name='dismiss_guide_step'),
    path('guide/restore/', views.restore_guide, name='restore_guide'),
    path('profile/delete/', views.delete_account, name='delete_account'),
    path('profile/api-token/regenerate/', views.regenerate_api_token, name='regenerate_api_token'),

    # Dashboard / audits
    path('dashboard/', views.dashboard, name='dashboard'),
    path('audit/start/', views.start_audit_for_repo, name='start_audit'),
    path('gitlab/', views.gitlab_dashboard, name='gitlab_dashboard'),

    # GitHub App (one-click install)
    path('auth/github/app/install/', views.github_app_install, name='github_app_install'),
    path('auth/github/app/callback/', views.github_app_callback, name='github_app_callback'),
    path('audit/gitlab/start/', views.start_gitlab_audit, name='start_gitlab_audit'),

    path('audit/<int:audit_id>/', views.audit_detail, name='audit_detail'),
    path('audit/<int:audit_id>/run/', views.run_audit, name='run_audit'),
    path('audit/<int:audit_id>/ai/', views.regenerate_ai, name='regenerate_ai'),
    path('audit/<int:audit_id>/status/', views.audit_status, name='audit_status'),
    path('audit/<int:audit_id>/pdf/', views.audit_pdf_download, name='audit_pdf'),
    path('audit/<int:audit_id>/toggle-public/', views.toggle_public, name='toggle_public'),
    path('audit/<int:audit_id>/history/', views.audit_history_json, name='audit_history'),
    path('audit/<int:audit_id>/fix/<int:check_id>/', views.fix_generate, name='fix_generate'),
    path('audit/<int:audit_id>/fix/<int:check_id>/pr/', views.fix_open_pr, name='fix_open_pr'),
    path('incident/<int:incident_id>/pr/', views.incident_open_pr, name='incident_open_pr'),
    path('incident/<int:incident_id>/rotated/', views.incident_mark_rotated, name='incident_mark_rotated'),

    # ── Team / Compliance ───────────────────────────────────────────────────
    path('organization/', views_team.org_dashboard, name='org_dashboard'),
    path('digest/', views_team.digest_settings, name='digest_settings'),
    path('digest/stop/<str:token>/', views_team.digest_unsubscribe, name='digest_unsubscribe'),
    path('audit/<int:audit_id>/compliance/', views_team.compliance_report, name='compliance_report'),
    path('audit/<int:audit_id>/compliance/<str:framework>/', views_team.compliance_report, name='compliance_report_framework'),
    path('audit/<int:audit_id>/compliance/<str:framework>/export/', views_team.compliance_export, name='compliance_export'),
    path('audit/<int:audit_id>/sbom/<str:fmt>/', views_team.sbom_download, name='sbom_download'),

    # Public sharing + badge
    path('audit/public/<str:token>/', views.public_audit_detail, name='public_audit'),
    path('badge/<str:token>.svg', views.badge_svg, name='badge_svg'),
    path('badge/<str:token>/', views.badge_svg, name='badge_svg_slash'),

    # Webhook auto-audit
    # The App-wide route must come first: <str:secret> below matches "app"
    # just as happily as a real secret, and Django resolves in order — with
    # the generic pattern first, every delivery to the App webhook was
    # swallowed as an unknown per-user secret and 404'd instead of running.
    # One URL for every GitHub App installation — configured once on the App
    # itself (GitHub → Settings → Developer settings → the App → Webhook),
    # not per customer. See app.views.github_app_webhook.
    path('webhook/github/app/', views.github_app_webhook, name='github_app_webhook'),
    path('webhook/github/<str:secret>/', views.github_webhook_auto, name='github_webhook'),

    # ── REST API ────────────────────────────────────────────────────────────
    path('api/v1/audits/', views.api_audits, name='api_audits'),
    path('api/v1/audit/start/', views.api_audit_start, name='api_audit_start'),
    path('api/v1/audit/<int:audit_id>/', views.api_audit_detail, name='api_audit_detail'),
    path('api/v1/ci-scan/', views_public.api_ci_scan_start, name='api_ci_scan_start'),
    path('api/v1/ci-scan/<int:scan_id>/', views_public.api_ci_scan_detail, name='api_ci_scan_detail'),

    # ── Billing ─────────────────────────────────────────────────────────────
    path('billing/', views.billing_view, name='billing'),
    path('billing/checkout/crypto/', views.create_crypto_checkout, name='crypto_checkout'),
    path('billing/cancel-sub/', views.cancel_subscription, name='cancel_subscription'),
    path('billing/success/', views.payment_success, name='payment_success'),
    path('billing/cancel/', views.payment_cancel, name='payment_cancel'),
    path('billing/webhooks/crypto/', views.cryptomus_webhook, name='crypto_webhook'),
    path('billing/checkout/ls/', views.create_ls_checkout, name='ls_checkout'),
    path('billing/early-access/', views.early_access, name='early_access'),
    path('billing/webhooks/ls/', views.ls_webhook, name='ls_webhook'),
]
