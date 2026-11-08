"""
URL configuration for the admin process.

The admin is not routed on the public site. It runs as its own process with
`ADMIN_SITE=1`, which points `ROOT_URLCONF` here, and it is published on its own
port — so on the public domain `/admin/` does not exist at all, rather than
existing behind a password. An admin login form reachable from the internet is
the most valuable target the product has: it holds every customer's account, and
the session behind it can read audit data for every repository they connected.

Nothing else is served here. There is no landing page, no signup, no OAuth
callback and no webhook on this port — a request for any of them 404s, which is
also the cheapest way to tell a scanner it has the wrong host.

Static files come from WhiteNoise inside this process, so the admin does not
depend on the public site's Nginx `/static/` block being reachable.
"""
from django.contrib import admin
from django.urls import path
from django.views.generic import RedirectView

# The project's own error pages. They use hardcoded hrefs rather than {% url %},
# so they render on this urlconf too — a template reversing 'landing' here would
# turn every 404 into a 500.
handler404 = 'app.views.error_404'
handler500 = 'app.views.error_500'
handler403 = 'app.views.error_403'

urlpatterns = [
    path('admin/metrics/', __import__('app.admin_metrics', fromlist=['metrics']).metrics, name='admin_metrics'),
    path('admin/', admin.site.urls),
    # The root exists only so this port behaves the same in development as in
    # production. Without it Django serves its "The install worked successfully"
    # placeholder whenever DEBUG is on, which reports the framework version to
    # anyone who asks. Nothing else is routed: any other path 404s.
    path('', RedirectView.as_view(url='/admin/', permanent=False)),
]
