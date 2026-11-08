"""
Django admin for the audit product.

Two things shape every registration below.

**Nothing here may leak a token.** `GithubProfile.access_token`,
`GitlabProfile.access_token` and `UserAISettings.api_key` are encrypted at rest
(`crypto_utils.EncryptedTextField`), and a `ModelAdmin` that includes the field
decrypts it straight onto the change page — which would make the admin the
easiest place in the system to steal a customer's credentials. They are excluded
from every form and shown only as a "set / not set" indicator. `SocialToken`
(django-allauth's own model, not one of ours) gets the same treatment below,
for the same reason — its `token`/`token_secret` are plain fields, and
allauth registers a default admin for it that renders them.

**Audits are append-only.** The score history and the trend chart exist because
a run is never edited or reused. The admin can read audits and remove or restore
a repository, and cannot change a score or delete a run.
"""
from django.conf import settings
from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.models import User
from django.db.models import Count, Max
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html
from datetime import timedelta

from app.models import (
    Audit, AuditCheck, FalsePositiveReport, FixAttempt, FunnelEvent, PlanInterest, GithubProfile, SecretIncident, GitlabProfile,
    MonthlyUsage, PublicScan, RepoWatch, UserAISettings, UserProfile, UserSubscription,
)

admin.site.site_header = settings.PRODUCT_NAME
admin.site.site_title = f'{settings.PRODUCT_NAME} admin'
admin.site.index_title = 'Operations — growth funnel: /admin/metrics/'


# ── Shared display helpers ────────────────────────────────────────────────────

def _secret_state(value):
    """A credential is reported as present or absent, never rendered."""
    return format_html(
        '<span style="color:{}">{}</span>',
        '#2e7d32' if value else '#999',
        'set' if value else 'not set',
    )


# ── django-allauth's own admin ────────────────────────────────────────────────
#
# `allauth.socialaccount` registers a ModelAdmin for SocialToken by default,
# with `token` and `token_secret` as plain, editable form fields — the exact
# thing this file's own invariant exists to prevent, just for a model this
# app does not own. In the ordinary case it would show nothing (`app.signals`
# blanks both the moment its own encrypted copy is saved — see that module's
# docstring), but "ordinarily blank" is not the same guarantee as "cannot be
# rendered", and a row from before that redaction shipped, or a future signal
# failure, would otherwise put a real token on an editable page whose default
# admin gave it no more protection than a hex TextField gets by default.
from allauth.socialaccount.models import SocialToken  # noqa: E402

admin.site.unregister(SocialToken)


@admin.register(SocialToken)
class SocialTokenAdmin(admin.ModelAdmin):
    exclude = ('token', 'token_secret')
    list_display = ('account', 'app', 'token_state', 'expires_at')
    list_select_related = ('account', 'app')
    readonly_fields = ('token_state',)

    @admin.display(description='token')
    def token_state(self, obj):
        return _secret_state(obj.token or obj.token_secret)


def _user_link(user):
    if not user:
        return '—'
    url = reverse('admin:auth_user_change', args=[user.pk])
    return format_html('<a href="{}">{}</a>', url, user.username)


# ── Subscriptions — the reason the admin exists ───────────────────────────────

def _grant(queryset, plan, period, days, request):
    """Move a set of subscriptions onto a plan, extending from now."""
    end = timezone.now() + timedelta(days=days)
    updated = queryset.update(
        plan=plan,
        billing_period=period,
        current_period_end=end,
        cancel_at_period_end=False,
        # A hand-granted plan is not a payment. Clearing the provider keeps the
        # cancellation path from calling Lemon Squeezy about a subscription that
        # does not exist there.
        payment_provider='manual',
        stripe_subscription_id='',
        expiry_notified_at=None,
    )
    messages.success(
        request,
        f'{updated} account(s) on {plan}/{period} until {end:%Y-%m-%d}.',
    )


@admin.register(UserSubscription)
class UserSubscriptionAdmin(admin.ModelAdmin):
    # cancel_at_period_end is a filter rather than a column: eight columns plus
    # the filter sidebar clips the last one out of view at a normal width.
    list_display = (
        'user_link', 'plan', 'billing_period', 'active_state',
        'current_period_end', 'days_left', 'payment_provider',
    )
    list_filter = ('plan', 'billing_period', 'payment_provider', 'cancel_at_period_end')
    search_fields = ('user__username', 'user__email', 'stripe_subscription_id')
    ordering = ('-updated_at',)
    autocomplete_fields = ('user',)
    readonly_fields = ('created_at', 'updated_at', 'active_state', 'days_left')
    date_hierarchy = 'current_period_end'
    list_select_related = ('user',)

    @admin.display(description='user', ordering='user__username')
    def user_link(self, obj):
        return _user_link(obj.user)

    @admin.display(description='access', boolean=True)
    def active_state(self, obj):
        # `is_active` is the property the whole product gates on; showing the raw
        # plan column alone hides an expired Pro that behaves like Free.
        return obj.is_active

    @admin.display(description='days left')
    def days_left(self, obj):
        left = obj.days_left
        return '∞' if left is None and obj.plan != UserSubscription.PLAN_FREE else left

    # ── Actions ──
    @admin.action(description='Grant Pro — 30 days')
    def grant_pro_month(self, request, queryset):
        _grant(queryset, UserSubscription.PLAN_PRO, 'monthly', 30, request)

    @admin.action(description='Grant Pro — 1 year')
    def grant_pro_year(self, request, queryset):
        _grant(queryset, UserSubscription.PLAN_PRO, 'annual', 365, request)

    @admin.action(description='Grant Team — 30 days')
    def grant_team_month(self, request, queryset):
        _grant(queryset, UserSubscription.PLAN_TEAM, 'monthly', 30, request)

    @admin.action(description='Grant Compliance — 1 year')
    def grant_compliance_year(self, request, queryset):
        _grant(queryset, UserSubscription.PLAN_COMPLIANCE, 'annual', 365, request)

    @admin.action(description='Expire now (back to Free)')
    def revoke(self, request, queryset):
        updated = queryset.update(
            plan=UserSubscription.PLAN_FREE,
            current_period_end=timezone.now(),
            cancel_at_period_end=False,
            expiry_notified_at=None,
        )
        messages.success(request, f'{updated} account(s) back on Free.')

    @admin.action(description='Expire in 2 days (test the reminder mail)')
    def expire_in_two_days(self, request, queryset):
        # send_expiry_reminders looks three days ahead, so this is the state the
        # job is supposed to pick up on its next run.
        updated = queryset.update(
            current_period_end=timezone.now() + timedelta(days=2),
            expiry_notified_at=None,
        )
        messages.success(request, f'{updated} account(s) expire in 2 days.')

    actions = (
        'grant_pro_month', 'grant_pro_year', 'grant_team_month',
        'grant_compliance_year', 'expire_in_two_days', 'revoke',
    )


# ── Audits ────────────────────────────────────────────────────────────────────

class AuditCheckInline(admin.TabularInline):
    model = AuditCheck
    extra = 0
    can_delete = False
    fields = ('check_id', 'severity', 'passed', 'applicable', 'name')
    readonly_fields = fields
    ordering = ('severity_rank', 'check_id')
    show_change_link = False

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(Audit)
class AuditAdmin(admin.ModelAdmin):
    # repo_kind is a filter, not a column — nine columns clip the last one, and
    # 'removed' is the one an operator is here to see.
    list_display = (
        'repo_display', 'user_link', 'source', 'status', 'score',
        'trigger', 'created_at', 'removed_state',
    )
    list_filter = (
        'status', 'source', 'trigger', 'repo_kind', 'is_public',
        ('archived_at', admin.EmptyFieldListFilter),
    )
    search_fields = ('repo_full_name', 'user__username', 'user__email', 'commit_sha')
    ordering = ('-created_at',)
    date_hierarchy = 'created_at'
    list_select_related = ('user',)
    inlines = (AuditCheckInline,)

    # Append-only: every field is readable, none is writable. A score edited by
    # hand would be indistinguishable from one the engine produced.
    def get_readonly_fields(self, request, obj=None):
        return [f.name for f in self.model._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description='user', ordering='user__username')
    def user_link(self, obj):
        return _user_link(obj.user)

    @admin.display(description='repository', ordering='repo_full_name')
    def repo_display(self, obj):
        return obj.repo_display

    @admin.display(description='removed', boolean=True)
    def removed_state(self, obj):
        return obj.archived_at is not None

    @admin.action(description='Remove repository (frees the quota slot)')
    def archive_repository(self, request, queryset):
        pairs = {(a.user_id, a.source, a.repo_full_name) for a in queryset}
        total = sum(
            Audit.objects.filter(
                user_id=uid, source=src, repo_full_name=name,
            ).active().update(archived_at=timezone.now())
            for uid, src, name in pairs
        )
        messages.success(
            request,
            f'{len(pairs)} repositor(y/ies) removed, {total} run(s) marked. '
            f'Nothing was deleted.',
        )

    @admin.action(description='Restore repository')
    def restore_repository(self, request, queryset):
        pairs = {(a.user_id, a.source, a.repo_full_name) for a in queryset}
        total = sum(
            Audit.objects.filter(
                user_id=uid, source=src, repo_full_name=name,
            ).archived().update(archived_at=None)
            for uid, src, name in pairs
        )
        messages.success(request, f'{len(pairs)} repositor(y/ies) restored, {total} run(s).')

    actions = ('archive_repository', 'restore_repository')


# ── Provider connections ──────────────────────────────────────────────────────

class ProviderAdminBase(admin.ModelAdmin):
    """Shared rules for the two connection models: never show the token."""
    exclude = ('access_token',)
    list_select_related = ('user',)
    search_fields = ('user__username', 'user__email')

    @admin.display(description='user', ordering='user__username')
    def user_link(self, obj):
        return _user_link(obj.user)

    @admin.display(description='token')
    def token_state(self, obj):
        return _secret_state(obj.access_token)

    @admin.action(description='Mark connection healthy (clears the outage)')
    def mark_healthy(self, request, queryset):
        count = 0
        for obj in queryset:
            obj.mark_working()
            count += 1
        messages.success(request, f'{count} connection(s) marked working.')

    actions = ('mark_healthy',)


@admin.register(GithubProfile)
class GithubProfileAdmin(ProviderAdminBase):
    list_display = ('github_login', 'user_link', 'token_state', 'token_status',
                    'is_app_install', 'installation_id', 'token_broken_since')
    list_filter = ('token_status',)
    readonly_fields = ('token_state', 'token_broken_since', 'token_notified_at')

    def get_search_fields(self, request):
        return super().search_fields + ('github_login',)

    @admin.display(description='app install', boolean=True)
    def is_app_install(self, obj):
        return obj.is_app_install


@admin.register(GitlabProfile)
class GitlabProfileAdmin(ProviderAdminBase):
    list_display = ('gitlab_username', 'user_link', 'gitlab_url', 'token_state',
                    'token_status', 'verify_ssl', 'token_broken_since')
    list_filter = ('token_status', 'verify_ssl')
    readonly_fields = ('token_state', 'token_broken_since', 'token_notified_at')

    def get_search_fields(self, request):
        return super().search_fields + ('gitlab_username', 'gitlab_url')


@admin.register(UserAISettings)
class UserAISettingsAdmin(admin.ModelAdmin):
    """The customer's own model key. Present or absent — never the value."""
    exclude = ('api_key',)
    list_display = ('user_link', 'provider', 'key_state')
    list_filter = ('provider',)
    search_fields = ('user__username', 'user__email')
    list_select_related = ('user',)
    readonly_fields = ('key_state',)

    @admin.display(description='user', ordering='user__username')
    def user_link(self, obj):
        return _user_link(obj.user)

    @admin.display(description='api key')
    def key_state(self, obj):
        return _secret_state(obj.api_key)


# ── Profiles, usage and the public corpus ─────────────────────────────────────

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """
    The per-user flags, which are what most testing actually needs to flip.

    The webhook secret and the API token authenticate requests, so they are
    reported as set or unset rather than printed.
    """
    exclude = ('webhook_secret', 'api_token')
    list_display = ('user_link', 'email_notifications', 'pr_comments_enabled',
                    'onboarding_done', 'webhook_state', 'api_token_state')
    list_filter = ('email_notifications', 'pr_comments_enabled', 'onboarding_done')
    list_editable = ('email_notifications', 'pr_comments_enabled', 'onboarding_done')
    search_fields = ('user__username', 'user__email')
    list_select_related = ('user',)
    readonly_fields = ('webhook_state', 'api_token_state')

    @admin.display(description='user', ordering='user__username')
    def user_link(self, obj):
        return _user_link(obj.user)

    @admin.display(description='webhook secret')
    def webhook_state(self, obj):
        return _secret_state(obj.webhook_secret)

    @admin.display(description='api token')
    def api_token_state(self, obj):
        return _secret_state(obj.api_token)

    @admin.action(description='Rotate webhook secret and API token')
    def rotate_credentials(self, request, queryset):
        for profile in queryset:
            profile.webhook_secret = ''
            profile.api_token = None
            profile.save(update_fields=['webhook_secret', 'api_token'])
            profile.ensure_webhook_secret()
            profile.ensure_api_token()
        messages.success(
            request,
            f'{queryset.count()} credential pair(s) rotated. The old webhook URL '
            f'and API token stop working immediately.',
        )

    actions = ('rotate_credentials',)


@admin.register(MonthlyUsage)
class MonthlyUsageAdmin(admin.ModelAdmin):
    list_display = ('user_link', 'period', 'ai_reports', 'pdf_exports', 'audits')
    list_filter = ('period',)
    search_fields = ('user__username', 'user__email')
    ordering = ('-period',)
    list_select_related = ('user',)

    @admin.display(description='user', ordering='user__username')
    def user_link(self, obj):
        return _user_link(obj.user)

    @admin.action(description='Reset this month\'s free credits')
    def reset_counters(self, request, queryset):
        updated = queryset.update(ai_reports=0, pdf_exports=0)
        messages.success(request, f'{updated} counter row(s) reset.')

    actions = ('reset_counters',)


@admin.register(PublicScan)
class PublicScanAdmin(admin.ModelAdmin):
    list_display = ('repo_full_name', 'status', 'score', 'primary_language',
                    'stars', 'view_count', 'score_version', 'queued_at', 'updated_at')
    list_filter = ('status', 'score_version', 'primary_language')
    search_fields = ('repo_full_name', 'description')
    ordering = ('-view_count', '-stars')
    date_hierarchy = 'created_at'
    readonly_fields = ('results', 'category_scores', 'created_at', 'updated_at')

    @admin.action(description='Re-queue for scanning')
    def requeue(self, request, queryset):
        # queued_at cleared as well as the status: the stuck-scan sweep reads it
        # to tell a job that died from one that was seeded and never started.
        updated = queryset.update(
            status=Audit.STATUS_PENDING, queued_at=None, error_message='',
        )
        messages.success(
            request,
            f'{updated} scan(s) queued. scan_pending_public_repos drains them hourly.',
        )

    actions = ('requeue',)


@admin.register(RepoWatch)
class RepoWatchAdmin(admin.ModelAdmin):
    """
    Addresses collected on the public scanner. The list every launch depends on.

    The token confirms and unsubscribes, so it is never rendered: anyone who
    reads it can end somebody else's subscription, and a screenshot of this page
    would carry them all.
    """
    exclude = ('token',)
    list_display = ('email', 'repo_full_name', 'state', 'last_score',
                    'last_notified_at', 'language', 'created_at')
    list_filter = ('language',
                   ('confirmed_at', admin.EmptyFieldListFilter),
                   ('unsubscribed_at', admin.EmptyFieldListFilter))
    search_fields = ('email', 'repo_full_name')
    ordering = ('-created_at',)
    date_hierarchy = 'created_at'
    readonly_fields = ('state', 'created_at', 'last_notified_at')

    @admin.display(description='state')
    def state(self, obj):
        colour = {'watching': '#2e7d32', 'pending': '#b26a00',
                  'unsubscribed': '#999'}[obj.state]
        return format_html('<b style="color:{}">{}</b>', colour, obj.state)

    @admin.action(description='Unsubscribe (as the reader would)')
    def unsubscribe(self, request, queryset):
        count = sum(1 for w in queryset if w.unsubscribe())
        messages.success(request, f'{count} subscription(s) ended.')

    actions = ('unsubscribe',)


# ── The user page, with everything about that user on it ──────────────────────

class UserSubscriptionInline(admin.StackedInline):
    model = UserSubscription
    can_delete = False
    extra = 0
    fields = ('plan', 'billing_period', 'current_period_end',
              'cancel_at_period_end', 'payment_provider')


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    extra = 0
    fields = ('email_notifications', 'pr_comments_enabled', 'onboarding_done')


class UserAdmin(DjangoUserAdmin):
    """
    Django's user page plus the two rows the product keys everything off.

    Granting a plan used to mean opening a second model and searching for the
    same person again; the plan is an attribute of the account, so it belongs on
    the account's page.
    """
    inlines = (UserSubscriptionInline, UserProfileInline)
    # Django's default carries first_name and last_name, which this product never
    # collects — two empty columns pushing the useful ones off the screen.
    list_display = ('username', 'email', 'plan_state', 'audit_count',
                    'last_audit', 'date_joined', 'is_staff')

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('subscription').annotate(
            _audits=Count('audits', distinct=True),
            _last_audit=Max('audits__created_at'),
        )

    @admin.display(description='plan')
    def plan_state(self, obj):
        sub = getattr(obj, 'subscription', None)
        if sub is None or sub.plan == UserSubscription.PLAN_FREE:
            return 'free'
        return format_html(
            '<b style="color:{}">{}</b>',
            '#2e7d32' if sub.is_active else '#b71c1c',
            f'{sub.plan}{"" if sub.is_active else " (expired)"}',
        )

    @admin.display(description='audits', ordering='_audits')
    def audit_count(self, obj):
        return obj._audits

    @admin.display(description='last audit', ordering='_last_audit')
    def last_audit(self, obj):
        return obj._last_audit


admin.site.unregister(User)
admin.site.register(User, UserAdmin)


def fix_agent_metrics(qs) -> dict:
    """The phase 5 numbers: how often the agent gets CI green, and what it costs."""
    finished = [a for a in qs if a.state not in FixAttempt.ACTIVE_STATES]
    judged = [a for a in finished if a.state in (FixAttempt.STATE_GREEN, FixAttempt.STATE_GAVE_UP)]
    closed = [a for a in finished if a.merged is not None]
    worked = [a for a in finished if a.iterations or a.state == FixAttempt.STATE_GAVE_UP]

    def pct(part, whole):
        return round(100 * part / whole) if whole else None
    return {
        'total': len(qs),
        'green_pct': pct(sum(a.state == FixAttempt.STATE_GREEN for a in judged), len(judged)),
        'merged_pct': pct(sum(bool(a.merged) for a in closed), len(closed)),
        'avg_iterations': round(sum(a.iterations for a in worked) / len(worked), 2) if worked else None,
        'llm_calls': sum(a.llm_calls for a in qs),
        'llm_chars': sum(a.llm_chars for a in qs),
    }


@admin.register(FixAttempt)
class FixAttemptAdmin(admin.ModelAdmin):
    """Read-only: every field is something the agent observed or did."""
    list_display = ('repo_full_name', 'pr_number', 'check_name', 'state', 'iterations',
                    'llm_calls', 'merged', 'created_at')
    list_filter = ('state', 'source', 'merged')
    search_fields = ('repo_full_name', 'check_name', 'user__email')
    readonly_fields = [f.name for f in FixAttempt._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def changelist_view(self, request, extra_context=None):
        m = fix_agent_metrics(list(FixAttempt.objects.all()))

        def show(v, suffix=''):
            return '—' if v is None else f'{v}{suffix}'
        extra_context = {**(extra_context or {}), 'title': (
            f"Fix PRs: {m['total']} · green {show(m['green_pct'], '%')} · merged {show(m['merged_pct'], '%')}"
            f" · avg iterations {show(m['avg_iterations'])} · model calls {m['llm_calls']}"
            f" ({m['llm_chars'] // 1000}k chars)")}
        return super().changelist_view(request, extra_context=extra_context)


@admin.register(SecretIncident)
class SecretIncidentAdmin(admin.ModelAdmin):
    """Read-only. There is no key to show: only a fingerprint was ever stored."""
    list_display = ('repo_full_name', 'label', 'file', 'status', 'liveness', 'first_seen_at', 'resolved_at')
    list_filter = ('status', 'rule', 'source')
    search_fields = ('repo_full_name', 'file', 'user__email')
    exclude = ('fingerprint',)
    readonly_fields = [f.name for f in SecretIncident._meta.fields if f.name != 'fingerprint']

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(FalsePositiveReport)
class FalsePositiveReportAdmin(admin.ModelAdmin):
    """Readers' "this FAIL is wrong" — new cases for docs/accuracy's evaluation set."""
    list_display = ('created_at', 'repo_full_name', 'check_id', 'source', 'score_version', 'user')
    list_filter = ('check_id', 'source', 'score_version')
    search_fields = ('repo_full_name', 'check_id', 'comment')
    readonly_fields = [f.name for f in FalsePositiveReport._meta.fields]

    def has_add_permission(self, request):
        return False


@admin.register(PlanInterest)
class PlanInterestAdmin(admin.ModelAdmin):
    """Who asked for a paid plan before payments went live — write to them at launch."""
    list_display = ('created_at', 'email', 'plan', 'period', 'user', 'notified_at')
    list_filter = ('plan', 'period')
    search_fields = ('email',)
    readonly_fields = ('created_at', 'email', 'plan', 'period', 'user')


@admin.register(FunnelEvent)
class FunnelEventAdmin(admin.ModelAdmin):
    """Raw funnel events. The weekly view is at /admin/metrics/."""
    list_display = ('created_at', 'name', 'source', 'ref', 'user')
    list_filter = ('name', 'source')
    readonly_fields = ('created_at', 'name', 'source', 'ref', 'user')

    def has_add_permission(self, request):
        return False
