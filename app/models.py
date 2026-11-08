import secrets
from datetime import timedelta
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from app.crypto_utils import EncryptedTextField


class ProviderConnection(models.Model):
    """
    Shared health state for a connected provider account.

    A personal access token expires, is revoked, or loses a scope, and until
    somebody notices, every audit for that account silently stops. The old
    behaviour was worse than silence: GitLab bounced the user back to the
    profile page, which reads as the page refusing to load, and GitHub *deleted
    the connection* on a single 401 — losing the installation id with it.

    A tool that stops working without saying so is a tool people cancel.
    """

    OK = 'ok'
    EXPIRED = 'expired'
    FORBIDDEN = 'forbidden'
    UNREACHABLE = 'unreachable'

    STATUS_CHOICES = [
        (OK, 'Working'),
        (EXPIRED, 'Token expired or revoked'),
        (FORBIDDEN, 'Token is missing a scope'),
        (UNREACHABLE, 'Provider could not be reached'),
    ]

    token_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=OK)
    token_checked_at = models.DateTimeField(null=True, blank=True)
    token_broken_since = models.DateTimeField(null=True, blank=True)
    token_notified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        abstract = True

    @property
    def is_healthy(self):
        return self.token_status == self.OK

    @property
    def status_message(self):
        """What to tell the owner, in the terms they can act on."""
        from django.utils.translation import gettext as _
        return {
            self.EXPIRED: _('The access token has expired or been revoked. '
                            'Create a new one and reconnect to resume audits.'),
            self.FORBIDDEN: _('The access token is missing a required scope. '
                              'Recreate it with read access to your repositories.'),
            self.UNREACHABLE: _('We could not reach the provider the last time we tried. '
                                'If this is a self-hosted instance, check that it is reachable.'),
        }.get(self.token_status, '')

    def mark_broken(self, status):
        """Record a failure without destroying the connection."""
        from django.utils import timezone
        fields = ['token_status', 'token_checked_at']
        self.token_status = status
        self.token_checked_at = timezone.now()
        if self.token_broken_since is None:
            self.token_broken_since = self.token_checked_at
            fields.append('token_broken_since')
        self.save(update_fields=fields)

    def mark_working(self):
        from django.utils import timezone
        if self.token_status == self.OK and self.token_broken_since is None:
            self.token_checked_at = timezone.now()
            self.save(update_fields=['token_checked_at'])
            return
        self.token_status = self.OK
        self.token_checked_at = timezone.now()
        self.token_broken_since = None
        self.token_notified_at = None
        self.save(update_fields=['token_status', 'token_checked_at',
                                 'token_broken_since', 'token_notified_at'])


class GithubProfile(ProviderConnection):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='github_profiles')
    github_id = models.IntegerField()
    github_login = models.CharField(max_length=100)
    access_token = EncryptedTextField()
    avatar_url = models.URLField(blank=True)
    # Set when the account was connected through the GitHub App rather than a PAT.
    installation_id = models.BigIntegerField(null=True, blank=True)

    class Meta:
        unique_together = ('user', 'github_id')

    def __str__(self):
        return self.github_login

    @property
    def is_app_install(self):
        return self.installation_id is not None

    @property
    def is_oauth(self):
        """Connected by signing in with GitHub (allauth), not by a pasted token or the App."""
        from allauth.socialaccount.models import SocialAccount
        return not self.is_app_install and SocialAccount.objects.filter(
            user_id=self.user_id, provider='github', uid=str(self.github_id)).exists()

    @property
    def current_token(self):
        """
        A token good to use right now — every caller about to make a GitHub
        API call reads this, never `access_token` directly.

        A PAT does not expire on its own. An App installation token does, in
        one hour, and `github_app_callback` stores only the one minted at
        connect time — nothing re-minted it after, so an App-connected
        account's first audit worked and every one after the first hour got a
        401 that read as "token expired, reconnect" when nothing was actually
        wrong. Raises `app.github_app.GitHubAppError` if the App was
        uninstalled or GitHub is unreachable; callers already handle that the
        same way they handle any other token failure.
        """
        if not self.is_app_install:
            return self.access_token
        from app import github_app
        token, _expires = github_app.installation_token(self.installation_id)
        return token

    @property
    def token_page_url(self):
        """Where this account's owner creates a replacement token."""
        return ('https://github.com/settings/tokens/new'
                '?scopes=repo,read:user&description=DevOps%20Audit')

    @property
    def host(self):
        return 'github.com'


class GitlabProfile(ProviderConnection):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='gitlab_profile')
    gitlab_id = models.IntegerField(unique=True)
    gitlab_username = models.CharField(max_length=100)
    access_token = EncryptedTextField()
    # Set only for an OAuth-login connection to gitlab.com — see
    # app.gitlab_oauth's module docstring for why this is never populated,
    # and never needs to be, for a personal access token or a self-hosted
    # instance. `current_token` falls through to `access_token` unchanged
    # when this is blank.
    refresh_token = EncryptedTextField(blank=True)
    token_expires_at = models.DateTimeField(null=True, blank=True)
    avatar_url = models.URLField(blank=True)
    gitlab_url = models.URLField(default='https://gitlab.com')
    verify_ssl = models.BooleanField(default=True)
    custom_dns = models.CharField(max_length=50, blank=True)

    def __str__(self):
        return self.gitlab_username

    @property
    def current_token(self):
        """
        A token good to use right now — every caller about to make a GitLab
        API call reads this, never `access_token` directly, the same
        convention `GithubProfile.current_token` established.

        A personal access token does not expire on its own; gitlab.com's
        OAuth2 access token always does (see app.gitlab_oauth). Refreshed
        here, two minutes ahead of the recorded expiry rather than exactly
        at it, so a request already in flight does not lose a race against
        the token going stale mid-call.
        """
        if not self.refresh_token:
            return self.access_token
        if self.token_expires_at and self.token_expires_at > timezone.now() + timedelta(minutes=2):
            return self.access_token
        from app import gitlab_oauth
        return gitlab_oauth.refresh(self)

    @property
    def is_oauth(self):
        """Connected through "Continue with GitLab" rather than a pasted token."""
        return bool(self.refresh_token)

    @property
    def host(self):
        """The instance this account lives on — not necessarily gitlab.com."""
        from urllib.parse import urlparse
        return urlparse(self.gitlab_url or 'https://gitlab.com').netloc or 'gitlab.com'

    @property
    def token_page_url(self):
        """
        Where this account's owner creates a replacement token.

        Sending someone with a self-hosted instance to gitlab.com is the kind of
        small wrongness that makes a product feel like it was built for somebody
        else. The path is the same on every instance; only the host differs.
        """
        base = (self.gitlab_url or 'https://gitlab.com').rstrip('/')
        return f'{base}/-/user_settings/personal_access_tokens'


class AuditQuerySet(models.QuerySet):
    def active(self):
        """Runs belonging to a repository the user has not removed."""
        return self.filter(archived_at__isnull=True)

    def archived(self):
        return self.filter(archived_at__isnull=False)

    def tracked_repo_count(self):
        """
        How many distinct repositories this queryset occupies against the quota.

        The free limit is on repositories watched, not runs taken, and it has to
        be releasable: counting every repository ever audited off append-only
        rows could only ever grow, so a free user who audited three repositories
        and no longer has them was locked out for good.
        """
        return self.active().values('repo_full_name').distinct().count()

    def latest_per_repo(self):
        """
        The most recent audit for each repository in this queryset.

        Audits are append-only — every run creates a new row so the score can be
        charted over time — so dashboards need the newest row per repo.

        Removed repositories are filtered out here rather than at each call site;
        a repository the user has taken off their list should not come back on a
        dashboard, and there are more dashboards than there are places to forget.
        Reports stay reachable by direct link, and restoring brings them back.
        """
        latest = {}
        for audit in self.active().order_by('-created_at'):
            key = (audit.source, audit.repo_full_name)
            if key not in latest:
                latest[key] = audit
        return list(latest.values())


class Audit(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_RUNNING = 'running'
    STATUS_DONE = 'done'
    STATUS_FAILED = 'failed'
    # English, like every other source string: nothing reads these labels except
    # the admin, and an English admin was printing Russian at it. The customer's
    # own status text comes from the templates, translated per audit.
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_DONE, 'Done'),
        (STATUS_FAILED, 'Failed'),
    ]
    SOURCE_GITHUB = 'github'
    SOURCE_GITLAB = 'gitlab'
    SOURCE_CHOICES = [
        (SOURCE_GITHUB, 'GitHub'),
        (SOURCE_GITLAB, 'GitLab'),
    ]
    TRIGGER_MANUAL = 'manual'
    TRIGGER_WEBHOOK = 'webhook'
    TRIGGER_API = 'api'
    TRIGGER_PR = 'pull_request'
    TRIGGER_CHOICES = [
        (TRIGGER_MANUAL, 'Manual'),
        (TRIGGER_WEBHOOK, 'Push webhook'),
        (TRIGGER_API, 'API'),
        (TRIGGER_PR, 'Pull request'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='audits')
    repo_full_name = models.CharField(max_length=255)
    repo_url = models.URLField()
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default=SOURCE_GITHUB)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    score = models.IntegerField(null=True, blank=True)
    ai_summary = models.TextField(blank=True)
    ai_provider = models.CharField(max_length=50, blank=True)
    category_scores = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=255, blank=True)
    language = models.CharField(max_length=5, default='ru')
    is_public = models.BooleanField(default=False)
    public_token = models.CharField(max_length=64, blank=True, null=True, unique=True)

    # Dependency inventory captured during the run, so the SBOM export does not
    # need to read the repository again — which would fail whenever a token has
    # since been revoked or the repository renamed.
    sbom_components = models.JSONField(default=list, blank=True)

    trigger = models.CharField(max_length=20, choices=TRIGGER_CHOICES, default=TRIGGER_MANUAL)
    commit_sha = models.CharField(max_length=40, blank=True)
    # The branch, tag or sha that was read. Blank means the default branch —
    # CI audits the commit under test, not whatever is on main.
    ref = models.CharField(max_length=255, blank=True)
    pr_number = models.IntegerField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    # What the engine decided this repository is — 'service', 'library',
    # 'infrastructure', 'cli', 'monorepo', 'docs' or 'unknown'. Blank on audits
    # taken before the distinction existed.
    repo_kind = models.CharField(max_length=20, blank=True)
    # How sure repo_kind.detect() was, 0.0-1.0 — 1.0 when the repository
    # declared its own kind in .devopsaudit.yml. Null on audits taken before
    # the classifier reported a confidence, which reads the same as "unknown"
    # everywhere this is used rather than as a false 0.0.
    kind_confidence = models.FloatField(null=True, blank=True)
    # Which definition of calculate_score() produced this row. Bumped only
    # when the weights or what counts toward the score change — never for a
    # new check or a wording change — so a trend chart can mark the point
    # where the scale itself moved instead of drawing it as an ordinary swing.
    # Null on audits taken before this was tracked.
    score_version = models.PositiveSmallIntegerField(null=True, blank=True)
    # Whether the audited repository is private, as the provider said at run
    # time. Decides which AI provider may see its content: the server's free
    # Gemini key is for public code only. True until known — an unknown
    # repository is treated as private.
    repo_is_private = models.BooleanField(default=True)
    # Problems a model found by reading the build, deploy and CI files, each
    # tied to a file and line whose text it had to quote (see app.ai_review).
    # Shown apart from the checks and never scored.
    ai_findings = models.JSONField(default=list, blank=True)
    # The gate the repository asked for in .devopsaudit.yml, and whatever was
    # wrong with that file. Null when the repository ships no config.
    fail_under = models.IntegerField(null=True, blank=True)
    config_errors = models.JSONField(default=list, blank=True)

    # What the repository actually is — languages, frameworks, base images,
    # ports, CI, Terraform providers — read during the run and kept, so the AI
    # step describes this repository instead of repositories in general, and so
    # the fix view can do the same long after the token that read it is gone.
    # Credentials are redacted before anything is stored here.
    repo_context = models.JSONField(default=dict, blank=True)

    # When the user removed this repository from their list. Set on every run of
    # that repository at once, never on a single run — removal is per repository,
    # and the rows are kept so the score history survives being removed and
    # restored. Null is the normal state.
    archived_at = models.DateTimeField(null=True, blank=True, db_index=True)

    objects = AuditQuerySet.as_manager()

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'source', 'repo_full_name', '-created_at']),
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['user', 'source', 'archived_at']),
        ]

    def __str__(self):
        return f"[{self.source}] {self.repo_full_name} — {self.status}"

    def generate_public_token(self):
        """Create a unique share token and mark audit public."""
        if not self.public_token:
            self.public_token = secrets.token_urlsafe(32)
        self.is_public = True
        self.save(update_fields=['public_token', 'is_public'])
        return self.public_token

    @property
    def repo_display(self):
        return self.repo_full_name.split('::')[0]

    @property
    def repo_owner(self):
        """Owner / group segment of the repo path — used to group an org's repos."""
        return self.repo_display.split('/')[0] if '/' in self.repo_display else ''

    @property
    def score_label(self):
        if self.score is None: return str(_('N/A'))
        if self.score >= 80: return str(_('Excellent'))
        if self.score >= 60: return str(_('Good'))
        if self.score >= 40: return str(_('Fair'))
        return str(_('Poor'))

    @property
    def score_color(self):
        if self.score is None: return 'gray'
        if self.score >= 80: return 'green'
        if self.score >= 60: return 'blue'
        if self.score >= 40: return 'amber'
        return 'red'

    def previous_run(self):
        """The run immediately before this one for the same repo, if any."""
        return (
            Audit.objects
            .filter(user_id=self.user_id, source=self.source,
                    repo_full_name=self.repo_full_name,
                    status=Audit.STATUS_DONE, created_at__lt=self.created_at)
            .order_by('-created_at')
            .first()
        )

    @property
    def score_delta(self):
        """Score change against the previous completed run, or None if this is the first."""
        if self.score is None:
            return None
        prev = self.previous_run()
        if prev is None or prev.score is None:
            return None
        return self.score - prev.score

    @property
    def gate(self):
        """
        Whether this run clears the threshold the repository set for itself.

        None when no `fail_under` was declared — most repositories have no gate,
        and inventing one for them would turn every audit into a failure.
        """
        if self.fail_under is None or self.score is None:
            return None
        return self.score >= self.fail_under

    def _failed_ids(self):
        return {
            c.check_id for c in
            self.checks.counted().filter(passed=False).only('check_id')
            if c.check_id
        }

    def changed_findings(self):
        """
        `(appeared, resolved)` against the previous run, as AuditCheck rows and ids.

        A whole-repository score tells a reviewer nothing about the change in
        front of them. What did this push break, and what did it fix, is the
        question a pull request comment has to answer — everything else is a
        dashboard nobody opens.
        """
        previous = self.previous_run()
        if previous is None:
            return [], []
        before = previous._failed_ids()
        now = self._failed_ids()
        appeared = sorted(now - before)
        resolved = sorted(before - now)
        rows = list(self.checks.filter(check_id__in=appeared).order_by('severity_rank'))
        return rows, resolved

    # ── Removing and restoring a repository ───────────────────────────────────
    #
    # Removal is a repository-level act expressed on every run of it, not a
    # delete. The rows stay, so a repository taken off the list and put back
    # keeps its whole score history and its trend chart, and a share link handed
    # to somebody else does not rot because the owner tidied their dashboard.

    @staticmethod
    def _repo_rows(user, source, repo_full_name):
        return Audit.objects.filter(
            user=user, source=source, repo_full_name=repo_full_name,
        )

    @classmethod
    def archive_repo(cls, user, source, repo_full_name):
        """Take a repository off the list and free its quota slot."""
        return cls._repo_rows(user, source, repo_full_name).active().update(
            archived_at=timezone.now(),
        )

    @classmethod
    def restore_repo(cls, user, source, repo_full_name):
        """Put a removed repository back. Costs a quota slot again."""
        return cls._repo_rows(user, source, repo_full_name).archived().update(
            archived_at=None,
        )

    @classmethod
    def removed_repos(cls, user, source=None):
        """
        The removed repositories, newest removal first, one row each.

        Shown next to the quota so "2 of 3 used" can be acted on rather than
        only read.
        """
        qs = cls.objects.filter(user=user).archived()
        if source:
            qs = qs.filter(source=source)
        seen, rows = set(), []
        for audit in qs.order_by('-archived_at', '-created_at'):
            key = (audit.source, audit.repo_full_name)
            if key not in seen:
                seen.add(key)
                rows.append(audit)
        return rows


class AuditCheckQuerySet(models.QuerySet):
    def counted(self):
        """Checks that count toward the score: applicable, and not hygiene (see checks.HYGIENE_CHECKS)."""
        return self.filter(applicable=True).exclude(category='hygiene')

    def hygiene(self):
        return self.filter(applicable=True, category='hygiene')


class AuditCheck(models.Model):
    SEVERITY_CHOICES = [
        ('ok', 'OK'),
        ('info', 'Info'),
        ('warn', 'Warning'),
        ('crit', 'Critical'),
    ]
    # Severity is stored as text, so ordering by the text column sorts
    # alphabetically — which put 'crit' *last*, below 'warn' and 'info'. Rank is
    # the sort key: lower is more urgent.
    SEVERITY_RANK = {'crit': 0, 'warn': 1, 'info': 2, 'ok': 3}

    audit = models.ForeignKey(Audit, on_delete=models.CASCADE, related_name='checks')
    name = models.CharField(max_length=200)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    passed = models.BooleanField()
    recommendation = models.TextField(blank=True)
    category = models.CharField(max_length=30, default='ops')
    ai_suggestion = models.TextField(blank=True)
    # Stable identifier used to map a check to compliance controls and to fix templates.
    check_id = models.CharField(max_length=60, blank=True)
    # Denormalised sort key, kept in sync with `severity` on save. A column
    # rather than a query expression so that Meta.ordering covers every caller,
    # including the ones that forget to order explicitly.
    severity_rank = models.PositiveSmallIntegerField(default=3, db_index=True)
    # False when the repository cannot act on this check — a library has no
    # container to harden. Excluded from the score, still shown in the report so
    # the reader can see what was set aside and disagree.
    applicable = models.BooleanField(default=True)
    not_applicable_reason = models.CharField(max_length=300, blank=True)
    # pass / fail / na / unknown (checks.finalize_statuses). `unknown` rows
    # are also applicable=False, so every existing score/filter path keeps
    # them out without knowing the new status exists.
    status = models.CharField(max_length=10, blank=True)
    # Where the check looked and what it found — shown under the check.
    evidence = models.CharField(max_length=500, blank=True)

    objects = AuditCheckQuerySet.as_manager()

    def save(self, *args, **kwargs):
        self.severity_rank = self.SEVERITY_RANK.get(self.severity, 3)
        super().save(*args, **kwargs)

    class Meta:
        ordering = ['passed', 'severity_rank']

    def __str__(self):
        return f"{'✓' if self.passed else '✗'} {self.name}"


class UserSubscription(models.Model):
    PLAN_FREE = 'free'
    PLAN_PRO = 'pro'
    PLAN_TEAM = 'team'
    PLAN_COMPLIANCE = 'compliance'
    PLAN_CHOICES = [
        (PLAN_FREE, 'Free'),
        (PLAN_PRO, 'Pro'),
        (PLAN_TEAM, 'Team'),
        (PLAN_COMPLIANCE, 'Compliance'),
    ]
    PAID_PLANS = (PLAN_PRO, PLAN_TEAM, PLAN_COMPLIANCE)
    PLAN_RANK = {PLAN_FREE: 0, PLAN_PRO: 1, PLAN_TEAM: 2, PLAN_COMPLIANCE: 3}

    PERIOD_MONTHLY = 'monthly'
    PERIOD_ANNUAL = 'annual'
    PERIOD_CHOICES = [
        (PERIOD_MONTHLY, 'Monthly'),
        (PERIOD_ANNUAL, 'Annual'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='subscription')
    plan = models.CharField(max_length=20, choices=PLAN_CHOICES, default=PLAN_FREE)
    billing_period = models.CharField(max_length=10, choices=PERIOD_CHOICES, default=PERIOD_MONTHLY)
    payment_provider = models.CharField(max_length=20, blank=True)  # 'lemonsqueezy' | 'cryptomus'
    stripe_customer_id = models.CharField(max_length=100, blank=True)
    stripe_subscription_id = models.CharField(max_length=100, blank=True)
    current_period_end = models.DateTimeField(null=True, blank=True)
    cancel_at_period_end = models.BooleanField(default=False)
    # Set when the "your access expires soon" reminder has been sent for the
    # current period, so the daily job does not send it again.
    expiry_notified_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def is_active(self):
        if self.plan == self.PLAN_FREE:
            return False
        if self.current_period_end is None:
            return True
        return self.current_period_end > timezone.now()

    @property
    def is_pro(self):
        """True on any paid plan. Kept as `is_pro` because it gates the AI features."""
        return self.plan in self.PAID_PLANS and self.is_active

    @property
    def is_team(self):
        return self.is_active and self.PLAN_RANK.get(self.plan, 0) >= self.PLAN_RANK[self.PLAN_TEAM]

    @property
    def is_compliance(self):
        return self.is_active and self.PLAN_RANK.get(self.plan, 0) >= self.PLAN_RANK[self.PLAN_COMPLIANCE]

    @property
    def plan_label(self):
        return dict(self.PLAN_CHOICES).get(self.plan, 'Free')

    @property
    def days_left(self):
        if not self.current_period_end:
            return None
        delta = self.current_period_end - timezone.now()
        return max(0, delta.days)

    def __str__(self):
        return f"{self.user.username} — {self.plan}"


class MonthlyUsage(models.Model):
    """
    Per-calendar-month counters for quota-limited features on the free plan.

    Free users get a taste of the paid features — one full AI report and one PDF
    export per month — because nobody pays for value they have never seen.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='usage')
    period = models.CharField(max_length=7)  # 'YYYY-MM'
    ai_reports = models.IntegerField(default=0)
    pdf_exports = models.IntegerField(default=0)
    audits = models.IntegerField(default=0)

    class Meta:
        unique_together = ('user', 'period')

    def __str__(self):
        return f"{self.user.username} {self.period}: ai={self.ai_reports} pdf={self.pdf_exports}"

    @staticmethod
    def current_period():
        return timezone.now().strftime('%Y-%m')

    @classmethod
    def for_user(cls, user):
        obj, _ = cls.objects.get_or_create(user=user, period=cls.current_period())
        return obj

    def consume(self, field: str) -> None:
        setattr(self, field, getattr(self, field) + 1)
        self.save(update_fields=[field])


class UserAISettings(models.Model):
    PROVIDER_CHOICES = [
        ('anthropic', 'Anthropic Claude'),
        ('openai', 'OpenAI GPT'),
        ('gemini', 'Google Gemini (free tier)'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='ai_settings')
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES, blank=True)
    api_key = EncryptedTextField(blank=True)

    def __str__(self):
        return f"{self.user.username} — {self.provider or 'not set'}"


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    email_notifications = models.BooleanField(default=True)
    webhook_secret = models.CharField(max_length=64, blank=True)
    api_token = models.CharField(max_length=64, blank=True, null=True, unique=True)
    onboarding_done = models.BooleanField(default=False)
    # Post a score summary on pull requests (Team plan and above).
    pr_comments_enabled = models.BooleanField(default=True)
    # Whether any repository content may be sent to an AI provider for this
    # account. Off means nothing leaves: the summary and the per-check advice
    # are written by the local rules instead, which lose the tailoring but keep
    # the feature. There was previously no way to say no — if the deployment
    # held a key, every customer's code was sent whether they wanted it or not.
    ai_analysis_enabled = models.BooleanField(default=True)
    # Guide steps the reader has waved away. A hint that cannot be dismissed is
    # not a hint, and one that comes back after being dismissed is worse.
    guide_dismissed = models.JSONField(default=list, blank=True)

    def __str__(self):
        return f"{self.user.username} profile"

    def ensure_webhook_secret(self):
        if not self.webhook_secret:
            self.webhook_secret = secrets.token_hex(20)
            self.save(update_fields=['webhook_secret'])
        return self.webhook_secret

    def ensure_api_token(self):
        if not self.api_token:
            self.api_token = secrets.token_urlsafe(32)
            self.save(update_fields=['api_token'])
        return self.api_token


class RepoWatch(models.Model):
    """
    Someone who asked to hear about a public repository, without an account.

    The public scanner is the top of the funnel and the emotional peak of the
    product — the moment a visitor reads "44/100, two critical". Until now there
    was nothing to do with that moment: no email capture anywhere public, and a
    call to action that assumed the reader had private repositories they cared
    about. A visit spike with nothing to keep it is a spike that leaves.

    A watch is deliberately not an account. No password, no profile, no consent
    to anything except mail about one repository, and every message carries a
    one-click unsubscribe.

    **Double opt-in.** Sending one report to an address a visitor typed is
    ordinary. Signing that address up for standing mail is not, and doing it
    without confirmation is how a product becomes a way to mail strangers.
    `confirmed_at` gates every recurring message; the first one only ever offers
    to confirm.
    """
    email = models.EmailField()
    repo_full_name = models.CharField(max_length=255)
    # Confirms and unsubscribes. Unguessable, so an unsubscribe link needs no
    # login, and knowing one token tells you nothing about any other watch.
    token = models.CharField(max_length=64, unique=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    unsubscribed_at = models.DateTimeField(null=True, blank=True)
    # The score at the last message sent, so a change is measured against what
    # the reader was actually told — not against the previous scan, which they
    # may never have heard about.
    last_score = models.IntegerField(null=True, blank=True)
    last_notified_at = models.DateTimeField(null=True, blank=True)
    language = models.CharField(max_length=5, default='en')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('email', 'repo_full_name')
        indexes = [
            models.Index(fields=['repo_full_name', 'confirmed_at']),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.email} → {self.repo_full_name}'

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(32)
        if self.email:
            self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    @property
    def is_active(self):
        return self.confirmed_at is not None and self.unsubscribed_at is None

    @property
    def state(self):
        if self.unsubscribed_at:
            return 'unsubscribed'
        return 'watching' if self.confirmed_at else 'pending'

    def confirm(self):
        if self.unsubscribed_at or self.confirmed_at:
            # Re-confirming after unsubscribing has to go through the form
            # again, or an old link in an inbox would resurrect a subscription
            # the reader ended.
            return False
        self.confirmed_at = timezone.now()
        self.save(update_fields=['confirmed_at'])
        return True

    def unsubscribe(self):
        if self.unsubscribed_at:
            return False
        self.unsubscribed_at = timezone.now()
        self.save(update_fields=['unsubscribed_at'])
        return True


class PublicScan(models.Model):
    """
    A cached audit of a public repository, run without an account.

    Powers the no-signup demo at /scan/<owner>/<repo>/ — the top of the funnel
    and the SEO surface. Results are cached so a popular repo is scanned once,
    not once per visitor.
    """
    repo_full_name = models.CharField(max_length=255, unique=True)
    repo_url = models.URLField()
    description = models.CharField(max_length=500, blank=True)
    stars = models.IntegerField(default=0)
    primary_language = models.CharField(max_length=50, blank=True)
    score = models.IntegerField(null=True, blank=True)
    category_scores = models.JSONField(default=dict)
    results = models.JSONField(default=list)
    repo_kind = models.CharField(max_length=20, blank=True)
    # See Audit.kind_confidence — same meaning, same 0.0-1.0 scale. Recorded so
    # a future noindex-below-threshold gate on public scan pages (Phase 10) has
    # something to read; nothing reads it yet, and no page currently sets
    # noindex based on it.
    kind_confidence = models.FloatField(null=True, blank=True)
    # checks.SCORE_VERSION that produced `score`; an older one is rescanned.
    score_version = models.PositiveSmallIntegerField(null=True, blank=True)
    status = models.CharField(max_length=20, default=Audit.STATUS_PENDING)
    error_message = models.CharField(max_length=300, blank=True)
    view_count = models.IntegerField(default=0)
    # Discovery is cheap (one search call returns a hundred repositories); the
    # scan itself is three calls. So a seeded row waits here with queued_at
    # unset until the drain task has room for it, and nothing that was never
    # queued can be mistaken for a job that died.
    queued_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']
        indexes = [
            models.Index(fields=['-view_count']),
            models.Index(fields=['-updated_at']),
            # The score distribution is read on every scan page to place a
            # repository against the others.
            models.Index(fields=['status', 'score']),
            models.Index(fields=['primary_language', 'status']),
            models.Index(fields=['queued_at']),
        ]

    def __str__(self):
        return f"public scan {self.repo_full_name} — {self.score}"

    @property
    def is_stale(self):
        from app.checks import SCORE_VERSION
        # A page scored under an older methodology is stale at any age.
        if self.score_version is not None and self.score_version != SCORE_VERSION:
            return True
        return timezone.now() - self.updated_at > timezone.timedelta(days=7)

    #: A visitor may ask for a fresh scan of the same repository this often.
    RESCAN_INTERVAL_MINUTES = 10

    @property
    def can_rescan(self):
        return self.status == 'done' and timezone.now() - self.updated_at > timezone.timedelta(
            minutes=self.RESCAN_INTERVAL_MINUTES)

    @property
    def awaiting_first_scan(self):
        """Discovered by the seeder and not yet handed to a worker."""
        return self.queued_at is None and self.status == Audit.STATUS_PENDING

    @property
    def is_stuck(self):
        """Queued or running for far longer than a scan can legitimately take."""
        if self.awaiting_first_scan:
            return False
        return (
            self.status in (Audit.STATUS_PENDING, Audit.STATUS_RUNNING)
            and timezone.now() - self.updated_at > timezone.timedelta(minutes=10)
        )

    @property
    def score_color(self):
        if self.score is None: return 'gray'
        if self.score >= 80: return 'green'
        if self.score >= 60: return 'blue'
        if self.score >= 40: return 'amber'
        return 'red'


class FixAttempt(models.Model):
    """
    A fix pull request we opened, followed until its CI is green (roadmap phase 5).

    Opening the pull request is not the job; a pull request whose CI is red is
    work handed back to the customer. `app.fix_agent` polls the checks on the
    branch, and when they fail it reads the failed jobs' logs, asks a model
    for a change to the files this pull request touched — and only those —
    runs the guardrail over the diff, and pushes to the same branch. At most
    MAX_ITERATIONS rounds, then `gave_up` with a comment saying what was tried.
    """
    STATE_CI_RUNNING = 'ci_running'
    STATE_CI_FAILED = 'ci_failed'
    STATE_FIXING = 'fixing'
    STATE_GREEN = 'green'
    STATE_GAVE_UP = 'gave_up'
    STATE_NO_CI = 'no_ci'
    STATE_CLOSED = 'closed'
    STATE_CHOICES = [
        (STATE_CI_RUNNING, 'CI running'), (STATE_CI_FAILED, 'CI failed'), (STATE_FIXING, 'Fixing'),
        (STATE_GREEN, 'Green'), (STATE_GAVE_UP, 'Gave up'), (STATE_NO_CI, 'No CI'),
        (STATE_CLOSED, 'PR closed'),
    ]
    ACTIVE_STATES = (STATE_CI_RUNNING, STATE_CI_FAILED, STATE_FIXING)

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='fix_attempts')
    audit = models.ForeignKey(Audit, on_delete=models.CASCADE, related_name='fix_attempts')
    check_id = models.CharField(max_length=60, blank=True)
    check_name = models.CharField(max_length=200, blank=True)
    recommendation = models.TextField(blank=True)
    source = models.CharField(max_length=10, default='github')
    repo_full_name = models.CharField(max_length=300)
    branch = models.CharField(max_length=200)
    pr_number = models.PositiveIntegerField(default=0)
    pr_url = models.URLField(max_length=500, blank=True)
    # The files this pull request created or changed. The agent may edit these
    # and nothing else — the guardrail's first rule.
    scope_files = models.JSONField(default=list)
    state = models.CharField(max_length=20, choices=STATE_CHOICES, default=STATE_CI_RUNNING, db_index=True)
    iterations = models.PositiveSmallIntegerField(default=0)
    head_sha = models.CharField(max_length=40, blank=True)
    llm_calls = models.PositiveSmallIntegerField(default=0)
    # Characters sent to and received from the model: a provider-neutral
    # stand-in for cost until real token accounting exists (roadmap phase 8).
    llm_chars = models.PositiveIntegerField(default=0)
    llm_provider = models.CharField(max_length=40, blank=True)
    history = models.JSONField(default=list, blank=True)
    gave_up_reason = models.TextField(blank=True)
    merged = models.BooleanField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.repo_full_name}#{self.pr_number} {self.state}'

    def log(self, event: str, **data):
        self.history = [*(self.history or []), {'at': timezone.now().isoformat(), 'event': event, **data}]


class SecretIncident(models.Model):
    """
    A credential the provider still accepted when we found it (roadmap phase 6).

    The value itself is never stored — only `fingerprint`, an HMAC of it keyed
    with the server's secret, so the same key is recognised on the next audit.
    That next audit is also how rotation is confirmed: the old key is still in
    git history, the scanner finds it again, asks the provider, and an
    `inactive` answer closes the incident. "I rotated it" alone does not.
    """
    STATUS_OPEN = 'open'
    STATUS_ROTATED = 'rotated'          # confirmed: the provider now rejects the old key
    STATUS_MARKED = 'marked_rotated'    # the owner says so; not confirmable (key no longer found)
    STATUS_CHOICES = [(STATUS_OPEN, 'Open'), (STATUS_ROTATED, 'Rotated (confirmed)'),
                      (STATUS_MARKED, 'Marked rotated')]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='secret_incidents')
    first_audit = models.ForeignKey(Audit, on_delete=models.CASCADE, related_name='secret_incidents')
    last_audit = models.ForeignKey(Audit, on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='+')
    source = models.CharField(max_length=10, default='github')
    repo_full_name = models.CharField(max_length=300)
    rule = models.CharField(max_length=40)
    label = models.CharField(max_length=80)
    file = models.CharField(max_length=500)
    line = models.PositiveIntegerField(null=True, blank=True)
    commit = models.CharField(max_length=40, blank=True)
    commit_date = models.CharField(max_length=20, blank=True)
    in_head = models.BooleanField(default=False)
    fingerprint = models.CharField(max_length=64)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_OPEN, db_index=True)
    liveness = models.CharField(max_length=10, default='active')
    fix_pr_url = models.URLField(max_length=500, blank=True)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(default=timezone.now)
    last_checked_at = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['status', '-first_seen_at']
        constraints = [models.UniqueConstraint(fields=['user', 'repo_full_name', 'fingerprint'],
                                               name='uniq_secret_incident')]

    def __str__(self):
        return f'{self.label} in {self.repo_full_name}:{self.file} ({self.status})'

    @property
    def is_open(self):
        return self.status == self.STATUS_OPEN


def _digest_token():
    return secrets.token_urlsafe(24)


class DigestSettings(models.Model):
    """
    The weekly digest for a Team-plan account (roadmap phase 7): who gets it,
    on which day, in which language — and the token behind its one-click
    unsubscribe link, which works without signing in.
    """
    WEEKDAYS = [(0, _('Monday')), (1, _('Tuesday')), (2, _('Wednesday')),
                (3, _('Thursday')), (4, _('Friday')), (5, _('Saturday')),
                (6, _('Sunday'))]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='digest_settings')
    enabled = models.BooleanField(default=True)
    weekday = models.PositiveSmallIntegerField(choices=WEEKDAYS, default=0)
    # Comma-separated addresses; empty means the account's own address.
    recipients = models.TextField(blank=True)
    language = models.CharField(max_length=5, default='en')
    unsubscribe_token = models.CharField(max_length=64, unique=True, default=_digest_token)
    last_sent_at = models.DateTimeField(null=True, blank=True)

    def recipient_list(self):
        listed = [a.strip() for a in (self.recipients or '').split(',') if a.strip()]
        return listed or ([self.user.email] if self.user.email else [])


class FalsePositiveReport(models.Model):
    """
    "This FAIL is wrong" from someone reading a report (accuracy spec, stage 7).

    The main source of new cases for the evaluation set: each row names the
    repository, the commit it was read at when known, the check and what the
    reader says. Nothing acts on it automatically — a human reads it and
    either fixes a detector or adds a fixture.
    """
    repo_full_name = models.CharField(max_length=255, db_index=True)
    source = models.CharField(max_length=20, default='public')     # public | audit
    commit_sha = models.CharField(max_length=64, blank=True)
    score_version = models.PositiveSmallIntegerField(null=True, blank=True)
    check_id = models.CharField(max_length=60)
    evidence = models.CharField(max_length=500, blank=True)
    comment = models.TextField(max_length=2000, blank=True)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.repo_full_name} · {self.check_id}'


class PlanInterest(models.Model):
    """
    "I want this plan" while payments are not live yet (settings.PAYMENTS_LIVE).

    The list to write to on launch day, and the only demand signal before the
    first sale. Nothing is charged and nothing is granted.
    """
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    email = models.EmailField(blank=True)
    plan = models.CharField(max_length=20)
    period = models.CharField(max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    notified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.email or self.user_id} · {self.plan}/{self.period}'


class FunnelEvent(models.Model):
    """One step of the growth funnel (app/funnel.py). No IP, no user agent."""
    name = models.CharField(max_length=40, db_index=True)
    source = models.CharField(max_length=40, blank=True, db_index=True)
    ref = models.CharField(max_length=200, blank=True)      # repo, plan — what the step was about
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']


class CIScan(models.Model):
    """
    A keyless scan of one commit of a public repository, started by the
    GitHub Action (growth plan B4). Not a page and not an account: it exists
    so a public project can gate its CI without signing up.
    """
    repo_full_name = models.CharField(max_length=255, db_index=True)
    ref = models.CharField(max_length=255, blank=True)
    commit_sha = models.CharField(max_length=64, blank=True)
    pr_number = models.PositiveIntegerField(null=True, blank=True)
    status = models.CharField(max_length=20, default='pending')
    score = models.IntegerField(null=True, blank=True)
    results = models.JSONField(default=list)
    repo_kind = models.CharField(max_length=20, blank=True)
    fail_under = models.PositiveSmallIntegerField(null=True, blank=True)
    config_errors = models.JSONField(default=list)
    error_message = models.CharField(max_length=300, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    @property
    def gate(self):
        if self.fail_under is None or self.score is None:
            return None
        return self.score >= self.fail_under

    def previous(self):
        return (CIScan.objects.filter(repo_full_name__iexact=self.repo_full_name, status='done',
                                      created_at__lt=self.created_at)
                .exclude(commit_sha=self.commit_sha).first())


class OrgScan(models.Model):
    """
    A public GitHub organisation (or user) at a glance (growth plan B7).

    The repositories themselves are ordinary PublicScan rows — each gets its
    own report page — and this row only remembers which ones belong here.
    """
    org = models.CharField(max_length=100, unique=True)
    status = models.CharField(max_length=20, default='pending')
    repos = models.JSONField(default=list)          # repo full names, most starred first
    total_public = models.PositiveIntegerField(default=0)
    error_message = models.CharField(max_length=300, blank=True)
    view_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    #: Repositories scanned per organisation, free.
    MAX_REPOS = 30

    @property
    def is_stale(self):
        return timezone.now() - self.updated_at > timezone.timedelta(days=7)
