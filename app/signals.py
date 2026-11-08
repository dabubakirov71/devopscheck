"""
Bridge allauth's social login into the profiles the product actually reads.

"Continue with GitHub" is the widest entrance the product has. It authenticated
the visitor and created a `SocialAccount` — and nothing else. Every dashboard,
every audit and every repository list reads `GithubProfile` / `GitlabProfile`,
so the new customer arrived at an empty dashboard and had to go and paste a
personal access token, having just been told that connecting GitHub was one
click. Most people do not do the second step.

The signals below turn the social account into the profile, so signing in with
GitHub connects GitHub.

A note on scope: the token allauth stores carries whatever the OAuth app asked
for. It is enough to read repositories; opening pull requests needs write, and
the connection page says so. Nothing here pretends otherwise.

A note on where the token actually lives: allauth's own `SocialToken.token`
(and `.token_secret`, which carries the refresh token for a provider that
issues one) is a plain `TextField` — not the `EncryptedTextField` `GithubProfile`
/`GitlabProfile.access_token` is. Copying the value into our own encrypted
field, the way `_link_github`/`_link_gitlab` do, does nothing for a token that
is *also* sitting in plaintext three tables away — the encryption on
`access_token` protects against reading our own model, not against reading
the database. Nothing in this codebase reads `SocialToken` again after the
copy below (verified: the only read is `_token_row_for`, here), so
`_redact_token()` blanks it the moment the copy is confirmed saved. What allauth needed the
token for — fetching the profile data already sitting in `extra_data` — has
already happened by the time this signal fires.
"""
import logging

from allauth.socialaccount.models import SocialToken
from allauth.socialaccount.signals import social_account_added, social_account_updated
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

logger = logging.getLogger(__name__)


def _token_row_for(social_account):
    """The SocialToken row itself, not just its value — GitLab needs `.token_secret`
    (the refresh token) and `.expires_at` too, before this gets redacted below."""
    return (SocialToken.objects
            .filter(account=social_account)
            .order_by('-id')
            .first())


def _redact_token(social_account) -> None:
    """
    Blank the plaintext copy once our own encrypted one is safely saved.

    `.update()`, not `.save()` on each row — this never needs to run
    `SocialToken`'s own save pipeline, and a bulk update is one query instead
    of one per token (there is normally exactly one, but a stale second row
    from a previous, failed OAuth dance is not this function's problem to
    diagnose).
    """
    SocialToken.objects.filter(account=social_account).update(token='', token_secret='')


def _keep_existing(profile, replace: bool) -> bool:
    """
    Whether a sign-in should leave an existing connection alone.

    Signing in is not asking to change what is connected: it must not swap a
    pasted personal access token (possibly with more scope, possibly for a
    self-hosted GitLab) or a write-scoped GitLab token from the step-up for
    the read-only token a plain sign-in carries. So a sign-in only creates a
    missing connection or repairs a broken one; replacing a healthy one takes
    an explicit connect (`replace=True`).
    """
    return profile is not None and not replace and profile.is_healthy


def _link_github(social_account, token_row=None, replace=True) -> bool:
    from app.models import GithubProfile

    token_row = token_row or _token_row_for(social_account)
    token = token_row.token if token_row and token_row.token else ''
    if not token:
        # Without a token there is nothing to read the repository with, and a
        # profile row that cannot answer is worse than none: the dashboard
        # would show a connected account and then fail on every request.
        logger.info('social github: no token stored for user_id=%s — not linking',
                    social_account.user_id)
        return False

    data = social_account.extra_data or {}
    github_id = data.get('id') or social_account.uid
    try:
        github_id = int(github_id)
    except (TypeError, ValueError):
        return False

    existing = GithubProfile.objects.filter(user=social_account.user, github_id=github_id).first()
    if _keep_existing(existing, replace):
        _redact_token(social_account)
        logger.info('social github: kept the existing healthy connection for user_id=%s',
                    social_account.user_id)
        return True

    # Keyed on (user, github_id) like every other connect path, so a person can
    # hold several GitHub accounts.
    profile, created = GithubProfile.objects.update_or_create(
        user=social_account.user, github_id=github_id,
        defaults={
            'github_login': data.get('login', '') or '',
            'access_token': token,
            'avatar_url': data.get('avatar_url', '') or '',
        },
    )
    profile.mark_working()
    _redact_token(social_account)
    logger.info('social github linked: user_id=%s login=%s created=%s',
                social_account.user_id, data.get('login'), created)
    return True


def _link_gitlab(social_account, token_row=None, replace=True) -> bool:
    from app.models import GitlabProfile

    token_row = token_row or _token_row_for(social_account)
    token = token_row.token if token_row and token_row.token else ''
    if not token:
        logger.info('social gitlab: no token stored for user_id=%s — not linking',
                    social_account.user_id)
        return False

    data = social_account.extra_data or {}
    gitlab_id = data.get('id') or social_account.uid
    try:
        gitlab_id = int(gitlab_id)
    except (TypeError, ValueError):
        return False

    # gitlab.com's OAuth2 access token always expires — token_secret carries
    # the refresh token GitLab issues alongside it. Captured into our own
    # encrypted fields before _redact_token() below blanks the plaintext
    # copy, so GitlabProfile.current_token can refresh it later instead of
    # the connection silently going stale the way the pre-fix GitHub App
    # installation token did.
    existing = GitlabProfile.objects.filter(user=social_account.user).first()
    if _keep_existing(existing, replace):
        _redact_token(social_account)
        logger.info('social gitlab: kept the existing healthy connection for user_id=%s',
                    social_account.user_id)
        return True

    defaults = {
        'gitlab_id': gitlab_id,
        'gitlab_username': data.get('username', '') or '',
        'access_token': token,
        'token_expires_at': token_row.expires_at if token_row else None,
        'avatar_url': data.get('avatar_url', '') or '',
        'gitlab_url': 'https://gitlab.com',
    }
    # allauth only overwrites its stored refresh token when the provider sent
    # a new one; do the same, so a re-authorisation that came back without
    # one keeps the connection refreshable instead of stranding it.
    refresh = (token_row.token_secret or '') if token_row else ''
    if refresh:
        defaults['refresh_token'] = refresh
    profile, created = GitlabProfile.objects.update_or_create(
        user=social_account.user, defaults=defaults,
    )
    profile.mark_working()
    _redact_token(social_account)
    logger.info('social gitlab linked: user_id=%s created=%s',
                social_account.user_id, created)
    return True


def link_social_account(social_account, token_row=None, replace=True) -> bool:
    """
    Create or refresh the provider profile behind a social account.

    `token_row` is the token to link from when the caller holds a fresher one
    than the database does (see `_on_updated`); by default, the stored row.
    `replace=False` is a sign-in: see `_keep_existing`.
    """
    try:
        if social_account.provider == 'github':
            return _link_github(social_account, token_row, replace)
        if social_account.provider == 'gitlab':
            return _link_gitlab(social_account, token_row, replace)
    except Exception:
        # A failure here must not take down the login it is attached to.
        logger.error('link_social_account failed: provider=%s user_id=%s',
                     social_account.provider, social_account.user_id, exc_info=True)
    return False


@receiver(social_account_added)
def _on_added(request, sociallogin, **kwargs):
    _link_from_login(sociallogin)


def _link_from_login(sociallogin):
    """
    Link from the token allauth holds in memory, then blank it there too.

    See `_on_updated` for why the in-memory token and not the stored row.
    """
    token = getattr(sociallogin, 'token', None)
    fresh = token if token is not None and token.token else None
    replace = (getattr(sociallogin, 'state', None) or {}).get('process') == 'connect'
    if link_social_account(sociallogin.account, fresh, replace) and fresh is not None:
        fresh.token = ''
        fresh.token_secret = ''


@receiver(social_account_updated)
def _on_updated(request, sociallogin, **kwargs):
    """
    An already-linked account authorised again — a re-login, or a connect
    such as the GitLab write-access step-up (`views._gitlab_write_reauth_url`).

    allauth sends this signal *before* it stores the new token
    (`SocialLogin._lookup_by_socialaccount`: signal, then `_store_token()`),
    so the database row still holds the previous, already-redacted token.
    Linking from it would find nothing and skip the link — the profile would
    keep its old token — and the `_store_token()` that follows would then
    write the new one to `SocialToken` in plaintext with nothing left to
    redact it. On a login `_on_login` runs afterwards and would cover for
    this; a connect fires no login, so the step-up's new token would never
    reach the profile at all.

    So link from the in-memory token, then blank it in memory too: the
    `_store_token()` that follows writes an empty value instead of the
    plaintext one. (`token_secret` is only overwritten by allauth when
    non-empty, so blanking it leaves the already-redacted stored value.)
    """
    _link_from_login(sociallogin)


@receiver(user_logged_in)
def _on_login(request, user, **kwargs):
    """
    Catch the sign-up case as well.

    On a first social sign-up allauth logs the user in without firing
    `social_account_added`, so a brand-new customer — the one this is for —
    would have been the only one it missed. This path has no `sociallogin`
    to take the token from, so it reads the stored row — which exists only
    because `SOCIALACCOUNT_STORE_TOKENS` is on (see config/settings.py).
    """
    from allauth.socialaccount.models import SocialAccount
    for account in SocialAccount.objects.filter(user=user, provider__in=('github', 'gitlab')):
        link_social_account(account, replace=False)


from allauth.account.signals import user_signed_up  # noqa: E402


@receiver(user_signed_up)
def _funnel_signup(request, user, **kwargs):
    """Sign-ups through Google/GitHub/GitLab; register_view records its own."""
    from app import funnel
    funnel.record('signup', request, user=user)
