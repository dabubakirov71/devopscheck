"""
One-time cleanup for whatever `allauth.socialaccount.SocialToken` rows exist
already, from before `app.signals` started blanking `token`/`token_secret`
right after copying the value into our own encrypted `GithubProfile`/
`GitlabProfile.access_token`.

A no-op on a database with no such rows yet (prod, at the time this shipped:
one user, zero GitHub/GitLab profiles) — kept anyway, because the same code
deployed to any environment that already has real OAuth-login connections
should not need a human to remember to run this by hand.
"""
from django.db import migrations


def redact_existing_tokens(apps, schema_editor):
    SocialToken = apps.get_model('socialaccount', 'SocialToken')
    SocialToken.objects.exclude(token='', token_secret='').update(token='', token_secret='')


def _noop(apps, schema_editor):
    """Redaction has no meaningful reverse — the plaintext is gone on purpose."""


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0028_audit_kind_confidence_audit_score_version_and_more'),
        ('socialaccount', '0006_alter_socialaccount_extra_data'),
    ]

    operations = [
        migrations.RunPython(redact_existing_tokens, _noop),
    ]
