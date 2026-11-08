import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('app', '0007_audit_public_token_userprofile'),
    ]

    operations = [
        # 1. Change user from OneToOneField to ForeignKey (drops unique constraint on user_id)
        migrations.AlterField(
            model_name='githubprofile',
            name='user',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='github_profiles',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        # 2. Drop unique constraint on github_id alone
        migrations.AlterField(
            model_name='githubprofile',
            name='github_id',
            field=models.IntegerField(),
        ),
        # 3. Add composite unique constraint (user, github_id)
        migrations.AlterUniqueTogether(
            name='githubprofile',
            unique_together={('user', 'github_id')},
        ),
    ]
