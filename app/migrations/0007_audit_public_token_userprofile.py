import uuid
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0006_useraisettings'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Add public sharing fields to Audit
        migrations.AddField(
            model_name='audit',
            name='is_public',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='audit',
            name='public_token',
            field=models.CharField(max_length=64, blank=True, unique=True, null=True),
        ),
        # UserProfile for email notifications + webhook secret
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email_notifications', models.BooleanField(default=True)),
                ('webhook_secret', models.CharField(max_length=64, blank=True)),
                ('api_token', models.CharField(max_length=64, blank=True, unique=True, null=True)),
                ('onboarding_done', models.BooleanField(default=False)),
                ('user', models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='profile',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
        ),
    ]
