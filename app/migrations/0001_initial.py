from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='GithubProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('github_id', models.IntegerField(unique=True)),
                ('github_login', models.CharField(max_length=100)),
                ('access_token', models.CharField(max_length=255)),
                ('avatar_url', models.URLField(blank=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='github_profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='GitlabProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('gitlab_id', models.IntegerField(unique=True)),
                ('gitlab_username', models.CharField(max_length=100)),
                ('access_token', models.CharField(max_length=255)),
                ('avatar_url', models.URLField(blank=True)),
                ('gitlab_url', models.URLField(default='https://gitlab.com')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='gitlab_profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Audit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('repo_full_name', models.CharField(max_length=255)),
                ('repo_url', models.URLField()),
                ('source', models.CharField(choices=[('github', 'GitHub'), ('gitlab', 'GitLab')], default='github', max_length=10)),
                ('status', models.CharField(choices=[('pending', 'Ожидает'), ('running', 'Выполняется'), ('done', 'Завершён'), ('failed', 'Ошибка')], default='pending', max_length=20)),
                ('score', models.IntegerField(blank=True, null=True)),
                ('ai_summary', models.TextField(blank=True)),
                ('ai_provider', models.CharField(blank=True, max_length=50)),
                ('category_scores', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('celery_task_id', models.CharField(blank=True, max_length=255)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='audits', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='AuditCheck',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('severity', models.CharField(choices=[('ok', 'OK'), ('info', 'Инфо'), ('warn', 'Предупреждение'), ('crit', 'Критично')], max_length=10)),
                ('passed', models.BooleanField()),
                ('recommendation', models.TextField(blank=True)),
                ('category', models.CharField(default='ops', max_length=30)),
                ('audit', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='checks', to='app.audit')),
            ],
            options={
                'ordering': ['passed', '-severity'],
            },
        ),
    ]
