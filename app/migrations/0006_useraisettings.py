from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0005_audit_language_auditcheck_ai_suggestion'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserAISettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('provider', models.CharField(blank=True, choices=[('anthropic', 'Anthropic Claude'), ('openai', 'OpenAI GPT'), ('gemini', 'Google Gemini (free tier)'), ('ollama', 'Ollama (local)')], max_length=20)),
                ('api_key', models.TextField(blank=True)),
                ('ollama_url', models.CharField(blank=True, default='http://localhost:11434', max_length=255)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='ai_settings', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
