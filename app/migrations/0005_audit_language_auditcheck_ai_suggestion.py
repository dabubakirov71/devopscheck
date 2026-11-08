from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0004_gitlabprofile_custom_dns'),
    ]

    operations = [
        migrations.AddField(
            model_name='audit',
            name='language',
            field=models.CharField(default='ru', max_length=5),
        ),
        migrations.AddField(
            model_name='auditcheck',
            name='ai_suggestion',
            field=models.TextField(blank=True),
        ),
    ]
