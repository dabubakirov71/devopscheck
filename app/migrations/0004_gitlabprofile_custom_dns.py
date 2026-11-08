from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_gitlabprofile_verify_ssl'),
    ]

    operations = [
        migrations.AddField(
            model_name='gitlabprofile',
            name='custom_dns',
            field=models.CharField(blank=True, max_length=50),
        ),
    ]
