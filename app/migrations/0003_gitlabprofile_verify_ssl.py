from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0002_usersubscription'),
    ]

    operations = [
        migrations.AddField(
            model_name='gitlabprofile',
            name='verify_ssl',
            field=models.BooleanField(default=True),
        ),
    ]
