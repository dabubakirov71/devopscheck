"""
Backfill severity_rank on existing checks.

Ordering used to be `-severity` on a text column, which sorts alphabetically:
warn > ok > info > crit. Critical findings landed at the bottom of the audit
email, the pull request comment and the PDF. New rows get the rank from
AuditCheck.save(); this fills in everything written before that existed.
"""
from django.db import migrations

RANK = {'crit': 0, 'warn': 1, 'info': 2, 'ok': 3}


def set_ranks(apps, schema_editor):
    AuditCheck = apps.get_model('app', 'AuditCheck')
    for severity, rank in RANK.items():
        AuditCheck.objects.filter(severity=severity).update(severity_rank=rank)


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ('app', '0011_alter_auditcheck_options_auditcheck_severity_rank_and_more'),
    ]
    operations = [migrations.RunPython(set_ranks, noop)]
