"""
Queue public reports for a fresh scan.

    manage.py rescan_public                    # older methodology, or older than 14 days
    manage.py rescan_public --older-than-days 3
    manage.py rescan_public --dry-run

Queued through the normal worker, one job per report; the worker's own pace
keeps visitors' scans from waiting long behind them.
"""
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from app.checks import SCORE_VERSION
from app.models import Audit, PublicScan


class Command(BaseCommand):
    help = 'Rescan public reports older than N days or scored under an older methodology.'

    def add_arguments(self, parser):
        parser.add_argument('--older-than-days', type=int, default=14)
        parser.add_argument('--limit', type=int, default=1000)
        parser.add_argument('--dry-run', action='store_true')

    def handle(self, *args, **opts):
        cutoff = timezone.now() - timezone.timedelta(days=opts['older_than_days'])
        rows = (PublicScan.objects.filter(status=Audit.STATUS_DONE)
                .filter(Q(updated_at__lt=cutoff) | ~Q(score_version=SCORE_VERSION)
                        | Q(score_version__isnull=True))
                .order_by('-view_count')[:opts['limit']])
        ids = list(rows.values_list('id', flat=True))
        if opts['dry_run']:
            self.stdout.write(f'{len(ids)} report(s) would be rescanned')
            return
        from app.tasks import run_public_scan_task
        now = timezone.now()
        for scan_id in ids:
            PublicScan.objects.filter(id=scan_id).update(status=Audit.STATUS_PENDING, queued_at=now)
            run_public_scan_task.delay(scan_id)
        self.stdout.write(self.style.SUCCESS(f'queued {len(ids)} rescan(s)'))
