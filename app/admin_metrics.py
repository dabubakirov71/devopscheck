"""/admin/metrics/ — the week-by-week funnel in one place (growth plan B2.4)."""
from collections import OrderedDict

from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Count
from django.db.models.functions import TruncWeek
from django.shortcuts import render
from django.utils import timezone

from app.funnel import EVENTS


@staff_member_required
def metrics(request):
    from app.models import FalsePositiveReport, FixAttempt, FunnelEvent, PlanInterest, PublicScan
    now = timezone.now()
    since = now - timezone.timedelta(weeks=8)
    rows = (FunnelEvent.objects.filter(created_at__gte=since)
            .annotate(week=TruncWeek('created_at')).values('week', 'name').annotate(n=Count('id')))
    weeks = OrderedDict()
    for r in sorted(rows, key=lambda r: r['week'], reverse=True):
        weeks.setdefault(r['week'].date(), {})[r['name']] = r['n']
    table = [(week, [counts.get(e, 0) for e in EVENTS]) for week, counts in weeks.items()]

    month = now - timezone.timedelta(days=30)
    totals = dict(FunnelEvent.objects.filter(created_at__gte=month).values_list('name')
                  .annotate(n=Count('id')))
    steps = []
    prev = None
    for e in EVENTS:
        n = totals.get(e, 0)
        rate = f'{n / prev * 100:.0f}%' if prev else ''
        steps.append((e, n, rate))
        prev = n or prev
    sources = (FunnelEvent.objects.filter(created_at__gte=month)
               .exclude(source='').values('source')
               .annotate(visits=Count('id', filter=_q('visit_landing')),
                         scans=Count('id', filter=_q('scan_started')),
                         signups=Count('id', filter=_q('signup')),
                         paid=Count('id', filter=_q('paid')))
               .order_by('-scans', '-visits')[:20])
    closed = FixAttempt.objects.filter(merged__isnull=False)
    merged = closed.filter(merged=True).count()
    return render(request, 'admin/metrics.html', {
        'title': 'Growth metrics',
        'events': EVENTS,
        'table': table,
        'steps': steps,
        'sources': sources,
        'top_scans': PublicScan.objects.filter(status='done').order_by('-view_count')[:15],
        'public_total': PublicScan.objects.filter(status='done').count(),
        'fix_merge': (f'{merged}/{closed.count()} ({merged / closed.count() * 100:.0f}%)'
                      if closed.count() else '—'),
        'plan_interest': PlanInterest.objects.count(),
        'false_positives': FalsePositiveReport.objects.count(),
    })


def _q(name):
    from django.db.models import Q
    return Q(name=name)
