"""
Views for the paid tiers: the organisation dashboard, the compliance report,
and SBOM export.

The organisation dashboard is the screen a manager buys — every repository they
own, ranked by score, with the change since last week. The compliance report is
the same audit data expressed as controls, which is what an auditor accepts.
"""
import json
import logging
from collections import defaultdict

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_exempt

from app.models import Audit, UserSubscription

logger = logging.getLogger(__name__)


def _get_subscription(user):
    sub, _created = UserSubscription.objects.get_or_create(user=user)
    return sub


# Matches the score colouring: under 60 stops being "good".
ATTENTION_SCORE = 60


@login_required
def org_dashboard(request):
    """
    Every repository this account audits, newest run first, grouped by owner.

    Free and Pro users see it with their own repositories; the value grows with
    the number of repositories, which is exactly what the Team plan is for.
    """
    sub = _get_subscription(request.user)
    latest = Audit.objects.filter(
        user=request.user, status=Audit.STATUS_DONE, score__isnull=False,
    ).latest_per_repo()

    selected_owner = request.GET.get('owner', '')
    owners = sorted({a.repo_owner for a in latest if a.repo_owner})
    if selected_owner:
        latest = [a for a in latest if a.repo_owner == selected_owner]

    rows = []
    for audit in latest:
        prev = audit.previous_run()
        # A check the engine set aside is not a finding; counting it here made
        # the organisation dashboard disagree with the report it links to.
        crit = audit.checks.counted().filter(passed=False, severity='crit').count()
        warn = audit.checks.counted().filter(passed=False, severity='warn').count()
        rows.append({
            'audit': audit,
            'name': audit.repo_display,
            'owner': audit.repo_owner,
            'score': audit.score,
            'delta': (audit.score - prev.score) if (prev and prev.score is not None) else None,
            'crit': crit,
            'warn': warn,
            'ran_at': audit.completed_at or audit.created_at,
            'source': audit.source,
        })

    sort = request.GET.get('sort', 'score')
    reverse = sort in ('score_desc', 'crit')
    if sort == 'name':
        rows.sort(key=lambda r: r['name'])
    elif sort == 'recent':
        rows.sort(key=lambda r: r['ran_at'], reverse=True)
    elif sort == 'crit':
        rows.sort(key=lambda r: (r['crit'], r['warn']), reverse=True)
    else:
        rows.sort(key=lambda r: r['score'], reverse=reverse)

    scores = [r['score'] for r in rows]
    avg = round(sum(scores) / len(scores)) if scores else 0
    total_crit = sum(r['crit'] for r in rows)

    # Weekly average across every repository — the line a manager watches.
    weekly = defaultdict(list)
    cutoff = timezone.now() - timezone.timedelta(days=84)
    for audit in Audit.objects.filter(
        user=request.user, status=Audit.STATUS_DONE,
        score__isnull=False, created_at__gte=cutoff,
    ).only('score', 'created_at'):
        week = audit.created_at.strftime('%Y-W%W')
        weekly[week].append(audit.score)
    trend = [
        {'week': week, 'score': round(sum(v) / len(v)), 'runs': len(v)}
        for week, v in sorted(weekly.items())
    ]
    from app.charts import series, color_for
    spark = series([point['score'] for point in trend])
    # Pair each point with the week it belongs to, so the chart can say what a
    # reading is rather than only draw it.
    if spark:
        for coord, point in zip(spark['coords'], trend):
            coord['label'] = point['week']

    return render(request, 'app/org_dashboard.html', {
        'rows': rows,
        'owners': owners,
        'selected_owner': selected_owner,
        'sort': sort,
        'avg_score': avg,
        'repo_count': len(rows),
        'total_crit': total_crit,
        # Was sorted(rows)[:5] — a count that always read min(5, repo_count)
        # however healthy the estate was. Count the repositories that are
        # actually below the line instead.
        'needs_attention': sum(1 for r in rows if r['score'] < ATTENTION_SCORE),
        'attention_score': ATTENTION_SCORE,
        'trend': trend,
        'spark': spark,
        'spark_color': color_for(trend[-1]['score']) if trend else 'var(--dim)',
        'subscription': sub,
        'is_team': sub.is_team,
    })


@login_required
def compliance_report(request, audit_id, framework='soc2'):
    """The audit expressed as controls, for SOC 2 or ISO 27001."""
    from app.compliance import build_report, FRAMEWORKS, unmapped_checks

    if framework not in FRAMEWORKS:
        framework = 'soc2'

    audit = get_object_or_404(Audit, id=audit_id, user=request.user)
    if audit.status != Audit.STATUS_DONE:
        return redirect('audit_detail', audit_id=audit.id)

    sub = _get_subscription(request.user)
    checks = list(audit.checks.all())
    report = build_report(checks, framework)

    # An auditor opens this to find what is *not* satisfied. Ordered by control
    # id, the gaps landed wherever the numbering happened to put them — usually
    # last, after a long scroll of controls that are already fine. The export
    # keeps canonical id order; only the page leads with the gaps.
    ordered = sorted(report['controls'], key=lambda c: (c['status'] != 'gap', c['id']))

    # Everyone sees the coverage number and the first few controls; the full
    # evidence list and the export are what the Compliance plan is for.
    full_access = sub.is_compliance
    visible = ordered if full_access else ordered[:3]

    return render(request, 'app/compliance_report.html', {
        'audit': audit,
        'repo_display': audit.repo_display,
        'report': report,
        'controls': visible,
        'hidden_count': 0 if full_access else max(0, report['total'] - len(visible)),
        'full_access': full_access,
        'framework': framework,
        'frameworks': FRAMEWORKS,
        'unmapped': unmapped_checks(checks, framework) if full_access else [],
        'subscription': sub,
        'generated_at': timezone.now(),
    })


@login_required
def compliance_export(request, audit_id, framework='soc2'):
    """Machine-readable evidence export — the artefact an auditor is handed."""
    from app.compliance import build_report, FRAMEWORKS, check_id_for

    sub = _get_subscription(request.user)
    if not sub.is_compliance:
        return redirect('billing')
    if framework not in FRAMEWORKS:
        framework = 'soc2'

    audit = get_object_or_404(Audit, id=audit_id, user=request.user)
    checks = list(audit.checks.all())
    report = build_report(checks, framework)

    payload = {
        'generated_at': timezone.now().isoformat(),
        'framework': FRAMEWORKS[framework]['long_name'],
        'repository': audit.repo_display,
        'repository_url': audit.repo_url,
        'commit': audit.commit_sha,
        'audit_id': audit.id,
        'audit_date': (audit.completed_at or audit.created_at).isoformat(),
        'overall_score': audit.score,
        'coverage_pct': report['coverage_pct'],
        'controls': [
            {
                'control': c['id'],
                'title': c['title'],
                'status': c['status'],
                'evidence': [
                    {
                        'check_id': check_id_for(chk),
                        'check': chk.name,
                        'result': 'pass' if chk.passed else 'fail',
                        'severity': chk.severity,
                        'detail': chk.description,
                        'remediation': chk.recommendation,
                    }
                    for chk in c['passed'] + c['failed']
                ],
            }
            for c in report['controls']
        ],
    }
    safe = audit.repo_display.replace('/', '_')
    response = JsonResponse(payload, json_dumps_params={'indent': 2})
    response['Content-Disposition'] = (
        f'attachment; filename="{safe}_{framework}_evidence.json"'
    )
    return response


@login_required
def sbom_download(request, audit_id, fmt='cyclonedx'):
    """
    Export the dependency inventory as CycloneDX or SPDX.

    Required reading for anyone shipping into the EU under the Cyber Resilience
    Act, which is why it sits on the Compliance plan.
    """
    from app.sbom import generate

    sub = _get_subscription(request.user)
    if not sub.is_compliance:
        return redirect('billing')
    if fmt not in ('cyclonedx', 'spdx'):
        fmt = 'cyclonedx'

    audit = get_object_or_404(Audit, id=audit_id, user=request.user)

    components = audit.sbom_components or None
    get_content = None
    if components is None:
        # Audits from before the inventory was captured need a live read.
        from app.repo_client import build_client_for_audit
        try:
            get_content = build_client_for_audit(audit).get_content
        except Exception:
            return HttpResponse(
                _('This audit predates SBOM capture and the repository can no longer be read. '
                  'Re-run the audit to generate an SBOM.'),
                status=400,
            )

    document, filename = generate(
        audit.repo_display, get_content, fmt, timezone.now(), components=components,
    )
    response = HttpResponse(
        json.dumps(document, indent=2), content_type='application/json',
    )
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


# ── Weekly digest (roadmap phase 7) ──────────────────────────────────────────

MAX_DIGEST_RECIPIENTS = 10


def _digest_settings(user, language='en'):
    from app.models import DigestSettings
    obj, _created = DigestSettings.objects.get_or_create(
        user=user, defaults={'language': language if language in ('en', 'ru') else 'en'})
    return obj


@login_required
def digest_settings(request):
    """Who gets the weekly digest, when, in which language — with a preview of this week's."""
    from django.core.validators import validate_email
    from django.core.exceptions import ValidationError
    from django.contrib import messages
    from app import digest

    sub = _get_subscription(request.user)
    if not sub.is_team:
        return render(request, 'app/digest.html', {'subscription': sub, 'locked': True})

    ds = _digest_settings(request.user, request.LANGUAGE_CODE)
    errors = []
    if request.method == 'POST':
        if request.POST.get('action') == 'send_test':
            if digest.send(request.user, ds, test=True):
                messages.success(request, _('A test digest was sent to %(to)s.') % {'to': ', '.join(ds.recipient_list())})
            else:
                messages.error(request, _('Nothing to send yet: run at least one audit first.'))
            return redirect('digest_settings')
        recipients = [a.strip() for a in request.POST.get('recipients', '').replace(';', ',').split(',') if a.strip()]
        for address in recipients:
            try:
                validate_email(address)
            except ValidationError:
                errors.append(_('Not an email address: %(a)s') % {'a': address})
        if len(recipients) > MAX_DIGEST_RECIPIENTS:
            errors.append(_('At most %(n)d recipients.') % {'n': MAX_DIGEST_RECIPIENTS})
        try:
            weekday = int(request.POST.get('weekday', ds.weekday))
        except ValueError:
            weekday = ds.weekday
        if not errors:
            ds.enabled = request.POST.get('enabled') == 'on'
            ds.weekday = weekday if 0 <= weekday <= 6 else 0
            ds.recipients = ', '.join(recipients)
            ds.language = request.POST.get('language') if request.POST.get('language') in ('en', 'ru') else 'en'
            ds.save()
            messages.success(request, _('Digest settings saved.'))
            return redirect('digest_settings')

    subject, html, _data = digest.render(request.user, ds, use_model=False)
    return render(request, 'app/digest.html', {
        'subscription': sub, 'settings': ds, 'errors': errors,
        'preview_subject': subject, 'preview_html': html,
        'weekdays': ds.WEEKDAYS,
    })


@csrf_exempt
def digest_unsubscribe(request, token):
    """
    One click, no sign-in: the alternative is the spam button. csrf_exempt
    because mail clients send RFC 8058 one-click unsubscribes as a bare POST.
    """
    from app.models import DigestSettings
    ds = DigestSettings.objects.filter(unsubscribe_token=token).first()
    if ds is not None and ds.enabled:
        ds.enabled = False
        ds.save(update_fields=['enabled'])
    return render(request, 'app/digest.html', {'stopped': True, 'found': ds is not None})
