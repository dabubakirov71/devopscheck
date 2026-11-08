"""
PDF report generation.

Written for paper, not for a screen. The previous version reused the app's dark
palette, which meant a document people print for an auditor arrived as white
pages carrying near-black blocks — heavy on toner and unmistakably a screenshot
of a web page rather than a report. This one is a light document: dark ink on
white, colour reserved for severity, a proper title block, and page numbers.

DejaVu is registered when available so Cyrillic renders.
"""
import io
import os
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

# ── Fonts ─────────────────────────────────────────────────────────────────────

FONT_CANDIDATES = [
    ('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
     '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
     '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf'),
    ('/usr/share/fonts/dejavu/DejaVuSans.ttf',
     '/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf',
     '/usr/share/fonts/dejavu/DejaVuSansMono.ttf'),
]

_UNICODE_OK = False


def _register_fonts():
    global _UNICODE_OK
    for regular, bold, mono in FONT_CANDIDATES:
        if os.path.exists(regular) and os.path.exists(bold):
            pdfmetrics.registerFont(TTFont('DejaVu', regular))
            pdfmetrics.registerFont(TTFont('DejaVu-Bold', bold))
            if os.path.exists(mono):
                pdfmetrics.registerFont(TTFont('DejaVu-Mono', mono))
            _UNICODE_OK = True
            return


_register_fonts()

FONT_NORMAL = 'DejaVu' if _UNICODE_OK else 'Helvetica'
FONT_BOLD = 'DejaVu-Bold' if _UNICODE_OK else 'Helvetica-Bold'
FONT_MONO = 'DejaVu-Mono' if _UNICODE_OK else 'Courier'

# ── Palette: a printed document, not a dark UI ───────────────────────────────

C_INK = colors.HexColor('#101418')
C_INK_2 = colors.HexColor('#3c4a53')
C_MUTED = colors.HexColor('#6b7a84')
C_RULE = colors.HexColor('#d8dee2')
C_PANEL = colors.HexColor('#f4f6f7')
C_WHITE = colors.white

C_CRIT = colors.HexColor('#b3202f')
C_WARN = colors.HexColor('#8a5a00')
C_INFO = colors.HexColor('#215fa6')
C_OK = colors.HexColor('#1f7a3f')

C_CRIT_BG = colors.HexColor('#fbeaec')
C_WARN_BG = colors.HexColor('#fbf1de')
C_INFO_BG = colors.HexColor('#e8f0fa')
C_OK_BG = colors.HexColor('#e7f3eb')

SEV_INK = {'crit': C_CRIT, 'warn': C_WARN, 'info': C_INFO, 'ok': C_OK}
SEV_BG = {'crit': C_CRIT_BG, 'warn': C_WARN_BG, 'info': C_INFO_BG, 'ok': C_OK_BG}
SEV_ORDER = {'crit': 0, 'warn': 1, 'info': 2, 'ok': 3}


def _score_ink(score):
    if score is None:
        return C_MUTED
    if score >= 80:
        return C_OK
    if score >= 60:
        return C_INFO
    if score >= 40:
        return C_WARN
    return C_CRIT


# ── Styles ────────────────────────────────────────────────────────────────────

def _s(name, **kw):
    base = dict(fontName=FONT_NORMAL, fontSize=9.5, leading=13.5, textColor=C_INK)
    base.update(kw)
    return ParagraphStyle(name, **base)


ST_TITLE = _s('title', fontName=FONT_BOLD, fontSize=21, leading=25, textColor=C_INK)
ST_SUBTITLE = _s('subtitle', fontSize=11, leading=15, textColor=C_MUTED)
ST_H2 = _s('h2', fontName=FONT_BOLD, fontSize=8.5, leading=12, textColor=C_MUTED,
           spaceBefore=2, spaceAfter=2)
ST_LEAD = _s('lead', fontSize=10.5, leading=16, textColor=C_INK_2)
ST_META_K = _s('metak', fontSize=8.5, leading=12, textColor=C_MUTED)
ST_META_V = _s('metav', fontSize=8.5, leading=12, textColor=C_INK, fontName=FONT_MONO)
ST_NAME = _s('name', fontName=FONT_BOLD, fontSize=10, leading=13.5, textColor=C_INK)
ST_DESC = _s('desc', fontSize=9, leading=13, textColor=C_INK_2)
ST_REC = _s('rec', fontName=FONT_MONO, fontSize=8, leading=11.5, textColor=C_INK_2)
ST_REC_LABEL = _s('reclabel', fontName=FONT_BOLD, fontSize=7.5, leading=11, textColor=C_MUTED)
ST_PASS = _s('pass', fontSize=9, leading=12.5, textColor=C_INK_2)
ST_SCORE = _s('score', fontName=FONT_BOLD, fontSize=40, leading=42, alignment=TA_CENTER)
ST_SCORE_SUB = _s('scoresub', fontSize=8.5, leading=11, textColor=C_MUTED, alignment=TA_CENTER)
ST_CELL_N = _s('celln', fontName=FONT_BOLD, fontSize=15, leading=18, alignment=TA_CENTER)
ST_CELL_L = _s('celll', fontSize=7.5, leading=10, textColor=C_MUTED, alignment=TA_CENTER)

CAT_LABELS = {
    'security': 'Security', 'ci_cd': 'CI/CD', 'docker': 'Docker',
    'docs': 'Documentation', 'deps': 'Dependencies', 'ops': 'Operations',
    'code': 'Code quality', 'iac': 'Infrastructure as Code',
    'ai_agents': 'AI agent safety',
}

_L = {
    'en': {
        'title': 'DevOpsCheck Report', 'repository': 'Repository', 'source': 'Source',
        'commit': 'Commit', 'audited': 'Audit date', 'generated': 'Generated',
        'scope': 'Scope', 'scope_v': 'Repository configuration, dependencies and infrastructure as code',
        'summary': 'SUMMARY', 'categories': 'SCORE BY CATEGORY', 'findings': 'FINDINGS',
        'passed': 'PASSED CHECKS', 'compliance': 'CONTROL COVERAGE', 'live_key': 'LIVE KEY',
        'failed_l': 'ISSUES', 'passed_l': 'PASSED', 'total_l': 'CHECKS', 'score_l': 'SCORE',
        'crit_l': 'CRITICAL', 'warn_l': 'WARNINGS',
        'remediation': 'REMEDIATION', 'advice': 'SUGGESTED CHANGE',
        'none_failed': 'No checks failed. Every check in the engine passed for this repository.',
        'page': 'Page', 'of': 'of', 'footer': 'DevOpsCheck',
        'controls_note': 'A control counts as satisfied only when every check mapped to it passes.',
        'satisfied': 'satisfied', 'gap': 'gap', 'control': 'Control', 'status': 'Status',
        'evidence': 'Evidence',
    },
    'ru': {
        'title': 'Отчёт DevOps-аудита', 'repository': 'Репозиторий', 'source': 'Источник',
        'commit': 'Коммит', 'audited': 'Дата аудита', 'generated': 'Сформирован',
        'scope': 'Область', 'scope_v': 'Конфигурация репозитория, зависимости и инфраструктура как код',
        'summary': 'РЕЗЮМЕ', 'categories': 'ОЦЕНКА ПО КАТЕГОРИЯМ', 'findings': 'НАХОДКИ',
        'passed': 'ПРОЙДЕННЫЕ ПРОВЕРКИ', 'compliance': 'ПОКРЫТИЕ КОНТРОЛЕЙ', 'live_key': 'КЛЮЧ АКТИВЕН',
        'failed_l': 'ПРОБЛЕМ', 'passed_l': 'ПРОЙДЕНО', 'total_l': 'ПРОВЕРОК', 'score_l': 'ОЦЕНКА',
        'crit_l': 'КРИТИЧНЫХ', 'warn_l': 'ПРЕДУПРЕЖДЕНИЙ',
        'remediation': 'ЧТО СДЕЛАТЬ', 'advice': 'ПРЕДЛАГАЕМОЕ ИЗМЕНЕНИЕ',
        'none_failed': 'Ни одна проверка не провалена. Для этого репозитория пройдены все проверки движка.',
        'page': 'Стр.', 'of': 'из', 'footer': 'DevOpsCheck',
        'controls_note': 'Контроль считается выполненным, только если пройдены все связанные проверки.',
        'satisfied': 'выполнен', 'gap': 'пробел', 'control': 'Контроль', 'status': 'Статус',
        'evidence': 'Доказательства',
    },
}


# ── Text helpers ──────────────────────────────────────────────────────────────

def _esc(text):
    return (text or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _md(text):
    """Minimal markdown → ReportLab inline markup, safely escaped."""
    text = text or ''
    text = re.sub(r'```[a-z]*\n?', '', text)
    text = re.sub(r'`([^`]+)`', r'\1', text)
    out = _esc(text)
    out = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', out)
    out = re.sub(r'(?<!\*)\*([^*\n]+)\*(?!\*)', r'<i>\1</i>', out)
    return out.strip()


def _pre(text, limit=700):
    """Preformatted block: keep the line breaks, cap runaway length."""
    text = (text or '').strip()
    if len(text) > limit:
        text = text[:limit].rsplit('\n', 1)[0] + '\n…'
    return _esc(text).replace('\n', '<br/>')


# ── Page furniture ────────────────────────────────────────────────────────────

class _Canvas:
    """Draws the running header rule and the footer with page numbers."""

    def __init__(self, repo_name, lang):
        self.repo_name = repo_name
        self.t = _L[lang]

    def __call__(self, canvas, doc):
        canvas.saveState()
        width, height = A4

        canvas.setStrokeColor(C_RULE)
        canvas.setLineWidth(0.5)
        canvas.line(2*cm, height - 1.45*cm, width - 2*cm, height - 1.45*cm)
        canvas.setFont(FONT_NORMAL, 7.5)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(2*cm, height - 1.3*cm, self.t['footer'])
        canvas.drawRightString(width - 2*cm, height - 1.3*cm, self.repo_name)

        canvas.line(2*cm, 1.5*cm, width - 2*cm, 1.5*cm)
        canvas.drawString(2*cm, 1.05*cm, self.t['footer'])
        canvas.drawRightString(width - 2*cm, 1.05*cm,
                               f'{self.t["page"]} {canvas.getPageNumber()}')
        canvas.restoreState()


# ── Blocks ────────────────────────────────────────────────────────────────────

def _title_block(audit, repo_name, t, content_width):
    score_ink = _score_ink(audit.score)
    score_cell = [
        Paragraph(f'{audit.score if audit.score is not None else "—"}',
                  _s('sc', fontName=FONT_BOLD, fontSize=38, leading=40,
                     alignment=TA_CENTER, textColor=score_ink)),
        # "/ 100" on its own line — as one cell with the number it used to wrap
        # mid-fraction and render as "/10" above a stray "0".
        Paragraph('/ 100', ST_SCORE_SUB),
    ]
    left = [
        Paragraph(_esc(t['title']), ST_TITLE),
        Spacer(1, 4),
        Paragraph(_esc(repo_name), _s('repo', fontName=FONT_MONO, fontSize=12,
                                      leading=16, textColor=C_INK_2)),
    ]
    table = Table([[left, score_cell]], colWidths=[content_width - 3.4*cm, 3.4*cm])
    table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (0, 0), 'TOP'),
        ('VALIGN', (1, 0), (1, 0), 'MIDDLE'),
        ('BOX', (1, 0), (1, 0), 1, score_ink),
        ('BACKGROUND', (1, 0), (1, 0), C_PANEL),
        ('LEFTPADDING', (0, 0), (0, 0), 0),
        ('TOPPADDING', (1, 0), (1, 0), 8),
        ('BOTTOMPADDING', (1, 0), (1, 0), 8),
    ]))
    return table


def _meta_block(audit, repo_name, t, generated_at, content_width):
    rows = [
        (t['repository'], repo_name),
        (t['source'], (audit.source or '').upper()),
    ]
    if audit.commit_sha:
        rows.append((t['commit'], audit.commit_sha[:12]))
    completed = audit.completed_at or audit.created_at
    rows.append((t['audited'], completed.strftime('%d %b %Y, %H:%M UTC')))
    rows.append((t['generated'], generated_at.strftime('%d %b %Y, %H:%M UTC')))
    rows.append((t['scope'], t['scope_v']))

    data = [[Paragraph(_esc(k), ST_META_K), Paragraph(_esc(v), ST_META_V)] for k, v in rows]
    table = Table(data, colWidths=[3.6*cm, content_width - 3.6*cm])
    table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LINEBELOW', (0, 0), (-1, -2), 0.4, C_RULE),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (0, -1), 0),
    ]))
    return table


def _counts_block(total, failed, passed, crit, warn, score, t, content_width):
    cells, styles = [], []
    spec = [
        (str(crit), t['crit_l'], C_CRIT),
        (str(warn), t['warn_l'], C_WARN),
        (str(passed), t['passed_l'], C_OK),
        (str(total), t['total_l'], C_INK),
        (str(score if score is not None else '—'), t['score_l'], _score_ink(score)),
    ]
    for value, label, ink in spec:
        cells.append([
            Paragraph(value, _s('cn', fontName=FONT_BOLD, fontSize=15, leading=18,
                                alignment=TA_CENTER, textColor=ink)),
            Paragraph(_esc(label), ST_CELL_L),
        ])
    col = content_width / len(spec)
    table = Table([cells], colWidths=[col] * len(spec))
    styles += [
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX', (0, 0), (-1, -1), 0.6, C_RULE),
        ('INNERGRID', (0, 0), (-1, -1), 0.6, C_RULE),
        ('BACKGROUND', (0, 0), (-1, -1), C_PANEL),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]
    table.setStyle(TableStyle(styles))
    return table


def _category_block(category_scores, content_width):
    if not category_scores:
        return None
    rows, styles = [], [
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (0, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LINEBELOW', (0, 0), (-1, -2), 0.4, C_RULE),
    ]
    ordered = sorted(category_scores.items(), key=lambda kv: kv[1])
    bar_width = content_width - 5.4*cm - 1.6*cm
    for i, (cat, value) in enumerate(ordered):
        ink = _score_ink(value)
        filled = max(0.06, min(1.0, value / 100.0)) * bar_width
        bar = Table([['', '']], colWidths=[filled, max(0.1, bar_width - filled)], rowHeights=[6])
        bar.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), ink),
            ('BACKGROUND', (1, 0), (1, 0), C_RULE),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        rows.append([
            Paragraph(_esc(CAT_LABELS.get(cat, cat.title())), _s('cat', fontSize=9, leading=12)),
            bar,
            Paragraph(f'{value}', _s('catv', fontName=FONT_BOLD, fontSize=9.5,
                                     leading=12, alignment=TA_RIGHT, textColor=ink)),
        ])
    table = Table(rows, colWidths=[5.4*cm, bar_width, 1.6*cm])
    table.setStyle(TableStyle(styles))
    return table


def _finding(check, t, content_width, index):
    ink = SEV_INK.get(check.severity, C_MUTED)
    bg = SEV_BG.get(check.severity, C_PANEL)

    head = Table(
        [[Paragraph(f'{index}', _s('idx', fontName=FONT_BOLD, fontSize=9, leading=12,
                                   alignment=TA_CENTER, textColor=C_WHITE)),
          Paragraph(_esc(check.name), ST_NAME),
          Paragraph(check.severity.upper() + (f" · {t['live_key']}"
                                              if check.check_id == 'security.secret_active' else ''),
                    _s('sev', fontName=FONT_BOLD, fontSize=7, leading=10,
                       alignment=TA_RIGHT, textColor=ink))]],
        colWidths=[0.85*cm, content_width - 3.1*cm, 2.25*cm],
    )
    head.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (0, 0), (0, 0), ink),
        ('BACKGROUND', (1, 0), (-1, 0), bg),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (2, 0), (2, 0), 8),
    ]))

    parts = [head, Spacer(1, 5), Paragraph(_md(check.description), ST_DESC)]

    if check.recommendation:
        parts += [
            Spacer(1, 6),
            Paragraph(_esc(t['remediation']), ST_REC_LABEL),
            Spacer(1, 2),
            Paragraph(_pre(check.recommendation), ST_REC),
        ]
    if check.ai_suggestion:
        parts += [
            Spacer(1, 6),
            Paragraph(_esc(t['advice']), ST_REC_LABEL),
            Spacer(1, 2),
            Paragraph(_pre(check.ai_suggestion, limit=900), ST_REC),
        ]
    parts.append(Spacer(1, 12))
    return KeepTogether(parts)


def _passed_block(passed, content_width):
    if not passed:
        return None
    rows = []
    for i in range(0, len(passed), 2):
        pair = passed[i:i + 2]
        row = [Paragraph('✓ ' + _esc(c.name), ST_PASS) for c in pair]
        if len(row) == 1:
            row.append(Paragraph('', ST_PASS))
        rows.append(row)
    table = Table(rows, colWidths=[content_width / 2] * 2)
    table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (0, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TEXTCOLOR', (0, 0), (-1, -1), C_INK_2),
    ]))
    return table


def _compliance_block(checks, t, content_width, framework='soc2'):
    """Control coverage — the section that makes this a compliance artefact."""
    try:
        from app.compliance import build_report, FRAMEWORKS
    except Exception:
        return None
    report = build_report(checks, framework)
    if not report['controls']:
        return None

    header = [
        Paragraph(_esc(t['control']), _s('th', fontName=FONT_BOLD, fontSize=7.5,
                                         leading=10, textColor=C_MUTED)),
        Paragraph(_esc(FRAMEWORKS[framework]['name']),
                  _s('th2', fontName=FONT_BOLD, fontSize=7.5, leading=10, textColor=C_MUTED)),
        Paragraph(_esc(t['status']), _s('th3', fontName=FONT_BOLD, fontSize=7.5,
                                        leading=10, textColor=C_MUTED, alignment=TA_RIGHT)),
    ]
    rows = [header]
    styles = [
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LINEBELOW', (0, 0), (-1, 0), 0.6, C_RULE),
        ('LINEBELOW', (0, 1), (-1, -2), 0.3, C_RULE),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (0, -1), 0),
    ]
    for i, control in enumerate(report['controls'], start=1):
        ok = control['status'] == 'satisfied'
        ink = C_OK if ok else C_CRIT
        rows.append([
            Paragraph(_esc(control['id']), _s('cid', fontName=FONT_MONO, fontSize=8.5, leading=12)),
            Paragraph(_esc(control['title']), _s('ct', fontSize=8.5, leading=12, textColor=C_INK_2)),
            Paragraph(_esc(t['satisfied'] if ok else t['gap']),
                      _s('cs', fontName=FONT_BOLD, fontSize=8, leading=11,
                         alignment=TA_RIGHT, textColor=ink)),
        ])
    table = Table(rows, colWidths=[2.2*cm, content_width - 5.2*cm, 3.0*cm])
    table.setStyle(TableStyle(styles))
    return report, table


# ── Entry point ───────────────────────────────────────────────────────────────

def generate_audit_pdf(audit, checks_qs, language='en', include_compliance=False,
                       framework='soc2'):
    from django.utils import timezone

    lang = language if language in _L else 'en'
    t = _L[lang]
    repo_name = audit.repo_full_name.split('::')[0]
    generated_at = timezone.now()

    # Hygiene checks are not findings (see checks.HYGIENE_CHECKS) and stay off the paper.
    checks = [c for c in checks_qs if getattr(c, 'category', '') != 'hygiene']
    failed = sorted((c for c in checks if not c.passed),
                    key=lambda c: (SEV_ORDER.get(c.severity, 9), c.name))
    passed = [c for c in checks if c.passed]
    crit = sum(1 for c in failed if c.severity == 'crit')
    warn = sum(1 for c in failed if c.severity == 'warn')

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm, topMargin=2.1*cm, bottomMargin=2.1*cm,
        title=f'{repo_name} — {t["title"]}', author='DevOpsCheck',
        subject=t['title'],
    )
    content_width = doc.width
    story = []

    story.append(_title_block(audit, repo_name, t, content_width))
    story.append(Spacer(1, 16))
    story.append(_meta_block(audit, repo_name, t, generated_at, content_width))
    story.append(Spacer(1, 16))
    story.append(_counts_block(len(checks), len(failed), len(passed), crit, warn,
                               audit.score, t, content_width))

    if audit.ai_summary:
        story += [
            Spacer(1, 20),
            Paragraph(_esc(t['summary']), ST_H2),
            HRFlowable(width='100%', thickness=1, color=C_INK, spaceBefore=3, spaceAfter=8),
            Paragraph(_md(audit.ai_summary), ST_LEAD),
        ]

    categories = _category_block(audit.category_scores or {}, content_width)
    if categories is not None:
        story += [
            Spacer(1, 20),
            Paragraph(_esc(t['categories']), ST_H2),
            HRFlowable(width='100%', thickness=1, color=C_INK, spaceBefore=3, spaceAfter=8),
            categories,
        ]

    if include_compliance:
        result = _compliance_block(checks, t, content_width, framework)
        if result:
            report, table = result
            story += [
                PageBreak(),
                Paragraph(_esc(t['compliance']), ST_H2),
                HRFlowable(width='100%', thickness=1, color=C_INK, spaceBefore=3, spaceAfter=8),
                Paragraph(
                    f"{_esc(t['controls_note'])} "
                    f"<b>{report['satisfied']}/{report['total']}</b> — {report['coverage_pct']}%.",
                    ST_DESC),
                Spacer(1, 10),
                table,
            ]

    story += [
        PageBreak(),
        Paragraph(f"{_esc(t['findings'])} — {len(failed)}", ST_H2),
        HRFlowable(width='100%', thickness=1, color=C_INK, spaceBefore=3, spaceAfter=10),
    ]
    if failed:
        for i, check in enumerate(failed, start=1):
            story.append(_finding(check, t, content_width, i))
    else:
        story.append(Paragraph(_esc(t['none_failed']), ST_LEAD))

    passed_block = _passed_block(passed, content_width)
    if passed_block is not None:
        story += [
            Spacer(1, 10),
            Paragraph(f"{_esc(t['passed'])} — {len(passed)}", ST_H2),
            HRFlowable(width='100%', thickness=1, color=C_INK, spaceBefore=3, spaceAfter=8),
            passed_block,
        ]

    furniture = _Canvas(repo_name, lang)
    doc.build(story, onFirstPage=furniture, onLaterPages=furniture)
    buf.seek(0)
    return buf
