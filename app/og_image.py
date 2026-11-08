"""
Social preview cards.

A report link pasted into Slack or posted on X currently unfurls as a bare URL.
This renders a 1200x630 PNG showing the repository and its score, so the result
itself is the thing people see — which is what makes a shared report spread.
"""
import io
import logging
import os

from PIL import Image, ImageDraw, ImageFont

logger = logging.getLogger(__name__)

WIDTH, HEIGHT = 1200, 630

BG = (5, 6, 7)
PANEL = (12, 16, 20)
GRID = (18, 26, 34)
TEXT = (240, 248, 255)
MUTED = (138, 163, 178)
ACCENT = (0, 255, 136)

SCORE_COLORS = {
    'green': (0, 204, 106),
    'blue':  (68, 136, 255),
    'amber': (255, 170, 0),
    'red':   (255, 68, 102),
    'gray':  (110, 130, 145),
}

FONT_DIRS = [
    '/usr/share/fonts/truetype/dejavu',
    '/usr/share/fonts/dejavu',
]


def _font(name: str, size: int):
    for directory in FONT_DIRS:
        path = os.path.join(directory, name)
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _color_for(score):
    if score is None:
        return SCORE_COLORS['gray']
    if score >= 80:
        return SCORE_COLORS['green']
    if score >= 60:
        return SCORE_COLORS['blue']
    if score >= 40:
        return SCORE_COLORS['amber']
    return SCORE_COLORS['red']


def _label_for(score):
    if score is None:
        return 'NOT SCORED'
    if score >= 80:
        return 'EXCELLENT'
    if score >= 60:
        return 'GOOD'
    if score >= 40:
        return 'FAIR'
    return 'NEEDS WORK'


def _truncate(draw, text, font, max_width):
    if draw.textlength(text, font=font) <= max_width:
        return text
    while text and draw.textlength(text + '…', font=font) > max_width:
        text = text[:-1]
    return text + '…'


def render_card(repo_name: str, score, categories: dict | None = None,
                failed: int = 0, passed: int = 0) -> bytes:
    """Render the PNG card and return its bytes."""
    img = Image.new('RGB', (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)

    for x in range(0, WIDTH, 56):
        draw.line([(x, 0), (x, HEIGHT)], fill=GRID, width=1)
    for y in range(0, HEIGHT, 56):
        draw.line([(0, y), (WIDTH, y)], fill=GRID, width=1)

    mono_bold = _font('DejaVuSansMono-Bold.ttf', 22)
    sans_bold = _font('DejaVuSans-Bold.ttf', 54)
    sans_reg = _font('DejaVuSans.ttf', 26)
    score_font = _font('DejaVuSans-Bold.ttf', 168)
    small_mono = _font('DejaVuSansMono.ttf', 20)

    draw.text((72, 64), 'DEVOPSCHECK', font=mono_bold, fill=ACCENT)
    draw.line([(72, 108), (WIDTH - 72, 108)], fill=GRID, width=2)

    text_width = WIDTH - 470
    name = _truncate(draw, repo_name, sans_bold, text_width)
    draw.text((72, 168), name, font=sans_bold, fill=TEXT)
    subtitle = _truncate(
        draw, 'Automated DevOps audit — security, CI/CD, Docker, dependencies',
        sans_reg, text_width,
    )
    draw.text((72, 248), subtitle, font=sans_reg, fill=MUTED)

    color = _color_for(score)
    score_text = str(score) if score is not None else '—'
    right = WIDTH - 96
    draw.text((right, 138), score_text, font=score_font, fill=color, anchor='ra')
    suffix_font = _font('DejaVuSans.ttf', 32)
    draw.text((right, 300), '/ 100', font=suffix_font, fill=MUTED, anchor='ra')
    draw.text((right, 344), _label_for(score), font=small_mono, fill=color, anchor='ra')

    # Category bars — the detail that makes the card worth looking at.
    if categories:
        order = ['security', 'ai_agents', 'ci_cd', 'docker', 'deps', 'ops', 'docs', 'iac']
        names = {'security': 'SECURITY', 'ci_cd': 'CI/CD', 'docker': 'DOCKER',
                 'deps': 'DEPS', 'ops': 'OPS', 'docs': 'DOCS', 'iac': 'IAC',
                 'ai_agents': 'AI AGENTS'}
        items = [(k, categories[k]) for k in order if k in categories][:5]
        x0, y0 = 72, 410
        bar_w, gap = 190, 24
        for i, (key, value) in enumerate(items):
            x = x0 + i * (bar_w + gap)
            draw.text((x, y0), names.get(key, key.upper()), font=small_mono, fill=MUTED)
            draw.rectangle([x, y0 + 34, x + bar_w, y0 + 44], fill=PANEL)
            fill_w = int(bar_w * max(0, min(100, value)) / 100)
            draw.rectangle([x, y0 + 34, x + fill_w, y0 + 44], fill=_color_for(value))
            draw.text((x, y0 + 56), f'{value}', font=small_mono, fill=TEXT)

    footer = f'{passed} passed · {failed} issues' if (passed or failed) else 'devopscheck.com'
    draw.line([(72, HEIGHT - 92), (WIDTH - 72, HEIGHT - 92)], fill=GRID, width=2)
    draw.text((72, HEIGHT - 66), footer, font=small_mono, fill=MUTED)
    domain = 'devopscheck.com'
    dw = draw.textlength(domain, font=small_mono)
    draw.text((WIDTH - 72 - dw, HEIGHT - 66), domain, font=small_mono, fill=ACCENT)

    buf = io.BytesIO()
    img.save(buf, format='PNG', optimize=True)
    return buf.getvalue()


#: Social cards for pages that are not a report: (headline, subtitle).
PAGE_CARDS = {
    'home': ('The audit that opens the pull request',
             'Secrets, CVEs, GitHub Actions, Docker, Kubernetes, Terraform'),
    'scan': ('Scan any public GitHub repository',
             'Free, no account — a 0–100 score in about five seconds'),
    'rankings': ('DevOps rankings of open-source repositories',
                 'Scores from real scans of popular public projects'),
    'trust': ('What happens to your repository',
              'What we read, what never leaves, how tokens are stored'),
    'pricing': ('Plans and pricing',
                'Free for public repositories — fixes as pull requests on Pro'),
    'checks': ('DevOps and security checks, explained',
               'Why each check matters and how to fix it, with code'),
}


def render_page_card(page: str) -> bytes:
    """A 1200x630 card for a non-report page (PAGE_CARDS)."""
    title, subtitle = PAGE_CARDS.get(page, PAGE_CARDS['home'])
    img = Image.new('RGB', (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)
    for x in range(0, WIDTH, 56):
        draw.line([(x, 0), (x, HEIGHT)], fill=GRID, width=1)
    for y in range(0, HEIGHT, 56):
        draw.line([(0, y), (WIDTH, y)], fill=GRID, width=1)
    mono_bold = _font('DejaVuSansMono-Bold.ttf', 22)
    title_font = _font('DejaVuSans-Bold.ttf', 60)
    sub_font = _font('DejaVuSans.ttf', 30)
    small_mono = _font('DejaVuSansMono.ttf', 22)
    draw.text((72, 64), 'DEVOPSCHECK', font=mono_bold, fill=ACCENT)
    draw.line([(72, 108), (WIDTH - 72, 108)], fill=GRID, width=2)
    # Wrap the headline onto at most three lines.
    words, lines, line = title.split(), [], ''
    for w in words:
        trial = f'{line} {w}'.strip()
        if draw.textlength(trial, font=title_font) > WIDTH - 144 and line:
            lines.append(line)
            line = w
        else:
            line = trial
    lines.append(line)
    y = 170
    for ln in lines[:3]:
        draw.text((72, y), ln, font=title_font, fill=TEXT)
        y += 76
    draw.text((72, y + 24), _truncate(draw, subtitle, sub_font, WIDTH - 144), font=sub_font, fill=MUTED)
    draw.line([(72, HEIGHT - 92), (WIDTH - 72, HEIGHT - 92)], fill=GRID, width=2)
    domain = 'devopscheck.com'
    dw = draw.textlength(domain, font=small_mono)
    draw.text((WIDTH - 72 - dw, HEIGHT - 66), domain, font=small_mono, fill=ACCENT)
    buf = io.BytesIO()
    img.save(buf, format='PNG', optimize=True)
    return buf.getvalue()
