from django import template
from django.utils.translation import gettext as _

register = template.Library()


@register.filter
def is_fixable(check):
    """
    True when a One-click Fix template exists for this check.

    Resolution goes through check_id. This filter used to pass the display
    name, which stopped matching once names became translated source strings —
    and silently hid the Fix button on every finding in the report.
    """
    from app.fix_templates import is_fixable as _is_fixable, resolve_check_id

    if hasattr(check, 'name') or hasattr(check, 'check_id'):
        # The repository's host decides the template — and whether there is
        # one: GitHub Actions pinning has nothing to fix on GitLab.
        audit = getattr(check, 'audit', None)
        return _is_fixable(resolve_check_id(check), host=getattr(audit, 'source', 'github'))
    return _is_fixable(str(check))


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)


@register.filter
def trans_str(value):
    """Translate a string stored in the database using Django's gettext."""
    if value:
        return _(str(value))
    return value


@register.filter
def markdown_code(text):
    """Very light markdown: wrap ```...``` blocks in <pre><code>, bold **...**."""
    import re, html
    if not text:
        return text
    safe = html.escape(str(text))
    # code blocks
    safe = re.sub(
        r'```(?:[a-z]*\n?)?(.*?)```',
        lambda m: f'<pre style="background:rgba(0,0,0,.4);border:1px solid #1a2230;border-radius:4px;padding:10px 14px;overflow-x:auto;font-family:monospace;font-size:12px;color:#d0e0f0;white-space:pre-wrap;margin:8px 0">{m.group(1).strip()}</pre>',
        safe,
        flags=re.DOTALL,
    )
    # inline code
    safe = re.sub(r'`([^`]+)`', r'<code style="background:rgba(0,0,0,.3);padding:1px 5px;border-radius:3px;font-size:11px">\1</code>', safe)
    # bold
    safe = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', safe)
    # newlines
    safe = safe.replace('\n', '<br>')
    return safe


@register.simple_tag(takes_context=True)
def localized(context, url):
    """An absolute URL on this site, moved under /ru/ when the page is served there."""
    prefix = context.get('lang_prefix') or ''
    base = context.get('base_url') or ''
    if prefix and base and url.startswith(base) and not url.startswith(base + prefix + '/'):
        return base + prefix + url[len(base):]
    return url
