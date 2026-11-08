"""
The next thing to do, worked out from what the account has actually done.

The product has a dozen pages and no thread between them: a new customer signs
up, lands somewhere, and has to guess which of "GitHub", "GitLab",
"Organization", "Subscription" and "Profile" is the one that moves them
forward. Most guess wrong and leave.

This is not a scripted tour. A tour tells everyone the same five things in the
same order and is wrong for anyone who arrived in the middle. Each step below
knows how to check whether it is already done, so the guide always points at the
first thing genuinely outstanding — and disappears entirely once there is
nothing left to say, which is the part tours never do.

Steps are cheap to evaluate: existence queries against rows the page has usually
loaded anyway.
"""
from django.urls import reverse
from django.utils.translation import gettext_lazy as _


class Step:
    def __init__(self, key, title, body, url_name, cta, anchor='', pages=()):
        self.key = key
        self.title = title
        self.body = body
        self.url_name = url_name
        self.cta = cta
        # The element the bubble points at, when the reader is already on the
        # right page. Empty means the bubble just sits at the top.
        self.anchor = anchor
        # Which pages this step is worth showing on. Empty means every page.
        self.pages = pages

    def url(self):
        return reverse(self.url_name)


STEPS = [
    Step(
        'connect',
        _('Connect a repository host'),
        _('Install the GitHub App or paste a token. Read access is enough to audit; '
          'opening fix pull requests needs write.'),
        'connect',
        _('Connect'),
        anchor='#connect',
    ),
    Step(
        'first_audit',
        _('Run your first audit'),
        _('Pick any repository and press "run audit". It reads the whole tree in three '
          'API calls and takes a few seconds.'),
        'dashboard',
        _('Open repositories'),
        anchor='.btn-audit',
    ),
    Step(
        'read_report',
        _('Open the report'),
        _('The score is the summary; the findings underneath are the work. They are '
          'ordered worst first, so the top one is where to start.'),
        'dashboard',
        _('Open the report'),
        anchor='.view-link',
    ),
    Step(
        'first_fix',
        _('Turn a finding into a pull request'),
        _('Press "AI Fix" on a finding that has one. You get the file, and a button that '
          'opens the pull request on a branch — nothing is pushed to your default branch.'),
        'dashboard',
        _('Open the report'),
        anchor='.btn-fix',
    ),
    Step(
        'go_public',
        _('Put the badge in your README'),
        _('One click opens the pull request that adds it. A badge is how the next person '
          'finds their way here.'),
        'dashboard',
        _('Open the report'),
    ),
]

STEP_KEYS = [s.key for s in STEPS]


def _is_done(step, user) -> bool:
    from app.models import Audit, GithubProfile, GitlabProfile

    if step.key == 'connect':
        return (GithubProfile.objects.filter(user=user).exists()
                or GitlabProfile.objects.filter(user=user).exists())
    if step.key == 'first_audit':
        return Audit.objects.filter(user=user).active().exists()
    if step.key == 'read_report':
        return Audit.objects.filter(user=user, status=Audit.STATUS_DONE).active().exists()
    if step.key == 'first_fix':
        return Audit.objects.filter(user=user, status=Audit.STATUS_DONE).active().exists()
    if step.key == 'go_public':
        return Audit.objects.filter(user=user, is_public=True).active().exists()
    return True


def progress(user):
    """
    `(steps, current)` — every step with a done flag, and the first outstanding one.

    `current` is None once the account has done everything, and the guide then
    shows nothing at all. A checklist that stays after it is finished is clutter
    on every page forever.
    """
    from app.models import UserProfile

    profile = UserProfile.objects.filter(user=user).first()
    dismissed = set((profile.guide_dismissed or []) if profile else [])

    rows, current = [], None
    for step in STEPS:
        done = _is_done(step, user)
        rows.append({'key': step.key, 'title': step.title, 'done': done})
        if not done and current is None and step.key not in dismissed:
            current = step
    return rows, current


def hint_for(user, page_name: str):
    """
    The bubble to show on `page_name`, or None.

    Only ever the *current* step, and only where it makes sense to show it —
    a hint about running an audit belongs on the page with the button, not on
    the billing page.
    """
    if not user or not user.is_authenticated:
        return None
    rows, current = progress(user)
    if current is None:
        return None
    if current.pages and page_name not in current.pages:
        return None
    done = sum(1 for r in rows if r['done'])
    # The step you are on, not the number behind you. "Step 0 of 5" is a
    # progress bar pretending to be an instruction.
    position = next(i for i, r in enumerate(rows, 1) if r['key'] == current.key)
    return {
        'key': current.key,
        'position': position,
        'title': current.title,
        'body': current.body,
        'cta': current.cta,
        'url': current.url(),
        'anchor': current.anchor,
        'on_page': page_name == current.url_name,
        'done': done,
        'total': len(rows),
        'rows': rows,
    }
