"""
The report's answer to "what do I do first".

A list of twelve failed checks tells someone their repository is bad. It does
not tell them where to start, and the flat list makes a leaked credential look
exactly as urgent as a missing CHANGELOG. So each finding gets two numbers the
audit already has enough information to compute:

  impact  — how many points the score gains when this check passes
  effort  — how much work that is, in three honest tiers

Ordering by impact per unit of effort turns the report into a to-do list, and
the projected score turns the fix button into an obvious next action.
"""
import logging

from django.utils.translation import gettext_lazy as _

from app.checks import SEVERITY_WEIGHTS

logger = logging.getLogger(__name__)

# Three tiers, because five would be false precision.
EFFORT_INSTANT = 'instant'    # we can write the file and open the pull request
EFFORT_QUICK = 'quick'        # a setting or a few lines, no thinking required
EFFORT_INVOLVED = 'involved'  # needs a decision, a rotation, or real work

EFFORT_META = {
    EFFORT_INSTANT: {'rank': 0, 'label': _('one click'), 'detail': _('we open the pull request')},
    EFFORT_QUICK: {'rank': 1, 'label': _('a few minutes'), 'detail': _('a setting or a few lines')},
    EFFORT_INVOLVED: {'rank': 2, 'label': _('needs a decision'), 'detail': _('someone has to choose how')},
}

# Checks that cannot be closed by dropping a file in. Everything not listed
# here is judged by whether a fix template exists.
EFFORT_OVERRIDES = {
    # Rotating a leaked credential and purging it from history is not a quick fix.
    'security.no_secrets': EFFORT_INVOLVED,
    'security.no_secrets_in_history': EFFORT_INVOLVED,
    'security.secret_active': EFFORT_INVOLVED,
    'security.env_not_committed': EFFORT_INVOLVED,
    'iac.no_hardcoded_credentials': EFFORT_INVOLVED,
    # Upgrading dependencies means testing them.
    'deps.cve': EFFORT_INVOLVED,
    'deps.pinned': EFFORT_QUICK,
    # Infrastructure changes touch running systems.
    'iac.remote_state': EFFORT_INVOLVED,
    'iac.open_ingress': EFFORT_INVOLVED,
    'iac.encryption_at_rest': EFFORT_INVOLVED,
    'iac.private_database': EFFORT_INVOLVED,
    'iac.no_public_buckets': EFFORT_INVOLVED,
    'docker.multistage': EFFORT_INVOLVED,
    'ci.tests': EFFORT_INVOLVED,
    'docs.readme_quality': EFFORT_INVOLVED,
    'ops.activity': EFFORT_INVOLVED,
    # Settings in the provider's UI: fast, but not something we can commit.
    'ci.branch_protection': EFFORT_QUICK,
    'actions.broad_permissions': EFFORT_QUICK,
    'actions.pull_request_target': EFFORT_INVOLVED,
    'actions.script_injection': EFFORT_QUICK,
    'actions.self_hosted_public': EFFORT_INVOLVED,
    'actions.cloud_oidc': EFFORT_INVOLVED,
    'gitlab_ci.pinned_includes': EFFORT_QUICK,
    'gitlab_ci.pinned_images': EFFORT_QUICK,
    'gitlab_ci.cloud_oidc': EFFORT_INVOLVED,
    'ai.mcp_secrets': EFFORT_QUICK,
    'ai.mcp_pinned': EFFORT_QUICK,
    'ai.agent_ci_exposed': EFFORT_QUICK,
    'ai.instructions_clean': EFFORT_QUICK,
    'security.env_gitignored': EFFORT_QUICK,
    'ops.gitignore': EFFORT_QUICK,
    'deps.lockfile': EFFORT_QUICK,
    'deps.manifest': EFFORT_QUICK,
    'docker.pinned_base': EFFORT_QUICK,
    'docker.healthcheck': EFFORT_QUICK,
    'docker.resource_limits': EFFORT_QUICK,
    'k8s.resource_limits': EFFORT_QUICK,
    'k8s.probes': EFFORT_QUICK,
    'k8s.nonroot': EFFORT_QUICK,
    'ops.observability': EFFORT_INVOLVED,
}


def _weight(check):
    return SEVERITY_WEIGHTS.get(check.severity, 5)


def effort_for(check) -> str:
    """How much work closing this check actually is."""
    from app.fix_templates import is_fixable, resolve_check_id

    key = resolve_check_id(check)
    if key in EFFORT_OVERRIDES:
        return EFFORT_OVERRIDES[key]
    audit = getattr(check, 'audit', None)
    if is_fixable(key, host=getattr(audit, 'source', 'github')):
        return EFFORT_INSTANT
    return EFFORT_QUICK


def score_with(checks, assume_passed) -> int:
    """The score this audit would have if `assume_passed` all passed."""
    ids = {id(c) for c in assume_passed}
    total = earned = 0
    for check in checks:
        w = _weight(check)
        total += w
        if check.passed or id(check) in ids:
            earned += w
    return round(earned / total * 100) if total else 0


def build(checks, limit=3) -> dict | None:
    """
    The "start here" block.

    Returns the chosen items, the score they would produce together, and the
    points still left on the table after them — or None when nothing failed.
    """
    # Only checks that count toward the score belong in a plan of what to fix —
    # telling a library to add a Dockerfile is advice it cannot take.
    checks = [c for c in checks if getattr(c, 'applicable', True)
              and getattr(c, 'category', '') != 'hygiene']
    failed = [c for c in checks if not c.passed]
    if not failed:
        return None

    total_weight = sum(_weight(c) for c in checks) or 1

    scored = []
    for check in failed:
        effort = effort_for(check)
        impact = round(_weight(check) / total_weight * 100, 1)
        scored.append({
            'check': check,
            'impact': impact,
            'effort': effort,
            'effort_rank': EFFORT_META[effort]['rank'],
            'effort_label': EFFORT_META[effort]['label'],
            'effort_detail': EFFORT_META[effort]['detail'],
            'severity': check.severity,
            # Value per unit of work. Critical findings still win on impact
            # alone, but among equals the cheap ones come first.
            'ratio': impact / (EFFORT_META[effort]['rank'] + 1),
        })

    # Critical findings lead regardless of effort — a leaked key is not something
    # to schedule behind an easier win.
    scored.sort(key=lambda s: (0 if s['severity'] == 'crit' else 1, -s['ratio'], s['effort_rank']))
    chosen = scored[:limit]

    current = score_with(checks, [])
    projected = score_with(checks, [s['check'] for s in chosen])
    everything = score_with(checks, failed)

    return {
        'items': chosen,
        'current_score': current,
        'projected_score': projected,
        'gain': projected - current,
        'max_score': everything,
        'remaining': len(failed) - len(chosen),
        'quick_wins': [s for s in scored if s['effort'] == EFFORT_INSTANT],
    }
