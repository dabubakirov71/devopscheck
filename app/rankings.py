"""
What the corpus of public scans knows about itself.

A score of 76 means nothing on its own. "Better than 68% of the Python
repositories we have scanned" means something — it is the difference between a
number and a standing, and a standing is what people screenshot.

The same aggregates answer the question a launch needs answered: of the top
repositories on GitHub, how many actually pin their dependencies, run tests in
CI, or ship a container that does not run as root. That is a finding, and a
finding travels further than a tool.

Everything here reads only finished scans and is cached, because it is computed
on the busiest page in the product.
"""
from django.core.cache import cache
from django.db.models import Count

from app.models import Audit, PublicScan
from app.checks import counts as _counts  # noqa: E402

# Below this many scans a percentile is noise dressed up as a fact, and a
# "better than 66%" drawn from three repositories is worse than saying nothing.
MIN_SAMPLE = 40

# Listing a language's leaderboard asks less of the data than claiming a
# percentile does: a table of twenty-five repositories is just a table, and it
# makes no statistical claim. Keeping one threshold for both left the language
# nav showing a single entry on a corpus that could rank six.
MIN_LANGUAGE = 25

# Long enough that the page is not doing arithmetic for every visitor, short
# enough that a corpus growing by a few hundred an hour stays honest.
CACHE_SECONDS = 900

_LANGUAGE_ALIASES = {'c#': 'csharp', 'c++': 'cpp', 'f#': 'fsharp'}


def language_slug(language: str) -> str:
    """URL-safe form of a language name. 'C#' cannot live in a path."""
    key = (language or '').strip().lower()
    return _LANGUAGE_ALIASES.get(key, key).replace(' ', '-').replace('/', '-')


def language_from_slug(slug: str) -> str:
    """
    The language name behind a URL slug, or '' when nothing matches.

    Derived from what has actually been scanned rather than a hardcoded table,
    so a language the corpus picks up tomorrow works without a code change.
    """
    wanted = language_slug(slug)
    if not wanted:
        return ''
    for entry in languages(limit=200):
        if entry['slug'] == wanted:
            return entry['name']
    return ''


def _done():
    return PublicScan.objects.filter(status=Audit.STATUS_DONE, score__isnull=False)


def _histogram(language: str = '') -> tuple[list[int], int]:
    """
    (counts indexed 0..100, total). One grouped query, not a row scan — the
    result has at most 101 rows however large the corpus grows.
    """
    slug = language_slug(language)
    key = f'rankings:hist:v1:{slug}'
    cached = cache.get(key)
    if cached is not None:
        return cached

    rows = _done()
    if language:
        rows = rows.filter(primary_language__iexact=language)

    counts = [0] * 101
    total = 0
    for entry in rows.values('score').annotate(n=Count('id')):
        score = entry['score']
        if score is None or not 0 <= score <= 100:
            continue
        counts[score] += entry['n']
        total += entry['n']

    result = (counts, total)
    try:
        cache.set(key, result, CACHE_SECONDS)
    except Exception:  # a cache that is down must not take the page with it
        pass
    return result


def standing(score, language: str = '') -> dict | None:
    """
    Where a score sits in the corpus.

    Returns None when there is not enough to compare against — the page then
    says nothing rather than inventing a ranking. Falls back to the whole
    corpus when a language on its own is too thin.
    """
    if score is None:
        return None

    scope = language or ''
    counts, total = _histogram(scope)
    if total < MIN_SAMPLE and scope:
        scope = ''
        counts, total = _histogram('')
    if total < MIN_SAMPLE:
        return None

    # Strictly below, so a tie does not inflate the claim.
    better_than = sum(counts[:max(0, min(int(score), 100))])
    return {
        'percentile': round(better_than / total * 100),
        'total': total,
        'language': scope,
        'slug': language_slug(scope) if scope else '',
        'scoped': bool(scope),
    }


def corpus_size() -> int:
    key = 'rankings:size:v1'
    cached = cache.get(key)
    if cached is not None:
        return cached
    value = _done().count()
    try:
        cache.set(key, value, CACHE_SECONDS)
    except Exception:
        pass
    return value


def languages(limit: int = 24) -> list[dict]:
    """Languages with enough finished scans to rank, most-scanned first."""
    key = f'rankings:langs:v1:{limit}'
    cached = cache.get(key)
    if cached is not None:
        return cached

    rows = (_done().exclude(primary_language='')
            .values('primary_language')
            .annotate(n=Count('id'))
            .order_by('-n')[:limit])
    result = [
        {'name': r['primary_language'],
         'slug': language_slug(r['primary_language']),
         'count': r['n']}
        for r in rows if r['n'] >= MIN_LANGUAGE
    ]
    try:
        cache.set(key, result, CACHE_SECONDS)
    except Exception:
        pass
    return result


def leaderboard(language: str = '', limit: int = 25, worst: bool = False):
    """Best- (or worst-) scoring repositories, weighted to ones people know."""
    rows = _done()
    if language:
        rows = rows.filter(primary_language__iexact=language)
    order = ('score', '-stars') if worst else ('-score', '-stars')
    return list(rows.order_by(*order)[:limit])


def check_prevalence(limit: int = 14) -> list[dict]:
    """
    How often each check fails across the corpus.

    This is the launch artefact: not "your repository is missing a lockfile"
    but "one in three of the most-starred repositories on GitHub is". Keyed on
    check_id, never on the display name — names are translated per scan.
    """
    key = f'rankings:prevalence:v1:{limit}'
    cached = cache.get(key)
    if cached is not None:
        return cached

    considered, failed_by_id, name_by_id, severity_by_id = 0, {}, {}, {}
    rows = _done().exclude(results=[]).values_list('results', flat=True)
    for results in rows.iterator(chunk_size=200):
        considered += 1
        for check in results or []:
            if not _counts(check):
                continue
            check_id = check.get('check_id') or ''
            if not check_id:
                continue
            name_by_id.setdefault(check_id, check.get('name') or check_id)
            severity_by_id.setdefault(check_id, check.get('severity') or 'info')
            failed_by_id.setdefault(check_id, [0, 0])
            failed_by_id[check_id][1] += 1
            if not check.get('passed'):
                failed_by_id[check_id][0] += 1

    result = []
    for check_id, (failed, seen) in failed_by_id.items():
        if seen < MIN_SAMPLE:
            continue
        result.append({
            'check_id': check_id,
            'name': name_by_id[check_id],
            'severity': severity_by_id[check_id],
            'failed': failed,
            'seen': seen,
            'pct': round(failed / seen * 100),
        })
    result.sort(key=lambda r: -r['pct'])
    result = result[:limit]

    try:
        cache.set(key, result, CACHE_SECONDS)
    except Exception:
        pass
    return result


def summary() -> dict:
    """Headline numbers for the statistics page and the launch post."""
    key = 'rankings:summary:v1'
    cached = cache.get(key)
    if cached is not None:
        return cached

    counts, total = _histogram('')
    if not total:
        value = {'total': 0, 'median': None, 'average': None, 'bands': []}
    else:
        weighted = sum(score * n for score, n in enumerate(counts))
        seen, median = 0, 0
        for score, n in enumerate(counts):
            seen += n
            if seen >= total / 2:
                median = score
                break
        bands = [
            ('green', 80, 100), ('blue', 60, 79),
            ('amber', 40, 59), ('red', 0, 39),
        ]
        value = {
            'total': total,
            'median': median,
            'average': round(weighted / total),
            'bands': [
                {'color': color, 'low': low, 'high': high,
                 'count': sum(counts[low:high + 1]),
                 'pct': round(sum(counts[low:high + 1]) / total * 100)}
                for color, low, high in bands
            ],
        }

    try:
        cache.set(key, value, CACHE_SECONDS)
    except Exception:
        pass
    return value


def invalidate():
    """Drop every cached aggregate. Called after a batch of scans lands."""
    keys = ['rankings:size:v1', 'rankings:summary:v1']
    keys += [f'rankings:langs:v1:{n}' for n in (12, 24)]
    keys += [f'rankings:prevalence:v1:{n}' for n in (14, 20)]
    keys += ['rankings:hist:v1:']
    try:
        cache.delete_many(keys)
    except Exception:
        pass
