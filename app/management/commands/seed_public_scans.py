"""
Discover public repositories worth scanning and record them for later.

Discovery and scanning are deliberately separate. One search call returns a
hundred repositories; scanning one costs three. Queueing everything the moment
it is found would burn an hour of API budget in a minute and leave the queue
full of jobs the rate limiter will reject. So this command only *records* what
it finds, with `queued_at` unset, and `scan_pending_public_repos` drains that
backlog at a rate the budget can carry.

    manage.py seed_public_scans --languages python,go --per-language 400

GitHub's search endpoint caps any single query at 1000 results, so a language is
walked in descending star bands rather than as one query.
"""
import time

import requests
from django.conf import settings
from django.core.management.base import BaseCommand

from app.models import Audit, PublicScan

SEARCH_URL = 'https://api.github.com/search/repositories'
PER_PAGE = 100
MAX_PAGES = 10          # the endpoint refuses to page past 1000 results
SEARCH_TIMEOUT = 20

# Descending, so the best-known repositories are recorded first: they are the
# ones a reader recognises on a leaderboard and the ones worth ranking for.
STAR_BANDS = [
    (50000, None), (20000, 49999), (10000, 19999), (5000, 9999),
    (2000, 4999), (1000, 1999), (500, 999), (200, 499), (100, 199),
]

DEFAULT_LANGUAGES = [
    'Python', 'JavaScript', 'TypeScript', 'Go', 'Java', 'Rust',
    'Ruby', 'PHP', 'C#', 'C++', 'Kotlin', 'Swift', 'Shell', 'HCL',
]


class Command(BaseCommand):
    help = 'Record public repositories for the scanner to work through.'

    def add_arguments(self, parser):
        parser.add_argument('--languages', default='',
                            help='Comma-separated. Default: a spread of popular ones.')
        parser.add_argument('--per-language', type=int, default=250)
        parser.add_argument('--min-stars', type=int, default=200)
        parser.add_argument('--sleep', type=float, default=2.5,
                            help='Seconds between search calls (limit is 30/min).')
        parser.add_argument('--dry-run', action='store_true')

    def handle(self, *args, **options):
        token = getattr(settings, 'PUBLIC_SCAN_GITHUB_TOKEN', '') or ''
        if not token:
            self.stderr.write(self.style.WARNING(
                'PUBLIC_SCAN_GITHUB_TOKEN is not set. Unauthenticated search allows '
                '10 requests a minute and 60 an hour, so this will crawl. Set the '
                'token in .env before seeding for real.'))

        languages = [s.strip() for s in options['languages'].split(',') if s.strip()]
        languages = languages or DEFAULT_LANGUAGES

        session = requests.Session()
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if token:
            headers['Authorization'] = f'token {token}'
        session.headers.update(headers)

        created = skipped = 0
        for language in languages:
            found = self._seed_language(
                session, language, options['per_language'],
                options['min_stars'], options['sleep'], options['dry_run'],
            )
            created += found['created']
            skipped += found['skipped']
            self.stdout.write(
                f"  {language:<12} +{found['created']:<5} "
                f"({found['skipped']} already known)")

        self.stdout.write(self.style.SUCCESS(
            f'\nrecorded {created} new repositories, {skipped} already known'))
        if created and not options['dry_run']:
            pending = PublicScan.objects.filter(
                queued_at__isnull=True, status=Audit.STATUS_PENDING).count()
            self.stdout.write(
                f'{pending} awaiting a first scan — scan_pending_public_repos '
                'drains them on the beat schedule.')

    def _seed_language(self, session, language, target, min_stars, sleep, dry_run):
        created = skipped = 0
        for low, high in STAR_BANDS:
            if created >= target:
                break
            if low < min_stars:
                break
            band = f'>={low}' if high is None else f'{low}..{high}'
            for page in range(1, MAX_PAGES + 1):
                if created >= target:
                    break
                items = self._search(session, language, band, page, sleep)
                if items is None:
                    return {'created': created, 'skipped': skipped}
                if not items:
                    break
                for repo in items:
                    if created >= target:
                        break
                    if repo.get('private') or repo.get('archived') or repo.get('fork'):
                        continue
                    full_name = repo.get('full_name') or ''
                    if '/' not in full_name:
                        continue
                    if dry_run:
                        created += 1
                        continue
                    _row, made = PublicScan.objects.get_or_create(
                        repo_full_name=full_name,
                        defaults={
                            'repo_url': repo.get('html_url') or f'https://github.com/{full_name}',
                            'description': (repo.get('description') or '')[:500],
                            'stars': repo.get('stargazers_count') or 0,
                            'primary_language': (repo.get('language') or '')[:50],
                            'status': Audit.STATUS_PENDING,
                        },
                    )
                    created += 1 if made else 0
                    skipped += 0 if made else 1
                if len(items) < PER_PAGE:
                    break
        return {'created': created, 'skipped': skipped}

    def _search(self, session, language, band, page, sleep):
        """One page of results, or None when the API tells us to stop."""
        params = {
            'q': f'language:{language} stars:{band} archived:false',
            'sort': 'stars', 'order': 'desc',
            'per_page': PER_PAGE, 'page': page,
        }
        try:
            response = session.get(SEARCH_URL, params=params, timeout=SEARCH_TIMEOUT)
        except requests.RequestException as exc:
            self.stderr.write(self.style.ERROR(f'search failed: {exc}'))
            return None

        if response.status_code == 403:
            # Secondary rate limit. Waiting is the documented remedy; give up on
            # this language rather than hammering.
            self.stderr.write(self.style.WARNING(
                f'rate limited on {language} {band} — stopping this language'))
            return None
        if response.status_code != 200:
            self.stderr.write(self.style.WARNING(
                f'search {language} {band} page {page}: HTTP {response.status_code}'))
            return None

        time.sleep(max(0.0, sleep))
        return (response.json() or {}).get('items') or []
