"""
Accuracy evaluation of the checks (docs/accuracy/spec.md, stage 1.4).

    python manage.py eval_checks                  # synthetic fixtures (no network)
    python manage.py eval_checks --set live       # pinned real repositories (cached snapshots)
    python manage.py eval_checks --set all --write-baseline
"""
import json

from django.core.management.base import BaseCommand

from app import evaluation


class Command(BaseCommand):
    help = 'Compare the checks with known right answers and report precision of FAIL.'

    def add_arguments(self, parser):
        parser.add_argument('--set', choices=['synthetic', 'live', 'all'], default='synthetic')
        parser.add_argument('--repo', action='append', help='live set: only these repositories')
        parser.add_argument('--write-baseline', action='store_true',
                            help='save this run as eval-baseline.json (after reviewing it)')
        parser.add_argument('--json', help='also write the full result to this file')
        parser.add_argument('--fetch-list', action='store_true',
                            help='print "url<TAB>path" for live snapshots not cached yet, and exit')

    def handle(self, *args, **opts):
        if opts['fetch_list']:
            for url, path in evaluation.fetch_list():
                self.stdout.write(f'{url}\t{path}')
            return
        results = {}
        if opts['set'] in ('synthetic', 'all'):
            results['synthetic'] = evaluation.evaluate(evaluation.synthetic_cases())
        if opts['set'] in ('live', 'all'):
            results['live'] = evaluation.evaluate(evaluation.live_cases(opts.get('repo')))

        baseline = evaluation.load_baseline()
        for name, result in results.items():
            diff = evaluation.compare(result, baseline.get(name))
            self.stdout.write(evaluation.render(name, result, diff) + '\n')

        if opts.get('json'):
            with open(opts['json'], 'w', encoding='utf-8') as fh:
                json.dump(results, fh, indent=1, default=str)
        if opts['write_baseline']:
            merged = {**baseline, **evaluation.baseline_payload(results)}
            with open(evaluation.BASELINE, 'w', encoding='utf-8') as fh:
                json.dump(merged, fh, indent=1, sort_keys=True)
                fh.write('\n')
            self.stdout.write(f'Baseline written: {evaluation.BASELINE}')
