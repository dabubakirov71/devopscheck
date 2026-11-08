"""
Verify that what the pricing pages advertise is what a buyer would actually be
charged.

Nothing in the checkout path fails loudly: a missing Cryptomus key, a variant
priced differently from PLAN_PRICES, or a store still in test mode all end with
the customer back on /billing/ and no money taken. This command asks the
providers directly and prints the mismatches.

    python manage.py check_payments          # config only, no network
    python manage.py check_payments --live   # also query the Lemon Squeezy API
"""
import requests
from django.conf import settings
from django.core.management.base import BaseCommand

LS_API = 'https://api.lemonsqueezy.com/v1'
PERIODS = ('monthly', 'annual')


class Command(BaseCommand):
    help = 'Check that the advertised prices match what the payment providers will charge.'

    def add_arguments(self, parser):
        parser.add_argument('--live', action='store_true',
                            help='Query the Lemon Squeezy API for the real variant prices.')

    def handle(self, *args, **options):
        self.problems = []
        self._check_mode()
        self._check_crypto()
        self._check_cards(live=options['live'])

        self.stdout.write('')
        if self.problems:
            self.stdout.write(self.style.ERROR(f'{len(self.problems)} problem(s) found:'))
            for line in self.problems:
                self.stdout.write(self.style.ERROR(f'  ✗ {line}'))
        else:
            self.stdout.write(self.style.SUCCESS('Payment configuration looks consistent.'))

    # ── helpers ──────────────────────────────────────────────────────────────

    def _fail(self, line):
        self.problems.append(line)

    def _section(self, title):
        self.stdout.write('')
        self.stdout.write(self.style.MIGRATE_HEADING(title))

    # ── checks ───────────────────────────────────────────────────────────────

    def _check_mode(self):
        self._section('Mode')
        mode = settings.PAYMENT_MODE
        self.stdout.write(f'  PAYMENT_MODE = {mode!r}')
        if mode not in ('test', 'live'):
            self._fail(f"PAYMENT_MODE is {mode!r}; the only values the code understands are 'test' and 'live'.")

    def _check_crypto(self):
        self._section('Cryptomus (crypto)')
        if not settings.CRYPTOMUS_MERCHANT_ID or not settings.CRYPTOMUS_API_KEY:
            self.stdout.write('  not configured — the crypto button is hidden')
            self.stdout.write('  set CRYPTOMUS_MERCHANT_ID and CRYPTOMUS_API_KEY to enable it')
        else:
            self.stdout.write('  configured')

    def _check_cards(self, live):
        self._section('Lemon Squeezy (card)')
        if not settings.LEMONSQUEEZY_API_KEY:
            self._fail('LEMONSQUEEZY_API_KEY is empty — no card payment is possible.')
            return

        from app.views import card_variant_for

        rows = []
        for plan in settings.PLAN_PRICES:
            for period in PERIODS:
                variant = card_variant_for(plan, period)
                rows.append((plan, period, variant))
                if not variant:
                    self._fail(
                        f'{plan}/{period} has no Lemon Squeezy variant '
                        f'(set LS_VARIANT_{plan.upper()}_{period.upper()}) — '
                        f'the billing page offers "talk to us" instead of a checkout.'
                    )

        configured = {v for _, _, v in rows if v}
        if len(configured) == 1 and len([r for r in rows if r[2]]) > 1:
            self._fail(
                f'Several (plan, period) pairs resolve to the same variant {configured.pop()} — '
                f'every one of them would charge the same amount.'
            )

        if not live:
            self.stdout.write('  (run with --live to compare against the real variant prices)')
            return

        headers = {
            'Authorization': f'Bearer {settings.LEMONSQUEEZY_API_KEY}',
            'Accept': 'application/vnd.api+json',
        }
        seen = {}
        for plan, period, variant in rows:
            if not variant or variant in seen and seen[variant] != (plan, period):
                continue
            seen[variant] = (plan, period)
            try:
                resp = requests.get(f'{LS_API}/variants/{variant}', headers=headers, timeout=20)
                resp.raise_for_status()
                attrs = resp.json()['data']['attributes']
            except Exception as exc:
                self._fail(f'{plan}/{period}: variant {variant} could not be read ({exc}).')
                continue

            cents = attrs.get('price') or 0
            expected = settings.PLAN_PRICES[plan][period] * 100
            interval = attrs.get('interval')
            status = attrs.get('status')
            self.stdout.write(
                f'  {plan}/{period}: variant {variant} — '
                f'${cents / 100:.2f} per {interval}, status={status}'
            )
            if cents != expected:
                self._fail(
                    f'{plan}/{period} is advertised at ${expected / 100:.0f} but variant {variant} '
                    f'charges ${cents / 100:.2f}.'
                )
            if period == 'annual' and interval != 'year':
                self._fail(
                    f'{plan}/annual is sold as a yearly plan but variant {variant} renews per {interval}.'
                )
            if period == 'monthly' and interval != 'month':
                self._fail(
                    f'{plan}/monthly is sold monthly but variant {variant} renews per {interval}.'
                )
            if status != 'published':
                self._fail(
                    f'{plan}/{period}: variant {variant} is {status!r}, not published — '
                    f'a buyer reaching this checkout cannot complete it.'
                )

        try:
            resp = requests.get(f'{LS_API}/checkouts?filter[store_id]={settings.LEMONSQUEEZY_STORE_ID}'
                                f'&page[size]=1', headers=headers, timeout=20)
            data = resp.json().get('data') or []
            if data and data[0]['attributes'].get('test_mode'):
                self._fail('The Lemon Squeezy store is in test mode — real cards will be declined.')
        except Exception:
            pass

        # Accounts that cannot pay by card at all.
        from django.contrib.auth.models import User
        no_email = User.objects.filter(email='').count()
        if no_email:
            self.stdout.write(
                f'  {no_email} account(s) have no email address; the checkout page will ask for one.'
            )
