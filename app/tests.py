"""
Core integration tests. Run inside the container:
  docker compose -f docker/docker-compose.yml exec web python manage.py test app --verbosity=2
"""
import base64
import hashlib
import json
import os
import re
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock
from django.core import mail
from django.core.cache import cache
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import AnonymousUser, User
from django.utils import translation
from app.models import (
    Audit, AuditCheck, GithubProfile, GitlabProfile, UserProfile, UserSubscription,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_user(username='tester', password='testpass123', email='tester@test.com'):
    return User.objects.create_user(username=username, password=password, email=email)


# ── Auth flow ──────────────────────────────────────────────────────────────────

class RegistrationTest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_register_page_loads(self):
        r = self.client.get(reverse('register'))
        self.assertEqual(r.status_code, 200)

    def test_register_new_user(self):
        r = self.client.post(reverse('register'), {
            'username': 'newuser', 'email': '', 'password': 'pass1234', 'password2': 'pass1234'
        })
        self.assertRedirects(r, '/onboarding/', fetch_redirect_response=False)
        self.assertTrue(User.objects.filter(username='newuser').exists())

    def test_register_duplicate_username(self):
        make_user('existing')
        r = self.client.post(reverse('register'), {
            'username': 'existing', 'email': '', 'password': 'pass1234', 'password2': 'pass1234'
        })
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'already')  # error message

    def test_register_password_mismatch(self):
        r = self.client.post(reverse('register'), {
            'username': 'newuser2', 'email': '', 'password': 'pass1234', 'password2': 'different'
        })
        self.assertEqual(r.status_code, 200)

    def test_register_short_password(self):
        r = self.client.post(reverse('register'), {
            'username': 'newuser3', 'email': '', 'password': 'abc', 'password2': 'abc'
        })
        self.assertEqual(r.status_code, 200)

    def test_register_next_redirect(self):
        r = self.client.post('/register/?next=/billing/', {
            'username': 'nextuser', 'email': '', 'password': 'pass1234', 'password2': 'pass1234'
        })
        self.assertRedirects(r, '/billing/', fetch_redirect_response=False)

    def test_register_next_open_redirect_blocked(self):
        r = self.client.post('/register/?next=//evil.com/', {
            'username': 'safeuser', 'email': '', 'password': 'pass1234', 'password2': 'pass1234'
        })
        # Must NOT redirect to external site
        self.assertRedirects(r, '/onboarding/', fetch_redirect_response=False)


class LoginTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = make_user()

    def test_login_page_loads(self):
        r = self.client.get(reverse('login'))
        self.assertEqual(r.status_code, 200)

    def test_login_success(self):
        r = self.client.post(reverse('login'), {'username': 'tester', 'password': 'testpass123'})
        self.assertRedirects(r, '/profile/', fetch_redirect_response=False)

    def test_login_wrong_password(self):
        r = self.client.post(reverse('login'), {'username': 'tester', 'password': 'wrongpass'})
        self.assertEqual(r.status_code, 200)

    def test_login_next_redirect(self):
        r = self.client.post('/login/?next=/billing/', {'username': 'tester', 'password': 'testpass123'})
        self.assertRedirects(r, '/billing/', fetch_redirect_response=False)

    def test_logout(self):
        self.client.login(username='tester', password='testpass123')
        r = self.client.post(reverse('logout'))
        self.assertRedirects(r, '/', fetch_redirect_response=False)


# ── Profile / connect views ────────────────────────────────────────────────────

class ProfileTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = make_user()
        self.client.login(username='tester', password='testpass123')

    def test_profile_page_loads(self):
        r = self.client.get(reverse('connect'))
        self.assertEqual(r.status_code, 200)

    def test_profile_page_has_tabs(self):
        r = self.client.get(reverse('connect'))
        content = r.content.decode()
        self.assertIn('data-tab="connect"', content)
        self.assertIn('data-tab="security"', content)

    def test_profile_update_username(self):
        r = self.client.post(reverse('update_profile'), {'username': 'tester_new', 'email': ''})
        self.assertRedirects(r, '/profile/?settings_success=1', fetch_redirect_response=False)
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'tester_new')

    def test_profile_update_duplicate_username(self):
        make_user('occupied')
        r = self.client.post(reverse('update_profile'), {'username': 'occupied', 'email': ''})
        self.assertIn('settings_error=username_taken', r['Location'])

    def test_change_password_success(self):
        r = self.client.post(reverse('change_password'), {
            'current_password': 'testpass123',
            'new_password': 'newpass456',
            'confirm_password': 'newpass456',
        })
        self.assertRedirects(r, '/profile/?pwd_success=1', fetch_redirect_response=False)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpass456'))

    def test_change_password_wrong_current(self):
        r = self.client.post(reverse('change_password'), {
            'current_password': 'wrongpass',
            'new_password': 'newpass456',
            'confirm_password': 'newpass456',
        })
        self.assertIn('pwd_error=wrong', r['Location'])

    def test_change_password_mismatch(self):
        r = self.client.post(reverse('change_password'), {
            'current_password': 'testpass123',
            'new_password': 'newpass456',
            'confirm_password': 'different',
        })
        self.assertIn('pwd_error=mismatch', r['Location'])

    def test_unauthenticated_redirect(self):
        self.client.logout()
        r = self.client.get(reverse('connect'))
        self.assertEqual(r.status_code, 302)
        self.assertIn('login', r['Location'])


# ── Landing page ───────────────────────────────────────────────────────────────

class LandingTest(TestCase):
    def test_landing_loads(self):
        r = self.client.get('/')
        self.assertEqual(r.status_code, 200)

    def test_landing_redirects_logged_in(self):
        user = make_user('landingtester')
        self.client.login(username='landingtester', password='testpass123')
        r = self.client.get('/')
        self.assertRedirects(r, '/profile/', fetch_redirect_response=False)


# ── Billing ────────────────────────────────────────────────────────────────────

@override_settings(PAYMENTS_LIVE=True)
class BillingTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = make_user('billtester')
        self.client.login(username='billtester', password='testpass123')

    def test_billing_page_loads(self):
        r = self.client.get(reverse('billing'))
        self.assertEqual(r.status_code, 200)

    def test_billing_shows_free_plan(self):
        r = self.client.get(reverse('billing'))
        self.assertContains(r, 'Free')

    @patch('app.views.requests.post')
    @patch('django.conf.settings.CRYPTOMUS_MERCHANT_ID', 'test-merchant-id')
    @patch('django.conf.settings.CRYPTOMUS_API_KEY', 'test-api-key')
    def test_create_crypto_checkout_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {'result': {'url': 'https://pay.cryptomus.com/pay/test-invoice'}}
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        r = self.client.post(reverse('crypto_checkout'))
        self.assertRedirects(r, 'https://pay.cryptomus.com/pay/test-invoice',
                             fetch_redirect_response=False)

    @patch('django.conf.settings.CRYPTOMUS_MERCHANT_ID', 'test-merchant-id')
    @patch('django.conf.settings.CRYPTOMUS_API_KEY', 'test-api-key')
    def test_create_crypto_checkout_already_pro(self):
        sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        sub.plan = UserSubscription.PLAN_PRO
        from django.utils import timezone
        sub.current_period_end = timezone.now() + timezone.timedelta(days=30)
        sub.save()

        r = self.client.post(reverse('crypto_checkout'))
        self.assertRedirects(r, '/billing/', fetch_redirect_response=False)

    def test_payment_success_page(self):
        r = self.client.get(reverse('payment_success'))
        self.assertEqual(r.status_code, 200)

    def test_payment_cancel_page(self):
        r = self.client.get(reverse('payment_cancel'))
        self.assertEqual(r.status_code, 200)


# ── GitHub PAT connect ─────────────────────────────────────────────────────────

class ConnectTokenTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = make_user('tokentest')
        self.client.login(username='tokentest', password='testpass123')

    @patch('requests.get')
    def test_connect_github_pat_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'id': 12345, 'login': 'ghuser', 'avatar_url': 'https://example.com/avatar.png'
        }
        mock_get.return_value = mock_resp

        r = self.client.post(reverse('connect_token'), {
            'provider': 'github', 'token': 'ghp_testtoken12345'
        })
        self.assertRedirects(r, '/dashboard/', fetch_redirect_response=False)
        self.assertTrue(GithubProfile.objects.filter(user=self.user).exists())

    @patch('requests.get')
    def test_connect_github_pat_invalid_token(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        r = self.client.post(reverse('connect_token'), {
            'provider': 'github', 'token': 'bad_token'
        })
        self.assertEqual(r.status_code, 200)
        self.assertFalse(GithubProfile.objects.filter(user=self.user).exists())

    @patch('requests.get')
    def test_connect_github_no_duplicate_on_relink(self, mock_get):
        """Second user can steal a github_id (re-link) from first user."""
        user2 = make_user('tokentest2')
        GithubProfile.objects.create(
            user=user2, github_id=99999, github_login='ghrelink',
            access_token='old_token', avatar_url='',
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'id': 99999, 'login': 'ghrelink', 'avatar_url': ''}
        mock_get.return_value = mock_resp

        # Should NOT raise IntegrityError
        r = self.client.post(reverse('connect_token'), {
            'provider': 'github', 'token': 'ghp_newtoken'
        })
        self.assertRedirects(r, '/dashboard/', fetch_redirect_response=False)
        # Now only current user has this profile
        self.assertFalse(GithubProfile.objects.filter(user=user2).exists())
        self.assertTrue(GithubProfile.objects.filter(user=self.user, github_id=99999).exists())

    def test_connect_token_empty(self):
        r = self.client.post(reverse('connect_token'), {'provider': 'github', 'token': ''})
        self.assertEqual(r.status_code, 200)


# ── Audit model ────────────────────────────────────────────────────────────────

class AuditModelTest(TestCase):
    def setUp(self):
        self.user = make_user('audittester')
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo',
            repo_url='https://github.com/org/repo', source='github',
        )

    def test_score_label_none(self):
        self.audit.score = None
        self.assertIn('N/A', self.audit.score_label)

    def test_score_label_excellent(self):
        self.audit.score = 85
        self.assertEqual(self.audit.score_color, 'green')

    def test_score_label_poor(self):
        self.audit.score = 20
        self.assertEqual(self.audit.score_color, 'red')

    def test_audit_detail_requires_login(self):
        c = Client()
        r = c.get(reverse('audit_detail', args=[self.audit.id]))
        self.assertEqual(r.status_code, 302)

    def test_audit_detail_loads_for_owner(self):
        c = Client()
        c.login(username='audittester', password='testpass123')
        r = c.get(reverse('audit_detail', args=[self.audit.id]))
        self.assertEqual(r.status_code, 200)

    def test_audit_detail_denied_for_other_user(self):
        make_user('otheraudi')
        c = Client()
        c.login(username='otheraudi', password='testpass123')
        r = c.get(reverse('audit_detail', args=[self.audit.id]))
        self.assertEqual(r.status_code, 404)

    def test_audit_detail_renders_full_run_history(self):
        """
        Every run is its own Audit row, so the report must show the whole series.

        The old model reused one row per repository, which capped the history at
        a single point and made the trend impossible to draw.
        """
        self.audit.status = Audit.STATUS_DONE
        self.audit.score = 70
        self.audit.save()
        Audit.objects.create(
            user=self.user, repo_full_name='org/repo',
            repo_url='https://github.com/org/repo', source='github',
            status=Audit.STATUS_DONE, score=55,
        )
        c = Client()
        c.login(username='audittester', password='testpass123')
        r = c.get(reverse('audit_detail', args=[self.audit.id]))
        self.assertEqual(r.status_code, 200)
        content = r.content.decode()
        # A Python repr of a datetime must never reach the page.
        self.assertNotIn('datetime.datetime(', content)
        self.assertEqual(r.context['history_count'], 2)
        self.assertIsNotNone(r.context['spark'])
        self.assertEqual(r.context['spark']['count'], 2)


# ── UserSubscription model ─────────────────────────────────────────────────────

class SubscriptionTest(TestCase):
    def setUp(self):
        self.user = make_user('subtester')

    def test_free_plan_is_not_pro(self):
        sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        self.assertFalse(sub.is_pro)

    def test_pro_plan_is_pro(self):
        from django.utils import timezone
        sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        sub.plan = UserSubscription.PLAN_PRO
        sub.current_period_end = timezone.now() + timezone.timedelta(days=30)
        sub.save()
        self.assertTrue(sub.is_pro)

    def test_expired_pro_is_not_pro(self):
        from django.utils import timezone
        sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        sub.plan = UserSubscription.PLAN_PRO
        sub.current_period_end = timezone.now() - timezone.timedelta(days=1)
        sub.save()
        self.assertFalse(sub.is_pro)


# ── Score calculation ──────────────────────────────────────────────────────────

class ScoreCalculationTest(TestCase):
    def test_calculate_score_all_passed(self):
        from app.checks import calculate_score
        checks = [
            {'severity': 'crit', 'passed': True},
            {'severity': 'warn', 'passed': True},
            {'severity': 'info', 'passed': True},
        ]
        self.assertEqual(calculate_score(checks), 100)

    def test_calculate_score_none_passed(self):
        from app.checks import calculate_score
        checks = [
            {'severity': 'crit', 'passed': False},
            {'severity': 'warn', 'passed': False},
        ]
        self.assertEqual(calculate_score(checks), 0)

    def test_calculate_score_partial(self):
        from app.checks import calculate_score
        checks = [
            {'severity': 'crit', 'passed': True},   # weight 30
            {'severity': 'crit', 'passed': False},  # weight 30
        ]
        self.assertEqual(calculate_score(checks), 50)

    def test_get_category_scores(self):
        from app.checks import get_category_scores
        checks = [
            {'severity': 'crit', 'passed': True,  'category': 'security'},
            {'severity': 'crit', 'passed': False, 'category': 'ci_cd'},
        ]
        scores = get_category_scores(checks)
        self.assertEqual(scores['security'], 100)
        self.assertEqual(scores['ci_cd'], 0)


# ── Health check ───────────────────────────────────────────────────────────────

class HealthCheckTest(TestCase):
    def test_health_endpoint(self):
        r = self.client.get('/health/')
        self.assertEqual(r.status_code, 200)
        self.assertIn('ok', r.json().get('status', ''))


# ── Cryptomus webhook ──────────────────────────────────────────────────────────

def _cryptomus_sign(payload: dict, api_key: str) -> str:
    """Compute the Cryptomus IPN signature for a given payload dict."""
    body = json.dumps(payload)
    return hashlib.md5(
        (base64.b64encode(body.encode()).decode() + api_key).encode()
    ).hexdigest()


class CryptomusWebhookTest(TestCase):
    TEST_API_KEY = 'test-api-key-abc123'
    WEBHOOK_URL = '/billing/webhooks/crypto/'

    def setUp(self):
        self.user = make_user('cryptotester')

    def _post(self, payload):
        return self.client.post(
            self.WEBHOOK_URL,
            data=json.dumps(payload),
            content_type='application/json',
        )

    def _signed_payload(self, status, order_id=None):
        payload = {
            'status': status,
            'order_id': str(order_id or self.user.id),
        }
        payload['sign'] = None
        sign = _cryptomus_sign(payload, self.TEST_API_KEY)
        payload['sign'] = sign
        return payload

    @patch('django.conf.settings.CRYPTOMUS_API_KEY', TEST_API_KEY)
    def test_paid_status_activates_pro(self):
        self._post(self._signed_payload('paid'))
        sub = UserSubscription.objects.get(user=self.user)
        self.assertEqual(sub.plan, UserSubscription.PLAN_PRO)
        self.assertIsNotNone(sub.current_period_end)

    @patch('django.conf.settings.CRYPTOMUS_API_KEY', TEST_API_KEY)
    def test_paid_over_status_activates_pro(self):
        self._post(self._signed_payload('paid_over'))
        sub = UserSubscription.objects.get(user=self.user)
        self.assertEqual(sub.plan, UserSubscription.PLAN_PRO)

    @patch('django.conf.settings.CRYPTOMUS_API_KEY', TEST_API_KEY)
    def test_invalid_signature_returns_400(self):
        payload = self._signed_payload('paid')
        payload['sign'] = 'deadbeefdeadbeef'
        r = self._post(payload)
        self.assertEqual(r.status_code, 400)
        self.assertFalse(UserSubscription.objects.filter(user=self.user).exists())

    @patch('django.conf.settings.CRYPTOMUS_API_KEY', TEST_API_KEY)
    def test_wrong_status_does_not_activate_pro(self):
        self._post(self._signed_payload('cancel'))
        self.assertFalse(UserSubscription.objects.filter(user=self.user).exists())

    @patch('django.conf.settings.CRYPTOMUS_API_KEY', TEST_API_KEY)
    def test_wrong_status_fail_does_not_activate_pro(self):
        self._post(self._signed_payload('fail'))
        self.assertFalse(UserSubscription.objects.filter(user=self.user).exists())

    @patch('django.conf.settings.CRYPTOMUS_API_KEY', TEST_API_KEY)
    def test_idempotent_second_ipn_keeps_pro(self):
        self._post(self._signed_payload('paid'))
        self._post(self._signed_payload('paid'))
        sub = UserSubscription.objects.get(user=self.user)
        self.assertEqual(sub.plan, UserSubscription.PLAN_PRO)

    @patch('django.conf.settings.CRYPTOMUS_API_KEY', TEST_API_KEY)
    def test_unknown_user_id_ignored(self):
        payload = self._signed_payload('paid', order_id=99999)
        r = self._post(payload)
        self.assertEqual(r.status_code, 200)

    def test_malformed_json_returns_400(self):
        r = self.client.post(self.WEBHOOK_URL, data='not-json', content_type='application/json')
        self.assertEqual(r.status_code, 400)


# ── checks_extra: CVE scanning ────────────────────────────────────────────────

class CVECheckTest(TestCase):
    """Tests for check_cve_vulnerabilities() using OSV.dev API."""

    def _get_content(self, content_map):
        return lambda path: content_map.get(path)

    @patch('app.checks_extra.requests.post')
    def test_no_dependency_files_returns_empty(self, _mock_post):
        from app.checks_extra import check_cve_vulnerabilities
        result = check_cve_vulnerabilities(self._get_content({}))
        self.assertEqual(result, [])

    @patch('app.checks_extra.requests.post')
    def test_clean_requirements_passes(self, mock_post):
        from app.checks_extra import check_cve_vulnerabilities
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'results': [{'vulns': []}]}
        mock_post.return_value = mock_resp

        content = {'requirements.txt': 'requests==2.31.0\n'}
        result = check_cve_vulnerabilities(self._get_content(content))
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]['passed'])
        self.assertEqual(result[0]['category'], 'deps')

    @patch('app.checks_extra.requests.post')
    def test_vulnerable_package_fails(self, mock_post):
        from app.checks_extra import check_cve_vulnerabilities
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'results': [{
                'vulns': [{'id': 'GHSA-xxxx', 'summary': 'RCE in requests', 'severity': []}]
            }]
        }
        mock_post.return_value = mock_resp

        content = {'requirements.txt': 'requests==2.25.0\n'}
        result = check_cve_vulnerabilities(self._get_content(content))
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]['passed'])
        self.assertIn('requests', result[0]['recommendation'])

    @patch('app.checks_extra.requests.post')
    def test_critical_cve_sets_crit_severity(self, mock_post):
        from app.checks_extra import check_cve_vulnerabilities
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'results': [{
                'vulns': [{
                    'id': 'GHSA-crit',
                    'summary': 'Critical RCE',
                    'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/CRITICAL'}],
                }]
            }]
        }
        mock_post.return_value = mock_resp

        content = {'requirements.txt': 'vuln-lib==1.0.0\n'}
        result = check_cve_vulnerabilities(self._get_content(content))
        self.assertEqual(result[0]['severity'], 'crit')
        self.assertFalse(result[0]['passed'])

    @patch('app.checks_extra.requests.post')
    def test_osv_timeout_does_not_crash(self, mock_post):
        from app.checks_extra import check_cve_vulnerabilities
        import requests as req_lib
        mock_post.side_effect = req_lib.exceptions.Timeout

        content = {'requirements.txt': 'django==4.2.0\n'}
        # Should not raise; returns empty (no scanned results from this ecosystem)
        result = check_cve_vulnerabilities(self._get_content(content))
        # scanned=1 but no results means no vulns found → passed check returned
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]['passed'])

    @patch('app.checks_extra.requests.post')
    def test_package_json_parsed_and_queried(self, mock_post):
        from app.checks_extra import check_cve_vulnerabilities
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'results': [{'vulns': []}]}
        mock_post.return_value = mock_resp

        content = {'package.json': json.dumps({
            'dependencies': {'express': '4.18.2', 'lodash': '4.17.21'}
        })}
        result = check_cve_vulnerabilities(self._get_content(content))
        self.assertEqual(len(result), 1)
        call_body = mock_post.call_args[1]['json']
        ecosystems = {q['package']['ecosystem'] for q in call_body['queries']}
        self.assertIn('npm', ecosystems)


# ── checks_extra: GitHub Actions security ─────────────────────────────────────

class GitHubActionsSecurityTest(TestCase):

    def _make_fns(self, files: dict, dirs: dict):
        return (
            lambda path: files.get(path),
            lambda path: dirs.get(path, []),
        )

    def test_no_workflows_returns_empty(self):
        from app.checks_extra import check_github_actions_security
        get_fn, list_fn = self._make_fns({}, {})
        result = check_github_actions_security(get_fn, list_fn)
        self.assertEqual(result, [])

    def test_pinned_sha_passes(self):
        from app.checks_extra import check_github_actions_security
        wf = 'on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n'
        get_fn, list_fn = self._make_fns(
            {'.github/workflows/ci.yml': wf},
            {'.github/workflows': ['ci.yml']},
        )
        result = check_github_actions_security(get_fn, list_fn)
        pinned_check = next(r for r in result if r['check_id'] == 'actions.pinned_sha')
        self.assertTrue(pinned_check['passed'])

    def test_floating_tag_fails(self):
        from app.checks_extra import check_github_actions_security
        wf = 'on: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n'
        get_fn, list_fn = self._make_fns(
            {'.github/workflows/ci.yml': wf},
            {'.github/workflows': ['ci.yml']},
        )
        result = check_github_actions_security(get_fn, list_fn)
        pinned_check = next(r for r in result if r['check_id'] == 'actions.pinned_sha')
        self.assertFalse(pinned_check['passed'])
        self.assertIn('actions/checkout@v4', pinned_check['description'])

    def test_dangerous_pull_request_target_detected(self):
        from app.checks_extra import check_github_actions_security
        wf = (
            'on:\n  pull_request_target:\n'
            'jobs:\n  build:\n    steps:\n'
            '      - uses: actions/checkout@v4\n'
            '        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n'
        )
        get_fn, list_fn = self._make_fns(
            {'.github/workflows/ci.yml': wf},
            {'.github/workflows': ['ci.yml']},
        )
        result = check_github_actions_security(get_fn, list_fn)
        prt_check = next((r for r in result if r['check_id'] == 'actions.pull_request_target'), None)
        self.assertIsNotNone(prt_check)
        self.assertFalse(prt_check['passed'])
        self.assertEqual(prt_check['severity'], 'crit')

    def test_write_all_permissions_detected(self):
        from app.checks_extra import check_github_actions_security
        wf = 'on: push\npermissions: write-all\njobs:\n  build:\n    steps: []\n'
        get_fn, list_fn = self._make_fns(
            {'.github/workflows/ci.yml': wf},
            {'.github/workflows': ['ci.yml']},
        )
        result = check_github_actions_security(get_fn, list_fn)
        perm_check = next((r for r in result if r['check_id'] == 'actions.broad_permissions'), None)
        self.assertIsNotNone(perm_check)
        self.assertFalse(perm_check['passed'])

    def test_local_action_not_flagged(self):
        from app.checks_extra import check_github_actions_security
        wf = 'on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/my-action\n'
        get_fn, list_fn = self._make_fns(
            {'.github/workflows/ci.yml': wf},
            {'.github/workflows': ['ci.yml']},
        )
        result = check_github_actions_security(get_fn, list_fn)
        pinned_check = next(r for r in result if r['check_id'] == 'actions.pinned_sha')
        self.assertTrue(pinned_check['passed'])


# ── checks_extra: Kubernetes ──────────────────────────────────────────────────

class KubernetesCheckTest(TestCase):

    def _make_fns(self, files: dict, dirs: dict):
        return (
            lambda path: files.get(path),
            lambda path: dirs.get(path, []),
        )

    def test_no_k8s_manifests_returns_empty(self):
        from app.checks_extra import check_kubernetes_security
        get_fn, list_fn = self._make_fns({}, {})
        result = check_kubernetes_security(get_fn, list_fn)
        self.assertEqual(result, [])

    def test_deployment_with_all_good_passes(self):
        from app.checks_extra import check_kubernetes_security
        manifest = (
            'kind: Deployment\n'
            'spec:\n'
            '  template:\n'
            '    spec:\n'
            '      securityContext:\n'
            '        runAsNonRoot: true\n'
            '      containers:\n'
            '        - name: app\n'
            '          resources:\n'
            '            requests:\n'
            '              memory: 128Mi\n'
            '            limits:\n'
            '              memory: 256Mi\n'
            '          readinessProbe:\n'
            '            httpGet:\n'
            '              path: /health\n'
            '          livenessProbe:\n'
            '            httpGet:\n'
            '              path: /health\n'
        )
        get_fn, list_fn = self._make_fns(
            {'k8s/deployment.yaml': manifest},
            {'k8s': ['deployment.yaml']},
        )
        result = check_kubernetes_security(get_fn, list_fn)
        self.assertTrue(all(r['passed'] for r in result))

    def test_missing_resource_limits_fails(self):
        from app.checks_extra import check_kubernetes_security
        manifest = 'kind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n'
        get_fn, list_fn = self._make_fns(
            {'k8s/deployment.yaml': manifest},
            {'k8s': ['deployment.yaml']},
        )
        result = check_kubernetes_security(get_fn, list_fn)
        limits_check = next(r for r in result if r['check_id'] == 'k8s.resource_limits')
        self.assertFalse(limits_check['passed'])

    def test_privileged_true_is_crit(self):
        from app.checks_extra import check_kubernetes_security
        manifest = (
            'kind: Deployment\n'
            'spec:\n  template:\n    spec:\n      containers:\n'
            '        - securityContext:\n            privileged: true\n'
        )
        get_fn, list_fn = self._make_fns(
            {'k8s/deployment.yaml': manifest},
            {'k8s': ['deployment.yaml']},
        )
        result = check_kubernetes_security(get_fn, list_fn)
        root_check = next(r for r in result if r['check_id'] == 'k8s.nonroot')
        self.assertFalse(root_check['passed'])
        self.assertEqual(root_check['severity'], 'crit')

    def test_missing_probes_fails(self):
        from app.checks_extra import check_kubernetes_security
        manifest = (
            'kind: Deployment\n'
            'spec:\n  template:\n    spec:\n'
            '      securityContext:\n        runAsNonRoot: true\n'
            '      containers:\n        - name: app\n'
            '          resources:\n            limits:\n              memory: 256Mi\n'
        )
        get_fn, list_fn = self._make_fns(
            {'k8s/deployment.yaml': manifest},
            {'k8s': ['deployment.yaml']},
        )
        result = check_kubernetes_security(get_fn, list_fn)
        probe_check = next(r for r in result if r['check_id'] == 'k8s.probes')
        self.assertFalse(probe_check['passed'])


# ── checks_extra: Observability ───────────────────────────────────────────────

class ObservabilityCheckTest(TestCase):

    def _get_content(self, content_map):
        return lambda path: content_map.get(path)

    def test_sentry_detected_passes(self):
        from app.checks_extra import check_observability
        result = check_observability(self._get_content({
            'requirements.txt': 'django==4.2\nsentry-sdk==2.0.0\n'
        }))
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]['passed'])
        self.assertIn('Sentry', result[0]['description'])

    def test_no_monitoring_fails(self):
        from app.checks_extra import check_observability
        result = check_observability(self._get_content({
            'requirements.txt': 'django==4.2\nrequests==2.31\n'
        }))
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]['passed'])

    def test_prometheus_client_detected(self):
        from app.checks_extra import check_observability
        result = check_observability(self._get_content({
            'requirements.txt': 'prometheus-client==0.19.0\n'
        }))
        self.assertTrue(result[0]['passed'])
        self.assertIn('Prometheus', result[0]['description'])

    def test_no_dependency_files_fails_gracefully(self):
        from app.checks_extra import check_observability
        result = check_observability(self._get_content({}))
        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]['passed'])


# ── checks_extra: dependency parsers ─────────────────────────────────────────

class DependencyParserTest(TestCase):

    def test_parse_requirements_txt_pinned(self):
        from app.checks_extra import _parse_requirements_txt
        content = 'django==4.2.16\nrequests==2.31.0\n# comment\n-r base.txt\n'
        pkgs = _parse_requirements_txt(content)
        self.assertEqual(pkgs, [('django', '4.2.16'), ('requests', '2.31.0')])

    def test_parse_requirements_txt_tilde(self):
        from app.checks_extra import _parse_requirements_txt
        pkgs = _parse_requirements_txt('celery~=5.4.0\n')
        self.assertEqual(pkgs, [('celery', '5.4.0')])

    def test_parse_requirements_txt_unpinned_skipped(self):
        from app.checks_extra import _parse_requirements_txt
        pkgs = _parse_requirements_txt('django>=4.0\n')
        self.assertEqual(pkgs, [])

    def test_parse_package_json(self):
        from app.checks_extra import _parse_package_json
        content = json.dumps({'dependencies': {'express': '^4.18.2'}, 'devDependencies': {'jest': '29.0.0'}})
        pkgs = _parse_package_json(content)
        self.assertIn(('express', '4.18.2'), pkgs)
        self.assertIn(('jest', '29.0.0'), pkgs)

    def test_parse_go_mod(self):
        from app.checks_extra import _parse_go_mod
        content = 'module example.com/app\ngo 1.21\nrequire (\n  github.com/gin-gonic/gin v1.9.1\n)\n'
        pkgs = _parse_go_mod(content)
        self.assertIn(('github.com/gin-gonic/gin', '1.9.1'), pkgs)

    def test_parse_cargo_toml(self):
        from app.checks_extra import _parse_cargo_toml
        content = '[dependencies]\nserde = "1.0.193"\ntokio = { version = "1.35.0", features = ["full"] }\n'
        pkgs = _parse_cargo_toml(content)
        self.assertIn(('serde', '1.0.193'), pkgs)
        self.assertIn(('tokio', '1.35.0'), pkgs)


# ── One-click Fix: view ───────────────────────────────────────────────────────

class FixGenerateViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = make_user('fixtester')
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo',
            repo_url='https://github.com/org/repo', source='github',
        )
        self.check = AuditCheck.objects.create(
            audit=self.audit, name='CODEOWNERS настроен',
            description='test', severity='warn', passed=False,
            recommendation='fix it', category='security',
        )

    def _url(self, audit_id, check_id):
        return reverse('fix_generate', args=[audit_id, check_id])

    def test_fix_requires_login(self):
        r = self.client.get(self._url(self.audit.id, self.check.id))
        self.assertEqual(r.status_code, 302)
        self.assertIn('/login', r['Location'])

    def test_fix_404_wrong_user(self):
        other = make_user('fixother')
        self.client.login(username='fixother', password='testpass123')
        r = self.client.get(self._url(self.audit.id, self.check.id))
        self.assertEqual(r.status_code, 404)

    def test_fix_no_template(self):
        unknown_check = AuditCheck.objects.create(
            audit=self.audit, name='Нет такой проверки',
            description='test', severity='info', passed=False,
            recommendation='', category='security',
        )
        self.client.login(username='fixtester', password='testpass123')
        r = self.client.get(self._url(self.audit.id, unknown_check.id))
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertFalse(data['ok'])
        self.assertEqual(data['error'], 'no_template')

    def test_fix_returns_template_for_free_user(self):
        self.client.login(username='fixtester', password='testpass123')
        r = self.client.get(self._url(self.audit.id, self.check.id))
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['ok'])
        self.assertEqual(data['filename'], '.github/CODEOWNERS')
        self.assertTrue(data['content'])
        self.assertFalse(data['is_ai'])

    def test_fix_template_dependabot(self):
        check = AuditCheck.objects.create(
            audit=self.audit, name='Автообновление зависимостей',
            description='test', severity='warn', passed=False,
            recommendation='fix it', category='security',
        )
        self.client.login(username='fixtester', password='testpass123')
        r = self.client.get(self._url(self.audit.id, check.id))
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['ok'])
        self.assertEqual(data['filename'], '.github/dependabot.yml')

    def test_fix_template_security_md(self):
        check = AuditCheck.objects.create(
            audit=self.audit, name='Security policy (SECURITY.md)',
            description='test', severity='warn', passed=False,
            recommendation='fix it', category='security',
        )
        self.client.login(username='fixtester', password='testpass123')
        r = self.client.get(self._url(self.audit.id, check.id))
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['ok'])
        self.assertEqual(data['filename'], 'SECURITY.md')


# ── One-click Fix: fix_templates module ──────────────────────────────────────

class FixTemplatesTest(TestCase):

    def test_get_fix_codeowners(self):
        from app.fix_templates import get_fix
        result = get_fix('CODEOWNERS настроен', 'generic', 'org/repo')
        self.assertIsNotNone(result)
        filename, content = result
        self.assertEqual(filename, '.github/CODEOWNERS')
        self.assertTrue(content)

    def test_get_fix_unknown_check(self):
        from app.fix_templates import get_fix
        result = get_fix('Нет такой проверки', 'generic', 'org/repo')
        self.assertIsNone(result)

    def test_is_fixable_known(self):
        from app.fix_templates import is_fixable
        self.assertTrue(is_fixable('CODEOWNERS настроен'))

    def test_is_fixable_unknown(self):
        from app.fix_templates import is_fixable
        self.assertFalse(is_fixable('Нет'))


# ══════════════════════════════════════════════════════════════════════════════
# Encryption at rest
# ══════════════════════════════════════════════════════════════════════════════

class TokenEncryptionTest(TestCase):
    """Provider tokens must never sit in the database as plain text."""

    def setUp(self):
        self.user = make_user('cryptouser')

    def test_round_trip(self):
        from app.crypto_utils import encrypt, decrypt
        self.assertEqual(decrypt(encrypt('ghp_secret_value_123')), 'ghp_secret_value_123')

    def test_ciphertext_is_not_the_plaintext(self):
        from app.crypto_utils import encrypt, is_encrypted
        blob = encrypt('ghp_secret_value_123')
        self.assertTrue(is_encrypted(blob))
        self.assertNotIn('ghp_secret_value_123', blob)

    def test_stored_column_is_ciphertext(self):
        from django.db import connection
        GithubProfile.objects.create(
            user=self.user, github_id=99, github_login='octo',
            access_token='ghp_super_secret_token',
        )
        with connection.cursor() as cur:
            cur.execute('SELECT access_token FROM app_githubprofile WHERE github_id = 99')
            raw = cur.fetchone()[0]
        self.assertNotIn('ghp_super_secret_token', raw)
        self.assertTrue(raw.startswith('enc:v1:'))

    def test_model_read_returns_plaintext(self):
        GithubProfile.objects.create(
            user=self.user, github_id=98, github_login='octo',
            access_token='ghp_super_secret_token',
        )
        profile = GithubProfile.objects.get(github_id=98)
        self.assertEqual(profile.access_token, 'ghp_super_secret_token')

    def test_legacy_plaintext_row_still_reads(self):
        """Rows written before encryption existed must keep working."""
        from django.db import connection
        GithubProfile.objects.create(
            user=self.user, github_id=97, github_login='octo', access_token='x',
        )
        with connection.cursor() as cur:
            cur.execute(
                "UPDATE app_githubprofile SET access_token = 'legacy_plain_token' WHERE github_id = 97"
            )
        self.assertEqual(GithubProfile.objects.get(github_id=97).access_token, 'legacy_plain_token')

    def test_empty_token_stays_empty(self):
        from app.crypto_utils import encrypt, decrypt
        self.assertEqual(encrypt(''), '')
        self.assertEqual(decrypt(''), '')


# ══════════════════════════════════════════════════════════════════════════════
# Audits are append-only, so the score history is real
# ══════════════════════════════════════════════════════════════════════════════

class AuditHistoryTest(TestCase):
    def setUp(self):
        self.user = make_user('historyuser')
        GithubProfile.objects.create(
            user=self.user, github_id=1, github_login='octo', access_token='tok',
        )
        self.client = Client()
        self.client.login(username='historyuser', password='testpass123')

    @patch('app.tasks.run_audit_task.delay')
    def test_each_run_creates_a_new_record(self, mock_delay):
        mock_delay.return_value = MagicMock(id='task-1')
        for _ in range(3):
            self.client.post(reverse('start_audit'), {
                'repo': 'org/repo', 'repo_url': 'https://github.com/org/repo',
            })
        self.assertEqual(Audit.objects.filter(repo_full_name='org/repo').count(), 3)

    @patch('app.tasks.run_audit_task.delay')
    def test_repeat_runs_do_not_consume_the_free_repo_limit(self, mock_delay):
        mock_delay.return_value = MagicMock(id='task-1')
        for _ in range(5):
            self.client.post(reverse('start_audit'), {'repo': 'org/repo'})
        r = self.client.post(reverse('start_audit'), {'repo': 'org/other'})
        self.assertEqual(r.status_code, 302)
        self.assertNotIn('/billing/', r.url)

    @patch('app.tasks.run_audit_task.delay')
    def test_free_limit_still_caps_distinct_repositories(self, mock_delay):
        mock_delay.return_value = MagicMock(id='task-1')
        for i in range(3):
            self.client.post(reverse('start_audit'), {'repo': f'org/repo{i}'})
        r = self.client.post(reverse('start_audit'), {'repo': 'org/fourth'})
        self.assertEqual(r.status_code, 302)
        self.assertIn('/billing/', r.url)

    def test_history_endpoint_returns_every_completed_run(self):
        for score in (40, 55, 70):
            Audit.objects.create(
                user=self.user, repo_full_name='org/repo',
                repo_url='https://github.com/org/repo', source='github',
                status=Audit.STATUS_DONE, score=score,
            )
        newest = Audit.objects.filter(repo_full_name='org/repo').first()
        r = self.client.get(reverse('audit_history', args=[newest.id]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()['history']), 3)

    def test_score_delta_compares_against_the_previous_run(self):
        first = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u',
            source='github', status=Audit.STATUS_DONE, score=40,
        )
        second = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u',
            source='github', status=Audit.STATUS_DONE, score=62,
        )
        self.assertIsNone(first.score_delta)
        self.assertEqual(second.score_delta, 22)

    def test_latest_per_repo_picks_the_newest_run(self):
        Audit.objects.create(user=self.user, repo_full_name='org/a', repo_url='u',
                             source='github', status=Audit.STATUS_DONE, score=10)
        newest = Audit.objects.create(user=self.user, repo_full_name='org/a', repo_url='u',
                                      source='github', status=Audit.STATUS_DONE, score=90)
        Audit.objects.create(user=self.user, repo_full_name='org/b', repo_url='u',
                             source='github', status=Audit.STATUS_DONE, score=50)
        latest = Audit.objects.filter(user=self.user).latest_per_repo()
        self.assertEqual(len(latest), 2)
        self.assertIn(newest.id, [a.id for a in latest])
        self.assertEqual(next(a.score for a in latest if a.repo_full_name == 'org/a'), 90)


# ══════════════════════════════════════════════════════════════════════════════
# Repository client: one tree fetch instead of a request per candidate path
# ══════════════════════════════════════════════════════════════════════════════

class RepoClientTest(TestCase):
    def _client(self, files=None):
        from app.repo_client import StaticRepoClient
        return StaticRepoClient(files or {
            'README.md': '# Demo\n\n## Installation\n\npip install demo\n' + 'x' * 600,
            'requirements.txt': 'django==4.2.16\n',
            'Dockerfile': 'FROM python:3.11-slim\nUSER app\n',
            'src/app/main.py': 'print("hi")',
            '.github/workflows/ci.yml': 'jobs:\n  test:\n    steps:\n      - run: pytest\n',
        })

    def test_exists_is_a_tree_lookup(self):
        c = self._client()
        self.assertTrue(c.exists('README.md'))
        self.assertFalse(c.exists('LICENSE'))

    def test_any_exists_returns_the_first_hit(self):
        c = self._client()
        self.assertEqual(c.any_exists(['LICENSE', 'README.md', 'Dockerfile']), 'README.md')
        self.assertIsNone(c.any_exists(['LICENSE', 'CHANGELOG.md']))

    def test_list_dir_returns_direct_children_only(self):
        c = self._client()
        self.assertEqual(c.list_dir('.github/workflows'), ['ci.yml'])
        self.assertEqual(c.list_dir('src'), [])

    def test_dirs_are_derived_from_file_paths(self):
        c = self._client()
        self.assertTrue(c.exists('src/app'))

    def test_walk_filters_by_suffix(self):
        c = self._client()
        self.assertEqual(c.walk(suffixes=('.py',)), ['src/app/main.py'])


class ChecksEngineTest(TestCase):
    """The engine runs against any RepoClient, GitHub and GitLab alike."""

    def _run(self, files, provider='github'):
        from app.repo_client import StaticRepoClient
        from app.checks import run_all_checks
        with patch('app.checks_extra.check_cve_vulnerabilities', return_value=[]):
            return run_all_checks(StaticRepoClient(files, provider=provider))

    def _by_id(self, results):
        return {c['check_id']: c for c in results}

    def test_every_check_carries_a_stable_id(self):
        results = self._run({'README.md': 'hi'})
        self.assertTrue(all(c.get('check_id') for c in results))

    def test_ids_are_unique(self):
        results = self._run({'README.md': 'hi'})
        ids = [c['check_id'] for c in results]
        self.assertEqual(len(ids), len(set(ids)))

    def test_empty_repository_fails_the_critical_checks(self):
        by_id = self._by_id(self._run({'README.md': 'hi'}))
        self.assertFalse(by_id['ops.gitignore']['passed'])
        self.assertFalse(by_id['deps.manifest']['passed'])

    def test_gitignore_with_env_passes(self):
        by_id = self._by_id(self._run({'.gitignore': '.env\n__pycache__/\n'}))
        self.assertTrue(by_id['ops.gitignore']['passed'])
        self.assertTrue(by_id['security.env_gitignored']['passed'])

    def test_wildcard_env_pattern_counts(self):
        by_id = self._by_id(self._run({'.gitignore': '*.env\n'}))
        self.assertTrue(by_id['security.env_gitignored']['passed'])

    def test_committed_env_file_is_critical(self):
        by_id = self._by_id(self._run({'.env': 'DEBUG=1\n'}))
        self.assertFalse(by_id['security.env_not_committed']['passed'])
        self.assertEqual(by_id['security.env_not_committed']['severity'], 'crit')

    def test_readme_quality_needs_setup_instructions(self):
        thin = self._by_id(self._run({'README.md': '# Project'}))
        self.assertFalse(thin['docs.readme_quality']['passed'])
        rich = self._by_id(self._run({
            'README.md': '# Project\n\n## Installation\n\n' + ('detail ' * 120),
        }))
        self.assertTrue(rich['docs.readme_quality']['passed'])

    def test_security_scanner_in_ci_is_detected(self):
        by_id = self._by_id(self._run({
            '.github/workflows/ci.yml': 'jobs:\n  s:\n    steps:\n      - run: trivy fs .\n',
        }))
        self.assertTrue(by_id['ci.security_scan']['passed'])

    def test_latest_base_image_fails(self):
        by_id = self._by_id(self._run({'Dockerfile': 'FROM python:latest\nUSER app\n'}))
        self.assertFalse(by_id['docker.pinned_base']['passed'])

    def test_untagged_base_image_fails(self):
        by_id = self._by_id(self._run({'Dockerfile': 'FROM python\nUSER app\n'}))
        self.assertFalse(by_id['docker.pinned_base']['passed'])

    def test_numeric_root_user_is_caught(self):
        by_id = self._by_id(self._run({'Dockerfile': 'FROM python:3.11\nUSER 0\n'}))
        self.assertFalse(by_id['docker.nonroot']['passed'])

    def test_docker_checks_not_applicable_without_compose(self):
        """
        These used to be recorded as passes, which paid a repository for input it
        never supplied. A compose check with no compose file is now set aside;
        a Dockerfile with no HEALTHCHECK is a finding, because there is a file
        to put one in.
        """
        by_id = self._by_id(self._run({'Dockerfile': 'FROM python:3.11\nUSER app\n'}))
        self.assertFalse(by_id['docker.resource_limits']['applicable'])
        self.assertTrue(by_id['docker.healthcheck']['applicable'])
        self.assertFalse(by_id['docker.healthcheck']['passed'])

    def test_gitlab_repository_skips_github_actions_checks(self):
        results = self._run({
            '.gitlab-ci.yml': 'test:\n  script:\n    - pytest\n',
            '.github/workflows/ci.yml': 'uses: actions/checkout@v4\n',
        }, provider='gitlab')
        self.assertNotIn('actions.pinned_sha', self._by_id(results))

    def test_gitlab_ci_satisfies_the_pipeline_check(self):
        by_id = self._by_id(self._run(
            {'.gitlab-ci.yml': 'test:\n  script:\n    - pytest\n'}, provider='gitlab',
        ))
        self.assertTrue(by_id['ci.pipeline']['passed'])
        self.assertTrue(by_id['ci.tests']['passed'])

    def test_passing_checks_carry_no_recommendation(self):
        results = self._run({'.gitignore': '.env\n'})
        for check in results:
            if check['passed']:
                self.assertEqual(check['recommendation'], '', check['check_id'])


# ══════════════════════════════════════════════════════════════════════════════
# Secret scanning across the whole tree
# ══════════════════════════════════════════════════════════════════════════════

class SecretScanTest(TestCase):
    def _find(self, files):
        from app.repo_client import StaticRepoClient
        from app.checks_secrets import find_secrets
        return find_secrets(StaticRepoClient(files))

    def test_aws_access_key_is_found(self):
        found = self._find({'config.py': 'AWS_KEY = "AKIA2E0A8F3B244C9986"'})
        self.assertIn('aws_access_key', [f['rule'] for f in found])

    def test_github_token_is_found(self):
        found = self._find({'deploy.sh': 'TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a'})
        self.assertIn('github_pat', [f['rule'] for f in found])

    def test_private_key_block_is_found(self):
        found = self._find({'certs/id_rsa': '-----BEGIN RSA PRIVATE KEY-----\nMIIE\n'})
        self.assertIn('private_key', [f['rule'] for f in found])

    def test_database_url_with_password_is_found(self):
        found = self._find({'settings.py': 'DB = "postgresql://user:hunter2xyz@db.internal/app"'})
        self.assertIn('db_url', [f['rule'] for f in found])

    def test_secret_outside_the_old_hardcoded_paths_is_found(self):
        """The previous scanner only looked at twenty fixed filenames."""
        found = self._find({'services/billing/internal/keys.py': 'API_KEY = "AKIA2E0A8F3B244C9986"'})
        self.assertTrue(found)

    def _no_secrets_check(self, files):
        from app.repo_client import StaticRepoClient
        from app.checks_secrets import scan_secrets
        return next(c for c in scan_secrets(StaticRepoClient(files))
                    if c['check_id'] == 'security.no_secrets')

    def test_a_generic_match_in_a_go_test_file_is_a_fixture(self):
        """gitlab-org/cli: `AccessToken: "oauth2-access-token"` in *_test.go failed a crit check."""
        for path in ('internal/auth/helper_test.go', 'src/api.spec.ts', 'lib/client.test.js',
                     'pkg/test_client.py', 'src/test/java/AuthTest.java'):
            c = self._no_secrets_check({path: 'access_token = "oauth2-access-token-x"\n'})
            self.assertTrue(c['passed'], path)

    def test_the_same_generic_match_in_source_still_fails(self):
        c = self._no_secrets_check({'internal/auth/helper.go': 'access_token = "oauth2-access-token-x"\n'})
        self.assertFalse(c['passed'])

    def test_a_provider_key_in_a_test_file_still_fails(self):
        """A live AWS key in a test is still a live AWS key."""
        c = self._no_secrets_check({'internal/aws_test.go': 'key := "AKIA2E0A8F3B244C9986"\n'})
        self.assertFalse(c['passed'])

    def test_environment_lookup_is_not_a_secret(self):
        found = self._find({'settings.py': 'SECRET_KEY = os.environ["SECRET_KEY"]'})
        self.assertEqual(found, [])

    def test_placeholder_values_are_ignored(self):
        found = self._find({'.env.example': 'PASSWORD = "your-password-here"\nAPI_KEY = "change-me"'})
        self.assertEqual(found, [])

    def test_low_entropy_value_is_ignored(self):
        found = self._find({'conf.py': 'password = "aaaaaaaaaaaaaaa"'})
        self.assertEqual(found, [])

    def test_lock_files_are_skipped(self):
        found = self._find({'package-lock.json': '{"token": "AKIA2E0A8F3B244C9986"}'})
        self.assertEqual(found, [])

    def test_vendored_code_is_skipped(self):
        found = self._find({'node_modules/pkg/index.js': 'const k = "AKIA2E0A8F3B244C9986"'})
        self.assertEqual(found, [])

    def test_clean_repository_passes_the_check(self):
        from app.repo_client import StaticRepoClient
        from app.checks_secrets import scan_secrets
        results = scan_secrets(StaticRepoClient({'main.py': 'print("hello")'}))
        no_secrets = next(c for c in results if c['check_id'] == 'security.no_secrets')
        self.assertTrue(no_secrets['passed'])

    def test_leaked_repository_fails_the_check(self):
        from app.repo_client import StaticRepoClient
        from app.checks_secrets import scan_secrets
        results = scan_secrets(StaticRepoClient({'main.py': 'K = "AKIA2E0A8F3B244C9986"'}))
        no_secrets = next(c for c in results if c['check_id'] == 'security.no_secrets')
        self.assertFalse(no_secrets['passed'])
        self.assertIn('rotate', no_secrets['recommendation'].lower())

    def test_entropy_of_random_string_beats_repetition(self):
        from app.checks_secrets import shannon_entropy
        self.assertGreater(shannon_entropy('a8Fk2Lm9Qw3Zx7Yt'), shannon_entropy('aaaaaaaaaaaaaaaa'))


# ══════════════════════════════════════════════════════════════════════════════
# Infrastructure as Code
# ══════════════════════════════════════════════════════════════════════════════

class IaCCheckTest(TestCase):
    def _run(self, files):
        from app.repo_client import StaticRepoClient
        from app.checks_iac import check_iac
        return {c['check_id']: c for c in check_iac(StaticRepoClient(files))}

    def test_repository_without_terraform_is_not_assessed(self):
        self.assertEqual(self._run({'main.py': 'x = 1'}), {})

    def test_ssh_open_to_the_internet_is_critical(self):
        result = self._run({'main.tf': '''
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''})
        self.assertFalse(result['iac.open_ingress']['passed'])
        self.assertEqual(result['iac.open_ingress']['severity'], 'crit')
        self.assertIn('22', result['iac.open_ingress']['description'])

    def test_restricted_ingress_passes(self):
        result = self._run({'main.tf': '''
resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["10.0.0.0/8"]
  }
}
'''})
        self.assertTrue(result['iac.open_ingress']['passed'])

    def test_https_open_to_the_internet_is_fine(self):
        result = self._run({'main.tf': '''
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''})
        self.assertTrue(result['iac.open_ingress']['passed'])

    def test_local_state_fails(self):
        result = self._run({'main.tf': 'resource "aws_instance" "a" {}'})
        self.assertFalse(result['iac.remote_state']['passed'])
        self.assertEqual(result['iac.remote_state']['severity'], 'crit')

    def test_locked_remote_state_passes(self):
        result = self._run({'backend.tf': '''
terraform {
  backend "s3" {
    bucket         = "state"
    dynamodb_table = "lock"
  }
}
'''})
        self.assertTrue(result['iac.remote_state']['passed'])

    def test_public_bucket_acl_is_critical(self):
        result = self._run({'s3.tf': 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}'})
        self.assertFalse(result['iac.no_public_buckets']['passed'])
        self.assertEqual(result['iac.no_public_buckets']['severity'], 'crit')

    def test_publicly_accessible_database_is_critical(self):
        result = self._run({'rds.tf': 'resource "aws_db_instance" "d" {\n  publicly_accessible = true\n}'})
        self.assertFalse(result['iac.private_database']['passed'])

    def test_hardcoded_provider_credentials_are_critical(self):
        result = self._run({'provider.tf': 'provider "aws" {\n  secret_key = "wJalrXUtnFEMIK7MDENG"\n}'})
        self.assertFalse(result['iac.no_hardcoded_credentials']['passed'])

    def test_variable_credentials_pass(self):
        result = self._run({'provider.tf': 'provider "aws" {\n  secret_key = var.secret_key\n}'})
        self.assertTrue(result['iac.no_hardcoded_credentials']['passed'])

    def test_provider_versions_constrained_passes(self):
        result = self._run({'versions.tf': '''
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
'''})
        self.assertTrue(result['iac.pinned_providers']['passed'])

    def test_iac_scanner_in_ci_is_detected(self):
        result = self._run({
            'main.tf': 'resource "aws_instance" "a" {}',
            '.github/workflows/scan.yml': 'steps:\n  - run: checkov -d .\n',
        })
        self.assertTrue(result['iac.scanning']['passed'])


# ══════════════════════════════════════════════════════════════════════════════
# Compliance mapping
# ══════════════════════════════════════════════════════════════════════════════

class ComplianceTest(TestCase):
    def setUp(self):
        self.user = make_user('complianceuser')
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u',
            source='github', status=Audit.STATUS_DONE, score=60,
        )

    def _check(self, check_id, passed, name='check'):
        return AuditCheck.objects.create(
            audit=self.audit, check_id=check_id, name=name, description='d',
            severity='warn', passed=passed, category='security',
        )

    def test_control_is_satisfied_only_when_every_mapped_check_passes(self):
        from app.compliance import build_report
        self._check('security.no_secrets', True)
        self._check('ops.gitignore', True)
        report = build_report(list(self.audit.checks.all()), 'soc2')
        cc61 = next(c for c in report['controls'] if c['id'] == 'CC6.1')
        self.assertEqual(cc61['status'], 'satisfied')

    def test_one_failing_check_opens_a_gap(self):
        from app.compliance import build_report
        self._check('security.no_secrets', False)
        self._check('ops.gitignore', True)
        report = build_report(list(self.audit.checks.all()), 'soc2')
        cc61 = next(c for c in report['controls'] if c['id'] == 'CC6.1')
        self.assertEqual(cc61['status'], 'gap')

    def test_coverage_percentage_is_computed(self):
        from app.compliance import build_report
        self._check('ops.license', True)   # CC2.1 only
        report = build_report(list(self.audit.checks.all()), 'soc2')
        self.assertEqual(report['coverage_pct'], 100)

    def test_iso_framework_maps_different_controls(self):
        from app.compliance import build_report
        self._check('security.no_secrets', True)
        report = build_report(list(self.audit.checks.all()), 'iso27001')
        self.assertIn('A.8.28', [c['id'] for c in report['controls']])

    def test_legacy_check_without_id_still_maps(self):
        from app.compliance import check_id_for
        legacy = AuditCheck.objects.create(
            audit=self.audit, name='Нет секретов в коде', description='d',
            severity='crit', passed=True, category='security',
        )
        self.assertEqual(check_id_for(legacy), 'security.no_secrets')

    def test_report_page_requires_login(self):
        r = Client().get(reverse('compliance_report', args=[self.audit.id]))
        self.assertEqual(r.status_code, 302)

    def test_report_page_renders_for_the_owner(self):
        self._check('security.no_secrets', True)
        c = Client()
        c.login(username='complianceuser', password='testpass123')
        r = c.get(reverse('compliance_report', args=[self.audit.id]))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'SOC 2')

    def test_free_user_sees_a_truncated_control_list(self):
        for cid in ('security.no_secrets', 'ci.pipeline', 'docker.nonroot',
                    'deps.lockfile', 'ops.license', 'ops.observability'):
            self._check(cid, True, name=cid)
        c = Client()
        c.login(username='complianceuser', password='testpass123')
        r = c.get(reverse('compliance_report', args=[self.audit.id]))
        self.assertFalse(r.context['full_access'])
        self.assertLessEqual(len(r.context['controls']), 3)
        self.assertGreater(r.context['hidden_count'], 0)

    def test_evidence_export_requires_the_compliance_plan(self):
        c = Client()
        c.login(username='complianceuser', password='testpass123')
        r = c.get(reverse('compliance_export', args=[self.audit.id, 'soc2']))
        self.assertEqual(r.status_code, 302)
        self.assertIn('/billing/', r.url)

    def test_evidence_export_returns_json_on_the_compliance_plan(self):
        from django.utils import timezone
        from datetime import timedelta
        sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        sub.plan = UserSubscription.PLAN_COMPLIANCE
        sub.current_period_end = timezone.now() + timedelta(days=30)
        sub.save()
        self._check('security.no_secrets', True)
        c = Client()
        c.login(username='complianceuser', password='testpass123')
        r = c.get(reverse('compliance_export', args=[self.audit.id, 'soc2']))
        self.assertEqual(r.status_code, 200)
        payload = json.loads(r.content)
        self.assertEqual(payload['repository'], 'org/repo')
        self.assertTrue(payload['controls'])


# ══════════════════════════════════════════════════════════════════════════════
# SBOM
# ══════════════════════════════════════════════════════════════════════════════

class SBOMTest(TestCase):
    FILES = {
        'requirements.txt': 'django==4.2.16\nrequests==2.32.3\n',
        'package.json': '{"dependencies": {"express": "^4.18.2"}}',
    }

    def _get_content(self, path):
        return self.FILES.get(path)

    def test_components_are_collected_across_ecosystems(self):
        from app.sbom import collect_components
        names = {c['name'] for c in collect_components(self._get_content)}
        self.assertIn('django', names)
        self.assertIn('express', names)

    def test_purl_is_ecosystem_qualified(self):
        from app.sbom import collect_components
        purls = {c['purl'] for c in collect_components(self._get_content)}
        self.assertIn('pkg:pypi/django@4.2.16', purls)
        self.assertIn('pkg:npm/express@4.18.2', purls)

    def test_cyclonedx_document_shape(self):
        from django.utils import timezone
        from app.sbom import generate
        doc, filename = generate('org/repo', self._get_content, 'cyclonedx', timezone.now())
        self.assertEqual(doc['bomFormat'], 'CycloneDX')
        self.assertEqual(doc['specVersion'], '1.5')
        self.assertTrue(filename.endswith('.cdx.json'))
        self.assertTrue(doc['components'])

    def test_spdx_document_shape(self):
        from django.utils import timezone
        from app.sbom import generate
        doc, filename = generate('org/repo', self._get_content, 'spdx', timezone.now())
        self.assertEqual(doc['spdxVersion'], 'SPDX-2.3')
        self.assertTrue(filename.endswith('.spdx.json'))
        self.assertEqual(len(doc['relationships']), len(doc['packages']))

    def test_serial_number_is_stable_for_a_repository(self):
        from app.sbom import _deterministic_serial
        self.assertEqual(_deterministic_serial('org/repo'), _deterministic_serial('org/repo'))
        self.assertNotEqual(_deterministic_serial('org/repo'), _deterministic_serial('org/other'))

    def test_no_dependency_files_yields_an_empty_bom(self):
        from django.utils import timezone
        from app.sbom import generate
        doc, _filename = generate('org/repo', lambda p: None, 'cyclonedx', timezone.now())
        self.assertEqual(doc['components'], [])


# ══════════════════════════════════════════════════════════════════════════════
# Plans, quotas and billing
# ══════════════════════════════════════════════════════════════════════════════

class PlanTierTest(TestCase):
    def setUp(self):
        self.user = make_user('planuser')
        self.sub, _ = UserSubscription.objects.get_or_create(user=self.user)

    def _activate(self, plan, days=30):
        from django.utils import timezone
        from datetime import timedelta
        self.sub.plan = plan
        self.sub.current_period_end = timezone.now() + timedelta(days=days)
        self.sub.save()

    def test_free_plan_has_no_paid_capability(self):
        self.assertFalse(self.sub.is_pro)
        self.assertFalse(self.sub.is_team)
        self.assertFalse(self.sub.is_compliance)

    def test_pro_unlocks_ai_but_not_team_features(self):
        self._activate(UserSubscription.PLAN_PRO)
        self.assertTrue(self.sub.is_pro)
        self.assertFalse(self.sub.is_team)

    def test_team_includes_pro(self):
        self._activate(UserSubscription.PLAN_TEAM)
        self.assertTrue(self.sub.is_pro)
        self.assertTrue(self.sub.is_team)
        self.assertFalse(self.sub.is_compliance)

    def test_compliance_includes_everything(self):
        self._activate(UserSubscription.PLAN_COMPLIANCE)
        self.assertTrue(self.sub.is_pro)
        self.assertTrue(self.sub.is_team)
        self.assertTrue(self.sub.is_compliance)

    def test_expired_paid_plan_loses_every_capability(self):
        self._activate(UserSubscription.PLAN_COMPLIANCE, days=-1)
        self.assertFalse(self.sub.is_pro)
        self.assertFalse(self.sub.is_team)
        self.assertFalse(self.sub.is_compliance)

    def test_days_left_is_reported(self):
        self._activate(UserSubscription.PLAN_PRO, days=10)
        self.assertIn(self.sub.days_left, (9, 10))


class CryptoOrderIdTest(TestCase):
    def test_plan_and_period_round_trip(self):
        from app.views import _parse_crypto_order_id
        self.assertEqual(
            _parse_crypto_order_id('42-team-annual-1700000000'), (42, 'team', 'annual'),
        )

    def test_bare_user_id_is_read_as_monthly_pro(self):
        """Invoices created before plans existed must still activate."""
        from app.views import _parse_crypto_order_id
        self.assertEqual(_parse_crypto_order_id('42'), (42, 'pro', 'monthly'))

    def test_unknown_plan_falls_back_to_pro(self):
        from app.views import _parse_crypto_order_id
        self.assertEqual(_parse_crypto_order_id('42-wizard-annual-1'), (42, 'pro', 'annual'))

    def test_garbage_yields_no_user(self):
        from app.views import _parse_crypto_order_id
        self.assertEqual(_parse_crypto_order_id('not-an-order')[0], None)


class FreeQuotaTest(TestCase):
    def setUp(self):
        self.user = make_user('quotauser')
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u',
            source='github', status=Audit.STATUS_DONE, score=50,
        )
        self.client = Client()
        self.client.login(username='quotauser', password='testpass123')

    def test_first_pdf_of_the_month_is_free(self):
        from app.models import MonthlyUsage
        r = self.client.get(reverse('audit_pdf', args=[self.audit.id]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r['Content-Type'], 'application/pdf')
        self.assertEqual(MonthlyUsage.for_user(self.user).pdf_exports, 1)

    def test_second_pdf_redirects_to_billing(self):
        self.client.get(reverse('audit_pdf', args=[self.audit.id]))
        r = self.client.get(reverse('audit_pdf', args=[self.audit.id]))
        self.assertEqual(r.status_code, 302)
        self.assertIn('/billing/', r.url)

    def test_paid_plan_is_not_metered(self):
        from django.utils import timezone
        from datetime import timedelta
        from app.models import MonthlyUsage
        sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        sub.plan = UserSubscription.PLAN_PRO
        sub.current_period_end = timezone.now() + timedelta(days=30)
        sub.save()
        for _ in range(3):
            r = self.client.get(reverse('audit_pdf', args=[self.audit.id]))
            self.assertEqual(r.status_code, 200)
        self.assertEqual(MonthlyUsage.for_user(self.user).pdf_exports, 0)

    def test_free_user_gets_one_ai_report_then_none(self):
        from app.tasks import _ai_allowance
        from app.models import MonthlyUsage
        allowed, consumes = _ai_allowance(self.audit)
        self.assertTrue(allowed)
        self.assertTrue(consumes)
        MonthlyUsage.for_user(self.user).consume('ai_reports')
        allowed, _consumes = _ai_allowance(self.audit)
        self.assertFalse(allowed)

    def test_paid_user_never_consumes_a_credit(self):
        from django.utils import timezone
        from datetime import timedelta
        from app.tasks import _ai_allowance
        sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        sub.plan = UserSubscription.PLAN_TEAM
        sub.current_period_end = timezone.now() + timedelta(days=30)
        sub.save()
        allowed, consumes = _ai_allowance(self.audit)
        self.assertTrue(allowed)
        self.assertFalse(consumes)


# ══════════════════════════════════════════════════════════════════════════════
# Public, no-account scanner
# ══════════════════════════════════════════════════════════════════════════════

class PublicScanTest(TestCase):
    def test_repository_forms_are_normalised(self):
        from app.views_public import _normalise
        for raw in ('django/django', 'https://github.com/django/django',
                    'github.com/django/django', 'https://github.com/django/django.git',
                    'www.github.com/django/django/'):
            self.assertEqual(_normalise(raw), 'django/django', raw)

    def test_invalid_input_is_rejected(self):
        from app.views_public import _normalise
        for raw in ('', 'django', '/', 'http://', '../../etc/passwd', 'owner/repo!'):
            self.assertIsNone(_normalise(raw))

    def test_extra_url_segments_are_tolerated(self):
        from app.views_public import _normalise
        self.assertEqual(
            _normalise('https://github.com/django/django/tree/main/docs'), 'django/django',
        )

    def test_index_renders(self):
        r = Client().get(reverse('scan_index'))
        self.assertEqual(r.status_code, 200)

    def test_submit_rejects_a_bad_repository(self):
        r = Client().post(reverse('scan_submit'), {'repo': 'nope'})
        self.assertEqual(r.status_code, 400)

    def test_submit_redirects_to_the_result_page(self):
        r = Client().post(reverse('scan_submit'), {'repo': 'https://github.com/django/django'})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.url, '/scan/django/django/')

    @patch('app.tasks.run_public_scan_task.delay')
    def test_first_visit_queues_a_scan(self, mock_delay):
        from app.models import PublicScan
        r = Client().get('/scan/django/django/')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(PublicScan.objects.filter(repo_full_name='django/django').exists())
        mock_delay.assert_called_once()

    @patch('app.tasks.run_public_scan_task.delay')
    def test_completed_scan_is_served_from_cache(self, mock_delay):
        from app.models import PublicScan
        PublicScan.objects.create(
            repo_full_name='django/django', repo_url='https://github.com/django/django',
            status=Audit.STATUS_DONE, score=72,
            results=[{'name': 'x', 'passed': False, 'severity': 'crit', 'description': 'd'}],
        )
        r = Client().get('/scan/django/django/')
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, '72')
        mock_delay.assert_not_called()

    @patch('app.tasks.run_public_scan_task.delay')
    def test_view_count_increments(self, _mock_delay):
        from app.models import PublicScan
        PublicScan.objects.create(
            repo_full_name='django/django', repo_url='u', status=Audit.STATUS_DONE, score=50,
        )
        Client().get('/scan/django/django/')
        self.assertEqual(PublicScan.objects.get(repo_full_name='django/django').view_count, 1)

    def test_status_endpoint_reports_progress(self):
        from app.models import PublicScan
        PublicScan.objects.create(
            repo_full_name='django/django', repo_url='u', status=Audit.STATUS_DONE, score=61,
        )
        r = Client().get('/scan/django/django/status/')
        self.assertEqual(r.json()['status'], 'done')
        self.assertEqual(r.json()['score'], 61)

    def test_sitemap_lists_public_scans(self):
        from app.models import PublicScan
        PublicScan.objects.create(
            repo_full_name='django/django', repo_url='u', status=Audit.STATUS_DONE, score=61,
        )
        r = Client().get('/sitemap.xml')
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, '/scan/django/django/')

    def test_robots_allows_the_scanner(self):
        r = Client().get('/robots.txt')
        self.assertContains(r, 'Allow: /scan/')


class SocialCardTest(TestCase):
    def test_card_is_a_png(self):
        from app.og_image import render_card
        data = render_card('org/repo', 64, {'security': 50, 'ci_cd': 70})
        self.assertTrue(data.startswith(b'\x89PNG'))

    def test_card_renders_without_a_score(self):
        from app.og_image import render_card
        self.assertTrue(render_card('org/repo', None).startswith(b'\x89PNG'))

    def test_scan_card_endpoint(self):
        from app.models import PublicScan
        PublicScan.objects.create(
            repo_full_name='django/django', repo_url='u', status=Audit.STATUS_DONE,
            score=61, category_scores={'security': 40},
        )
        r = Client().get('/og/scan/django/django.png')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r['Content-Type'], 'image/png')

    def test_audit_card_requires_a_public_token(self):
        r = Client().get('/og/audit/nonexistent.png')
        self.assertEqual(r.status_code, 404)


# ══════════════════════════════════════════════════════════════════════════════
# Organisation dashboard
# ══════════════════════════════════════════════════════════════════════════════

class OrgDashboardTest(TestCase):
    def setUp(self):
        self.user = make_user('orguser')
        self.client = Client()
        self.client.login(username='orguser', password='testpass123')

    def _audit(self, name, score):
        return Audit.objects.create(
            user=self.user, repo_full_name=name, repo_url='u',
            source='github', status=Audit.STATUS_DONE, score=score,
        )

    def test_requires_login(self):
        r = Client().get(reverse('org_dashboard'))
        self.assertEqual(r.status_code, 302)

    def test_empty_state_renders(self):
        r = self.client.get(reverse('org_dashboard'))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context['rows'], [])

    def test_one_row_per_repository(self):
        self._audit('acme/api', 40)
        self._audit('acme/api', 65)   # newer run of the same repo
        self._audit('acme/web', 80)
        r = self.client.get(reverse('org_dashboard'))
        self.assertEqual(len(r.context['rows']), 2)

    def test_average_score_uses_the_latest_run(self):
        self._audit('acme/api', 40)
        self._audit('acme/api', 60)
        self._audit('acme/web', 80)
        r = self.client.get(reverse('org_dashboard'))
        self.assertEqual(r.context['avg_score'], 70)

    def test_delta_against_the_previous_run(self):
        self._audit('acme/api', 40)
        self._audit('acme/api', 62)
        r = self.client.get(reverse('org_dashboard'))
        self.assertEqual(r.context['rows'][0]['delta'], 22)

    def test_owner_filter(self):
        self._audit('acme/api', 40)
        self._audit('other/lib', 90)
        r = self.client.get(reverse('org_dashboard'), {'owner': 'acme'})
        self.assertEqual(len(r.context['rows']), 1)
        self.assertEqual(r.context['rows'][0]['owner'], 'acme')

    def test_default_sort_puts_the_worst_first(self):
        self._audit('acme/good', 90)
        self._audit('acme/bad', 20)
        r = self.client.get(reverse('org_dashboard'))
        self.assertEqual(r.context['rows'][0]['name'], 'acme/bad')

    def test_only_the_owners_audits_are_listed(self):
        other = make_user('someoneelse')
        Audit.objects.create(user=other, repo_full_name='theirs/repo', repo_url='u',
                             source='github', status=Audit.STATUS_DONE, score=10)
        self._audit('acme/api', 70)
        r = self.client.get(reverse('org_dashboard'))
        self.assertEqual(len(r.context['rows']), 1)


# ══════════════════════════════════════════════════════════════════════════════
# Sparklines
# ══════════════════════════════════════════════════════════════════════════════

class ChartTest(TestCase):
    def test_empty_series_returns_nothing(self):
        from app.charts import series
        self.assertIsNone(series([]))
        self.assertIsNone(series([None, None]))

    def test_point_count_matches_the_input(self):
        from app.charts import series
        result = series([10, 50, 90])
        self.assertEqual(result['count'], 3)
        self.assertEqual(len(result['points'].split(' ')), 3)

    def test_higher_score_sits_higher_on_the_canvas(self):
        from app.charts import series
        low = series([10])
        high = series([90])
        # Coordinates leave charts.py as text so no locale can reformat them.
        self.assertGreater(float(low['last_y']), float(high['last_y']))

    def test_values_are_clamped_to_the_range(self):
        from app.charts import series
        result = series([-20, 150])
        for _x, y in (p.split(',') for p in result['points'].split(' ')):
            self.assertGreaterEqual(float(y), 0)

    def test_area_path_is_closed(self):
        from app.charts import series
        self.assertTrue(series([10, 20])['area'].endswith('Z'))


# ══════════════════════════════════════════════════════════════════════════════
# Pull request output
# ══════════════════════════════════════════════════════════════════════════════

class PullRequestFixTest(TestCase):
    def setUp(self):
        self.user = make_user('pruser')
        GithubProfile.objects.create(
            user=self.user, github_id=5, github_login='octo', access_token='tok',
        )
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u',
            source='github', status=Audit.STATUS_DONE, score=50,
        )
        self.check = AuditCheck.objects.create(
            audit=self.audit, check_id='security.dependency_updates',
            name='Automated dependency updates', description='d',
            severity='warn', passed=False, category='security',
        )
        self.client = Client()
        self.client.login(username='pruser', password='testpass123')

    def test_branch_names_are_slugged(self):
        from app.github_writer import _slug
        self.assertEqual(_slug('Automated dependency updates!'), 'automated-dependency-updates')

    def test_fix_offers_a_pull_request_when_github_is_connected(self):
        r = self.client.get(reverse('fix_generate', args=[self.audit.id, self.check.id]))
        self.assertTrue(r.json()['ok'])
        self.assertTrue(r.json()['can_open_pr'])

    def test_a_gitlab_audit_with_no_gitlab_account_connected_is_reported(self):
        """
        Was "Pull requests are supported for GitHub repositories" — a wall
        for every GitLab audit regardless of whether an account was even
        connected. Now that GitLab can open a merge request too, the only
        reason left to refuse is the one this test covers: no account to
        open it with, this test's setUp only connects GitHub.
        """
        self.audit.source = Audit.SOURCE_GITLAB
        self.audit.save()
        r = self.client.post(reverse('fix_open_pr', args=[self.audit.id, self.check.id]))
        self.assertEqual(r.status_code, 400)
        self.assertFalse(r.json()['ok'])
        self.assertIn('GitLab', r.json()['error'])

    @patch('app.github_writer.open_fix_pull_request_details')
    def test_successful_pull_request_returns_its_url(self, mock_open):
        mock_open.return_value = {'url': 'https://github.com/org/repo/pull/7', 'number': 7,
                                  'branch': 'devops-audit/x-1'}
        r = self.client.post(reverse('fix_open_pr', args=[self.audit.id, self.check.id]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['pr_url'], 'https://github.com/org/repo/pull/7')

    @patch('app.github_writer.open_fix_pull_request_details')
    def test_read_only_token_surfaces_a_useful_message(self, mock_open):
        from app.github_writer import GitHubWriteError
        mock_open.side_effect = GitHubWriteError('The connected token has read-only access.')
        r = self.client.post(reverse('fix_open_pr', args=[self.audit.id, self.check.id]))
        self.assertEqual(r.status_code, 400)
        self.assertIn('read-only', r.json()['error'])

    @patch('app.gitlab_writer.open_fix_merge_request')
    def test_a_gitlab_audit_with_an_account_connected_opens_a_merge_request(self, mock_open):
        mock_open.return_value = 'https://gitlab.com/org/repo/-/merge_requests/4'
        GitlabProfile.objects.create(
            user=self.user, gitlab_id=9, gitlab_username='octo-gl', access_token='glpat-tok',
        )
        self.audit.source = Audit.SOURCE_GITLAB
        self.audit.repo_full_name = 'org/repo::42'
        self.audit.save()
        r = self.client.post(reverse('fix_open_pr', args=[self.audit.id, self.check.id]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['pr_url'], 'https://gitlab.com/org/repo/-/merge_requests/4')
        self.assertEqual(mock_open.call_args.kwargs['project_id'], 42)

    @patch('app.gitlab_writer.open_fix_merge_request')
    def test_a_gitlab_write_error_surfaces_the_same_way_a_github_one_does(self, mock_open):
        from app.gitlab_writer import GitlabWriteError
        mock_open.side_effect = GitlabWriteError('The connected token can read this project but not write to it.')
        GitlabProfile.objects.create(
            user=self.user, gitlab_id=9, gitlab_username='octo-gl', access_token='glpat-tok',
        )
        self.audit.source = Audit.SOURCE_GITLAB
        self.audit.repo_full_name = 'org/repo::42'
        self.audit.save()
        r = self.client.post(reverse('fix_open_pr', args=[self.audit.id, self.check.id]))
        self.assertEqual(r.status_code, 400)
        self.assertIn('not write to it', r.json()['error'])

    def _gitlab_audit(self, **profile):
        GitlabProfile.objects.create(
            user=self.user, gitlab_id=9, gitlab_username='octo-gl', access_token='tok', **profile)
        self.audit.source = Audit.SOURCE_GITLAB
        self.audit.repo_full_name = 'org/repo::42'
        self.audit.save()

    @patch('app.gitlab_writer.open_fix_merge_request')
    def test_a_read_only_gitlab_sign_in_is_offered_write_access_not_a_dead_end(self, mock_open):
        """
        "Continue with GitLab" asks for read_api only. The first time someone
        wants a merge request, the answer is a link back through GitLab's
        consent screen with api added, as a connect, returning to this report.
        """
        from urllib.parse import parse_qs, urlparse
        from app.gitlab_writer import GitlabScopeError
        mock_open.side_effect = GitlabScopeError('no api scope')
        self._gitlab_audit(refresh_token='refresh',
                           token_expires_at=timezone.now() + timedelta(hours=1))
        r = self.client.post(reverse('fix_open_pr', args=[self.audit.id, self.check.id]))
        self.assertEqual(r.status_code, 403)
        url = urlparse(r.json()['reauth_url'])
        self.assertEqual(url.path, reverse('gitlab_login'))
        q = parse_qs(url.query)
        self.assertEqual(q['process'], ['connect'])
        self.assertEqual(q['scope'], ['api'])
        self.assertEqual(q['next'], [reverse('audit_detail', args=[self.audit.id])])

    @patch('app.gitlab_writer.open_fix_merge_request')
    def test_a_personal_access_token_without_api_is_told_to_recreate_it(self, mock_open):
        """No OAuth consent screen can widen a pasted token — no reauth link."""
        from app.gitlab_writer import GitlabScopeError
        mock_open.side_effect = GitlabScopeError('no api scope')
        self._gitlab_audit()
        r = self.client.post(reverse('fix_open_pr', args=[self.audit.id, self.check.id]))
        self.assertEqual(r.status_code, 400)
        self.assertNotIn('reauth_url', r.json())
        self.assertIn('api scope', r.json()['error'])

    def test_the_step_up_adds_api_to_the_configured_scopes(self):
        """
        Guards the allauth behaviour the step-up depends on: `?scope=` extends
        SOCIALACCOUNT_PROVIDERS' list rather than replacing it, and the base
        list — what every plain sign-in asks for — stays read-only.
        """
        from django.test import RequestFactory
        from allauth.socialaccount.adapter import get_adapter
        from allauth.socialaccount.models import SocialApp
        from django.contrib.sites.models import Site
        app = SocialApp.objects.create(provider='gitlab', name='GitLab', client_id='id', secret='s')
        app.sites.add(Site.objects.get_current())
        request = RequestFactory().get('/', {'scope': 'api'})
        provider = get_adapter().get_provider(request, 'gitlab')
        self.assertNotIn('api', provider.get_scope())
        self.assertIn('read_api', provider.get_scope())
        self.assertEqual(set(provider.get_scope_from_request(request)),
                         {'read_user', 'read_api', 'api'})

    def test_check_without_a_template_is_reported(self):
        unfixable = AuditCheck.objects.create(
            audit=self.audit, check_id='ops.activity', name='Repository is actively maintained',
            description='d', severity='info', passed=False, category='ops',
        )
        r = self.client.get(reverse('fix_generate', args=[self.audit.id, unfixable.id]))
        self.assertFalse(r.json()['ok'])
        self.assertEqual(r.json()['error'], 'no_template')


# ══════════════════════════════════════════════════════════════════════════════
# Webhook: push and pull request
# ══════════════════════════════════════════════════════════════════════════════

class WebhookTest(TestCase):
    def setUp(self):
        import hmac as _hmac
        from app.models import UserProfile
        self.user = make_user('hookuser')
        GithubProfile.objects.create(
            user=self.user, github_id=7, github_login='octo', access_token='tok',
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        self.secret = self.profile.ensure_webhook_secret()
        self.hmac = _hmac

    def _post(self, body, event):
        sig = 'sha256=' + self.hmac.new(
            self.secret.encode(), json.dumps(body).encode(), hashlib.sha256,
        ).hexdigest()
        return Client().post(
            f'/webhook/github/{self.secret}/',
            data=json.dumps(body), content_type='application/json',
            HTTP_X_HUB_SIGNATURE_256=sig, HTTP_X_GITHUB_EVENT=event,
        )

    def _make_pro(self, plan=UserSubscription.PLAN_PRO):
        from django.utils import timezone
        from datetime import timedelta
        sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        sub.plan = plan
        sub.current_period_end = timezone.now() + timedelta(days=30)
        sub.save()

    def test_unsigned_request_is_rejected(self):
        r = Client().post(
            f'/webhook/github/{self.secret}/', data='{}',
            content_type='application/json', HTTP_X_GITHUB_EVENT='push',
        )
        self.assertEqual(r.status_code, 403)

    def test_bad_signature_is_rejected(self):
        r = Client().post(
            f'/webhook/github/{self.secret}/', data='{}',
            content_type='application/json',
            HTTP_X_HUB_SIGNATURE_256='sha256=deadbeef', HTTP_X_GITHUB_EVENT='push',
        )
        self.assertEqual(r.status_code, 403)

    def test_free_plan_cannot_use_push_auto_audit(self):
        r = self._post({
            'ref': 'refs/heads/main',
            'repository': {'full_name': 'org/repo', 'html_url': 'u', 'default_branch': 'main'},
        }, 'push')
        self.assertEqual(r.status_code, 403)

    @patch('app.tasks.run_audit_task.delay')
    def test_push_to_default_branch_creates_a_run(self, mock_delay):
        mock_delay.return_value = MagicMock(id='t')
        self._make_pro()
        r = self._post({
            'ref': 'refs/heads/main', 'after': 'a' * 40,
            'repository': {'full_name': 'org/repo', 'html_url': 'u', 'default_branch': 'main'},
        }, 'push')
        self.assertEqual(r.status_code, 200)
        audit = Audit.objects.get(repo_full_name='org/repo')
        self.assertEqual(audit.trigger, Audit.TRIGGER_WEBHOOK)
        self.assertEqual(audit.commit_sha, 'a' * 40)

    @patch('app.tasks.run_audit_task.delay')
    def test_push_to_a_feature_branch_is_ignored(self, mock_delay):
        self._make_pro()
        r = self._post({
            'ref': 'refs/heads/feature-x',
            'repository': {'full_name': 'org/repo', 'html_url': 'u', 'default_branch': 'main'},
        }, 'push')
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Audit.objects.exists())

    def test_pull_request_events_need_a_paid_plan(self):
        """Free is still gated; the comment is the cheapest paid feature, not a free one."""
        r = self._post({
            'action': 'opened', 'number': 12,
            'pull_request': {'number': 12, 'head': {'sha': 'b' * 40}},
            'repository': {'full_name': 'org/repo', 'html_url': 'u', 'default_branch': 'main'},
        }, 'pull_request')
        self.assertEqual(r.status_code, 403)

    @patch('app.tasks.run_audit_task.delay')
    def test_pull_request_comments_are_a_pro_feature_not_a_team_one(self, mock_delay):
        """
        Moved down from Team on purpose. It is the most visible surface the
        product has — every engineer sees it on every pull request — and behind
        the $99 tier almost nobody ever did.
        """
        mock_delay.return_value = MagicMock(id='t')
        self._make_pro(UserSubscription.PLAN_PRO)
        r = self._post({
            'action': 'opened', 'number': 12,
            'pull_request': {'number': 12, 'head': {'sha': 'b' * 40}},
            'repository': {'full_name': 'org/repo', 'html_url': 'u', 'default_branch': 'main'},
        }, 'pull_request')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(Audit.objects.get(repo_full_name='org/repo').trigger,
                         Audit.TRIGGER_PR)

    @patch('app.tasks.run_audit_task.delay')
    def test_pull_request_creates_a_pr_scoped_run(self, mock_delay):
        mock_delay.return_value = MagicMock(id='t')
        self._make_pro(UserSubscription.PLAN_TEAM)
        r = self._post({
            'action': 'opened', 'number': 12,
            'pull_request': {'number': 12, 'head': {'sha': 'b' * 40}},
            'repository': {'full_name': 'org/repo', 'html_url': 'u', 'default_branch': 'main'},
        }, 'pull_request')
        self.assertEqual(r.status_code, 200)
        audit = Audit.objects.get(repo_full_name='org/repo')
        self.assertEqual(audit.trigger, Audit.TRIGGER_PR)
        self.assertEqual(audit.pr_number, 12)

    @patch('app.tasks.run_audit_task.delay')
    def test_closed_pull_requests_are_ignored(self, _mock_delay):
        self._make_pro(UserSubscription.PLAN_TEAM)
        r = self._post({
            'action': 'closed', 'number': 12,
            'pull_request': {'number': 12},
            'repository': {'full_name': 'org/repo', 'html_url': 'u', 'default_branch': 'main'},
        }, 'pull_request')
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Audit.objects.exists())

    def test_unknown_secret_is_a_404(self):
        r = Client().post('/webhook/github/wrongsecret/', data='{}',
                          content_type='application/json',
                          HTTP_X_HUB_SIGNATURE_256='sha256=x', HTTP_X_GITHUB_EVENT='push')
        self.assertEqual(r.status_code, 404)


class GithubAppWebhookTest(TestCase):
    """
    One URL, configured once on the App rather than pasted into every
    customer's own repo settings — the whole point of the App flow over a
    PAT. `installation.id` in the payload is how a delivery is matched back
    to a GithubProfile, in place of the per-user secret in the URL.
    """

    SECRET = 'app-webhook-secret'

    def setUp(self):
        import hmac as _hmac
        self.hmac = _hmac
        self.user = make_user('appwebhookuser')
        self.profile = GithubProfile.objects.create(
            user=self.user, github_id=8, github_login='octo-app',
            access_token='initial', installation_id=4242,
        )

    def _post(self, body, event):
        body_bytes = json.dumps(body).encode()
        sig = 'sha256=' + self.hmac.new(self.SECRET.encode(), body_bytes, hashlib.sha256).hexdigest()
        with override_settings(GITHUB_APP_WEBHOOK_SECRET=self.SECRET):
            return Client().post(
                '/webhook/github/app/',
                data=body_bytes, content_type='application/json',
                HTTP_X_HUB_SIGNATURE_256=sig, HTTP_X_GITHUB_EVENT=event,
            )

    def _make_pro(self):
        sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        sub.plan = UserSubscription.PLAN_PRO
        sub.current_period_end = timezone.now() + timedelta(days=30)
        sub.save()

    def test_with_no_secret_configured_the_endpoint_refuses_everything(self):
        with override_settings(GITHUB_APP_WEBHOOK_SECRET=''):
            r = Client().post('/webhook/github/app/', data='{}', content_type='application/json',
                              HTTP_X_HUB_SIGNATURE_256='sha256=x', HTTP_X_GITHUB_EVENT='ping')
        self.assertEqual(r.status_code, 503)

    def test_unsigned_request_is_rejected(self):
        with override_settings(GITHUB_APP_WEBHOOK_SECRET=self.SECRET):
            r = Client().post('/webhook/github/app/', data='{}', content_type='application/json',
                              HTTP_X_GITHUB_EVENT='push')
        self.assertEqual(r.status_code, 403)

    def test_bad_signature_is_rejected(self):
        with override_settings(GITHUB_APP_WEBHOOK_SECRET=self.SECRET):
            r = Client().post('/webhook/github/app/', data='{}', content_type='application/json',
                              HTTP_X_HUB_SIGNATURE_256='sha256=deadbeef', HTTP_X_GITHUB_EVENT='push')
        self.assertEqual(r.status_code, 403)

    def test_ping_is_accepted_without_a_body(self):
        r = self._post({}, 'ping')
        self.assertEqual(r.status_code, 200)

    def test_an_installation_with_no_matching_profile_is_a_no_op_not_an_error(self):
        r = self._post({'installation': {'id': 999999}, 'ref': 'refs/heads/main',
                        'repository': {'full_name': 'org/repo', 'default_branch': 'main'}}, 'push')
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Audit.objects.exists())

    def test_uninstalling_the_app_marks_the_connection_expired(self):
        r = self._post({'action': 'deleted', 'installation': {'id': 4242}}, 'installation')
        self.assertEqual(r.status_code, 200)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.token_status, GithubProfile.EXPIRED)
        # mark_broken(), not a bulk update — the broken-connection email and
        # the profile page both read token_broken_since to say *when*.
        self.assertIsNotNone(self.profile.token_broken_since)

    def test_installation_repositories_event_is_accepted_and_does_nothing(self):
        r = self._post({'action': 'added', 'installation': {'id': 4242},
                        'repositories_added': [{'full_name': 'org/new-repo'}]}, 'installation_repositories')
        self.assertEqual(r.status_code, 200)

    def test_free_plan_cannot_use_push_auto_audit(self):
        r = self._post({'installation': {'id': 4242}, 'ref': 'refs/heads/main',
                        'repository': {'full_name': 'org/repo', 'html_url': 'u', 'default_branch': 'main'}},
                       'push')
        self.assertEqual(r.status_code, 403)

    @patch('app.tasks.run_audit_task.delay')
    def test_push_to_default_branch_creates_a_run_keyed_on_installation(self, mock_delay):
        mock_delay.return_value = MagicMock(id='t')
        self._make_pro()
        r = self._post({
            'installation': {'id': 4242}, 'ref': 'refs/heads/main', 'after': 'c' * 40,
            'repository': {'full_name': 'org/repo', 'html_url': 'u', 'default_branch': 'main'},
        }, 'push')
        self.assertEqual(r.status_code, 200)
        audit = Audit.objects.get(repo_full_name='org/repo')
        self.assertEqual(audit.user, self.user)
        self.assertEqual(audit.trigger, Audit.TRIGGER_WEBHOOK)
        self.assertEqual(audit.commit_sha, 'c' * 40)

    @patch('app.tasks.run_audit_task.delay')
    def test_pull_request_opened_creates_a_run(self, mock_delay):
        mock_delay.return_value = MagicMock(id='t')
        self._make_pro()
        r = self._post({
            'installation': {'id': 4242}, 'action': 'opened', 'number': 9,
            'pull_request': {'number': 9, 'head': {'sha': 'd' * 40}},
            'repository': {'full_name': 'org/repo', 'html_url': 'u', 'default_branch': 'main'},
        }, 'pull_request')
        self.assertEqual(r.status_code, 200)
        audit = Audit.objects.get(repo_full_name='org/repo')
        self.assertEqual(audit.trigger, Audit.TRIGGER_PR)
        self.assertEqual(audit.pr_number, 9)

    def test_pull_request_comments_disabled_is_a_quiet_no_op(self):
        self._make_pro()
        UserProfile.objects.update_or_create(user=self.user, defaults={'pr_comments_enabled': False})
        r = self._post({
            'installation': {'id': 4242}, 'action': 'opened', 'number': 9,
            'pull_request': {'number': 9, 'head': {'sha': 'e' * 40}},
            'repository': {'full_name': 'org/repo', 'html_url': 'u', 'default_branch': 'main'},
        }, 'pull_request')
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Audit.objects.exists())


# ══════════════════════════════════════════════════════════════════════════════
# Subscription expiry reminders
# ══════════════════════════════════════════════════════════════════════════════

class ExpiryReminderTest(TestCase):
    def _sub(self, days, email='user@example.com'):
        from django.utils import timezone
        from datetime import timedelta
        user = User.objects.create_user(
            username=f'expiry{days}{email[:3]}', password='x', email=email,
        )
        sub, _ = UserSubscription.objects.get_or_create(user=user)
        sub.plan = UserSubscription.PLAN_PRO
        sub.current_period_end = timezone.now() + timedelta(days=days)
        sub.save()
        return sub

    def test_expiring_subscription_gets_one_reminder(self):
        from django.core import mail
        from app.tasks import send_expiry_reminders
        self._sub(2)
        self.assertEqual(send_expiry_reminders(), 1)
        self.assertEqual(len(mail.outbox), 1)

    def test_reminder_is_not_repeated(self):
        from app.tasks import send_expiry_reminders
        self._sub(2)
        send_expiry_reminders()
        self.assertEqual(send_expiry_reminders(), 0)

    def test_subscription_far_from_expiry_is_left_alone(self):
        from app.tasks import send_expiry_reminders
        self._sub(20)
        self.assertEqual(send_expiry_reminders(), 0)

    def test_user_without_an_email_is_skipped(self):
        from app.tasks import send_expiry_reminders
        self._sub(2, email='')
        self.assertEqual(send_expiry_reminders(), 0)


# ══════════════════════════════════════════════════════════════════════════════
# Repository archive: one download instead of one request per file
# ══════════════════════════════════════════════════════════════════════════════

class RepoArchiveTest(TestCase):
    @staticmethod
    def _tarball(files, root='pallets-flask-a1b2c3'):
        import io as _io
        import tarfile as _tarfile
        buf = _io.BytesIO()
        with _tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for name, content in files.items():
                data = content if isinstance(content, bytes) else content.encode()
                info = _tarfile.TarInfo(f'{root}/{name}')
                info.size = len(data)
                tar.addfile(info, _io.BytesIO(data))
        buf.seek(0)
        return buf

    def test_generated_root_directory_is_stripped(self):
        from app.repo_client import _extract_text_files
        files, paths = _extract_text_files(self._tarball({'README.md': '# Hi', 'src/app.py': 'x = 1'}))
        self.assertEqual(set(files), {'README.md', 'src/app.py'})
        self.assertEqual(paths, {'README.md', 'src/app.py'})

    def test_binary_members_are_skipped(self):
        from app.repo_client import _extract_text_files
        files, paths = _extract_text_files(self._tarball({
            'logo.png': b'\x89PNG\r\n\x1a\n\x00\x00binary',
            'README.md': '# Hi',
        }))
        self.assertEqual(set(files), {'README.md'})
        # The path is still known, so an existence check on a binary file works.
        self.assertIn('logo.png', paths)

    def test_oversized_members_are_skipped(self):
        from app.repo_client import _extract_text_files
        import app.repo_client as rc
        files, paths = _extract_text_files(self._tarball({
            'big.txt': 'x' * (rc.ARCHIVE_MAX_MEMBER + 10),
            'small.txt': 'ok',
        }))
        self.assertEqual(set(files), {'small.txt'})
        self.assertIn('big.txt', paths)

    def test_corrupt_archive_returns_none(self):
        import io as _io
        from app.repo_client import _extract_text_files
        self.assertIsNone(_extract_text_files(_io.BytesIO(b'not a tarball')))

    def test_client_serves_content_from_the_archive_without_extra_requests(self):
        from app.repo_client import GithubRepoClient
        client = GithubRepoClient('org/repo')
        client.files = {'README.md', 'src/app.py'}
        client._archive = {'README.md': '# Hi', 'src/app.py': 'x = 1'}
        before = client.api_calls
        self.assertEqual(client.get_content('README.md'), '# Hi')
        self.assertEqual(client.get_content('src/app.py'), 'x = 1')
        self.assertEqual(client.api_calls, before)

    def test_prefetch_is_a_no_op_when_the_archive_is_loaded(self):
        from app.repo_client import GithubRepoClient
        client = GithubRepoClient('org/repo')
        client.files = {'a.py'}
        client._archive = {'a.py': 'x'}
        before = client.api_calls
        client.prefetch(['a.py', 'b.py', 'c.py'])
        self.assertEqual(client.api_calls, before)

    def test_archive_rebuilds_the_tree_when_the_tree_call_failed(self):
        from app.repo_client import GithubRepoClient
        client = GithubRepoClient('org/repo')
        client.tree_truncated = True
        client._archive = {'README.md': '# Hi', 'deep/nested/file.py': 'x'}
        client._index_from_archive()
        self.assertFalse(client.tree_truncated)
        self.assertTrue(client.exists('README.md'))
        self.assertTrue(client.exists('deep/nested'))

    def test_rate_limit_is_reported_distinctly(self):
        from app.repo_client import GithubRepoClient, RateLimitedError
        client = GithubRepoClient('org/repo')
        response = MagicMock(status_code=403, headers={'X-RateLimit-Remaining': '0'})
        with patch.object(client, '_get', return_value=response):
            with self.assertRaises(RateLimitedError):
                client.load()

    def test_missing_repository_is_a_plain_access_error(self):
        from app.repo_client import GithubRepoClient, RepoAccessError, RateLimitedError
        client = GithubRepoClient('org/nope')
        response = MagicMock(status_code=404, headers={})
        with patch.object(client, '_get', return_value=response):
            with self.assertRaises(RepoAccessError) as ctx:
                client.load()
            self.assertNotIsInstance(ctx.exception, RateLimitedError)


class DotenvCheckTest(TestCase):
    """The .env rules only apply to projects that actually use a .env file."""

    def _run(self, files):
        from app.repo_client import StaticRepoClient
        from app.checks import run_all_checks
        with patch('app.checks_extra.check_cve_vulnerabilities', return_value=[]):
            return {c['check_id']: c for c in run_all_checks(StaticRepoClient(files))}

    def test_project_without_dotenv_is_not_penalised(self):
        result = self._run({'README.md': '# Hi', '.gitignore': '__pycache__/\n'})
        self.assertTrue(result['security.env_gitignored']['passed'])

    def test_project_with_env_example_must_ignore_dotenv(self):
        result = self._run({'.env.example': 'KEY=\n', '.gitignore': '__pycache__/\n'})
        self.assertFalse(result['security.env_gitignored']['passed'])

    def test_dotenv_dependency_triggers_the_rule(self):
        result = self._run({'requirements.txt': 'python-dotenv==1.0.0\n', '.gitignore': 'x\n'})
        self.assertFalse(result['security.env_gitignored']['passed'])

    def test_sample_env_in_examples_is_not_a_leak(self):
        result = self._run({'examples/tutorial/.env': 'KEY=demo\n'})
        self.assertTrue(result['security.env_not_committed']['passed'])

    def test_root_env_is_a_leak(self):
        result = self._run({'.env': 'SECRET_KEY=abc\n'})
        self.assertFalse(result['security.env_not_committed']['passed'])

    def test_changelog_in_restructured_text_counts(self):
        result = self._run({'CHANGES.rst': 'Version 1.0\n'})
        self.assertTrue(result['docs.changelog']['passed'])

    def test_contributing_in_restructured_text_counts(self):
        result = self._run({'CONTRIBUTING.rst': 'How to help\n'})
        self.assertTrue(result['docs.contributing']['passed'])


class SBOMExportTest(TestCase):
    """The export must not depend on still being able to read the repository."""

    def setUp(self):
        from django.utils import timezone
        from datetime import timedelta
        self.user = make_user('sbomuser')
        sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        sub.plan = UserSubscription.PLAN_COMPLIANCE
        sub.current_period_end = timezone.now() + timedelta(days=30)
        sub.save()
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u',
            source='github', status=Audit.STATUS_DONE, score=70,
            sbom_components=[{
                'name': 'django', 'version': '4.2.16',
                'purl': 'pkg:pypi/django@4.2.16', 'ecosystem': 'PyPI',
                'source_file': 'requirements.txt',
            }],
        )
        self.client = Client()
        self.client.login(username='sbomuser', password='testpass123')

    def test_export_uses_the_captured_inventory(self):
        r = self.client.get(reverse('sbom_download', args=[self.audit.id, 'cyclonedx']))
        self.assertEqual(r.status_code, 200)
        doc = json.loads(r.content)
        self.assertEqual(len(doc['components']), 1)
        self.assertEqual(doc['components'][0]['purl'], 'pkg:pypi/django@4.2.16')

    def test_spdx_export_uses_the_captured_inventory(self):
        r = self.client.get(reverse('sbom_download', args=[self.audit.id, 'spdx']))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(json.loads(r.content)['spdxVersion'], 'SPDX-2.3')

    def test_download_is_offered_as_a_file(self):
        r = self.client.get(reverse('sbom_download', args=[self.audit.id, 'cyclonedx']))
        self.assertIn('attachment', r['Content-Disposition'])
        self.assertIn('org_repo.cdx.json', r['Content-Disposition'])

    def test_free_plan_is_redirected_to_billing(self):
        UserSubscription.objects.filter(user=self.user).update(
            plan=UserSubscription.PLAN_FREE,
        )
        r = self.client.get(reverse('sbom_download', args=[self.audit.id, 'cyclonedx']))
        self.assertEqual(r.status_code, 302)

    def test_audit_without_a_captured_inventory_explains_itself(self):
        self.audit.sbom_components = []
        self.audit.save()
        with patch('app.repo_client.build_client_for_audit', side_effect=Exception('no token')):
            r = self.client.get(reverse('sbom_download', args=[self.audit.id, 'cyclonedx']))
        self.assertEqual(r.status_code, 400)
        self.assertIn(b'Re-run the audit', r.content)


# ══════════════════════════════════════════════════════════════════════════════
# Severity ordering — critical findings must lead, everywhere
# ══════════════════════════════════════════════════════════════════════════════

class SeverityOrderingTest(TestCase):
    """
    Ordering used to be `-severity` on a text column, which sorts alphabetically:
    warn > ok > info > crit. Critical findings landed last in the audit email,
    the pull request comment and the PDF.
    """

    def setUp(self):
        self.user = make_user('severityuser')
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u',
            source='github', status=Audit.STATUS_DONE, score=50,
        )
        for severity, name in [('warn', 'a warning'), ('info', 'a note'),
                               ('crit', 'a leaked secret'), ('warn', 'another warning')]:
            AuditCheck.objects.create(
                audit=self.audit, name=name, description='d',
                severity=severity, passed=False, category='security',
            )

    def test_rank_is_derived_from_severity_on_save(self):
        check = AuditCheck.objects.get(name='a leaked secret')
        self.assertEqual(check.severity_rank, 0)

    def test_default_ordering_puts_critical_first(self):
        first = self.audit.checks.filter(passed=False).first()
        self.assertEqual(first.severity, 'crit')

    def test_top_three_for_the_email_contains_the_critical_finding(self):
        top = list(self.audit.checks.filter(passed=False)
                   .order_by('severity_rank')[:3].values_list('severity', flat=True))
        self.assertEqual(top[0], 'crit')

    def test_bulk_created_checks_get_a_rank(self):
        from app.tasks import _apply_checks
        _apply_checks(self.audit, [{
            'check_id': 'security.no_secrets', 'name': 'Secrets', 'description': 'd',
            'severity': 'crit', 'passed': False, 'category': 'security', 'recommendation': 'r',
        }])
        self.assertEqual(self.audit.checks.first().severity_rank, 0)

    def test_apply_checks_stamps_the_score_version(self):
        """
        A trend chart needs to know when the definition of the score itself
        moved, not just that the number changed — see checks.SCORE_VERSION.
        """
        from app.checks import SCORE_VERSION
        from app.tasks import _apply_checks
        _apply_checks(self.audit, [{
            'check_id': 'security.no_secrets', 'name': 'Secrets', 'description': 'd',
            'severity': 'crit', 'passed': True, 'category': 'security', 'recommendation': '',
        }])
        self.assertEqual(self.audit.score_version, SCORE_VERSION)

    def test_pdf_lists_critical_findings_before_warnings(self):
        from app.pdf_report import generate_audit_pdf
        buf = generate_audit_pdf(self.audit, self.audit.checks.all(), language='en')
        data = buf.read()
        self.assertTrue(data.startswith(b'%PDF'))
        self.assertGreater(len(data), 2000)


class PublicPricingTest(TestCase):
    """The pricing page is the last thing someone reads before paying."""

    def test_anonymous_visitor_sees_prices(self):
        r = Client().get(reverse('pricing'))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Compliance')

    def test_it_is_not_behind_a_login(self):
        r = Client().get(reverse('pricing'))
        self.assertNotIn('login', r.get('Location', ''))

    def test_annual_and_monthly_both_render(self):
        for period in ('monthly', 'annual'):
            r = Client().get(reverse('pricing'), {'period': period})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.context['period'], period)

    def test_an_unknown_period_falls_back_to_annual(self):
        r = Client().get(reverse('pricing'), {'period': 'weekly'})
        self.assertEqual(r.context['period'], 'annual')

    def test_signed_in_users_go_to_billing(self):
        make_user('pricinguser')
        c = Client()
        c.login(username='pricinguser', password='testpass123')
        r = c.get(reverse('pricing'))
        self.assertEqual(r.status_code, 302)
        self.assertIn('/billing/', r.url)


class TrustPageTest(TestCase):
    """
    Whether repository content reaches a third party is a decision every
    visitor is entitled to see the answer to before they connect anything —
    not behind a login, and not gated on signing up.
    """

    def test_it_is_public(self):
        r = Client().get(reverse('trust'))
        self.assertEqual(r.status_code, 200)

    def test_signed_in_users_see_it_too(self):
        """Unlike /pricing/, this is not a conversion page — no redirect to billing."""
        make_user('trustuser')
        c = Client()
        c.login(username='trustuser', password='testpass123')
        r = c.get(reverse('trust'))
        self.assertEqual(r.status_code, 200)

    def test_the_ai_toggle_link_points_at_the_tab_the_page_js_actually_opens(self):
        """
        connect.html's switchTab() reads the hash against
        ['connect', 'ai', 'notifications', 'security'] — '#tab-ai' is not in
        that list and silently falls back to the connect tab.
        """
        r = Client().get(reverse('trust'))
        self.assertContains(r, '#ai"')
        self.assertNotContains(r, '#tab-ai')

    def test_links_to_the_profile_page_for_deletion_and_the_ai_setting(self):
        r = Client().get(reverse('trust'))
        self.assertContains(r, reverse('connect'))

    def test_states_the_support_email(self):
        r = Client().get(reverse('trust'))
        self.assertContains(r, settings.SUPPORT_EMAIL)


class SecurityTxtTest(TestCase):

    def test_it_is_public_and_plain_text(self):
        r = Client().get('/.well-known/security.txt')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r['Content-Type'], 'text/plain')

    def test_required_rfc9116_fields_are_present(self):
        r = Client().get('/.well-known/security.txt')
        body = r.content.decode()
        self.assertIn(f'Contact: mailto:{settings.SUPPORT_EMAIL}', body)
        self.assertIn('Expires:', body)
        self.assertIn(f'Canonical: {settings.BASE_URL}/.well-known/security.txt', body)

    def test_expires_is_in_the_future(self):
        from datetime import datetime, timezone as dt_timezone
        r = Client().get('/.well-known/security.txt')
        line = next(l for l in r.content.decode().splitlines() if l.startswith('Expires:'))
        expires = datetime.strptime(line.split(': ', 1)[1], '%Y-%m-%dT%H:%M:%S.000Z').replace(tzinfo=dt_timezone.utc)
        self.assertGreater(expires, datetime.now(dt_timezone.utc))

    def test_robots_txt_allows_trust_and_lists_it_explicitly(self):
        r = Client().get('/robots.txt')
        self.assertIn('Allow: /trust/', r.content.decode())


class SecurityHeadersTest(TestCase):
    def test_csp_is_present(self):
        r = Client().get(reverse('scan_index'))
        self.assertIn('Content-Security-Policy', r)
        self.assertIn("frame-ancestors 'none'", r['Content-Security-Policy'])

    def test_permissions_policy_is_present(self):
        r = Client().get(reverse('scan_index'))
        self.assertIn('camera=()', r['Permissions-Policy'])

    def test_badges_stay_embeddable(self):
        """A README badge must survive being hot-linked from anywhere."""
        user = make_user('badgeuser')
        audit = Audit.objects.create(
            user=user, repo_full_name='org/repo', repo_url='u',
            source='github', status=Audit.STATUS_DONE, score=70,
        )
        token = audit.generate_public_token()
        r = Client().get(f'/badge/{token}.svg')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r['X-Frame-Options'], 'SAMEORIGIN')
        self.assertEqual(r['Access-Control-Allow-Origin'], '*')


class FailureReasonTest(TestCase):
    def setUp(self):
        self.user = make_user('failuser')
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u', source='github',
            status=Audit.STATUS_FAILED, error_message='GitHub returned 404 for org/repo',
        )
        self.client = Client()
        self.client.login(username='failuser', password='testpass123')

    def test_status_endpoint_reports_the_reason(self):
        r = self.client.get(reverse('audit_status', args=[self.audit.id]))
        self.assertEqual(r.json()['error'], 'GitHub returned 404 for org/repo')
        self.assertTrue(r.json()['can_retry'])

    def test_report_page_shows_the_reason(self):
        r = self.client.get(reverse('audit_detail', args=[self.audit.id]))
        self.assertContains(r, 'GitHub returned 404')


class StuckScanTest(TestCase):
    def test_a_scan_stuck_in_the_queue_is_closed_out(self):
        from django.utils import timezone
        from app.models import PublicScan
        from app.tasks import expire_stuck_public_scans
        scan = PublicScan.objects.create(
            repo_full_name='ghost/repo', repo_url='u', status=Audit.STATUS_PENDING,
        )
        stale = timezone.now() - timezone.timedelta(hours=2)
        # queued_at is what separates a job the worker never finished from a
        # seeded row still waiting its turn. This test is about the former.
        PublicScan.objects.filter(pk=scan.pk).update(updated_at=stale, queued_at=stale)
        self.assertEqual(expire_stuck_public_scans(), 1)
        scan.refresh_from_db()
        self.assertEqual(scan.status, Audit.STATUS_FAILED)
        self.assertTrue(scan.error_message)

    def test_a_fresh_scan_is_left_alone(self):
        from app.models import PublicScan
        from app.tasks import expire_stuck_public_scans
        PublicScan.objects.create(
            repo_full_name='fresh/repo', repo_url='u', status=Audit.STATUS_PENDING,
        )
        self.assertEqual(expire_stuck_public_scans(), 0)

    def test_the_page_times_a_stuck_scan_out_on_view(self):
        from django.utils import timezone
        from app.models import PublicScan
        scan = PublicScan.objects.create(
            repo_full_name='ghost/repo', repo_url='u', status=Audit.STATUS_PENDING,
        )
        PublicScan.objects.filter(pk=scan.pk).update(
            updated_at=timezone.now() - timezone.timedelta(hours=2),
        )
        with patch('app.tasks.run_public_scan_task.delay'):
            r = Client().get('/scan/ghost/repo/')
        self.assertEqual(r.status_code, 200)


class PublicReportPageTest(TestCase):
    """The shared report is the page people without an account see."""

    def setUp(self):
        self.user = make_user('shareuser')
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='https://github.com/org/repo',
            source='github', status=Audit.STATUS_DONE, score=64,
            category_scores={'security': 50},
        )
        AuditCheck.objects.create(
            audit=self.audit, name='Secrets in code', description='d',
            severity='crit', passed=False, category='security',
        )
        self.token = self.audit.generate_public_token()

    def test_it_renders_without_an_account(self):
        r = Client().get(f'/audit/public/{self.token}/')
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'org/repo')

    def test_it_carries_a_social_card(self):
        r = Client().get(f'/audit/public/{self.token}/')
        self.assertContains(r, f'/og/audit/{self.token}.png')

    def test_the_card_renders(self):
        r = Client().get(f'/og/audit/{self.token}.png')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r['Content-Type'], 'image/png')

    def test_a_private_audit_is_not_reachable(self):
        self.audit.is_public = False
        self.audit.save()
        r = Client().get(f'/audit/public/{self.token}/')
        self.assertEqual(r.status_code, 404)


@override_settings(PAYMENTS_LIVE=True)
class CheckoutTest(TestCase):
    """
    Everything that stood between a buyer and a payment page.

    Each of these was live at once: the CSP aborted the redirect, an account
    without an email got a 422 from Lemon Squeezy, and every plan resolved to
    the one variant that sells Pro.
    """

    def setUp(self):
        self.user = make_user('buyer', email='buyer@test.com')
        self.client = Client()
        self.client.force_login(self.user)

    # ── CSP ─────────────────────────────────────────────────────────────────

    def test_csp_allows_posting_to_the_payment_hosts(self):
        """
        form-action covers the whole redirect chain. With 'self' alone Chrome
        aborts the hop to the provider and the buyer sees nothing happen.
        """
        csp = Client().get(reverse('billing'), follow=True)['Content-Security-Policy']
        form_action = [d for d in csp.split(';') if d.strip().startswith('form-action')][0]
        self.assertIn("'self'", form_action)
        self.assertIn('lemonsqueezy.com', form_action)
        self.assertIn('cryptomus.com', form_action)

    # ── Variant resolution ──────────────────────────────────────────────────

    def test_legacy_variant_only_answers_for_monthly_pro(self):
        from app.views import card_variant_for
        with self.settings(LEMONSQUEEZY_VARIANT_ID='999', LS_VARIANTS={}):
            self.assertEqual(card_variant_for('pro', 'monthly'), '999')
            for plan, period in (('pro', 'annual'), ('team', 'monthly'),
                                 ('team', 'annual'), ('compliance', 'monthly')):
                self.assertEqual(
                    card_variant_for(plan, period), '',
                    f'{plan}/{period} must not fall back to the monthly Pro variant',
                )

    def test_only_a_plan_with_its_own_variant_can_be_charged(self):
        """
        Every plan shows both buttons — one button next to two reads as the
        plan not being for sale. Only the combination with its own variant can
        be charged; the rest say so instead of charging the wrong amount.
        """
        with self.settings(LEMONSQUEEZY_API_KEY='k', LEMONSQUEEZY_VARIANT_ID='999',
                           LS_VARIANTS={}, CRYPTOMUS_MERCHANT_ID='', CRYPTOMUS_API_KEY=''):
            html = self.client.get(reverse('billing') + '?period=monthly').content.decode()
        # Every plan shows both buttons; only Pro monthly can be charged today,
        # and the others say so on the way back rather than charging wrong.
        from app.views import card_variant_for
        self.assertTrue(card_variant_for('pro', 'monthly'))
        for plan, period in (('pro', 'annual'), ('team', 'monthly'), ('compliance', 'annual')):
            self.assertEqual(card_variant_for(plan, period), '')
        self.assertIn('Pay $99 by card', html)
        self.assertIn('Pay $99 in crypto', html)

    def test_checkout_refuses_a_plan_with_no_variant(self):
        with self.settings(LEMONSQUEEZY_API_KEY='k', LEMONSQUEEZY_VARIANT_ID='999', LS_VARIANTS={}):
            r = self.client.post(reverse('ls_checkout'), {'plan': 'team', 'period': 'monthly'})
        self.assertRedirects(r, reverse('billing'))

    # ── The email that broke every account created without one ──────────────

    def test_no_email_is_omitted_rather_than_sent_empty(self):
        """Lemon Squeezy answers an empty email with a 422, and registration does not ask for one."""
        self.user.email = ''
        self.user.save()
        captured = {}

        def fake_post(url, **kwargs):
            captured['json'] = kwargs['json']
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = {'data': {'attributes': {'url': 'https://ls.example/checkout'}}}
            return resp

        with self.settings(LEMONSQUEEZY_API_KEY='k', LEMONSQUEEZY_VARIANT_ID='999', LS_VARIANTS={}):
            with patch('app.views.requests.post', side_effect=fake_post):
                r = self.client.post(reverse('ls_checkout'), {'plan': 'pro', 'period': 'monthly'})

        checkout_data = captured['json']['data']['attributes']['checkout_data']
        self.assertNotIn('email', checkout_data)
        self.assertEqual(checkout_data['custom']['plan'], 'pro')
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r['Location'], 'https://ls.example/checkout')

    def test_email_is_passed_through_when_there_is_one(self):
        captured = {}

        def fake_post(url, **kwargs):
            captured['json'] = kwargs['json']
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = {'data': {'attributes': {'url': 'https://ls.example/c'}}}
            return resp

        with self.settings(LEMONSQUEEZY_API_KEY='k', LEMONSQUEEZY_VARIANT_ID='999', LS_VARIANTS={}):
            with patch('app.views.requests.post', side_effect=fake_post):
                self.client.post(reverse('ls_checkout'), {'plan': 'pro', 'period': 'monthly'})

        self.assertEqual(
            captured['json']['data']['attributes']['checkout_data']['email'],
            'buyer@test.com',
        )

    # ── Crypto ──────────────────────────────────────────────────────────────

    def test_crypto_button_appears_only_when_configured(self):
        with self.settings(CRYPTOMUS_MERCHANT_ID='m', CRYPTOMUS_API_KEY='k'):
            html = self.client.get(reverse('billing')).content.decode()
        self.assertIn('/billing/checkout/crypto/', html)


class PriceConsistencyTest(TestCase):
    """The landing and the pricing page must not advertise different numbers."""

    def test_landing_and_pricing_show_the_same_monthly_price(self):
        from django.conf import settings as dj

        landing = Client().get(reverse('landing')).content.decode()
        pricing = Client().get(reverse('pricing') + '?period=monthly').content.decode()
        for plan, prices in dj.PLAN_PRICES.items():
            self.assertIn(str(prices['monthly']), landing, f'{plan} monthly missing from the landing')
            self.assertIn(str(prices['monthly']), pricing, f'{plan} monthly missing from /pricing/')

    def test_landing_also_shows_the_annual_equivalent(self):
        """Otherwise /pricing/ defaulting to annual reads as a different price."""
        from django.conf import settings as dj

        landing = Client().get(reverse('landing')).content.decode()
        self.assertIn(str(dj.PLAN_PRICES['pro']['annual']), landing)

    def test_crypto_is_not_advertised_while_it_is_off(self):
        with self.settings(CRYPTOMUS_MERCHANT_ID='', CRYPTOMUS_API_KEY=''):
            html = Client().get(reverse('pricing')).content.decode()
        self.assertNotIn('Cryptomus', html)


class SourceLanguageTest(TestCase):
    """
    English is the source language and the Russian catalogue is kept at 100%.

    Both drifted: nine templates and views.py still carried Russian source
    strings, and a makemessages run left 111 entries fuzzy or empty — every one
    of them silently falling back to English for a Russian reader.
    """

    CYRILLIC = re.compile('[А-Яа-яЁё]')

    def _sources(self):
        import glob
        return (sorted(glob.glob('app/templates/**/*.html', recursive=True))
                + sorted(glob.glob('app/*.py')))

    def test_no_russian_source_strings(self):
        offenders = []
        patterns = (
            re.compile(r'\{%\s*trans\s+["\']([^"\']*)["\']\s*%\}'),
            re.compile(r'_\(["\']([^"\']*)["\']\)'),
        )
        for path in self._sources():
            if path.endswith('tests.py'):
                continue
            body = open(path, encoding='utf-8').read()
            for pattern in patterns:
                for text in pattern.findall(body):
                    if self.CYRILLIC.search(text):
                        offenders.append(f'{path}: {text[:60]}')
        self.assertEqual(offenders, [], 'translate at the catalogue, not at the source string')

    def _entries(self, po):
        blocks = re.split(r'\n\n+', open(po, encoding='utf-8').read())
        for block in blocks:
            if not re.search(r'^msgid ', block, re.M):
                continue
            def values(key):
                return [''.join(re.findall(r'"([^"]*)"', m.group(1)))
                        for m in re.finditer(r'^%s(?:\[\d\])? ((?:"[^"]*"\s*\n?)+)' % key,
                                             block, re.M)]
            msgid = values('msgid')
            if not msgid or not msgid[0]:
                continue
            yield msgid[0], values('msgstr'), '#, fuzzy' in block

    def test_russian_catalogue_is_complete(self):
        broken = [
            msgid for msgid, msgstr, fuzzy in self._entries('locale/ru/LC_MESSAGES/django.po')
            if fuzzy or not (msgstr and all(v.strip() for v in msgstr))
        ]
        self.assertEqual(
            broken, [],
            f'{len(broken)} Russian entries fall back to English; '
            f'first: {broken[:3]}',
        )

    def test_english_catalogue_stays_empty(self):
        """
        A translation of the source language can only ever be wrong. The stale
        one held gems like 'Password' → 'Passed', kept out of the build only by
        a fuzzy flag anyone could clear.
        """
        overrides = [
            msgid for msgid, msgstr, _fuzzy in self._entries('locale/en/LC_MESSAGES/django.po')
            if msgstr and any(v.strip() for v in msgstr)
        ]
        self.assertEqual(overrides, [], 'English text belongs in the source, not in locale/en')


class LocalisedChartTest(TestCase):
    """
    A sparkline must survive a locale with a decimal comma.

    Under Russian, `viewBox="0 0 {{ spark.width }} {{ spark.height }}"` rendered
    as `0 0 100,0 30,0` and the browser threw the whole element away — the
    organisation trend and the score history were blank for every Russian user.
    """

    def test_geometry_is_text_not_numbers(self):
        from app.charts import series

        spark = series([40, 55, 70])
        for field in ('width', 'height', 'last_x', 'last_y'):
            self.assertIsInstance(spark[field], str, f'{field} must not be a float')
            self.assertNotIn(',', spark[field])

    def test_viewbox_survives_the_russian_locale(self):
        from django.utils import translation

        user = make_user('chartru')
        UserSubscription.objects.update_or_create(
            user=user, defaults={'plan': UserSubscription.PLAN_TEAM,
                                 'current_period_end': timezone.now() + timedelta(days=30)},
        )
        for score in (40, 61):
            Audit.objects.create(
                user=user, repo_full_name='org/repo', repo_url='u', source='github',
                status=Audit.STATUS_DONE, score=score,
            )
        client = Client()
        client.force_login(user)
        with translation.override('ru'):
            html = client.get(reverse('org_dashboard'), HTTP_ACCEPT_LANGUAGE='ru').content.decode()
        for view_box in re.findall(r'viewBox="([^"]*)"', html):
            self.assertNotIn(',', view_box, f'localised viewBox: {view_box!r}')


class EngineAccuracyTest(TestCase):
    """
    Two findings that were wrong on real, well-run repositories.

    Checked against psf/requests: a critical "3 credentials committed" for the
    TLS fixtures its own test suite needs, and "tests run in CI: no" for a
    project whose CI runs an eight-version matrix.
    """

    def _client(self, files):
        from app.repo_client import StaticRepoClient
        return StaticRepoClient(files, full_name='acme/lib')

    def test_test_certificates_are_not_a_critical_leak(self):
        from app.checks_secrets import scan_secrets

        key = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----\n'
        checks = scan_secrets(self._client({
            'tests/certs/valid/server/server.key': key,
            'tests/certs/mtls/client/client.key': key,
            'README.md': '# lib',
        }))
        secrets = [c for c in checks if c['check_id'] == 'security.no_secrets'][0]
        self.assertTrue(secrets['passed'], secrets['description'])
        self.assertIn('fixture', secrets['description'].lower())

    def test_a_key_outside_the_test_tree_is_still_critical(self):
        from app.checks_secrets import scan_secrets

        checks = scan_secrets(self._client({
            'deploy/id_rsa': '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC\n-----END RSA PRIVATE KEY-----\n',
        }))
        secrets = [c for c in checks if c['check_id'] == 'security.no_secrets'][0]
        self.assertFalse(secrets['passed'])
        self.assertEqual(secrets['severity'], 'crit')

    def test_tests_run_through_a_task_runner_still_count(self):
        from app.checks import run_all_checks

        for runner in ('make test', 'nox -s tests', 'tox -e py311', 'hatch test'):
            with self.subTest(runner=runner):
                checks = run_all_checks(self._client({
                    '.github/workflows/ci.yml': f'name: CI\non: [push]\njobs:\n  t:\n    steps:\n      - run: {runner}\n',
                    'README.md': '# lib',
                }))
                ci_tests = [c for c in checks if c['check_id'] == 'ci.tests'][0]
                self.assertTrue(ci_tests['passed'], f'{runner} not recognised as a test run')

    def test_a_workflow_named_tests_counts_even_when_the_step_is_opaque(self):
        from app.checks import run_all_checks

        checks = run_all_checks(self._client({
            '.github/workflows/run-tests.yml': 'name: Tests\non: [push]\njobs:\n  b:\n    steps:\n      - run: ./ci.sh\n',
            'README.md': '# lib',
        }))
        self.assertTrue([c for c in checks if c['check_id'] == 'ci.tests'][0]['passed'])

    def test_a_workflow_that_does_not_test_is_still_reported(self):
        from app.checks import run_all_checks

        checks = run_all_checks(self._client({
            '.github/workflows/publish.yml': 'name: Publish\non:\n  release:\njobs:\n  p:\n    steps:\n      - run: twine upload dist/*\n',
            'README.md': '# lib',
        }))
        self.assertFalse([c for c in checks if c['check_id'] == 'ci.tests'][0]['passed'])

    def test_uv_run_is_recognised_as_a_test_invocation(self):
        from app.checks import run_all_checks

        checks = run_all_checks(self._client({
            '.github/workflows/ci.yml': 'name: CI\non: [push]\njobs:\n  t:\n    steps:\n      - run: uv run pytest\n',
            'README.md': '# lib',
        }))
        self.assertTrue([c for c in checks if c['check_id'] == 'ci.tests'][0]['passed'])

    def test_a_call_to_a_script_named_test_counts_even_unread(self):
        """`scripts/test.sh` is opaque shell, but its own name already says what it is."""
        from app.checks import run_all_checks

        checks = run_all_checks(self._client({
            '.github/workflows/ci.yml':
                'name: CI\non: [push]\njobs:\n  t:\n    steps:\n      - run: ./scripts/test.sh\n',
            'README.md': '# lib',
        }))
        self.assertTrue([c for c in checks if c['check_id'] == 'ci.tests'][0]['passed'])

    def test_a_reusable_workflow_named_test_counts_even_from_another_repository(self):
        """The called workflow lives outside this repository and cannot be read — its path can."""
        from app.checks import run_all_checks

        checks = run_all_checks(self._client({
            '.github/workflows/ci.yml': (
                'name: CI\non: [push]\njobs:\n  t:\n'
                '    uses: acme/shared-workflows/.github/workflows/test-suite.yml@main\n'
            ),
            'README.md': '# lib',
        }))
        self.assertTrue([c for c in checks if c['check_id'] == 'ci.tests'][0]['passed'])

    def test_a_reusable_workflow_with_an_unrelated_name_is_not_assumed_to_test(self):
        from app.checks import run_all_checks

        checks = run_all_checks(self._client({
            '.github/workflows/publish.yml': (
                'name: Publish\non:\n  release:\njobs:\n  p:\n'
                '    uses: acme/shared-workflows/.github/workflows/npm-publish.yml@main\n'
            ),
            'README.md': '# lib',
        }))
        self.assertFalse([c for c in checks if c['check_id'] == 'ci.tests'][0]['passed'])


class RepoKindTest(TestCase):
    """
    The score is only worth putting in a README badge if it grades a repository
    on what it could have done. A library was being marked down for having no
    Dockerfile, no .dockerignore and no non-root container user — three findings
    it can never act on.
    """

    LIBRARY = {
        'README.md': '# lib',
        'pyproject.toml': '[project]\nname = "httpkit"\nversion = "1.0"\n',
        'src/httpkit/__init__.py': 'x = 1\n',
    }
    SERVICE = {
        'README.md': '# app',
        'requirements.txt': 'django==5.0.6\n',
        'Dockerfile': 'FROM python:3.11-slim\nCMD ["gunicorn"]\n',
        'src/app.py': 'x = 1\n',
    }

    def _client(self, files):
        from app.repo_client import StaticRepoClient
        return StaticRepoClient(files, full_name='acme/thing')

    def test_a_published_package_with_no_deployment_is_a_library(self):
        from app.repo_kind import detect, LIBRARY

        kind, skipped, reason, _confidence = detect(self._client(self.LIBRARY))
        self.assertEqual(kind, LIBRARY)
        self.assertIn('docker.dockerfile', skipped)
        self.assertIn('ops.observability', skipped)
        self.assertTrue(reason)

    def test_a_library_that_also_ships_a_dockerfile_is_a_service(self):
        """The Docker checks have something to read, so they apply."""
        from app.repo_kind import detect, SERVICE

        files = dict(self.LIBRARY, Dockerfile='FROM python:3.11\n')
        kind, skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, SERVICE)
        self.assertEqual(skipped, set())

    def test_kubernetes_manifests_alone_make_it_a_service(self):
        from app.repo_kind import detect, SERVICE

        files = dict(self.LIBRARY)
        files['k8s/deployment.yaml'] = 'kind: Deployment\n'
        kind, _skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, SERVICE)

    def test_a_repository_with_no_real_signal_is_unknown_but_still_graded_in_full(self):
        """
        Before `unknown` existed, this was silently labelled `service` — a
        confident-looking guess with nothing behind it. The safe default is
        unchanged (nothing is quietly forgiven when the evidence is thin); what
        changed is that the label now admits the guess is a guess.
        """
        from app.repo_kind import detect, UNKNOWN

        kind, skipped, _reason, confidence = detect(self._client({'README.md': '# notes'}))
        self.assertEqual(kind, UNKNOWN)
        self.assertEqual(skipped, set())
        self.assertLess(confidence, 0.5)

    def test_terraform_only_repository_loses_the_dependency_checks(self):
        from app.repo_kind import detect, INFRASTRUCTURE

        files = {
            'README.md': '# infra',
            'main.tf': 'provider "aws" {}\n',
            'variables.tf': 'variable "region" {}\n',
            'outputs.tf': 'output "id" {}\n',
        }
        kind, skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, INFRASTRUCTURE)
        self.assertIn('deps.manifest', skipped)
        self.assertIn('docker.dockerfile', skipped)

    # ── the score ───────────────────────────────────────────────────────────

    def test_a_library_is_not_marked_down_for_the_container_it_has_no_reason_to_build(self):
        from app.checks import run_all_checks

        checks = run_all_checks(self._client(self.LIBRARY))
        docker = [c for c in checks if c['check_id'].startswith('docker.')]
        self.assertTrue(docker)
        self.assertTrue(all(not c['applicable'] for c in docker))

    def test_a_missing_dockerfile_costs_a_service_rather_than_paying_it(self):
        """
        The four checks that read a Dockerfile used to pass when there was none —
        sixty warn-weight points for shipping no container at all, which put a
        repository with no Docker above one with a mediocre Dockerfile.
        """
        from app.checks import run_all_checks, calculate_score

        without = dict(self.SERVICE)
        del without['Dockerfile']
        without['k8s/deployment.yaml'] = 'kind: Deployment\n'
        with_good = dict(self.SERVICE)
        with_good['Dockerfile'] = (
            'FROM python:3.11 AS build\nFROM python:3.11-slim\n'
            'RUN adduser -S app\nUSER app\nHEALTHCHECK CMD curl -f /\n'
        )
        with_good['.dockerignore'] = '.git\n'

        score_without = calculate_score(run_all_checks(self._client(without)))
        score_with = calculate_score(run_all_checks(self._client(with_good)))
        self.assertGreater(score_with, score_without)

        vacuous = [
            c for c in run_all_checks(self._client(without))
            if c['check_id'] in ('docker.healthcheck', 'docker.pinned_base',
                                 'docker.multistage', 'docker.resource_limits')
        ]
        self.assertTrue(vacuous)
        for check in vacuous:
            self.assertFalse(check['applicable'], f"{check['check_id']} still scores without input")

    def test_a_service_without_a_dockerfile_is_still_marked_down(self):
        from app.checks import run_all_checks

        files = dict(self.SERVICE)
        del files['Dockerfile']
        files['k8s/deployment.yaml'] = 'kind: Deployment\n'
        checks = run_all_checks(self._client(files))
        dockerfile = [c for c in checks if c['check_id'] == 'docker.dockerfile'][0]
        self.assertTrue(dockerfile['applicable'])
        self.assertFalse(dockerfile['passed'])

    def test_set_aside_checks_are_kept_and_explained(self):
        """A check that simply vanished would read as one that was quietly failed."""
        from app.checks import run_all_checks

        checks = run_all_checks(self._client(self.LIBRARY))
        skipped = [c for c in checks if not c['applicable']]
        self.assertTrue(skipped)
        for check in skipped:
            self.assertTrue(check['not_applicable_reason'])

    def test_category_scores_ignore_what_does_not_apply(self):
        from app.checks import run_all_checks, get_category_scores

        checks = run_all_checks(self._client(self.LIBRARY))
        # Every Docker check is set aside, so the category carries no weight.
        self.assertNotIn('docker', get_category_scores(checks))

    # ── downstream of the score ─────────────────────────────────────────────

    def test_the_action_plan_does_not_suggest_the_impossible(self):
        from app.checks import run_all_checks
        from app.action_plan import build

        checks = run_all_checks(self._client(self.LIBRARY))
        rows = []
        for c in checks:
            rows.append(AuditCheck(
                check_id=c['check_id'], name=c['name'], description=c['description'],
                severity=c['severity'], passed=c['passed'], category=c['category'],
                recommendation=c['recommendation'], applicable=c['applicable'],
            ))
        plan = build(rows)
        if plan:
            for item in plan['items']:
                self.assertFalse(item['check'].check_id.startswith('docker.'))

    def test_compliance_does_not_report_an_unclosable_gap(self):
        from app.compliance import build_report

        rows = [
            AuditCheck(check_id='docker.nonroot', name='n', description='d',
                       severity='warn', passed=False, category='docker', applicable=False),
            AuditCheck(check_id='security.no_secrets', name='n', description='d',
                       severity='crit', passed=True, category='security', applicable=True),
        ]
        report = build_report(rows, 'soc2')
        for control in report['controls']:
            for check in control['failed']:
                self.assertNotEqual(check.check_id, 'docker.nonroot')

    # ── new kinds (Phase 1: cli / monorepo / docs / unknown) ──────────────────

    def test_a_python_console_script_does_not_override_the_library_reading(self):
        """
        Caught against the real fastapi/fastapi: its pyproject.toml declares
        both `[project]` and `[project.scripts]` (the `fastapi` dev/run
        command) — under PEP 621, `[project.scripts]` is a subtable of
        `[project]`, so the two are not independent signals and a console
        script is never, on its own, evidence that a Python package is *only*
        a CLI. Filing it as CLI cost the framework its Docker/observability
        checks for a wrapper it ships alongside a very real public API — the
        golden corpus (see tests/golden/) caught this on the first recording.
        """
        from app.repo_kind import detect, LIBRARY

        files = {
            'README.md': '# tool',
            'pyproject.toml': '[project]\nname = "widget"\n[project.scripts]\nwidget = "widget.cli:main"\n',
            'src/widget/__init__.py': 'def public_api(): pass\n',
        }
        kind, _skipped, _reason, confidence = detect(self._client(files))
        self.assertEqual(kind, LIBRARY)
        self.assertGreater(confidence, 0.5)

    def test_a_package_json_bin_with_no_exports_is_a_cli(self):
        from app.repo_kind import detect, CLI

        files = {
            'README.md': '# tool',
            'package.json': '{"name": "widget-cli", "bin": {"widget": "./cli.js"}}',
            'cli.js': 'console.log("hi")\n',
        }
        kind, _skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, CLI)

    def test_a_package_json_with_bin_and_exports_is_still_a_library(self):
        """A CLI helper bundled with a real import surface is the library, not the tool."""
        from app.repo_kind import detect, LIBRARY

        files = {
            'README.md': '# lib',
            'package.json': '{"name": "widget", "main": "index.js", "bin": {"widget": "./cli.js"}}',
            'index.js': 'module.exports = {}\n',
        }
        kind, _skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, LIBRARY)

    def test_a_go_cmd_main_with_no_deploy_artefact_is_a_cli(self):
        from app.repo_kind import detect, CLI

        files = {
            'README.md': '# tool',
            'go.mod': 'module example.com/widget\n\ngo 1.22\n',
            'cmd/widget/main.go': 'package main\n\nfunc main() {}\n',
        }
        kind, _skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, CLI)

    def test_a_go_module_with_a_top_level_package_is_a_library_not_a_cli(self):
        """A cmd/ helper shipped alongside an importable root package is the SDK, not the tool."""
        from app.repo_kind import detect, CLI

        files = {
            'README.md': '# sdk',
            'go.mod': 'module example.com/widget\n\ngo 1.22\n',
            'client.go': 'package widget\n\nfunc New() {}\n',
            'cmd/widget/main.go': 'package main\n\nfunc main() {}\n',
        }
        kind, _skipped, _reason, _confidence = detect(self._client(files))
        self.assertNotEqual(kind, CLI)

    def test_a_rust_crate_with_a_demo_binary_and_a_library_root_is_a_library(self):
        """`src/main.rs` next to `src/lib.rs` is a demo binary, not the product."""
        from app.repo_kind import detect, LIBRARY

        files = {
            'README.md': '# crate',
            'Cargo.toml': '[package]\nname = "widget"\nversion = "0.1.0"\n',
            'src/lib.rs': 'pub fn run() {}\n',
            'src/main.rs': 'fn main() { widget::run(); }\n',
        }
        kind, _skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, LIBRARY)

    def test_a_rust_crate_with_only_a_binary_is_a_cli(self):
        from app.repo_kind import detect, CLI

        files = {
            'README.md': '# tool',
            'Cargo.toml': '[package]\nname = "widget"\nversion = "0.1.0"\n',
            'src/main.rs': 'fn main() {}\n',
        }
        kind, _skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, CLI)

    def test_an_npm_package_with_a_files_allowlist_and_no_main_field_is_a_library(self):
        """
        Caught against the real expressjs/express: Node defaults to `index.js`
        when `main` is not declared, so express's package.json never names an
        entry point at all — only `"files"`, the allowlist actually published
        to the npm registry. The original heuristic required `main`/`exports`/
        `module`/`types` and missed it entirely.
        """
        from app.repo_kind import detect, LIBRARY

        files = {
            'README.md': '# lib',
            'package.json': '{"name": "widget", "files": ["index.js", "lib/"]}',
            'index.js': 'module.exports = {}\n',
        }
        kind, _skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, LIBRARY)

    def test_a_workspace_marker_makes_it_a_monorepo(self):
        from app.repo_kind import detect, MONOREPO

        files = {
            'README.md': '# workspace',
            'pnpm-workspace.yaml': "packages:\n  - 'packages/*'\n",
            'packages/a/package.json': '{"name": "a"}',
            'packages/b/package.json': '{"name": "b"}',
        }
        kind, skipped, reason, confidence = detect(self._client(files))
        self.assertEqual(kind, MONOREPO)
        self.assertIn('deps.pinned', skipped)
        self.assertTrue(reason)
        self.assertGreaterEqual(confidence, 0.85)

    def test_several_manifests_in_different_directories_suggest_a_monorepo(self):
        """Weaker than an explicit workspace marker — scored lower, not ignored."""
        from app.repo_kind import detect, MONOREPO

        files = {
            'README.md': '# workspace',
            'services/api/go.mod': 'module api\n',
            'services/worker/go.mod': 'module worker\n',
        }
        kind, _skipped, _reason, confidence = detect(self._client(files))
        self.assertEqual(kind, MONOREPO)
        self.assertLess(confidence, 0.85)

    def test_one_root_manifest_is_not_a_monorepo(self):
        from app.repo_kind import detect, MONOREPO

        kind, _skipped, _reason, _confidence = detect(self._client(self.LIBRARY))
        self.assertNotEqual(kind, MONOREPO)

    def test_a_monorepo_with_no_root_manifest_does_not_fail_deps_manifest(self):
        """
        A workspace whose every manifest sits one level down, with nothing at
        the root at all: `deps.manifest` (crit, 30 points) only reads the
        repository root, and would fail a repository that pins its
        dependencies just not at the one path the check looks at.
        """
        from app.repo_kind import detect, MONOREPO

        files = {
            'pnpm-workspace.yaml': "packages:\n  - 'backend'\n  - 'frontend'\n",
            'backend/pyproject.toml': '[project]\nname = "backend"\n',
            'frontend/package.json': '{"name": "frontend", "main": "index.js"}',
        }
        kind, skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, MONOREPO)
        self.assertIn('deps.manifest', skipped)
        self.assertIn('deps.lockfile', skipped)
        self.assertIn('deps.cve', skipped)

    def test_mkdocs_with_no_source_code_is_a_docs_site(self):
        from app.repo_kind import detect, DOCS

        files = {
            'mkdocs.yml': 'site_name: Widget docs\n',
            'docs/index.md': '# Widget\n',
            'docs/guide.md': '## Guide\n',
        }
        kind, skipped, reason, confidence = detect(self._client(files))
        self.assertEqual(kind, DOCS)
        self.assertIn('docker.dockerfile', skipped)
        self.assertIn('deps.manifest', skipped)
        self.assertTrue(reason)
        self.assertGreaterEqual(confidence, 0.8)

    def test_a_docs_site_with_a_dockerfile_is_a_service(self):
        """Someone deploys this with a real container — the container checks have something to read."""
        from app.repo_kind import detect, SERVICE

        files = {
            'mkdocs.yml': 'site_name: Widget docs\n',
            'docs/index.md': '# Widget\n',
            'Dockerfile': 'FROM squidfunk/mkdocs-material\n',
        }
        kind, _skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, SERVICE)

    def test_mostly_markdown_with_no_code_is_a_weak_docs_signal(self):
        from app.repo_kind import detect, DOCS

        files = {f'docs/page{i}.md': f'# page {i}\n' for i in range(6)}
        kind, _skipped, _reason, confidence = detect(self._client(files))
        self.assertEqual(kind, DOCS)
        self.assertLess(confidence, 0.8)

    def test_a_well_documented_terraform_module_is_not_a_docs_site(self):
        """
        Caught against the real terraform-aws-modules/terraform-aws-vpc: `.tf`
        is not a CODE_SUFFIXES extension, so `code_files == 0` was true of any
        Terraform module, and a well-kept one easily has five-plus markdown
        files in its README and examples. Filed as DOCS, it lost the
        infrastructure checks entirely instead of gaining the ones that
        actually apply to it.
        """
        from app.repo_kind import detect, INFRASTRUCTURE

        files = {
            'README.md': '# VPC module\n' + 'details\n' * 50,
            'main.tf': 'resource "aws_vpc" "this" {}\n',
            'variables.tf': 'variable "cidr" {}\n',
            'outputs.tf': 'output "id" {}\n',
            'examples/README.md': '# Example\n',
            'examples/complete/README.md': '# Complete example\n',
            'docs/faq.md': '# FAQ\n',
        }
        kind, _skipped, _reason, _confidence = detect(self._client(files))
        self.assertEqual(kind, INFRASTRUCTURE)

    def test_an_empty_repository_is_unknown_not_silently_a_service(self):
        from app.repo_kind import detect, UNKNOWN

        kind, skipped, _reason, confidence = detect(self._client({}))
        self.assertEqual(kind, UNKNOWN)
        # Same skip set as SERVICE — thin evidence is flagged, not forgiven.
        self.assertEqual(skipped, set())
        self.assertLess(confidence, 0.5)

    def test_unknown_is_still_graded_in_full(self):
        """Low confidence changes what a public page may claim, never what a check counts."""
        from app.checks import run_all_checks

        checks = run_all_checks(self._client({}))
        docker = [c for c in checks if c['check_id'] == 'docker.dockerfile'][0]
        self.assertTrue(docker['applicable'])

    def test_a_repository_declaring_its_own_kind_gets_full_confidence(self):
        from app.repo_kind import detect, LIBRARY

        kind, _skipped, reason, confidence = detect(self._client({'README.md': '# x'}), forced_kind=LIBRARY)
        self.assertEqual(kind, LIBRARY)
        self.assertEqual(confidence, 1.0)
        self.assertIn('.devopsaudit.yml', reason)


class GoldenCorpusTest(TestCase):
    """
    Regression guard for the audit engine against real, recorded repositories.

    `tests/golden/run_golden.py` does the same comparison from the command
    line, with a readable diff — reach for `make golden` when this test fails
    and the reason is not obvious from the assertion message alone. Both read
    the same fixtures and the same expected/ snapshots; this copy exists so a
    regression here fails an ordinary `manage.py test` run, not only a step
    someone has to remember to run separately.
    """
    FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'tests', 'golden', 'fixtures')
    EXPECTED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'tests', 'golden', 'expected')

    def test_every_fixture_matches_its_golden_expectation(self):
        from app.repo_client import StaticRepoClient
        from app.repo_kind import detect
        from app.checks import run_all_checks, calculate_score

        fixture_dir = os.path.normpath(self.FIXTURE_DIR)
        expected_dir = os.path.normpath(self.EXPECTED_DIR)
        fixtures = sorted(f for f in os.listdir(fixture_dir) if f.endswith('.json'))
        self.assertTrue(fixtures, 'tests/golden/fixtures/ is empty — nothing to check')

        for name in fixtures:
            with self.subTest(fixture=name):
                fx = json.load(open(os.path.join(fixture_dir, name)))
                client = StaticRepoClient(fx['files'], full_name=fx['full_name'])
                # Unkept content is '' in a fixture — unread, not empty (see run_golden.py).
                client.local_text = lambda path, files=fx['files']: files.get(path.strip('/')) or None
                kind, _skipped, _reason, confidence = detect(client)
                checks = run_all_checks(client)

                expected = json.load(open(os.path.join(expected_dir, name)))
                self.assertEqual(kind, expected['kind'], f'{name}: repo_kind changed')
                self.assertEqual(confidence, expected['confidence'], f'{name}: confidence changed')
                self.assertEqual(calculate_score(checks), expected['score'], f'{name}: score changed')

                actual_checks = {c['check_id']: c['passed'] for c in checks if c.get('applicable', True)}
                self.assertEqual(actual_checks, expected['checks'], f'{name}: a check outcome changed')


class AuditConfigTest(TestCase):
    """
    `.devopsaudit.yml` — the repository's own say.

    A scanner that cannot be argued with gets muted wholesale. This is the way
    out that does not involve turning the tool off, and the constraints on it
    are what keep the report usable as evidence.
    """

    BASE = {
        'README.md': '# app\n\n## Installation\n\n```\nmake up\n```\n',
        'requirements.txt': 'django==5.0.6\n',
        'Dockerfile': 'FROM python:3.11-slim\nCMD ["gunicorn"]\n',
        'src/app.py': 'x = 1\n',
    }

    def _run(self, config_text=None, extra=None):
        from app.repo_client import StaticRepoClient
        from app.checks import run_all_checks
        from app import audit_config

        files = dict(self.BASE, **(extra or {}))
        if config_text is not None:
            files['.devopsaudit.yml'] = config_text
        client = StaticRepoClient(files, full_name='acme/app')
        config = audit_config.load(client)
        return run_all_checks(client, config=config), config

    def _by_id(self, checks):
        return {c['check_id']: c for c in checks}

    # ── ignore ──────────────────────────────────────────────────────────────

    def test_an_ignored_check_leaves_the_score_and_stays_in_the_report(self):
        checks, config = self._run(
            'ignore:\n  - id: docker.nonroot\n    reason: base image runs as nobody\n'
        )
        check = self._by_id(checks)['docker.nonroot']
        self.assertFalse(check['applicable'])
        self.assertIn('base image runs as nobody', check['not_applicable_reason'])
        self.assertIn('devopsaudit.yml', check['not_applicable_reason'])
        self.assertEqual(config.errors, [])

    def test_an_ignore_without_a_reason_is_refused(self):
        """Someone reading this in a year has to be able to see why."""
        checks, config = self._run('ignore:\n  - docker.nonroot\n')
        self.assertTrue(self._by_id(checks)['docker.nonroot']['applicable'])
        self.assertEqual(len(config.errors), 1)
        self.assertIn('without a reason', config.errors[0])

    def test_the_secret_scanner_cannot_be_switched_off(self):
        checks, config = self._run(
            'ignore:\n  - id: security.no_secrets\n    reason: we know\n'
        )
        self.assertTrue(self._by_id(checks)['security.no_secrets']['applicable'])
        self.assertIn('cannot be ignored', ' '.join(config.errors))

    def test_ignoring_raises_the_score(self):
        from app.checks import calculate_score

        plain, _ = self._run()
        tuned, _ = self._run('ignore:\n  - id: docker.nonroot\n    reason: runs as nobody\n')
        self.assertGreater(calculate_score(tuned), calculate_score(plain))

    # ── severity ────────────────────────────────────────────────────────────

    def test_severity_can_be_lowered(self):
        checks, config = self._run('severity:\n  deps.lockfile: info\n')
        self.assertEqual(self._by_id(checks)['deps.lockfile']['severity'], 'info')
        self.assertEqual(config.errors, [])

    def test_an_invalid_severity_is_reported_and_ignored(self):
        checks, config = self._run('severity:\n  deps.lockfile: whatever\n')
        self.assertEqual(self._by_id(checks)['deps.lockfile']['severity'], 'warn')
        self.assertIn('must be one of', ' '.join(config.errors))

    # ── kind ────────────────────────────────────────────────────────────────

    def test_the_repository_can_declare_its_own_kind(self):
        """A heuristic nobody can correct is one people work around."""
        checks, config = self._run('kind: library\n')
        self.assertEqual(config.kind, 'library')
        self.assertFalse(self._by_id(checks)['docker.nonroot']['applicable'])

    def test_an_unknown_kind_is_reported_and_detection_stands(self):
        checks, config = self._run('kind: potato\n')
        self.assertEqual(config.kind, '')
        self.assertTrue(self._by_id(checks)['docker.nonroot']['applicable'])
        self.assertIn('kind must be one of', ' '.join(config.errors))

    # ── allow_secrets ───────────────────────────────────────────────────────

    def test_allowed_paths_are_not_scanned_for_secrets(self):
        key = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----\n'
        extra = {'deploy/keys/id_rsa': key}

        without, _ = self._run(extra=extra)
        self.assertFalse(self._by_id(without)['security.no_secrets']['passed'])

        allowed, config = self._run('allow_secrets:\n  - deploy/keys/\n', extra=extra)
        self.assertTrue(self._by_id(allowed)['security.no_secrets']['passed'])
        self.assertEqual(config.errors, [])

    # ── fail_under ──────────────────────────────────────────────────────────

    def test_fail_under_is_read_and_bounded(self):
        _checks, ok = self._run('fail_under: 70\n')
        self.assertEqual(ok.fail_under, 70)

        _checks, bad = self._run('fail_under: 500\n')
        self.assertIsNone(bad.fail_under)
        self.assertIn('between 0 and 100', ' '.join(bad.errors))

    # ── a broken file must never be a broken audit ──────────────────────────

    def test_unparseable_yaml_is_reported_and_the_audit_runs(self):
        checks, config = self._run('ignore: [unclosed\n')
        self.assertTrue(checks)
        self.assertTrue(config.errors)

    def test_no_config_is_the_normal_case(self):
        checks, config = self._run()
        self.assertFalse(config.present)
        self.assertEqual(config.errors, [])
        # Nothing is set aside on the repository's say-so, because it said nothing.
        # Checks the engine itself skipped for want of input are a separate thing.
        self.assertEqual(
            [c['check_id'] for c in checks
             if 'devopsaudit.yml' in (c.get('not_applicable_reason') or '')],
            [],
        )
        self.assertTrue(self._by_id(checks)['docker.nonroot']['applicable'])


class ChangedFindingsTest(TestCase):
    """
    What this push broke, rather than what the repository scores.

    A reviewer is looking at one change. A whole-repository number tells them
    nothing about it, which is how a pull request comment turns into something
    people mute.
    """

    def setUp(self):
        self.user = make_user('deltauser')

    def _audit(self, failing_ids, when=None):
        audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u',
            source='github', status=Audit.STATUS_DONE, score=50,
        )
        if when:
            Audit.objects.filter(pk=audit.pk).update(created_at=when)
            audit.refresh_from_db()
        AuditCheck.objects.bulk_create([
            AuditCheck(audit=audit, check_id=cid, name=cid, description='d',
                       severity='warn', passed=cid in failing_ids and False or True,
                       category='ops', applicable=True, severity_rank=1)
            for cid in ('a.one', 'a.two', 'a.three')
        ])
        AuditCheck.objects.filter(audit=audit, check_id__in=failing_ids).update(passed=False)
        return audit

    def test_first_run_reports_nothing_as_new(self):
        audit = self._audit({'a.one'})
        appeared, resolved = audit.changed_findings()
        self.assertEqual(appeared, [])
        self.assertEqual(resolved, [])

    def test_a_new_failure_is_reported_as_new(self):
        self._audit({'a.one'}, when=timezone.now() - timedelta(days=1))
        latest = self._audit({'a.one', 'a.two'})
        appeared, resolved = latest.changed_findings()
        self.assertEqual([c.check_id for c in appeared], ['a.two'])
        self.assertEqual(resolved, [])

    def test_a_fixed_failure_is_reported_as_resolved(self):
        self._audit({'a.one', 'a.two'}, when=timezone.now() - timedelta(days=1))
        latest = self._audit({'a.one'})
        appeared, resolved = latest.changed_findings()
        self.assertEqual(appeared, [])
        self.assertEqual(resolved, ['a.two'])

    def test_a_check_set_aside_does_not_count_as_fixed(self):
        """Otherwise ignoring a finding would read as having solved it."""
        self._audit({'a.one'}, when=timezone.now() - timedelta(days=1))
        latest = self._audit({'a.one'})
        AuditCheck.objects.filter(audit=latest, check_id='a.one').update(applicable=False)
        appeared, resolved = latest.changed_findings()
        self.assertEqual(appeared, [])
        self.assertEqual(resolved, ['a.one'])


class ScoreGateTest(TestCase):
    """`fail_under` is what turns the report into something CI can block on."""

    def setUp(self):
        self.user = make_user('gateuser')

    def _audit(self, score, fail_under):
        return Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u', source='github',
            status=Audit.STATUS_DONE, score=score, fail_under=fail_under,
        )

    def test_no_threshold_means_no_verdict(self):
        """Most repositories set none, and inventing one makes every audit a failure."""
        self.assertIsNone(self._audit(40, None).gate)

    def test_a_score_at_the_threshold_passes(self):
        self.assertTrue(self._audit(70, 70).gate)

    def test_a_score_below_the_threshold_fails(self):
        self.assertFalse(self._audit(69, 70).gate)

    def test_the_report_shows_the_verdict(self):
        audit = self._audit(40, 70)
        client = Client()
        client.force_login(self.user)
        html = client.get(reverse('audit_detail', args=[audit.id])).content.decode()
        self.assertIn('fail_under', html)

    def test_the_report_shows_what_is_wrong_with_the_config(self):
        audit = self._audit(80, None)
        audit.config_errors = ['kind must be one of service, library, infrastructure.']
        audit.save(update_fields=['config_errors'])
        client = Client()
        client.force_login(self.user)
        html = client.get(reverse('audit_detail', args=[audit.id])).content.decode()
        self.assertIn('kind must be one of', html)


class ProviderConnectionTest(TestCase):
    """
    A dead token used to be invisible.

    GitLab bounced the owner back to the profile page, which reads as the page
    refusing to load; GitHub deleted the connection outright on a single 401,
    losing the installation id with it. Neither said anything.
    """

    def setUp(self):
        self.user = make_user('connuser', email='conn@test.com')
        self.client = Client()
        self.client.force_login(self.user)

    def _gitlab(self):
        return GitlabProfile.objects.create(
            user=self.user, gitlab_id=4242, gitlab_username='acme-gl',
            access_token='glpat-whatever',
        )

    def _github(self):
        return GithubProfile.objects.create(
            user=self.user, github_id=4242, github_login='acme-gh',
            access_token='gho_whatever', installation_id=99,
        )

    # ── state ───────────────────────────────────────────────────────────────

    def test_a_fresh_connection_is_healthy(self):
        self.assertTrue(self._gitlab().is_healthy)

    def test_breaking_records_when_it_started_and_keeps_it(self):
        profile = self._gitlab()
        profile.mark_broken(GitlabProfile.EXPIRED)
        first = profile.token_broken_since
        self.assertIsNotNone(first)

        profile.mark_broken(GitlabProfile.EXPIRED)
        profile.refresh_from_db()
        self.assertEqual(profile.token_broken_since, first,
                         'the outage started when it started, not on the last check')

    def test_recovery_clears_the_outage_and_rearms_the_alert(self):
        profile = self._gitlab()
        profile.mark_broken(GitlabProfile.EXPIRED)
        profile.token_notified_at = timezone.now()
        profile.save(update_fields=['token_notified_at'])

        profile.mark_working()
        profile.refresh_from_db()
        self.assertTrue(profile.is_healthy)
        self.assertIsNone(profile.token_broken_since)
        self.assertIsNone(profile.token_notified_at)

    def test_every_broken_state_explains_itself(self):
        profile = self._gitlab()
        for status in (GitlabProfile.EXPIRED, GitlabProfile.FORBIDDEN, GitlabProfile.UNREACHABLE):
            profile.token_status = status
            self.assertTrue(profile.status_message, f'{status} says nothing')

    # ── the dashboard that did nothing ──────────────────────────────────────

    def test_an_expired_gitlab_token_is_recorded_rather_than_swallowed(self):
        profile = self._gitlab()

        class Resp:
            status_code = 401
            def json(self):
                return {}

        with patch('app.views.requests.get', return_value=Resp()):
            response = self.client.get(reverse('gitlab_dashboard'))

        profile.refresh_from_db()
        self.assertEqual(profile.token_status, GitlabProfile.EXPIRED)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(GitlabProfile.objects.filter(pk=profile.pk).exists())

    #: The notice element; matched on markup rather than on wording, because the
    #: stylesheet ships inline and its comments would satisfy a text search.
    NOTICE = '<div class="conn-notice" role="status">'
    BROKEN_CARD = 'connect-status-ok needs-token'

    def test_the_profile_page_says_what_happened(self):
        profile = self._gitlab()
        profile.mark_broken(GitlabProfile.EXPIRED)
        html = self.client.get(reverse('connect')).content.decode()
        self.assertIn(self.NOTICE, html)
        self.assertIn('acme-gl', html)
        self.assertIn(str(profile.status_message), html)

    def test_a_healthy_account_shows_no_alarm(self):
        self._gitlab()
        html = self.client.get(reverse('connect')).content.decode()
        self.assertNotIn(self.NOTICE, html)
        self.assertNotIn(self.BROKEN_CARD, html)

    def test_a_broken_account_does_not_wear_a_green_tick(self):
        """
        The card said "connected" while the notice above said the opposite.
        Contradicting yourself on one page teaches people to read neither.
        """
        profile = self._gitlab()
        profile.mark_broken(GitlabProfile.EXPIRED)
        html = self.client.get(reverse('connect')).content.decode()
        self.assertIn(self.BROKEN_CARD, html)

    def test_a_broken_connection_is_not_offered_a_dashboard_link(self):
        """That link is the one that appeared to do nothing."""
        profile = self._gitlab()
        profile.mark_broken(GitlabProfile.EXPIRED)
        html = self.client.get(reverse('connect')).content.decode()
        self.assertNotIn('Open Dashboard', html)
        self.assertIn('Add a new token below', html)

    def test_a_github_401_no_longer_deletes_the_connection(self):
        """Deleting it turns a token refresh into a full re-install."""
        profile = self._github()

        class Resp:
            status_code = 401
            def json(self):
                return []

        # An App install (installation_id=99, see _github()) mints a fresh
        # token before every call now (see GithubProfile.current_token) — the
        # 401 under test is GitHub's, on the request that follows, not a
        # minting failure, so the mint itself has to succeed here.
        with patch('app.github_app.installation_token', return_value=('fresh', '2099-01-01T00:00:00Z')):
            with patch('app.views.requests.get', return_value=Resp()):
                self.client.get(reverse('dashboard'))

        profile.refresh_from_db()
        self.assertEqual(profile.token_status, GithubProfile.EXPIRED)
        self.assertEqual(profile.installation_id, 99)

    # ── noticing before the customer does ───────────────────────────────────

    def test_the_scheduled_check_emails_once_per_outage(self):
        from django.core import mail
        from app.tasks import check_provider_connections

        self._gitlab()

        class Resp:
            status_code = 401

        with patch('requests.get', return_value=Resp()):
            self.assertEqual(check_provider_connections(), 1)
            self.assertEqual(len(mail.outbox), 1)
            self.assertIn('stopped working', mail.outbox[0].subject)

            # A second run during the same outage must stay quiet.
            self.assertEqual(check_provider_connections(), 0)
            self.assertEqual(len(mail.outbox), 1)

    def test_a_recovered_connection_can_alert_again(self):
        from django.core import mail
        from app.tasks import check_provider_connections

        profile = self._gitlab()

        class Bad:
            status_code = 401

        class Good:
            status_code = 200

        with patch('requests.get', return_value=Bad()):
            check_provider_connections()
        with patch('requests.get', return_value=Good()):
            check_provider_connections()
        profile.refresh_from_db()
        self.assertTrue(profile.is_healthy)

        with patch('requests.get', return_value=Bad()):
            check_provider_connections()
        self.assertEqual(len(mail.outbox), 2)

    def test_someone_who_turned_notifications_off_is_left_alone(self):
        from django.core import mail
        from app.models import UserProfile
        from app.tasks import check_provider_connections

        self._gitlab()
        UserProfile.objects.update_or_create(
            user=self.user, defaults={'email_notifications': False},
        )

        class Resp:
            status_code = 401

        with patch('requests.get', return_value=Resp()):
            check_provider_connections()
        self.assertEqual(len(mail.outbox), 0)


class GithubAppTokenRefreshTest(TestCase):
    """
    GitHub App installation tokens expire in one hour. `github_app_callback`
    only ever minted one, at connect time, and every caller read it straight
    off `GithubProfile.access_token` with no expiry check and no re-mint —
    so an App-connected account's first audit worked and every one after the
    first hour got a 401 that read as "token expired, reconnect" when nothing
    was actually wrong. Found reading the code during Phase 0, not reported
    by a user — `GithubProfile.current_token` is the fix: every caller reads
    it instead of `access_token` directly, and it mints fresh for an App
    install rather than trusting whatever was stored at connect time.
    """

    def setUp(self):
        self.user = make_user('appuser', email='app@test.com')

    def _pat_profile(self):
        return GithubProfile.objects.create(
            user=self.user, github_id=1, github_login='pat-acct',
            access_token='ghp_the_real_pat',
        )

    def _app_profile(self, stored='stale_token_from_connect_time'):
        return GithubProfile.objects.create(
            user=self.user, github_id=2, github_login='app-acct',
            access_token=stored, installation_id=555,
        )

    def test_a_pat_connection_returns_its_own_token_unchanged(self):
        profile = self._pat_profile()
        with patch('app.github_app.installation_token') as mint:
            self.assertEqual(profile.current_token, 'ghp_the_real_pat')
            mint.assert_not_called()

    def test_an_app_connection_mints_a_fresh_token_rather_than_trusting_the_stored_one(self):
        profile = self._app_profile()
        with patch('app.github_app.installation_token', return_value=('fresh_token', '2099-01-01T00:00:00Z')) as mint:
            token = profile.current_token
        self.assertEqual(token, 'fresh_token')
        self.assertNotEqual(token, 'stale_token_from_connect_time')
        mint.assert_called_once_with(555)

    def test_a_failed_mint_raises_rather_than_silently_falling_back_to_the_stale_token(self):
        from app.github_app import GitHubAppError
        profile = self._app_profile()
        with patch('app.github_app.installation_token', side_effect=GitHubAppError('installation revoked')):
            with self.assertRaises(GitHubAppError):
                profile.current_token

    def test_build_client_for_audit_uses_the_fresh_token(self):
        from app.repo_client import build_client_for_audit
        profile = self._app_profile()
        audit = Audit.objects.create(
            user=self.user, repo_full_name='acme/thing', repo_url='https://github.com/acme/thing',
            source=Audit.SOURCE_GITHUB,
        )
        with patch('app.github_app.installation_token', return_value=('fresh_token', '2099-01-01T00:00:00Z')):
            with patch('app.repo_client.GithubRepoClient') as client_cls:
                client_cls.return_value.load.return_value = MagicMock()
                build_client_for_audit(audit)
        self.assertEqual(client_cls.call_args.args[1], 'fresh_token')

    def test_post_pr_comment_authenticates_with_the_fresh_token(self):
        from app.tasks import post_pr_comment
        self._app_profile()
        audit = Audit.objects.create(
            user=self.user, repo_full_name='acme/thing', repo_url='https://github.com/acme/thing',
            source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=80,
            pr_number=7, trigger=Audit.TRIGGER_PR,
        )
        with patch('app.github_app.installation_token', return_value=('fresh_token', '2099-01-01T00:00:00Z')):
            with patch('requests.post') as post:
                post.return_value = MagicMock(status_code=201)
                post_pr_comment(audit.id)
        self.assertEqual(post.call_args.kwargs['headers']['Authorization'], 'token fresh_token')

    def test_the_daily_health_check_does_not_flag_an_app_connection_broken_from_a_stale_stored_token(self):
        """
        Before this fix, check_provider_connections read access_token
        directly — an App connection older than an hour would fail the
        health-check's own GitHub call with the same 401 an audit would have
        hit, and the daily job (crontab hour=7) would mail the owner a false
        "reconnect" notice once a day, forever, for an account nothing was
        wrong with.
        """
        from app.tasks import check_provider_connections
        profile = self._app_profile()

        with patch('app.github_app.installation_token', return_value=('fresh_token', '2099-01-01T00:00:00Z')):
            with patch('requests.get', return_value=MagicMock(status_code=200)) as get:
                check_provider_connections()

        self.assertEqual(get.call_args.kwargs['headers']['Authorization'], 'token fresh_token')
        profile.refresh_from_db()
        self.assertTrue(profile.is_healthy)


class GitlabOAuthTokenRefreshTest(TestCase):
    """
    gitlab.com's OAuth2 provider always expires the access token it issues
    (~2h) and hands back a rotating refresh token alongside it — unlike a
    personal access token, which never expires on its own. Found while
    investigating whether "Continue with GitLab" connections needed the same
    fix `GithubProfile.current_token` got for App installation tokens;
    surfaced a more urgent bug along the way (allauth's own SocialToken table
    holding the same token in plaintext — fixed separately, see
    docs/CHANGELOG_INTERNAL.md). This is the refresh mechanism itself.
    """

    def setUp(self):
        self.user = make_user('gloauthuser', email='gloauth@test.com')

    def _pat_profile(self):
        return GitlabProfile.objects.create(
            user=self.user, gitlab_id=1, gitlab_username='pat-acct',
            access_token='glpat-the-real-pat',
        )

    def _oauth_profile(self, expires_at, stored='stale_access_token'):
        return GitlabProfile.objects.create(
            user=self.user, gitlab_id=2, gitlab_username='oauth-acct',
            access_token=stored, refresh_token='the_refresh_token',
            token_expires_at=expires_at,
        )

    def test_a_pat_connection_returns_its_own_token_unchanged(self):
        profile = self._pat_profile()
        with patch('app.gitlab_oauth.refresh') as refresh:
            self.assertEqual(profile.current_token, 'glpat-the-real-pat')
            refresh.assert_not_called()

    def test_an_unexpired_oauth_token_is_returned_without_refreshing(self):
        profile = self._oauth_profile(
            expires_at=timezone.now() + timedelta(hours=1), stored='still_good',
        )
        with patch('app.gitlab_oauth.refresh') as refresh:
            self.assertEqual(profile.current_token, 'still_good')
            refresh.assert_not_called()

    def test_a_token_inside_the_two_minute_safety_margin_is_refreshed(self):
        profile = self._oauth_profile(
            expires_at=timezone.now() + timedelta(seconds=30),
        )
        with patch('app.gitlab_oauth.refresh', return_value='fresh_access_token') as refresh:
            token = profile.current_token
        self.assertEqual(token, 'fresh_access_token')
        refresh.assert_called_once_with(profile)

    def test_an_already_expired_token_is_refreshed(self):
        profile = self._oauth_profile(
            expires_at=timezone.now() - timedelta(minutes=5),
        )
        with patch('app.gitlab_oauth.refresh', return_value='fresh_access_token') as refresh:
            token = profile.current_token
        self.assertEqual(token, 'fresh_access_token')
        refresh.assert_called_once_with(profile)

    def test_a_token_with_no_recorded_expiry_is_refreshed_rather_than_trusted(self):
        """
        `token_expires_at` is null whenever gitlab.com's response omitted
        `expires_in` — treated as already-expired rather than as "never
        expires", since only a genuinely-empty `refresh_token` means that.
        """
        profile = self._oauth_profile(expires_at=None)
        with patch('app.gitlab_oauth.refresh', return_value='fresh_access_token') as refresh:
            token = profile.current_token
        self.assertEqual(token, 'fresh_access_token')
        refresh.assert_called_once_with(profile)

    def test_a_failed_refresh_raises_rather_than_silently_falling_back_to_the_stale_token(self):
        from app.gitlab_oauth import GitlabOAuthError
        profile = self._oauth_profile(expires_at=timezone.now() - timedelta(minutes=5))
        with patch('app.gitlab_oauth.refresh', side_effect=GitlabOAuthError('reconnect')):
            with self.assertRaises(GitlabOAuthError):
                profile.current_token

    def test_build_client_for_audit_uses_the_fresh_token(self):
        from app.repo_client import build_client_for_audit
        profile = self._oauth_profile(expires_at=timezone.now() - timedelta(minutes=5))
        audit = Audit.objects.create(
            user=self.user, repo_full_name='acme/thing::999',
            repo_url='https://gitlab.com/acme/thing',
            source=Audit.SOURCE_GITLAB,
        )
        with patch('app.gitlab_oauth.refresh', return_value='fresh_access_token'):
            with patch('app.repo_client.GitlabRepoClient') as client_cls:
                client_cls.return_value.load.return_value = MagicMock()
                build_client_for_audit(audit)
        self.assertEqual(client_cls.call_args.args[1], 'fresh_access_token')

    def test_the_daily_health_check_authenticates_with_the_fresh_token(self):
        from app.tasks import check_provider_connections
        self._oauth_profile(expires_at=timezone.now() - timedelta(minutes=5))

        with patch('app.gitlab_oauth.refresh', return_value='fresh_access_token'):
            with patch('requests.get', return_value=MagicMock(status_code=200)) as get:
                check_provider_connections()

        self.assertEqual(
            get.call_args.kwargs['headers']['Authorization'], 'Bearer fresh_access_token',
        )


class GitlabOAuthRefreshRequestTest(TestCase):
    """
    `gitlab_oauth.refresh()` itself — the HTTP exchange, kept separate from
    `current_token`'s expiry logic above so a change to when refresh is
    triggered can't hide a break in how it talks to gitlab.com.
    """

    def setUp(self):
        self.user = make_user('gloauthreq', email='gloauthreq@test.com')
        self.profile = GitlabProfile.objects.create(
            user=self.user, gitlab_id=3, gitlab_username='refreshed-acct',
            access_token='stale_access_token', refresh_token='original_refresh_token',
            token_expires_at=timezone.now() - timedelta(minutes=5),
        )

    def test_a_successful_refresh_saves_the_new_access_and_refresh_tokens(self):
        from app.gitlab_oauth import refresh
        with patch('requests.post') as post:
            post.return_value = MagicMock(
                status_code=200,
                json=lambda: {
                    'access_token': 'brand_new_access_token',
                    'refresh_token': 'brand_new_refresh_token',
                    'expires_in': 7200,
                },
            )
            token = refresh(self.profile)

        self.assertEqual(token, 'brand_new_access_token')
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.access_token, 'brand_new_access_token')
        self.assertEqual(self.profile.refresh_token, 'brand_new_refresh_token')
        self.assertGreater(self.profile.token_expires_at, timezone.now() + timedelta(hours=1, minutes=59))

    def test_the_request_spends_the_refresh_token_gitlab_actually_has_on_file(self):
        from app.gitlab_oauth import refresh
        with patch('requests.post') as post:
            post.return_value = MagicMock(
                status_code=200,
                json=lambda: {'access_token': 'x', 'refresh_token': 'y', 'expires_in': 7200},
            )
            refresh(self.profile)
        self.assertEqual(post.call_args.kwargs['data']['refresh_token'], 'original_refresh_token')
        self.assertEqual(post.call_args.kwargs['data']['grant_type'], 'refresh_token')

    def test_a_response_with_no_rotated_refresh_token_keeps_the_previous_one(self):
        """
        Unusual, since GitLab rotates it on every use, but a response that
        omits it should not discard a refresh token that is still the one
        gitlab.com expects next time.
        """
        from app.gitlab_oauth import refresh
        with patch('requests.post') as post:
            post.return_value = MagicMock(
                status_code=200,
                json=lambda: {'access_token': 'brand_new_access_token', 'expires_in': 7200},
            )
            refresh(self.profile)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.refresh_token, 'original_refresh_token')

    def test_a_missing_expires_in_clears_the_recorded_expiry_rather_than_keeping_a_stale_one(self):
        from app.gitlab_oauth import refresh
        with patch('requests.post') as post:
            post.return_value = MagicMock(
                status_code=200,
                json=lambda: {'access_token': 'brand_new_access_token', 'refresh_token': 'r'},
            )
            refresh(self.profile)
        self.profile.refresh_from_db()
        self.assertIsNone(self.profile.token_expires_at)

    def test_a_non_200_response_raises_a_user_facing_error_and_saves_nothing(self):
        from app.gitlab_oauth import refresh, GitlabOAuthError
        with patch('requests.post') as post:
            post.return_value = MagicMock(status_code=400, json=lambda: {'error': 'invalid_grant'})
            with self.assertRaises(GitlabOAuthError):
                refresh(self.profile)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.access_token, 'stale_access_token')
        self.assertEqual(self.profile.refresh_token, 'original_refresh_token')

    def test_the_request_authenticates_as_the_gitlab_app_not_the_user(self):
        from app.gitlab_oauth import refresh
        with patch('requests.post') as post:
            post.return_value = MagicMock(
                status_code=200,
                json=lambda: {'access_token': 'x', 'refresh_token': 'y', 'expires_in': 7200},
            )
            refresh(self.profile)
        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs['data']['client_id'], settings.GITLAB_APP_ID)
        self.assertEqual(kwargs['data']['client_secret'], settings.GITLAB_APP_SECRET)


class CiApiTest(TestCase):
    """
    The API the GitHub Action drives.

    A gate is only meaningful if it grades the commit under test. Auditing the
    default branch and calling it a check on a pull request reports on code the
    change has not touched.
    """

    def setUp(self):
        self.user = make_user('ciuser', email='ci@test.com')
        profile = self.user.profile if hasattr(self.user, 'profile') else None
        from app.models import UserProfile
        profile, _ = UserProfile.objects.get_or_create(user=self.user)
        profile.ensure_api_token()
        self.token = profile.api_token
        self.client = Client()

    def _post(self, payload):
        return self.client.post(
            reverse('api_audit_start'), data=json.dumps(payload),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
        )

    def _get(self, audit_id):
        return self.client.get(
            reverse('api_audit_detail', args=[audit_id]),
            HTTP_AUTHORIZATION=f'Bearer {self.token}',
        )

    # ── starting a run ──────────────────────────────────────────────────────

    def test_the_ref_under_test_is_recorded(self):
        with patch('app.tasks.run_audit_task') as task:
            task.delay.return_value = MagicMock(id='t1')
            response = self._post({'repo': 'org/repo', 'ref': 'feat/thing',
                                   'commit_sha': 'a' * 40, 'pr_number': 7})
        self.assertEqual(response.status_code, 201)
        audit = Audit.objects.get(id=response.json()['audit_id'])
        self.assertEqual(audit.ref, 'feat/thing')
        self.assertEqual(audit.commit_sha, 'a' * 40)
        self.assertEqual(audit.pr_number, 7)
        self.assertEqual(audit.trigger, Audit.TRIGGER_PR)

    def test_two_branches_of_one_repository_both_run(self):
        """Two CI jobs on two branches is a normal Tuesday, not a duplicate."""
        with patch('app.tasks.run_audit_task') as task:
            task.delay.return_value = MagicMock(id='t1')
            first = self._post({'repo': 'org/repo', 'ref': 'main'})
            second = self._post({'repo': 'org/repo', 'ref': 'feat/other'})
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 201)
        self.assertNotEqual(first.json()['audit_id'], second.json()['audit_id'])

    def test_the_same_ref_twice_joins_the_run_already_going(self):
        """Failing the second job would fail a check for a reason nobody can see."""
        with patch('app.tasks.run_audit_task') as task:
            task.delay.return_value = MagicMock(id='t1')
            first = self._post({'repo': 'org/repo', 'ref': 'main'})
            second = self._post({'repo': 'org/repo', 'ref': 'main'})
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()['duplicate'])
        self.assertEqual(second.json()['audit_id'], first.json()['audit_id'])

    def test_a_token_is_required(self):
        response = self.client.post(
            reverse('api_audit_start'), data=json.dumps({'repo': 'org/repo'}),
            content_type='application/json',
        )
        self.assertIn(response.status_code, (401, 403))

    # ── what CI needs back ──────────────────────────────────────────────────

    def test_the_result_carries_everything_the_gate_needs(self):
        audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u', source='github',
            status=Audit.STATUS_DONE, score=61, fail_under=70, ref='feat/thing',
            repo_kind='service', config_errors=['kind must be one of service, library, infrastructure.'],
        )
        AuditCheck.objects.create(
            audit=audit, check_id='iac.open_ingress', name='Open ingress', description='d',
            severity='crit', passed=False, category='iac', applicable=True, severity_rank=0,
        )
        AuditCheck.objects.create(
            audit=audit, check_id='docker.nonroot', name='Non-root', description='d',
            severity='warn', passed=False, category='docker', applicable=False,
            not_applicable_reason='library', severity_rank=1,
        )

        body = self._get(audit.id).json()
        self.assertEqual(body['ref'], 'feat/thing')
        self.assertEqual(body['fail_under'], 70)
        self.assertIs(body['gate'], False)
        self.assertEqual(body['repo_kind'], 'service')
        self.assertTrue(body['config_errors'])
        self.assertIn('url', body)

        by_id = {c['check_id']: c for c in body['checks']}
        self.assertTrue(by_id['iac.open_ingress']['applicable'])
        self.assertFalse(by_id['docker.nonroot']['applicable'])
        self.assertEqual(by_id['docker.nonroot']['not_applicable_reason'], 'library')

    def test_the_result_says_what_this_run_introduced(self):
        earlier = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u', source='github',
            status=Audit.STATUS_DONE, score=70,
        )
        AuditCheck.objects.create(
            audit=earlier, check_id='a.one', name='n', description='d',
            severity='warn', passed=False, category='ops', applicable=True, severity_rank=1,
        )
        latest = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u', source='github',
            status=Audit.STATUS_DONE, score=60,
        )
        for cid, passed in (('a.one', False), ('a.two', False)):
            AuditCheck.objects.create(
                audit=latest, check_id=cid, name='n', description='d',
                severity='warn', passed=passed, category='ops', applicable=True, severity_rank=1,
            )

        body = self._get(latest.id).json()
        self.assertEqual(body['new_findings'], ['a.two'])
        self.assertEqual(body['resolved_findings'], [])
        self.assertEqual(body['score_delta'], -10)

    def test_no_threshold_means_no_verdict_for_ci(self):
        audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u', source='github',
            status=Audit.STATUS_DONE, score=20,
        )
        self.assertIsNone(self._get(audit.id).json()['gate'])

    def test_another_users_audit_is_not_readable(self):
        other = make_user('ciother', email='o@test.com')
        audit = Audit.objects.create(
            user=other, repo_full_name='org/repo', repo_url='u', source='github',
            status=Audit.STATUS_DONE, score=90,
        )
        self.assertEqual(self._get(audit.id).status_code, 404)


class RefReadingTest(TestCase):
    """The client has to read the ref it was given, not whatever is on main."""

    def test_a_github_client_defaults_to_the_default_branch(self):
        from app.repo_client import GithubRepoClient
        self.assertEqual(GithubRepoClient('org/repo').ref, '')

    def test_a_github_client_keeps_the_ref_it_was_given(self):
        from app.repo_client import GithubRepoClient
        self.assertEqual(GithubRepoClient('org/repo', ref='feat/x').ref, 'feat/x')

    def test_the_audit_ref_reaches_the_client(self):
        from app.repo_client import build_client_for_audit

        user = make_user('refuser')
        GithubProfile.objects.create(
            user=user, github_id=1, github_login='x', access_token='t',
        )
        audit = Audit.objects.create(
            user=user, repo_full_name='org/repo', repo_url='u',
            source='github', status=Audit.STATUS_PENDING, ref='release/2.0',
        )
        with patch('app.repo_client.GithubRepoClient.load', side_effect=lambda self=None: None):
            with patch('app.repo_client.GithubRepoClient.__init__', return_value=None) as init:
                try:
                    build_client_for_audit(audit)
                except Exception:
                    pass
        self.assertEqual(init.call_args.kwargs.get('ref'), 'release/2.0')


class ReconnectDestinationTest(TestCase):
    """
    Where "reconnect" sends you.

    A customer on a self-hosted GitLab sent to gitlab.com is the kind of small
    wrongness that makes a product feel built for somebody else — and the form
    they land on used to default the instance URL back to gitlab.com, so
    reconnecting quietly pointed the account at the wrong server.
    """

    SELF_HOSTED = 'https://gitlab.acme-internal.example.com'

    def setUp(self):
        self.user = make_user('reconnector', email='r@test.com')
        self.client = Client()
        self.client.force_login(self.user)

    def _gitlab(self, url='https://gitlab.com', **extra):
        return GitlabProfile.objects.create(
            user=self.user, gitlab_id=11, gitlab_username='acme-gl',
            access_token='glpat-x', gitlab_url=url, **extra,
        )

    # ── the link out ────────────────────────────────────────────────────────

    def test_a_cloud_account_points_at_gitlab_com(self):
        profile = self._gitlab()
        self.assertEqual(profile.host, 'gitlab.com')
        self.assertTrue(profile.token_page_url.startswith('https://gitlab.com/'))

    def test_a_self_hosted_account_points_at_its_own_instance(self):
        profile = self._gitlab(url=self.SELF_HOSTED)
        self.assertEqual(profile.host, 'gitlab.acme-internal.example.com')
        self.assertTrue(profile.token_page_url.startswith(self.SELF_HOSTED + '/'))
        self.assertNotIn('gitlab.com', profile.token_page_url)

    def test_a_trailing_slash_does_not_double_up(self):
        profile = self._gitlab(url=self.SELF_HOSTED + '/')
        self.assertNotIn('//-/', profile.token_page_url)

    def test_github_points_at_a_prefilled_token_form(self):
        profile = GithubProfile.objects.create(
            user=self.user, github_id=11, github_login='acme', access_token='gho_x',
        )
        self.assertIn('github.com/settings/tokens/new', profile.token_page_url)
        self.assertIn('scopes=repo', profile.token_page_url)

    # ── what the page offers ────────────────────────────────────────────────

    def test_the_notice_links_to_the_right_instance(self):
        profile = self._gitlab(url=self.SELF_HOSTED)
        profile.mark_broken(GitlabProfile.EXPIRED)
        html = self.client.get(reverse('connect')).content.decode()
        self.assertIn(self.SELF_HOSTED + '/-/user_settings/personal_access_tokens', html)
        self.assertIn('gitlab.acme-internal.example.com', html)

    def test_the_reconnect_form_comes_back_with_the_same_instance(self):
        """It used to default to gitlab.com, pointing the account at the wrong server."""
        profile = self._gitlab(url=self.SELF_HOSTED, custom_dns='10.0.0.53', verify_ssl=False)
        profile.mark_broken(GitlabProfile.EXPIRED)
        html = self.client.get(reverse('connect')).content.decode()
        self.assertIn(f'name="gitlab_url" id="gitlab-url-input" value="{self.SELF_HOSTED}"', html)

    def test_a_cloud_account_still_gets_the_cloud_default(self):
        profile = self._gitlab()
        profile.mark_broken(GitlabProfile.EXPIRED)
        html = self.client.get(reverse('connect')).content.decode()
        self.assertIn('name="gitlab_url" id="gitlab-url-input" value="https://gitlab.com"', html)

    def test_the_two_gitlab_forms_do_not_share_element_ids(self):
        """
        Duplicate ids meant getElementById always answered with the first form,
        so typing a self-hosted URL into the second updated the first one's link
        and never revealed its own options.
        """
        self._gitlab()
        html = self.client.get(reverse('connect')).content.decode()
        for element_id in ('gitlab-url-input', 'selfhosted-options',
                           'gitlab-token-link', 'ssl-checkbox', 'custom-dns-input'):
            self.assertLessEqual(
                html.count(f'id="{element_id}"'), 1,
                f'{element_id} appears more than once',
            )


@override_settings(PAYMENTS_LIVE=True)
class PurchasePathTest(TestCase):
    """
    Both methods on every plan and every period.

    Monthly could be bought and annual said "talk to us", which reads as the
    annual plan not being for sale. It is — card is the method that cannot take
    it yet, because one Lemon Squeezy variant cannot sell six prices and
    custom_price only overrides the first charge, not what renews.
    """

    def setUp(self):
        self.user = make_user('shopper', email='shopper@test.com')
        self.client = Client()
        self.client.force_login(self.user)

    def _billing(self, period='monthly'):
        with self.settings(LEMONSQUEEZY_API_KEY='k', LEMONSQUEEZY_VARIANT_ID='999',
                           LS_VARIANTS={}, CRYPTOMUS_MERCHANT_ID='', CRYPTOMUS_API_KEY=''):
            return self.client.get(reverse('billing') + f'?period={period}').content.decode()

    def test_every_paid_plan_offers_both_methods_on_both_periods(self):
        from django.conf import settings as dj

        for period in ('monthly', 'annual'):
            html = self._billing(period)
            for plan, prices in dj.PLAN_PRICES.items():
                price = prices[period]
                with self.subTest(plan=plan, period=period):
                    self.assertIn(f'Pay ${price} by card', html)
                    self.assertIn(f'Pay ${price} in crypto', html)

    def test_no_plan_is_left_with_a_dead_mailto(self):
        self.assertNotIn('mailto:', self._billing('annual'))

    def test_both_buttons_post_to_a_real_checkout(self):
        """One behaviour to understand: the button charges, or it says why."""
        html = self._billing('annual')
        self.assertEqual(html.count(reverse('ls_checkout')), 3)
        self.assertEqual(html.count(reverse('crypto_checkout')), 3)

    def test_a_plan_with_no_variant_is_told_so_rather_than_charged_wrong(self):
        with self.settings(LEMONSQUEEZY_API_KEY='k', LEMONSQUEEZY_VARIANT_ID='999', LS_VARIANTS={}):
            response = self.client.post(reverse('ls_checkout'),
                                        {'plan': 'team', 'period': 'annual'})
        self.assertRedirects(response, reverse('billing'))

    def test_crypto_sells_every_plan_once_it_is_configured(self):
        """Cryptomus is a one-off charge for the exact amount, so it needs no variants."""
        from app.views import _plan_rows

        with self.settings(CRYPTOMUS_MERCHANT_ID='m', CRYPTOMUS_API_KEY='k'):
            for period in ('monthly', 'annual'):
                for row in _plan_rows(period):
                    self.assertTrue(row['crypto_available'], f"{row['key']}/{period}")


# ── What a surface is allowed to count, and what it may sell twice ────────────

class ApplicableCountingTest(TestCase):
    """
    A check the engine set aside is neither a finding nor a pass.

    The report page and the score already knew that; the organisation
    dashboard, the notification email, the Open Graph card, the landing
    showcase and the AI prompt did not, so one audit reported a different
    number of problems depending on where you read it.
    """

    def setUp(self):
        self.user = make_user('counter')
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='acme/lib', repo_url='https://github.com/acme/lib',
            source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=70,
        )
        rows = [
            ('security.no_secrets', 'crit', False, True),
            ('ci.tests', 'warn', False, True),
            ('docker.nonroot', 'crit', False, False),   # set aside: it is a library
            ('docker.healthcheck', 'warn', False, False),
            ('docs.readme', 'info', True, True),
        ]
        AuditCheck.objects.bulk_create([
            AuditCheck(
                audit=self.audit, check_id=cid, name=cid, description='',
                severity=sev, passed=passed, category='ops', applicable=applicable,
                severity_rank=AuditCheck.SEVERITY_RANK.get(sev, 3),
            )
            for cid, sev, passed, applicable in rows
        ])

    def test_org_dashboard_counts_only_what_can_be_acted_on(self):
        self.client.login(username='counter', password='testpass123')
        rows = self.client.get(reverse('org_dashboard')).context['rows']
        row = next(r for r in rows if r['name'] == 'acme/lib')
        self.assertEqual(row['crit'], 1, 'the set-aside docker.nonroot is not a finding')
        self.assertEqual(row['warn'], 1)

    def test_needs_attention_is_a_measurement_not_a_constant(self):
        """It used to render min(5, repo_count) however healthy the estate was."""
        from app.views_team import ATTENTION_SCORE

        self.client.login(username='counter', password='testpass123')
        response = self.client.get(reverse('org_dashboard'))
        self.assertEqual(response.context['needs_attention'], 0)

        self.audit.score = ATTENTION_SCORE - 1
        self.audit.save(update_fields=['score'])
        response = self.client.get(reverse('org_dashboard'))
        self.assertEqual(response.context['needs_attention'], 1)

    def test_notification_email_reports_the_same_counts_as_the_report(self):
        from app.tasks import _send_audit_email

        from django.core import mail
        from app.models import UserProfile

        UserProfile.objects.create(user=self.user, email_notifications=True)
        _send_audit_email(self.audit)

        self.assertEqual(len(mail.outbox), 1)
        body = ' '.join([mail.outbox[0].body] +
                        [alt[0] for alt in mail.outbox[0].alternatives])
        # Two findings and two passes — the set-aside pair is in neither count.
        self.assertNotIn('docker.nonroot', body)
        self.assertNotIn('docker.healthcheck', body)
        self.assertIn('security.no_secrets', body)

    def test_ai_is_not_asked_about_checks_that_do_not_apply(self):
        from app.ai_providers import _builtin_summary

        checks = [
            {'name': 'no secrets', 'passed': False, 'severity': 'crit',
             'category': 'security', 'applicable': True},
            {'name': 'container runs as non-root', 'passed': False, 'severity': 'crit',
             'category': 'docker', 'applicable': False},
        ]
        summary = _builtin_summary('acme/lib', checks, 70, 'en')
        self.assertNotIn('non-root', summary)


class CurrentPlanIsNotForSaleTest(TestCase):
    """
    Buying the plan you are already subscribed to on Lemon Squeezy opens a
    second subscription and charges the card again. A Cryptomus payment is a
    one-off, so repeating it genuinely extends access.
    """

    def setUp(self):
        self.user = make_user('renewer')
        self.client.login(username='renewer', password='testpass123')
        self.sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        self.sub.plan = UserSubscription.PLAN_PRO
        self.sub.current_period_end = timezone.now() + timedelta(days=20)
        self.sub.save()

    def _plan(self, key='pro'):
        response = self.client.get(reverse('billing'))
        return next(p for p in response.context['plans'] if p['key'] == key), response

    def test_a_recurring_subscription_is_not_offered_for_sale_again(self):
        self.sub.stripe_subscription_id = 'ls_12345'
        self.sub.save(update_fields=['stripe_subscription_id'])
        plan, response = self._plan()
        self.assertTrue(plan['renews'])
        self.assertFalse(plan['extendable'])
        self.assertContains(response, 'This is your plan')

    def test_a_one_off_payment_can_be_extended(self):
        self.sub.stripe_subscription_id = ''
        self.sub.save(update_fields=['stripe_subscription_id'])
        plan, response = self._plan()
        self.assertFalse(plan['renews'])
        self.assertTrue(plan['extendable'])
        self.assertNotContains(response, 'This is your plan')

    def test_a_cancelled_subscription_can_be_extended(self):
        self.sub.stripe_subscription_id = 'ls_12345'
        self.sub.cancel_at_period_end = True
        self.sub.save(update_fields=['stripe_subscription_id', 'cancel_at_period_end'])
        plan, _ = self._plan()
        self.assertTrue(plan['extendable'])

    def test_a_plan_you_are_not_on_is_still_for_sale(self):
        self.sub.stripe_subscription_id = 'ls_12345'
        self.sub.save(update_fields=['stripe_subscription_id'])
        team, _ = self._plan('team')
        self.assertFalse(team['renews'])
        self.assertFalse(team['extendable'])


class DashboardSurvivesADeadTokenTest(TestCase):
    """
    A dead token stops new audits; it does not make the finished ones
    worthless. The dashboard used to redirect to the connect page, so a paying
    customer opened the product and found nothing they had paid for.
    """

    def setUp(self):
        self.user = make_user('expired')
        self.client.login(username='expired', password='testpass123')
        GithubProfile.objects.create(user=self.user, github_id=1, github_login='acme',
                                     access_token='dead')
        Audit.objects.create(
            user=self.user, repo_full_name='acme/api', repo_url='https://github.com/acme/api',
            source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=61,
        )

    @patch('app.views.requests.get')
    def test_the_reports_stay_reachable(self, mock_get):
        mock_get.return_value = MagicMock(status_code=401)
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200, 'no longer bounced to /profile/')
        self.assertTrue(response.context['connection_broken'])
        self.assertEqual(len(response.context['past_audits']), 1)
        self.assertContains(response, 'acme/api')


class ShowcaseProvesSomethingTest(TestCase):
    """The landing showcase is the only place the product demonstrates itself."""

    def _cards(self):
        return self.client.get(reverse('landing')).context['demo_scans']

    def test_finished_scans_fill_the_slots_even_when_none_are_pinned(self):
        from app.models import PublicScan
        from app.views import LANDING_DEMO_SLOTS

        for i in range(LANDING_DEMO_SLOTS):
            PublicScan.objects.create(
                repo_full_name=f'someone/repo{i}', repo_url='https://github.com/someone/repo',
                status=Audit.STATUS_DONE, score=50 + i, view_count=i,
                results=[{'check_id': 'x', 'passed': False, 'severity': 'warn', 'applicable': True}],
            )
        cards = self._cards()
        self.assertEqual(len(cards), LANDING_DEMO_SLOTS)
        self.assertTrue(all(c['score'] is not None for c in cards),
                        'no card may read "no score yet" while finished scans exist')

    def test_the_issue_count_ignores_checks_that_do_not_apply(self):
        from app.models import PublicScan

        PublicScan.objects.create(
            repo_full_name='django/django', repo_url='https://github.com/django/django',
            status=Audit.STATUS_DONE, score=80, view_count=9,
            results=[
                {'check_id': 'a', 'passed': False, 'severity': 'crit', 'applicable': True},
                {'check_id': 'b', 'passed': False, 'severity': 'warn', 'applicable': True},
                {'check_id': 'c', 'passed': False, 'severity': 'crit', 'applicable': False},
            ],
        )
        card = next(c for c in self._cards() if c['repo'] == 'django/django')
        self.assertEqual(card['issues'], 2)
        self.assertEqual(card['crit'], 1)


class ErrorPagesSpeakTheReadersLanguageTest(TestCase):
    """A Russian visitor hitting a rate limit used to be answered in English."""

    def _render(self, view_name, lang):
        from django.test import RequestFactory
        from app import views

        request = RequestFactory().get('/nope/')
        self.client.cookies[settings.LANGUAGE_COOKIE_NAME] = lang
        with translation.override(lang):
            return getattr(views, view_name)(request).content.decode()

    def test_russian(self):
        for view_name, expected in [('error_404', 'Страница не найдена'),
                                    ('error_403', 'Доступ запрещён'),
                                    ('error_429', 'Слишком часто'),
                                    ('error_500', 'Идут технические работы')]:
            html = self._render(view_name, 'ru')
            self.assertIn(expected, html, view_name)
            self.assertIn('lang="ru"', html, view_name)

    def test_english_is_unchanged(self):
        html = self._render('error_404', 'en')
        self.assertIn('Page not found', html)
        self.assertIn('lang="en"', html)


class SignOutActuallySignsOutTest(TestCase):
    """
    The profile page's sign-out pointed at allauth's own view, which answers a
    GET with an unstyled confirmation page and leaves the session signed in
    until that page is posted. Both controls use the product's logout now.
    """

    def setUp(self):
        self.user = make_user('leaver')
        self.client.login(username='leaver', password='testpass123')

    def _sign_out_links(self, path):
        html = self.client.get(path).content.decode()
        return re.findall(r'href="([^"]*logout[^"]*)"', html)

    def test_every_sign_out_control_uses_the_product_logout(self):
        for path in (reverse('connect'), reverse('billing')):
            for href in self._sign_out_links(path):
                self.assertEqual(href, reverse('logout'),
                                 f'{path} still links to {href}')

    def test_the_session_is_gone_afterwards(self):
        response = self.client.get(reverse('logout'))
        self.assertRedirects(response, reverse('landing'))
        self.assertNotIn('_auth_user_id', self.client.session)
        # And a page behind the login wall no longer opens.
        self.assertEqual(self.client.get(reverse('dashboard')).status_code, 302)


class TemplatesDoNotLeakTheirOwnSyntaxTest(TestCase):
    """
    Django's {# #} comment is single-line. Written across several lines it is
    not a comment at all: the text renders, and any markup inside it becomes
    real elements. That shipped a paragraph of source commentary into the site
    header and pushed the nav out of shape.
    """

    LEAKS = ('{#', '#}', '{% comment', '{% endcomment', '{% trans', '{% blocktrans')

    def setUp(self):
        self.user = make_user('leakcheck')
        self.client.login(username='leakcheck', password='testpass123')
        UserSubscription.objects.update_or_create(
            user=self.user,
            defaults={'plan': UserSubscription.PLAN_COMPLIANCE,
                      'current_period_end': timezone.now() + timedelta(days=30)},
        )
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='acme/api', repo_url='https://github.com/acme/api',
            source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=72,
            is_public=True, public_token='leaktoken123',
        )
        AuditCheck.objects.create(
            audit=self.audit, check_id='ci.tests', name='Tests run in CI',
            description='', severity='warn', passed=False, category='ci_cd',
            severity_rank=1, recommendation='Add a test step.',
        )

    def test_no_rendered_page_shows_template_syntax(self):
        paths = [
            reverse('landing'), reverse('pricing'), reverse('scan_index'),
            reverse('register'), reverse('login'), reverse('connect'),
            reverse('billing'), reverse('org_dashboard'), reverse('onboarding'),
            reverse('audit_detail', args=[self.audit.id]),
            reverse('compliance_report', args=[self.audit.id]),
            reverse('public_audit', args=['leaktoken123']),
            reverse('payment_success'), reverse('payment_cancel'),
        ]
        for path in paths:
            html = self.client.get(path, follow=True).content.decode()
            for token in self.LEAKS:
                self.assertNotIn(token, html, f'{path} rendered {token!r}')

    def test_no_template_source_holds_a_multiline_hash_comment(self):
        import glob

        pattern = re.compile(r'\{#(?:(?!#\}).)*?\n(?:(?!#\}).)*?#\}', re.S)
        offenders = []
        for path in glob.glob('app/templates/**/*.html', recursive=True):
            with open(path, encoding='utf-8') as handle:
                for match in pattern.finditer(handle.read()):
                    offenders.append(f'{path}: {match.group(0)[:60]!r}')
        self.assertEqual(offenders, [], 'use {% comment %} for more than one line')


# ── The corpus as a public reference ──────────────────────────────────────────

def make_scan(name, score, language='Python', stars=100, results=None, **kw):
    from app.models import PublicScan

    return PublicScan.objects.create(
        repo_full_name=name, repo_url=f'https://github.com/{name}',
        status=Audit.STATUS_DONE, score=score, primary_language=language,
        stars=stars, results=results if results is not None else [], **kw)


class StandingTest(TestCase):
    """
    A score on its own says nothing. A standing does — but only once there is
    enough behind it, so the page says nothing rather than inventing a ranking.
    """

    def setUp(self):
        from django.core.cache import cache
        cache.clear()

    def _fill(self, n, language='Python', start=0):
        for i in range(n):
            make_scan(f'{language.lower()}/r{start + i}', i % 101, language=language)

    def test_says_nothing_when_the_corpus_is_too_small(self):
        from app import rankings

        self._fill(rankings.MIN_SAMPLE - 1)
        self.assertIsNone(rankings.standing(70, 'Python'))

    def test_a_percentile_once_there_is_enough(self):
        from app import rankings

        # Fifty scores, 0..49. A score of 40 beats the forty below it.
        for i in range(50):
            make_scan(f'python/r{i}', i)
        result = rankings.standing(40, 'Python')
        self.assertEqual(result['percentile'], 80)
        self.assertEqual(result['total'], 50)
        self.assertTrue(result['scoped'])

    def test_a_tie_does_not_inflate_the_claim(self):
        from app import rankings

        for i in range(rankings.MIN_SAMPLE + 10):
            make_scan(f'python/r{i}', 70)
        self.assertEqual(rankings.standing(70, 'Python')['percentile'], 0)

    def test_a_thin_language_falls_back_to_the_whole_corpus(self):
        from app import rankings

        self._fill(rankings.MIN_SAMPLE + 5, language='Python')
        make_scan('haskell/only-one', 90, language='Haskell')
        result = rankings.standing(90, 'Haskell')
        self.assertIsNotNone(result)
        self.assertFalse(result['scoped'], 'must not claim a Haskell ranking from one repo')

    def test_a_language_slug_survives_a_hash(self):
        from app import rankings

        self.assertEqual(rankings.language_slug('C#'), 'csharp')
        self.assertEqual(rankings.language_slug('C++'), 'cpp')


class CheckPrevalenceTest(TestCase):
    """The launch artefact: how often each check fails across everything scanned."""

    def setUp(self):
        from django.core.cache import cache
        cache.clear()

    def test_counts_only_repositories_the_check_applies_to(self):
        from app import rankings

        # The docker check applies to fifty of these and fails in twenty-five —
        # that is 50%, not 25% of the whole corpus.
        applicable_count = rankings.MIN_SAMPLE + 10
        for i in range(applicable_count * 2):
            applicable = i < applicable_count
            make_scan(f'acme/r{i}', 60, results=[
                {'check_id': 'docker.nonroot', 'name': 'Non-root', 'severity': 'crit',
                 'passed': not (applicable and i < applicable_count // 2),
                 'applicable': applicable},
                {'check_id': 'ci.tests', 'name': 'Tests in CI', 'severity': 'warn',
                 'passed': True, 'applicable': True},
            ])
        by_id = {row['check_id']: row for row in rankings.check_prevalence()}
        self.assertEqual(by_id['docker.nonroot']['seen'], applicable_count)
        self.assertEqual(by_id['docker.nonroot']['failed'], applicable_count // 2)
        self.assertEqual(by_id['docker.nonroot']['pct'], 50)

    def test_a_check_seen_too_rarely_is_left_out(self):
        from app import rankings

        for i in range(rankings.MIN_SAMPLE):
            results = [{'check_id': 'ci.tests', 'name': 'Tests in CI', 'severity': 'warn',
                        'passed': True, 'applicable': True}]
            if i < 3:
                results.append({'check_id': 'iac.open_ingress', 'name': 'Open ingress',
                                'severity': 'crit', 'passed': False, 'applicable': True})
            make_scan(f'acme/r{i}', 60, results=results)
        ids = {row['check_id'] for row in rankings.check_prevalence()}
        self.assertIn('ci.tests', ids)
        self.assertNotIn('iac.open_ingress', ids)


class RankingsPageTest(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()

    def test_it_says_so_rather_than_ranking_three_repositories(self):
        from app import rankings

        make_scan('acme/one', 80)
        response = self.client.get(reverse('rankings'))
        self.assertEqual(response.status_code, 200)
        # Matched with the attribute prefix: the bare class name also appears
        # in the stylesheet, both as a selector and as a section comment.
        self.assertNotContains(response, 'class="rk-band-track"')
        self.assertContains(response, str(rankings.MIN_SAMPLE))

    def test_it_ranks_once_there_is_enough(self):
        from app import rankings

        for i in range(rankings.MIN_SAMPLE + 5):
            make_scan(f'python/r{i}', 50 + (i % 40), results=[
                {'check_id': 'ci.tests', 'name': 'Tests in CI', 'severity': 'warn',
                 'passed': i % 2 == 0, 'applicable': True}])
        response = self.client.get(reverse('rankings'))
        self.assertContains(response, 'class="rk-band-track"')
        self.assertContains(response, 'python/r0')

    def test_an_unknown_language_goes_to_the_index_not_a_dead_end(self):
        response = self.client.get(reverse('rankings_language', args=['klingon']))
        self.assertRedirects(response, reverse('rankings'))

    def test_it_is_public(self):
        """/rankings/ is what robots.txt invites search engines to."""
        self.assertEqual(self.client.get(reverse('rankings')).status_code, 200)
        self.assertIn('Allow: /rankings/',
                      self.client.get('/robots.txt').content.decode())

    def test_the_language_pages_are_in_the_sitemap(self):
        from app import rankings

        for i in range(rankings.MIN_LANGUAGE + 2):
            make_scan(f'go/r{i}', 60 + i % 30, language='Go')
        body = self.client.get('/sitemap.xml').content.decode()
        self.assertIn('/rankings/', body)
        self.assertIn('/rankings/go/', body)


class SeededBacklogTest(TestCase):
    """
    Discovery is cheap and scanning is not, so seeded rows wait with queued_at
    unset. Nothing that was never queued may be mistaken for a job that died.
    """

    def setUp(self):
        from app.models import PublicScan

        self.row = PublicScan.objects.create(
            repo_full_name='acme/seeded', repo_url='https://github.com/acme/seeded',
            status=Audit.STATUS_PENDING, stars=900)
        PublicScan.objects.filter(pk=self.row.pk).update(
            updated_at=timezone.now() - timedelta(hours=3))
        self.row.refresh_from_db()

    def test_the_stuck_sweep_leaves_the_backlog_alone(self):
        from app.tasks import expire_stuck_public_scans

        self.assertFalse(self.row.is_stuck)
        expire_stuck_public_scans()
        self.row.refresh_from_db()
        self.assertEqual(self.row.status, Audit.STATUS_PENDING)

    def test_a_row_that_was_queued_and_died_is_still_closed_out(self):
        from app.models import PublicScan
        from app.tasks import expire_stuck_public_scans

        PublicScan.objects.filter(pk=self.row.pk).update(
            queued_at=timezone.now() - timedelta(hours=3))
        expire_stuck_public_scans()
        self.row.refresh_from_db()
        self.assertEqual(self.row.status, Audit.STATUS_FAILED)

    @patch('app.tasks.run_public_scan_task.delay')
    def test_draining_claims_the_row_so_a_second_tick_cannot_double_queue(self, delay):
        from app.tasks import scan_pending_public_repos

        self.assertEqual(scan_pending_public_repos(limit=10), 1)
        self.row.refresh_from_db()
        self.assertIsNotNone(self.row.queued_at)
        self.assertEqual(scan_pending_public_repos(limit=10), 0)
        self.assertEqual(delay.call_count, 1)

    @patch('app.tasks.run_public_scan_task.delay')
    def test_the_best_known_repositories_go_first(self, delay):
        from app.models import PublicScan
        from app.tasks import scan_pending_public_repos

        PublicScan.objects.create(
            repo_full_name='acme/obscure', repo_url='https://github.com/acme/obscure',
            status=Audit.STATUS_PENDING, stars=3)
        scan_pending_public_repos(limit=1)
        self.row.refresh_from_db()
        self.assertIsNotNone(self.row.queued_at, 'the 900-star repo should be first')


# ─────────────────────────────────────────────────────────────────────────────
# Removing a repository frees its slot
# ─────────────────────────────────────────────────────────────────────────────

class RepoSlotIsReleasableTest(TestCase):
    """
    The free quota counts repositories watched, and a count that can only grow
    is a lock, not a quota: three repositories audited once and since abandoned
    used to shut a free account out of the product for good.
    """

    def setUp(self):
        self.user = make_user('slotuser')
        self.client = Client()
        self.client.login(username='slotuser', password='testpass123')
        for i in range(settings.FREE_REPO_LIMIT):
            Audit.objects.create(
                user=self.user, repo_full_name=f'org/repo{i}', repo_url='u',
                source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=60,
            )

    def _exceeded(self, repo='org/brand-new'):
        from app.views import _repo_quota_exceeded
        return _repo_quota_exceeded(self.user, Audit.SOURCE_GITHUB, repo)

    def test_a_full_quota_blocks_a_new_repository(self):
        self.assertTrue(self._exceeded())

    def test_removing_one_frees_a_slot(self):
        r = self.client.post(reverse('remove_repo'), {
            'source': 'github', 'repo': 'org/repo0',
        })
        self.assertEqual(r.status_code, 302)
        self.assertFalse(self._exceeded())

    def test_removing_keeps_every_run_and_its_score(self):
        Audit.objects.create(
            user=self.user, repo_full_name='org/repo0', repo_url='u',
            source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=71,
        )
        self.client.post(reverse('remove_repo'), {'source': 'github', 'repo': 'org/repo0'})
        rows = Audit.objects.filter(user=self.user, repo_full_name='org/repo0')
        self.assertEqual(rows.count(), 2)
        self.assertEqual(rows.archived().count(), 2, 'removal is per repository, not per run')
        self.assertEqual(sorted(a.score for a in rows), [60, 71])

    def test_a_removed_repository_leaves_every_dashboard(self):
        self.client.post(reverse('remove_repo'), {'source': 'github', 'repo': 'org/repo0'})
        latest = Audit.objects.filter(user=self.user).latest_per_repo()
        self.assertNotIn('org/repo0', [a.repo_full_name for a in latest])

    def test_the_report_stays_readable_by_link(self):
        audit = Audit.objects.get(repo_full_name='org/repo0')
        self.client.post(reverse('remove_repo'), {'source': 'github', 'repo': 'org/repo0'})
        r = self.client.get(reverse('audit_detail', args=[audit.id]))
        self.assertEqual(r.status_code, 200)

    def test_restoring_brings_the_history_back(self):
        self.client.post(reverse('remove_repo'), {'source': 'github', 'repo': 'org/repo0'})
        r = self.client.post(reverse('restore_repo'), {'source': 'github', 'repo': 'org/repo0'})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(self._exceeded())
        latest = Audit.objects.filter(user=self.user).latest_per_repo()
        self.assertIn('org/repo0', [a.repo_full_name for a in latest])

    def test_restoring_past_a_full_quota_is_refused(self):
        """Remove one, audit something else, then try to have both."""
        self.client.post(reverse('remove_repo'), {'source': 'github', 'repo': 'org/repo0'})
        Audit.objects.create(
            user=self.user, repo_full_name='org/replacement', repo_url='u',
            source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=44,
        )
        r = self.client.post(reverse('restore_repo'), {'source': 'github', 'repo': 'org/repo0'})
        self.assertIn('repo_limit=1', r.url)
        self.assertTrue(Audit.objects.filter(repo_full_name='org/repo0').archived().exists())

    def test_removing_is_post_only(self):
        r = self.client.get(reverse('remove_repo'))
        self.assertEqual(r.status_code, 405)

    def test_one_user_cannot_remove_another_users_repository(self):
        other = make_user('intruder')
        self.client.logout()
        self.client.login(username='intruder', password='testpass123')
        self.client.post(reverse('remove_repo'), {'source': 'github', 'repo': 'org/repo0'})
        self.assertFalse(Audit.objects.filter(repo_full_name='org/repo0').archived().exists())
        self.assertEqual(other.audits.count(), 0)

    def test_a_paid_plan_is_never_blocked(self):
        sub, _ = UserSubscription.objects.get_or_create(user=self.user)
        sub.plan = UserSubscription.PLAN_PRO
        sub.current_period_end = timezone.now() + timedelta(days=30)
        sub.save()
        self.assertFalse(self._exceeded())

    def test_auditing_a_removed_repository_restores_it_rather_than_splitting_it(self):
        """
        A second history for the same repository would restart the trend chart
        from nothing, which is the bug append-only rows exist to prevent.
        """
        from app.views import _start_audit
        self.client.post(reverse('remove_repo'), {'source': 'github', 'repo': 'org/repo0'})
        with patch('app.tasks.run_audit_task.delay') as delay:
            delay.return_value = MagicMock(id="t1")
            _start_audit(self.user, 'org/repo0', 'u', Audit.SOURCE_GITHUB)
        rows = Audit.objects.filter(user=self.user, repo_full_name='org/repo0')
        self.assertEqual(rows.count(), 2)
        self.assertEqual(rows.archived().count(), 0)

    def test_a_bad_source_is_ignored_rather_than_obeyed(self):
        r = self.client.post(reverse('remove_repo'), {'source': 'bitbucket', 'repo': 'org/repo0'})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(Audit.objects.filter(repo_full_name='org/repo0').archived().exists())


class RepoQuotaIsReportedConsistentlyTest(TestCase):
    """
    Every surface showing "x of 3" reads the same number. The billing page used
    to sum both providers against a limit applied to each, so a user with three
    GitHub and three GitLab repositories was told they had used "6 / 3".
    """

    def setUp(self):
        self.user = make_user('countuser')
        self.client = Client()
        self.client.login(username='countuser', password='testpass123')
        for i in range(3):
            Audit.objects.create(
                user=self.user, repo_full_name=f'org/gh{i}', repo_url='u',
                source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=60,
            )
        for i in range(2):
            Audit.objects.create(
                user=self.user, repo_full_name=f'org/gl{i}::{i}', repo_url='u',
                source=Audit.SOURCE_GITLAB, status=Audit.STATUS_DONE, score=60,
            )

    def test_billing_reports_each_provider_against_its_own_limit(self):
        r = self.client.get(reverse('billing'))
        rows = {row['label']: row for row in r.context['repo_quota']}
        self.assertEqual(rows['GitHub']['used'], 3)
        self.assertEqual(rows['GitLab']['used'], 2)
        for row in rows.values():
            self.assertLessEqual(row['used'], row['limit'],
                                 'a usage bar can never read more than its limit')

    def test_a_removed_repository_stops_being_counted_everywhere(self):
        self.client.post(reverse('remove_repo'), {'source': 'github', 'repo': 'org/gh0'})
        r = self.client.get(reverse('billing'))
        rows = {row['label']: row for row in r.context['repo_quota']}
        self.assertEqual(rows['GitHub']['used'], 2)
        self.assertEqual(
            [a.repo_full_name for a in r.context['removed_repos']], ['org/gh0'])

    def test_gitlab_row_is_hidden_until_gitlab_is_used(self):
        Audit.objects.filter(user=self.user, source=Audit.SOURCE_GITLAB).delete()
        r = self.client.get(reverse('billing'))
        self.assertEqual([row['label'] for row in r.context['repo_quota']], ['GitHub'])


# ─────────────────────────────────────────────────────────────────────────────
# The admin
# ─────────────────────────────────────────────────────────────────────────────

@override_settings(ROOT_URLCONF='config.urls_admin')
class AdminIsUsableTest(TestCase):
    """
    `/admin/` was routed with nothing registered on it, so the operator had no
    way to grant a plan, inspect a run or re-queue a scan without a shell.

    Run against the admin urlconf, because that is where the admin lives now —
    the public site does not route it. See `AdminIsNotOnThePublicSiteTest`.
    """

    def setUp(self):
        self.staff = User.objects.create_superuser(
            'root', 'root@test.com', 'testpass123')
        self.customer = make_user('customer')
        UserSubscription.objects.get_or_create(user=self.customer)
        self.audit = Audit.objects.create(
            user=self.customer, repo_full_name='org/repo', repo_url='u',
            source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=64,
        )
        AuditCheck.objects.create(
            audit=self.audit, name='Secrets', description='d', severity='crit',
            passed=False, check_id='security.no_secrets', severity_rank=0,
        )
        self.client = Client()
        self.client.login(username='root', password='testpass123')

    def test_every_registered_model_has_a_working_changelist(self):
        from django.contrib import admin as dj_admin
        from app import admin as app_admin  # noqa: F401  (registers the models)
        for model in dj_admin.site._registry:
            url = reverse(
                f'admin:{model._meta.app_label}_{model._meta.model_name}_changelist')
            with self.subTest(model=model.__name__):
                self.assertEqual(self.client.get(url).status_code, 200)

    def test_granting_pro_makes_the_product_treat_the_user_as_paid(self):
        sub = self.customer.subscription
        self.assertFalse(sub.is_pro)
        self.client.post(reverse('admin:app_usersubscription_changelist'), {
            'action': 'grant_pro_month',
            '_selected_action': [str(sub.pk)],
        }, follow=True)
        sub.refresh_from_db()
        self.assertTrue(sub.is_pro)
        self.assertEqual(sub.billing_period, 'monthly')
        self.assertEqual(sub.payment_provider, 'manual')

    def test_a_hand_granted_plan_is_not_mistaken_for_a_lemon_squeezy_one(self):
        """cancel_subscription calls the LS API on an `ls_` id; a gift has none."""
        sub = self.customer.subscription
        sub.stripe_subscription_id = 'ls_123'
        sub.save()
        self.client.post(reverse('admin:app_usersubscription_changelist'), {
            'action': 'grant_compliance_year',
            '_selected_action': [str(sub.pk)],
        }, follow=True)
        sub.refresh_from_db()
        self.assertEqual(sub.stripe_subscription_id, '')

    def test_revoking_puts_the_user_back_on_free(self):
        sub = self.customer.subscription
        sub.plan = UserSubscription.PLAN_TEAM
        sub.current_period_end = timezone.now() + timedelta(days=90)
        sub.save()
        self.client.post(reverse('admin:app_usersubscription_changelist'), {
            'action': 'revoke', '_selected_action': [str(sub.pk)],
        }, follow=True)
        sub.refresh_from_db()
        self.assertFalse(sub.is_pro)

    def test_an_audit_cannot_be_edited_or_deleted_from_the_admin(self):
        """Append-only is the reason the trend chart exists."""
        from django.contrib import admin as dj_admin
        model_admin = dj_admin.site._registry[Audit]
        request = MagicMock(user=self.staff)
        self.assertFalse(model_admin.has_add_permission(request))
        self.assertFalse(model_admin.has_delete_permission(request, self.audit))
        editable = set(f.name for f in Audit._meta.fields) - set(
            model_admin.get_readonly_fields(request, self.audit))
        self.assertEqual(editable, set())

    def test_removing_a_repository_from_the_admin_frees_the_slot(self):
        from app.views import _repo_quota_exceeded
        for i in range(settings.FREE_REPO_LIMIT - 1):
            Audit.objects.create(
                user=self.customer, repo_full_name=f'org/filler{i}', repo_url='u',
                source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=50,
            )
        self.assertTrue(_repo_quota_exceeded(self.customer, Audit.SOURCE_GITHUB, 'org/new'))
        self.client.post(reverse('admin:app_audit_changelist'), {
            'action': 'archive_repository',
            '_selected_action': [str(self.audit.pk)],
        }, follow=True)
        self.assertFalse(_repo_quota_exceeded(self.customer, Audit.SOURCE_GITHUB, 'org/new'))

    def test_requeuing_a_public_scan_clears_the_stuck_marker(self):
        from app.models import PublicScan
        scan = PublicScan.objects.create(
            repo_full_name='o/r', repo_url='u', status=Audit.STATUS_FAILED,
            error_message='boom', queued_at=timezone.now(),
        )
        self.client.post(reverse('admin:app_publicscan_changelist'), {
            'action': 'requeue', '_selected_action': [str(scan.pk)],
        }, follow=True)
        scan.refresh_from_db()
        self.assertEqual(scan.status, Audit.STATUS_PENDING)
        self.assertIsNone(scan.queued_at)
        self.assertEqual(scan.error_message, '')


@override_settings(ROOT_URLCONF='config.urls_admin')
class AdminNeverRendersACredentialTest(TestCase):
    """
    Every token the product holds is encrypted at rest. A ModelAdmin that
    includes the field decrypts it onto the page, which would make the admin the
    easiest place in the system to read a customer's credentials.
    """

    SECRETS = {
        GithubProfile: ('access_token', 'gho_topsecretgithubvalue'),
        GitlabProfile: ('access_token', 'glpat_topsecretgitlabvalue'),
    }

    def setUp(self):
        self.staff = User.objects.create_superuser(
            'root2', 'root2@test.com', 'testpass123')
        self.customer = make_user('tokenowner')
        self.client = Client()
        self.client.login(username='root2', password='testpass123')

    def _assert_absent(self, url, secret):
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, secret)

    def test_a_github_token_is_never_on_the_page(self):
        p = GithubProfile.objects.create(
            user=self.customer, github_id=1, github_login='octocat',
            access_token='gho_topsecretgithubvalue')
        self._assert_absent(reverse('admin:app_githubprofile_changelist'),
                            'gho_topsecretgithubvalue')
        self._assert_absent(reverse('admin:app_githubprofile_change', args=[p.pk]),
                            'gho_topsecretgithubvalue')

    def test_a_gitlab_token_is_never_on_the_page(self):
        p = GitlabProfile.objects.create(
            user=self.customer, gitlab_id=1, gitlab_username='u',
            access_token='glpat_topsecretgitlabvalue')
        self._assert_absent(reverse('admin:app_gitlabprofile_changelist'),
                            'glpat_topsecretgitlabvalue')
        self._assert_absent(reverse('admin:app_gitlabprofile_change', args=[p.pk]),
                            'glpat_topsecretgitlabvalue')

    def test_a_customers_own_ai_key_is_never_on_the_page(self):
        from app.models import UserAISettings
        s = UserAISettings.objects.create(
            user=self.customer, provider='anthropic',
            api_key='sk-ant-topsecretaivalue')
        self._assert_absent(reverse('admin:app_useraisettings_changelist'),
                            'sk-ant-topsecretaivalue')
        self._assert_absent(reverse('admin:app_useraisettings_change', args=[s.pk]),
                            'sk-ant-topsecretaivalue')

    def test_the_api_token_and_webhook_secret_are_never_on_the_page(self):
        from app.models import UserProfile
        p = UserProfile.objects.create(
            user=self.customer, webhook_secret='whsec_topsecretvalue',
            api_token='apitok_topsecretvalue')
        self._assert_absent(reverse('admin:app_userprofile_changelist'),
                            'whsec_topsecretvalue')
        self._assert_absent(reverse('admin:app_userprofile_change', args=[p.pk]),
                            'apitok_topsecretvalue')

    def test_a_non_staff_user_cannot_reach_the_admin_at_all(self):
        self.client.logout()
        self.client.login(username='tokenowner', password='testpass123')
        r = self.client.get(reverse('admin:app_githubprofile_changelist'))
        self.assertIn(r.status_code, (302, 403))
        self.assertNotEqual(r.status_code, 200)

    def test_a_socialtoken_is_never_on_the_page_either(self):
        """
        Not one of our own models — django-allauth's, auto-registered with
        `token`/`token_secret` as plain editable fields by its own default
        admin. In the ordinary case app.signals blanks both the moment its
        own encrypted copy is saved, so this also covers the row that
        predates that fix, or a future signal failure: the admin itself must
        never be able to show the value, not just usually not have one to show.
        """
        from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken
        app = SocialApp.objects.create(provider='github', name='GitHub', client_id='x', secret='y')
        account = SocialAccount.objects.create(user=self.customer, provider='github', uid='1')
        t = SocialToken.objects.create(app=app, account=account, token='gho_unredacted_leak_check')
        self._assert_absent(reverse('admin:socialaccount_socialtoken_changelist'),
                            'gho_unredacted_leak_check')
        self._assert_absent(reverse('admin:socialaccount_socialtoken_change', args=[t.pk]),
                            'gho_unredacted_leak_check')


class AdminIsNotOnThePublicSiteTest(TestCase):
    """
    The admin runs as its own process on its own port. On the customer-facing
    domain /admin/ must not exist at all — an admin login form reachable from
    the internet is the most valuable target the product has, and "it is behind
    a password" is a weaker answer than "it is not there".
    """

    def test_the_public_urlconf_does_not_route_the_admin(self):
        from django.urls import resolve, Resolver404
        with self.assertRaises(Resolver404):
            resolve('/admin/', urlconf='config.urls')

    def test_the_public_site_returns_404_for_the_admin(self):
        r = Client().get('/admin/')
        self.assertEqual(r.status_code, 404)

    def test_the_public_site_still_serves_its_own_pages(self):
        """The separation must not have taken anything else with it."""
        for url in ('/', '/pricing/', '/scan/', '/login/'):
            with self.subTest(url=url):
                self.assertEqual(Client().get(url).status_code, 200)

    @override_settings(ROOT_URLCONF='config.urls_admin')
    def test_the_admin_urlconf_serves_the_admin(self):
        r = Client().get('/admin/')
        # Anonymous: redirected to the admin login, which is the admin working.
        self.assertEqual(r.status_code, 302)
        self.assertIn('/admin/login/', r.url)

    @override_settings(ROOT_URLCONF='config.urls_admin')
    def test_the_admin_urlconf_serves_nothing_else(self):
        """
        No landing page, no signup, no OAuth callback, no webhook on this port.
        A separate process that still answered for the whole site would have
        separated nothing.
        """
        for url in ('/pricing/', '/login/', '/register/', '/scan/',
                    '/accounts/github/login/', '/billing/webhooks/ls/'):
            with self.subTest(url=url):
                self.assertEqual(Client().get(url).status_code, 404)

    @override_settings(ROOT_URLCONF='config.urls_admin')
    def test_the_root_does_not_fall_through_to_djangos_placeholder(self):
        """
        With no root route and DEBUG on, Django serves "The install worked
        successfully", which reports the framework version to anyone who asks.
        """
        r = Client().get('/')
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.url, '/admin/')

    @override_settings(ROOT_URLCONF='config.urls_admin')
    def test_a_404_on_the_admin_port_renders_rather_than_500s(self):
        """
        The error templates are shared with the public site. One `{% url %}`
        naming a route this urlconf does not have would turn every 404 here
        into a 500 — and 404 is the most common response on this port.
        """
        with self.settings(DEBUG=False, ALLOWED_HOSTS=['testserver']):
            r = Client().get('/nothing/here/')
            self.assertEqual(r.status_code, 404)
            self.assertContains(r, 'DevOpsCheck', status_code=404)


# ─────────────────────────────────────────────────────────────────────────────
# Keeping the visitor: email capture on the public scanner
# ─────────────────────────────────────────────────────────────────────────────

class WatchSubscribeTest(TestCase):
    """
    The scan result is the one moment this product has someone's full attention.
    There was no way to keep that person: no email capture anywhere public.
    """

    def setUp(self):
        from app.models import PublicScan
        self.scan = PublicScan.objects.create(
            repo_full_name='acme/widget',
            repo_url='https://github.com/acme/widget',
            status=Audit.STATUS_DONE, score=44, primary_language='Python',
            results=[
                {'name': 'Secrets', 'severity': 'crit', 'passed': False,
                 'recommendation': 'Rotate them', 'applicable': True},
                {'name': 'Lockfile', 'severity': 'warn', 'passed': False,
                 'recommendation': 'Commit it', 'applicable': True},
                {'name': 'README', 'severity': 'info', 'passed': True, 'applicable': True},
            ],
        )
        self.client = Client()
        self.url = reverse('watch_subscribe', args=['acme', 'widget'])
        cache.clear()

    def _subscribe(self, email='reader@example.com'):
        with patch('app.tasks.send_watch_confirmation.delay') as delay:
            r = self.client.post(self.url, {'email': email})
        return r, delay

    def test_the_form_appears_on_a_finished_scan(self):
        r = self.client.get('/scan/acme/widget/')
        self.assertContains(r, 'watch-email')
        self.assertContains(r, self.url)

    def test_an_address_is_captured_and_the_report_queued(self):
        from app.models import RepoWatch
        r, delay = self._subscribe()
        self.assertEqual(r.status_code, 302)
        self.assertIn('watch=sent', r.url)
        watch = RepoWatch.objects.get(email='reader@example.com')
        self.assertEqual(watch.repo_full_name, 'acme/widget')
        delay.assert_called_once_with(watch.id)

    def test_a_new_subscription_is_not_yet_confirmed(self):
        """Nothing recurring may be sent to an address that only typed itself in."""
        from app.models import RepoWatch
        self._subscribe()
        watch = RepoWatch.objects.get(email='reader@example.com')
        self.assertFalse(watch.is_active)
        self.assertEqual(watch.state, 'pending')

    def test_the_address_is_normalised(self):
        from app.models import RepoWatch
        self._subscribe('  Reader@Example.COM  ')
        self.assertTrue(RepoWatch.objects.filter(email='reader@example.com').exists())

    def test_a_bad_address_is_refused(self):
        from app.models import RepoWatch
        r, delay = self._subscribe('not-an-email')
        self.assertIn('watch=invalid', r.url)
        self.assertEqual(RepoWatch.objects.count(), 0)
        delay.assert_not_called()

    def test_subscribing_twice_says_the_same_thing_both_times(self):
        """
        Answering differently for a known address turns the form into a way to
        test whether somebody uses this product.
        """
        from app.models import RepoWatch
        first, _ = self._subscribe()
        second, _ = self._subscribe()
        self.assertEqual(first.url, second.url)
        self.assertEqual(RepoWatch.objects.filter(email='reader@example.com').count(), 1)

    def test_an_unfinished_scan_captures_nothing(self):
        from app.models import PublicScan, RepoWatch
        PublicScan.objects.filter(pk=self.scan.pk).update(status=Audit.STATUS_PENDING)
        r, delay = self._subscribe()
        self.assertIn('watch=notready', r.url)
        self.assertEqual(RepoWatch.objects.count(), 0)
        delay.assert_not_called()

    def test_the_form_is_post_only(self):
        self.assertEqual(self.client.get(self.url).status_code, 405)

    def test_the_mailer_is_rate_limited_per_address(self):
        """
        Sending mail on somebody else's behalf is not a cheap public operation
        like scanning, and the cap is what stops the form being a way to mail
        strangers.
        """
        from app.views_public import WATCH_SIGNUPS_PER_HOUR
        from app.models import RepoWatch
        for i in range(WATCH_SIGNUPS_PER_HOUR):
            self._subscribe(f'reader{i}@example.com')
        r, delay = self._subscribe('one-too-many@example.com')
        self.assertIn('watch=throttled', r.url)
        self.assertFalse(RepoWatch.objects.filter(email='one-too-many@example.com').exists())
        delay.assert_not_called()


class WatchConfirmAndUnsubscribeTest(TestCase):
    def setUp(self):
        from app.models import RepoWatch
        self.watch = RepoWatch.objects.create(
            email='reader@example.com', repo_full_name='acme/widget')
        self.client = Client()

    def test_a_token_is_generated_and_is_not_guessable(self):
        self.assertTrue(self.watch.token)
        self.assertGreaterEqual(len(self.watch.token), 32)

    def test_confirming_activates_the_subscription(self):
        r = self.client.get(reverse('watch_confirm', args=[self.watch.token]))
        self.assertEqual(r.status_code, 200)
        self.watch.refresh_from_db()
        self.assertTrue(self.watch.is_active)

    def test_confirming_twice_is_harmless(self):
        self.client.get(reverse('watch_confirm', args=[self.watch.token]))
        first = self.watch.__class__.objects.get(pk=self.watch.pk).confirmed_at
        self.client.get(reverse('watch_confirm', args=[self.watch.token]))
        self.watch.refresh_from_db()
        self.assertEqual(self.watch.confirmed_at, first)

    def test_unsubscribing_takes_one_click_and_no_login(self):
        self.watch.confirm()
        r = self.client.get(reverse('watch_unsubscribe', args=[self.watch.token]))
        self.assertEqual(r.status_code, 200)
        self.watch.refresh_from_db()
        self.assertFalse(self.watch.is_active)
        self.assertEqual(self.watch.state, 'unsubscribed')

    def test_an_old_confirm_link_cannot_resurrect_an_unsubscribed_address(self):
        self.watch.confirm()
        self.watch.unsubscribe()
        self.client.get(reverse('watch_confirm', args=[self.watch.token]))
        self.watch.refresh_from_db()
        self.assertFalse(self.watch.is_active)

    def test_an_unknown_token_404s_without_saying_why(self):
        r = self.client.get(reverse('watch_confirm', args=['not-a-real-token']))
        self.assertEqual(r.status_code, 404)

    def test_the_status_page_is_not_indexed(self):
        r = self.client.get(reverse('watch_confirm', args=[self.watch.token]))
        self.assertContains(r, 'noindex')


class WatchEmailTest(TestCase):
    """What actually lands in the inbox."""

    def setUp(self):
        from app.models import PublicScan, RepoWatch
        self.scan = PublicScan.objects.create(
            repo_full_name='acme/widget', repo_url='u',
            status=Audit.STATUS_DONE, score=44,
            results=[
                {'name': 'Hardcoded secrets', 'severity': 'crit', 'passed': False,
                 'recommendation': 'Rotate and move to a secret store', 'applicable': True},
                {'name': 'README', 'severity': 'info', 'passed': True, 'applicable': True},
                {'name': 'Healthcheck', 'severity': 'warn', 'passed': False,
                 'applicable': False, 'not_applicable_reason': 'no container'},
            ],
        )
        self.watch = RepoWatch.objects.create(
            email='reader@example.com', repo_full_name='acme/widget')

    def test_the_first_email_carries_the_report_and_the_confirm_link(self):
        from app.tasks import send_watch_confirmation
        self.assertTrue(send_watch_confirmation(self.watch.id))
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ['reader@example.com'])
        self.assertIn('44/100', msg.subject)
        body = msg.alternatives[0][0]
        self.assertIn('Hardcoded secrets', body)
        self.assertIn(f'/watch/confirm/{self.watch.token}/', body)

    def test_every_message_carries_an_unsubscribe_link(self):
        from app.tasks import send_watch_confirmation
        send_watch_confirmation(self.watch.id)
        self.assertIn(f'/watch/stop/{self.watch.token}/', mail.outbox[0].alternatives[0][0])

    def test_the_email_counts_agree_with_the_page(self):
        """
        A check the engine set aside is not a finding. The email reporting a
        different number from the report it links to was the exact bug fixed on
        five other surfaces.
        """
        from app.tasks import send_watch_confirmation
        send_watch_confirmation(self.watch.id)
        body = mail.outbox[0].alternatives[0][0]
        self.assertIn('Findings: 1 · Checks passed: 1', body)

    def test_the_score_sent_is_recorded_so_the_first_change_is_measured_from_it(self):
        from app.tasks import send_watch_confirmation
        send_watch_confirmation(self.watch.id)
        self.watch.refresh_from_db()
        self.assertEqual(self.watch.last_score, 44)

    def test_an_unsubscribed_address_is_never_sent_to(self):
        from app.tasks import send_watch_confirmation
        self.watch.unsubscribe()
        self.assertFalse(send_watch_confirmation(self.watch.id))
        self.assertEqual(len(mail.outbox), 0)


class WatchChangeNotificationTest(TestCase):
    def setUp(self):
        from app.models import PublicScan, RepoWatch
        self.scan = PublicScan.objects.create(
            repo_full_name='acme/widget', repo_url='u',
            status=Audit.STATUS_DONE, score=44,
            results=[{'name': 'Secrets', 'severity': 'crit', 'passed': False,
                      'applicable': True}],
        )
        self.watch = RepoWatch.objects.create(
            email='reader@example.com', repo_full_name='acme/widget', last_score=44)
        self.watch.confirm()

    def _rescore(self, score):
        from app.models import PublicScan
        PublicScan.objects.filter(pk=self.scan.pk).update(score=score)

    def test_a_changed_score_is_reported(self):
        from app.tasks import notify_watched_score_changes
        self._rescore(61)
        self.assertEqual(notify_watched_score_changes(), 1)
        msg = mail.outbox[0]
        self.assertIn('44', msg.subject)
        self.assertIn('61', msg.subject)
        self.assertIn('The score went up', msg.alternatives[0][0])

    def test_an_unchanged_score_sends_nothing(self):
        from app.tasks import notify_watched_score_changes
        self.assertEqual(notify_watched_score_changes(), 0)
        self.assertEqual(len(mail.outbox), 0)

    def test_a_drop_is_reported_as_a_drop(self):
        from app.tasks import notify_watched_score_changes
        self._rescore(30)
        notify_watched_score_changes()
        self.assertIn('The score went down', mail.outbox[0].alternatives[0][0])

    def test_an_unconfirmed_address_is_never_mailed_about_changes(self):
        """The whole point of double opt-in."""
        from app.models import RepoWatch
        from app.tasks import notify_watched_score_changes
        RepoWatch.objects.filter(pk=self.watch.pk).update(confirmed_at=None)
        self._rescore(61)
        self.assertEqual(notify_watched_score_changes(), 0)
        self.assertEqual(len(mail.outbox), 0)

    def test_an_unsubscribed_address_is_never_mailed_about_changes(self):
        from app.tasks import notify_watched_score_changes
        self.watch.unsubscribe()
        self._rescore(61)
        self.assertEqual(notify_watched_score_changes(), 0)

    def test_the_next_change_is_measured_from_what_was_last_sent(self):
        """
        A score that dips and recovers between two messages is not a change the
        reader ever saw. Comparing against the previous scan rather than against
        what was sent would mail them about nothing.
        """
        from app.tasks import notify_watched_score_changes
        self._rescore(61)
        notify_watched_score_changes()
        self.watch.refresh_from_db()
        self.assertEqual(self.watch.last_score, 61)
        self.assertEqual(notify_watched_score_changes(), 0)
        self.assertEqual(len(mail.outbox), 1)

    def test_only_watched_repositories_are_refreshed_and_only_when_stale(self):
        from app.models import PublicScan
        from app.tasks import refresh_watched_public_scans
        PublicScan.objects.create(
            repo_full_name='other/repo', repo_url='u',
            status=Audit.STATUS_DONE, score=90)
        PublicScan.objects.update(updated_at=timezone.now() - timedelta(days=10))
        with patch('app.tasks.run_public_scan_task.delay') as delay:
            self.assertEqual(refresh_watched_public_scans(), 1)
            delay.assert_called_once_with(self.scan.id)


# ─────────────────────────────────────────────────────────────────────────────
# The badge, as a pull request
# ─────────────────────────────────────────────────────────────────────────────

BADGE_NOW = ('[![DevOps Score](https://img.shields.io/badge/DevOps_Score-96%2F100-00cc6a)]'
             '(http://testserver/scan/acme/widget/)')
BADGE_OLD = ('[![DevOps Score](https://img.shields.io/badge/DevOps_Score-44%2F100-ff4466)]'
             '(http://testserver/scan/acme/widget/)')


class InsertBadgeTest(TestCase):
    """
    This edits somebody else's README. The one unforgivable outcome is a second
    badge stacked beside the first, so every case below counts them.
    """

    def _insert(self, readme):
        from app.github_writer import insert_badge
        return insert_badge(readme, BADGE_NOW)

    def test_it_goes_under_the_title(self):
        out = self._insert('# My Project\n\nDoes things.\n')
        lines = out.split('\n')
        self.assertEqual(lines[0], '# My Project')
        self.assertIn(BADGE_NOW, lines[2])
        self.assertIn('Does things.', out)

    def test_it_joins_a_badge_row_that_already_exists(self):
        readme = ('# P\n\n[![CI](https://img.shields.io/badge/ci-ok-green)](https://ci)\n\nText.\n')
        out = self._insert(readme)
        row = out.split('\n')[2]
        self.assertEqual(row.count('!['), 2, 'the badge belongs on the existing row')
        self.assertIn('ci-ok-green', row)

    def test_a_readme_with_no_title_gets_it_at_the_top(self):
        out = self._insert('Just prose.\n')
        self.assertTrue(out.startswith(BADGE_NOW))
        self.assertIn('Just prose.', out)

    def test_a_stale_badge_is_replaced_not_duplicated(self):
        out = self._insert(f'# P\n\n{BADGE_OLD}\n\nText.\n')
        self.assertEqual(out.count('DevOps_Score'), 1)
        self.assertIn(BADGE_NOW, out)
        self.assertNotIn(BADGE_OLD, out)

    def test_a_stale_badge_on_a_shared_row_keeps_its_neighbours(self):
        readme = f'# P\n\n[![CI](https://img.shields.io/badge/ci-ok-green)](https://ci) {BADGE_OLD}\n'
        out = self._insert(readme)
        self.assertEqual(out.count('DevOps_Score'), 1)
        self.assertIn('ci-ok-green', out)
        self.assertIn(BADGE_NOW, out)

    def test_an_identical_badge_produces_no_pull_request(self):
        from app.github_writer import NothingToChange
        with self.assertRaises(NothingToChange):
            self._insert(f'# P\n\n{BADGE_NOW}\n\nText.\n')

    def test_an_unrewritable_marker_leaves_the_file_alone(self):
        """
        Better a pull request that never opens than one that adds a second badge
        next to something this could not parse.
        """
        from app.github_writer import NothingToChange
        with self.assertRaises(NothingToChange):
            self._insert('# P\n\n<img src="...DevOps_Score...">\n')

    def test_the_rest_of_the_file_is_untouched(self):
        readme = '# P\n\nPara one.\n\n## Install\n\n```sh\nnpm i\n```\n'
        out = self._insert(readme)
        for fragment in ('Para one.', '## Install', '```sh', 'npm i'):
            self.assertIn(fragment, out)

    def test_a_badge_containing_a_backslash_is_not_read_as_a_group_reference(self):
        """re.sub treats the replacement as a template; the badge is data."""
        from app.github_writer import insert_badge
        odd = r'[![DevOps Score](https://img.shields.io/badge/DevOps_Score-1%2F100-x\g)](u)'
        out = insert_badge(f'# P\n\n{BADGE_OLD}\n', odd)
        self.assertIn(r'x\g', out)


@override_settings(BASE_URL='http://testserver')
class BadgePullRequestTest(TestCase):
    def setUp(self):
        from app.models import PublicScan
        self.scan = PublicScan.objects.create(
            repo_full_name='acme/widget', repo_url='u',
            status=Audit.STATUS_DONE, score=96, results=[])
        self.user = make_user('badger')
        GithubProfile.objects.create(
            user=self.user, github_id=7, github_login='badger', access_token='gho_x')
        self.client = Client()
        self.url = reverse('badge_pull_request', args=['acme', 'widget'])

    def test_the_markdown_shown_is_the_markdown_committed(self):
        """
        Built in two places they drift, and the pull request starts adding a
        badge the page never showed.
        """
        from app.views_public import badge_markdown
        r = self.client.get('/scan/acme/widget/')
        self.assertEqual(r.context['badge_markdown'],
                         badge_markdown('acme/widget', 96))
        self.assertContains(r, 'DevOps_Score-96%2F100')

    def test_an_anonymous_visitor_is_sent_to_sign_up_and_back(self):
        r = self.client.post(self.url)
        self.assertEqual(r.status_code, 302)
        self.assertIn('/register/', r.url)
        self.assertIn('next=/scan/acme/widget/', r.url)

    def test_the_page_offers_signup_to_an_anonymous_visitor(self):
        r = self.client.get('/scan/acme/widget/')
        self.assertFalse(r.context['can_open_badge_pr'])
        self.assertContains(r, '/register/?next=/scan/acme/widget/')

    def test_a_connected_user_gets_the_button(self):
        self.client.login(username='badger', password='testpass123')
        r = self.client.get('/scan/acme/widget/')
        self.assertTrue(r.context['can_open_badge_pr'])
        self.assertContains(r, self.url)

    def test_a_user_without_github_is_sent_to_connect_one(self):
        make_user('nogithub')
        self.client.login(username='nogithub', password='testpass123')
        r = self.client.post(self.url)
        self.assertIn('/profile/', r.url)

    def test_opening_the_pull_request(self):
        self.client.login(username='badger', password='testpass123')
        with patch('app.github_writer.open_badge_pull_request') as writer:
            writer.return_value = 'https://github.com/acme/widget/pull/7'
            r = self.client.post(self.url)
        self.assertIn('badge=opened', r.url)
        _, kwargs = writer.call_args
        self.assertEqual(kwargs['repo_full_name'], 'acme/widget')
        self.assertIn('DevOps_Score-96%2F100', kwargs['badge'])

    def test_the_pull_request_link_is_shown_once_and_not_kept(self):
        self.client.login(username='badger', password='testpass123')
        with patch('app.github_writer.open_badge_pull_request') as writer:
            writer.return_value = 'https://github.com/acme/widget/pull/7'
            self.client.post(self.url)
        first = self.client.get('/scan/acme/widget/?badge=opened')
        self.assertContains(first, 'https://github.com/acme/widget/pull/7')
        second = self.client.get('/scan/acme/widget/?badge=opened')
        self.assertNotContains(second, '/pull/7')

    def test_a_badge_already_present_says_so_rather_than_failing(self):
        from app.github_writer import NothingToChange
        self.client.login(username='badger', password='testpass123')
        with patch('app.github_writer.open_badge_pull_request',
                   side_effect=NothingToChange('already there')):
            r = self.client.post(self.url)
        self.assertIn('badge=already', r.url)

    def test_a_permission_problem_is_reported_in_the_readers_words(self):
        from app.github_writer import GitHubWriteError
        self.client.login(username='badger', password='testpass123')
        with patch('app.github_writer.open_badge_pull_request',
                   side_effect=GitHubWriteError('The connected token has read-only access.')):
            r = self.client.post(self.url)
        self.assertIn('badge=error', r.url)
        page = self.client.get('/scan/acme/widget/?badge=error')
        self.assertContains(page, 'read-only access')

    def test_an_unexpected_failure_does_not_leak_a_traceback(self):
        self.client.login(username='badger', password='testpass123')
        with patch('app.github_writer.open_badge_pull_request',
                   side_effect=RuntimeError('boom')):
            r = self.client.post(self.url)
        self.assertIn('badge=error', r.url)
        page = self.client.get('/scan/acme/widget/?badge=error')
        self.assertNotContains(page, 'boom')

    def test_an_unfinished_scan_opens_nothing(self):
        from app.models import PublicScan
        PublicScan.objects.filter(pk=self.scan.pk).update(status=Audit.STATUS_PENDING)
        self.client.login(username='badger', password='testpass123')
        with patch('app.github_writer.open_badge_pull_request') as writer:
            r = self.client.post(self.url)
        self.assertIn('badge=notready', r.url)
        writer.assert_not_called()

    def test_it_is_post_only(self):
        self.client.login(username='badger', password='testpass123')
        self.assertEqual(self.client.get(self.url).status_code, 405)


class PullRequestCommentIsSoldWhereItIsGivenTest(TestCase):
    """
    The gate moved to Pro; three plan tables had it printed under Team. A price
    page that contradicts the code is worse than either version of the rule.
    """

    PAGES = (('/pricing/', 'pr-feat'), ('/', 'plan-feature'))

    def test_every_public_plan_table_lists_it_under_pro(self):
        for url, _cls in self.PAGES:
            with self.subTest(url=url):
                body = Client().get(url).content.decode()
                self.assertIn('Score comment on every pull request', body)
                pro = body.index('Unlimited private repositories')
                team = body.index('Everything in Pro')
                comment = body.index('Score comment on every pull request')
                self.assertTrue(pro < comment < team,
                                'the comment must sit inside the Pro card')

    def test_the_billing_matrix_grants_it_to_a_pro_subscriber(self):
        user = make_user('procomment')
        sub, _ = UserSubscription.objects.get_or_create(user=user)
        sub.plan = UserSubscription.PLAN_PRO
        sub.current_period_end = timezone.now() + timedelta(days=30)
        sub.save()
        client = Client()
        client.login(username='procomment', password='testpass123')
        body = client.get(reverse('billing')).content.decode()
        row = body[body.index('Score comment on every pull request') - 200:
                   body.index('Score comment on every pull request')]
        self.assertIn('plan-feature yes', row)


class BadgeWriterTalksToGitHubCorrectlyTest(TestCase):
    """
    The view tests mock the writer away, so the request sequence it actually
    sends is untested — and that is the part that breaks against real GitHub.
    """

    README = '# Widget\n\nDoes widget things.\n'

    def _github(self):
        """A stub GitHub recording what it was asked to do."""
        calls = []

        def get(url, **kw):
            calls.append(('GET', url, kw.get('params')))
            resp = MagicMock(status_code=200)
            if url.endswith('/repos/acme/widget'):
                resp.json.return_value = {
                    'permissions': {'push': True}, 'default_branch': 'trunk'}
            elif '/git/ref/heads/' in url:
                resp.json.return_value = {'object': {'sha': 'basesha'}}
            elif '/contents/README.md' in url:
                resp.json.return_value = {
                    'encoding': 'base64', 'sha': 'blobsha',
                    'content': base64.b64encode(self.README.encode()).decode()}
            else:
                resp.status_code = 404
            return resp

        def post(url, **kw):
            calls.append(('POST', url, kw.get('json')))
            resp = MagicMock(status_code=201)
            resp.json.return_value = {'html_url': 'https://github.com/acme/widget/pull/3'}
            return resp

        def put(url, **kw):
            calls.append(('PUT', url, kw.get('json')))
            return MagicMock(status_code=200)

        return calls, get, post, put

    def _run(self, badge=BADGE_NOW):
        from app import github_writer
        calls, get, post, put = self._github()
        with patch.object(github_writer.requests, 'get', side_effect=get), \
             patch.object(github_writer.requests, 'post', side_effect=post), \
             patch.object(github_writer.requests, 'put', side_effect=put):
            url = github_writer.open_badge_pull_request(
                'tok', 'acme/widget', badge, report_url='http://testserver/scan/acme/widget/')
        return url, calls

    def test_it_opens_the_pull_request_and_returns_its_url(self):
        url, _ = self._run()
        self.assertEqual(url, 'https://github.com/acme/widget/pull/3')

    def test_the_branch_is_cut_from_the_repositorys_own_default(self):
        """Not 'main' — plenty of repositories call it something else."""
        _, calls = self._run()
        refs = [c for c in calls if c[0] == 'GET' and '/git/ref/heads/' in c[1]]
        self.assertTrue(refs[0][1].endswith('/git/ref/heads/trunk'))
        created = next(c for c in calls if c[0] == 'POST' and c[1].endswith('/git/refs'))
        self.assertTrue(created[2]['ref'].startswith('refs/heads/devopscheck/'))
        self.assertEqual(created[2]['sha'], 'basesha')

    def test_the_commit_carries_the_existing_blob_sha(self):
        """Without it GitHub refuses to overwrite an existing file."""
        _, calls = self._run()
        put = next(c for c in calls if c[0] == 'PUT')
        self.assertEqual(put[2]['sha'], 'blobsha')

    def test_the_committed_readme_keeps_its_content_and_gains_the_badge(self):
        _, calls = self._run()
        put = next(c for c in calls if c[0] == 'PUT')
        written = base64.b64decode(put[2]['content']).decode()
        self.assertIn('# Widget', written)
        self.assertIn('Does widget things.', written)
        self.assertIn(BADGE_NOW, written)
        self.assertEqual(written.count('DevOps_Score'), 1)

    def test_nothing_is_ever_committed_to_the_default_branch(self):
        _, calls = self._run()
        put = next(c for c in calls if c[0] == 'PUT')
        self.assertNotEqual(put[2]['branch'], 'trunk')
        pr = next(c for c in calls if c[0] == 'POST' and c[1].endswith('/pulls'))
        self.assertEqual(pr[2]['base'], 'trunk')
        self.assertEqual(pr[2]['head'], put[2]['branch'])

    def test_a_read_only_token_is_refused_before_anything_is_written(self):
        from app import github_writer
        calls, get, post, put = self._github()

        def readonly(url, **kw):
            resp = get(url, **kw)
            if url.endswith('/repos/acme/widget'):
                resp.json.return_value = {'permissions': {'push': False},
                                          'default_branch': 'trunk'}
            return resp

        with patch.object(github_writer.requests, 'get', side_effect=readonly), \
             patch.object(github_writer.requests, 'post', side_effect=post), \
             patch.object(github_writer.requests, 'put', side_effect=put):
            with self.assertRaises(github_writer.GitHubWriteError) as ctx:
                github_writer.open_badge_pull_request('tok', 'acme/widget', BADGE_NOW)
        self.assertIn('not write to it', str(ctx.exception))
        self.assertFalse([c for c in calls if c[0] in ('PUT', 'POST')])

    def test_a_repository_with_no_readme_is_refused_with_a_useful_message(self):
        from app import github_writer
        calls, get, post, put = self._github()

        def no_readme(url, **kw):
            resp = get(url, **kw)
            if '/contents/' in url:
                resp.status_code = 404
            return resp

        with patch.object(github_writer.requests, 'get', side_effect=no_readme), \
             patch.object(github_writer.requests, 'post', side_effect=post), \
             patch.object(github_writer.requests, 'put', side_effect=put):
            with self.assertRaises(github_writer.GitHubWriteError) as ctx:
                github_writer.open_badge_pull_request('tok', 'acme/widget', BADGE_NOW)
        self.assertIn('no README', str(ctx.exception))
        self.assertFalse([c for c in calls if c[0] == 'PUT'])

    def test_a_readme_that_already_has_the_badge_writes_nothing(self):
        from app import github_writer
        self.README = f'# Widget\n\n{BADGE_NOW}\n\nText.\n'
        with self.assertRaises(github_writer.NothingToChange):
            self._run()


class FixWriterTalksToGitlabCorrectlyTest(TestCase):
    """
    Same purpose as BadgeWriterTalksToGitHubCorrectlyTest, for the GitLab
    half: `gitlab_writer.open_fix_merge_request`, which the fix button on a
    GitLab audit's report page had nothing behind until this phase — every
    click landed on "Pull requests are supported for GitHub repositories."
    """

    def _gitlab(self, push_access=True, default_branch='main', file_exists=False):
        calls = []

        def handler(method, url, **kw):
            calls.append((method, url, kw.get('json'), kw.get('params')))
            resp = MagicMock(status_code=200)
            if method == 'GET' and url.endswith('/api/v4/projects/42'):
                access = {'access_level': 30} if push_access else {'access_level': 10}
                resp.json.return_value = {
                    'default_branch': default_branch,
                    'permissions': {'project_access': access, 'group_access': None},
                }
            elif method == 'GET' and '/repository/branches/' in url:
                resp.json.return_value = {'commit': {'id': 'basesha'}}
            elif method == 'GET' and '/repository/files/' in url:
                if file_exists:
                    resp.json.return_value = {
                        'content': base64.b64encode(b'old content').decode()}
                else:
                    resp.status_code = 404
            elif method == 'POST' and url.endswith('/repository/branches'):
                resp.status_code = 201
            elif method == 'POST' and url.endswith('/repository/commits'):
                resp.status_code = 201
            elif method == 'POST' and url.endswith('/merge_requests'):
                resp.status_code = 201
                resp.json.return_value = {'web_url': 'https://gitlab.com/acme/widget/-/merge_requests/5'}
            else:
                resp.status_code = 404
            return resp

        return calls, handler

    def _run(self, **kw):
        from app import gitlab_writer
        calls, handler = self._gitlab(**kw)
        with patch.object(gitlab_writer.requests, 'request', side_effect=handler):
            url = gitlab_writer.open_fix_merge_request(
                'tok', 42, 'Dockerfile', 'FROM python:3.11-slim\n',
                check_name='docker.pinned_base', recommendation='Pin the base image.',
                audit_url='http://testserver/audit/1/',
            )
        return url, calls

    def test_it_opens_the_merge_request_and_returns_its_url(self):
        url, _ = self._run()
        self.assertEqual(url, 'https://gitlab.com/acme/widget/-/merge_requests/5')

    def test_the_branch_is_cut_from_the_projects_own_default(self):
        """Not 'main' by assumption — plenty of projects call it something else."""
        _, calls = self._run(default_branch='develop')
        ref = next(c for c in calls if c[0] == 'GET' and '/repository/branches/' in c[1])
        self.assertTrue(ref[1].endswith('/repository/branches/develop'))
        created = next(c for c in calls if c[0] == 'POST' and c[1].endswith('/repository/branches'))
        self.assertEqual(created[2]['ref'], 'basesha')
        self.assertTrue(created[2]['branch'].startswith('devopscheck/'))

    def test_a_new_file_is_committed_as_create_not_update(self):
        _, calls = self._run(file_exists=False)
        commit = next(c for c in calls if c[0] == 'POST' and c[1].endswith('/repository/commits'))
        self.assertEqual(commit[2]['actions'][0]['action'], 'create')

    def test_an_existing_file_is_committed_as_update_not_create(self):
        _, calls = self._run(file_exists=True)
        commit = next(c for c in calls if c[0] == 'POST' and c[1].endswith('/repository/commits'))
        self.assertEqual(commit[2]['actions'][0]['action'], 'update')

    def test_the_merge_request_targets_the_default_branch(self):
        _, calls = self._run(default_branch='develop')
        commit = next(c for c in calls if c[0] == 'POST' and c[1].endswith('/repository/commits'))
        mr = next(c for c in calls if c[0] == 'POST' and c[1].endswith('/merge_requests'))
        self.assertEqual(mr[2]['target_branch'], 'develop')
        self.assertEqual(mr[2]['source_branch'], commit[2]['branch'])
        self.assertNotEqual(mr[2]['source_branch'], 'develop')

    def test_a_developer_role_is_the_floor_reporter_is_refused(self):
        """Reporter (access_level 10) can read but not push — refused before any write."""
        from app import gitlab_writer
        calls, handler = self._gitlab(push_access=False)
        with patch.object(gitlab_writer.requests, 'request', side_effect=handler):
            with self.assertRaises(gitlab_writer.GitlabWriteError) as ctx:
                gitlab_writer.open_fix_merge_request('tok', 42, 'Dockerfile', 'x', check_name='c')
        self.assertIn('not write to it', str(ctx.exception))
        self.assertFalse([c for c in calls if c[0] == 'POST'])

    def _run_with_scopes(self, oauth_scopes=None, pat_scopes=None):
        """Answer the two token-info endpoints; everything else as `_gitlab`."""
        from app import gitlab_writer
        calls, base = self._gitlab()

        def handler(method, url, **kw):
            if url.endswith('/oauth/token/info'):
                calls.append((method, url, None, None, kw.get('headers')))
                resp = MagicMock(status_code=200 if oauth_scopes is not None else 401)
                resp.json.return_value = {'scope': oauth_scopes}
                return resp
            if url.endswith('/personal_access_tokens/self'):
                calls.append((method, url, None, None, kw.get('headers')))
                resp = MagicMock(status_code=200 if pat_scopes is not None else 401)
                resp.json.return_value = {'scopes': pat_scopes}
                return resp
            return base(method, url, **kw)

        with patch.object(gitlab_writer.requests, 'request', side_effect=handler):
            try:
                url = gitlab_writer.open_fix_merge_request('tok', 42, 'Dockerfile', 'x', check_name='c')
            except gitlab_writer.GitlabWriteError as exc:
                return exc, calls
        return url, calls

    def test_an_oauth_token_with_read_api_only_is_refused_before_any_write(self):
        from app.gitlab_writer import GitlabScopeError
        result, calls = self._run_with_scopes(oauth_scopes=['read_user', 'read_api'])
        self.assertIsInstance(result, GitlabScopeError)
        self.assertFalse([c for c in calls if c[0] == 'POST'])

    def test_a_personal_access_token_with_read_api_only_is_refused_too(self):
        from app.gitlab_writer import GitlabScopeError
        result, calls = self._run_with_scopes(pat_scopes=['read_api'])
        self.assertIsInstance(result, GitlabScopeError)
        self.assertFalse([c for c in calls if c[0] == 'POST'])

    def test_an_api_scoped_token_goes_through(self):
        for kw in ({'oauth_scopes': ['read_user', 'read_api', 'api']}, {'pat_scopes': ['api']}):
            result, _ = self._run_with_scopes(**kw)
            self.assertEqual(result, 'https://gitlab.com/acme/widget/-/merge_requests/5', kw)

    def test_unknown_scopes_do_not_block_the_write(self):
        """Neither endpoint answering is "unknown", not "none" — the write decides."""
        result, _ = self._run_with_scopes()
        self.assertEqual(result, 'https://gitlab.com/acme/widget/-/merge_requests/5')

    def test_the_token_is_sent_as_bearer_which_gitlab_accepts_for_oauth_tokens(self):
        """
        GitLab only looks a PRIVATE-TOKEN header up as a personal/project/group
        access token, so an OAuth ("Continue with GitLab") token sent that way
        is a 401. Bearer is accepted for both.
        """
        from app import gitlab_writer
        headers = []
        _, base = self._gitlab()

        def handler(method, url, **kw):
            headers.append(kw.get('headers') or {})
            return base(method, url, **kw)

        with patch.object(gitlab_writer.requests, 'request', side_effect=handler):
            gitlab_writer.open_fix_merge_request('tok', 42, 'Dockerfile', 'x', check_name='c')
        self.assertTrue(headers)
        for h in headers:
            self.assertEqual(h.get('Authorization'), 'Bearer tok')
            self.assertNotIn('PRIVATE-TOKEN', h)

    def test_the_audit_reader_sends_bearer_too(self):
        from app import repo_client
        seen = []

        def fake_get(url, headers=None, **kw):
            seen.append(headers or {})
            return MagicMock(status_code=401)

        with patch.object(repo_client.requests, 'get', side_effect=fake_get):
            with self.assertRaises(repo_client.RepoAccessError):
                repo_client.GitlabRepoClient(42, 'tok').load()
        self.assertEqual(seen[0].get('Authorization'), 'Bearer tok')
        self.assertNotIn('PRIVATE-TOKEN', seen[0])


class GitlabReauthorisationReachesTheProfileTest(TestCase):
    """
    The write-access step-up re-authorises an already-linked GitLab account.
    allauth sends `social_account_updated` *before* storing the new token, so
    linking from the database found the old, already-redacted row: the
    profile kept its read-only token, and the new api-scoped one landed in
    `SocialToken` in plaintext. Runs allauth's own `lookup()` — signal, then
    `_store_token()` — rather than calling our handler directly, because the
    ordering is the bug.
    """

    def setUp(self):
        from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken
        from django.contrib.sites.models import Site
        self.user = make_user('glstepup')
        self.app = SocialApp.objects.create(provider='gitlab', name='GitLab', client_id='x', secret='y')
        self.app.sites.add(Site.objects.get_current())
        self.account = SocialAccount.objects.create(
            user=self.user, provider='gitlab', uid='55',
            extra_data={'id': 55, 'username': 'gl', 'avatar_url': ''})
        # State after the original sign-in: our encrypted copy holds the
        # read-only token, allauth's row has been redacted.
        SocialToken.objects.create(app=self.app, account=self.account, token='', token_secret='')
        GitlabProfile.objects.create(
            user=self.user, gitlab_id=55, gitlab_username='gl', access_token='read-only-old',
            refresh_token='refresh-old', token_expires_at=timezone.now() + timedelta(hours=1))

    def _reauthorise(self, token='api-new', secret='refresh-new', process='connect'):
        from allauth.core import context
        from allauth.socialaccount.models import SocialAccount, SocialLogin, SocialToken
        from django.test import RequestFactory
        account = SocialAccount(provider='gitlab', uid='55',
                                extra_data={'id': 55, 'username': 'gl', 'avatar_url': ''})
        fresh = SocialToken(app=self.app, account=account, token=token, token_secret=secret,
                            expires_at=timezone.now() + timedelta(hours=2))
        # As allauth's own provider code builds it: an unsaved placeholder user.
        login = SocialLogin(user=User(), account=account, token=fresh)
        login.state['process'] = process
        request = RequestFactory().get('/')
        request.user = self.user
        with context.request_context(request):
            login.lookup()

    def test_the_new_token_reaches_the_profile(self):
        self._reauthorise()
        profile = GitlabProfile.objects.get(user=self.user)
        self.assertEqual(profile.access_token, 'api-new')
        self.assertEqual(profile.refresh_token, 'refresh-new')

    def test_the_new_token_never_rests_in_plaintext(self):
        from allauth.socialaccount.models import SocialToken
        self._reauthorise()
        for row in SocialToken.objects.filter(account=self.account):
            self.assertEqual(row.token, '')
            self.assertEqual(row.token_secret, '')

    def test_a_plain_sign_in_does_not_downgrade_the_step_up_token(self):
        """A sign-in asks for read_api only; it must not undo granted write access."""
        self._reauthorise(token='read-only-login', process='login')
        profile = GitlabProfile.objects.get(user=self.user)
        self.assertEqual(profile.access_token, 'read-only-old')

    def test_a_sign_in_repairs_a_broken_connection(self):
        profile = GitlabProfile.objects.get(user=self.user)
        profile.token_status = profile.EXPIRED
        profile.save()
        self._reauthorise(token='repaired', process='login')
        self.assertEqual(GitlabProfile.objects.get(user=self.user).access_token, 'repaired')

    def test_a_sign_in_never_replaces_a_pasted_or_self_hosted_token(self):
        from allauth.socialaccount.models import SocialToken
        GitlabProfile.objects.filter(user=self.user).update(
            refresh_token='', token_expires_at=None, gitlab_url='https://git.corp.example')
        profile = GitlabProfile.objects.get(user=self.user)
        profile.access_token = 'glpat-selfhosted'
        profile.save()
        self._reauthorise(token='oauth-login', process='login')
        profile = GitlabProfile.objects.get(user=self.user)
        self.assertEqual(profile.access_token, 'glpat-selfhosted')
        self.assertEqual(profile.gitlab_url, 'https://git.corp.example')
        # Kept or not, the plaintext copy still does not stay behind.
        for row in SocialToken.objects.filter(account=self.account):
            self.assertEqual(row.token, '')

    def test_allauth_is_told_to_store_tokens(self):
        """
        allauth 0.58+ defaults SOCIALACCOUNT_STORE_TOKENS to False and then
        never writes a SocialToken; a first sign-up (linked by `_on_login`,
        which has only the stored row to read) would connect nothing.
        """
        from allauth.socialaccount import app_settings
        self.assertTrue(app_settings.STORE_TOKENS)

    def test_connecting_a_new_account_links_it_and_leaves_no_plaintext(self):
        """`SocialLogin.connect` as allauth runs it: save, then social_account_added."""
        from allauth.core import context
        from allauth.socialaccount.models import SocialAccount, SocialLogin, SocialToken
        from django.test import RequestFactory
        other = make_user('glnewconnect')
        account = SocialAccount(provider='gitlab', uid='66',
                                extra_data={'id': 66, 'username': 'gl2', 'avatar_url': ''})
        token = SocialToken(app=self.app, account=account, token='new-tok', token_secret='new-ref',
                            expires_at=timezone.now() + timedelta(hours=2))
        login = SocialLogin(user=User(), account=account, token=token)
        request = RequestFactory().get('/')
        request.user = other
        with context.request_context(request):
            login.connect(request, other)
        profile = GitlabProfile.objects.get(user=other)
        self.assertEqual(profile.access_token, 'new-tok')
        self.assertEqual(profile.refresh_token, 'new-ref')
        stored = SocialToken.objects.get(account__uid='66')
        self.assertEqual((stored.token, stored.token_secret), ('', ''))

    def test_a_reauthorisation_without_a_refresh_token_keeps_the_old_one(self):
        self._reauthorise(secret='')
        profile = GitlabProfile.objects.get(user=self.user)
        self.assertEqual(profile.access_token, 'api-new')
        self.assertEqual(profile.refresh_token, 'refresh-old')


class GitlabPatReplacesOAuthConnectionTest(TestCase):
    """
    Pasting a personal access token over an earlier "Continue with GitLab"
    connection used to keep the OAuth refresh token and expiry. current_token
    then saw the old expiry, "refreshed", and overwrote the new PAT — which is
    exactly the token someone pastes to get write access.
    """

    def setUp(self):
        self.user = make_user('glpatover')
        GitlabProfile.objects.create(
            user=self.user, gitlab_id=77, gitlab_username='gl', access_token='oauth-old',
            refresh_token='refresh-old', token_expires_at=timezone.now() - timedelta(hours=1),
        )
        self.client = Client()
        self.client.login(username='glpatover', password='testpass123')

    @patch('requests.get')
    def test_the_pat_drops_the_oauth_refresh_state(self, mock_get):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {'id': 77, 'username': 'gl', 'avatar_url': ''}
        mock_get.return_value = resp
        self.client.post(reverse('connect_token'), {'provider': 'gitlab', 'token': 'glpat-new'})
        profile = GitlabProfile.objects.get(user=self.user)
        self.assertEqual(profile.refresh_token, '')
        self.assertIsNone(profile.token_expires_at)
        self.assertFalse(profile.is_oauth)
        with patch('app.gitlab_oauth.refresh') as refresh:
            self.assertEqual(profile.current_token, 'glpat-new')
        refresh.assert_not_called()


class FormLabelsAreAssociatedWithTheirFieldTest(TestCase):
    """
    A `<label>` that neither carries `for=` nor wraps its input is a caption, not
    a label: it looks right and announces nothing. Eight fields on the profile
    page were in that state — including both password fields and the API token —
    so a screen reader read them out as bare edit boxes.

    Static check on the templates, because the failure is invisible in a
    screenshot and only shows up in a browser's accessibility tree.
    """

    TEMPLATE_DIR = Path(__file__).resolve().parent / 'templates'
    LABEL = re.compile(r'<label\b([^>]*)>(.*?)</label>', re.S)

    def _unassociated(self, path):
        html = path.read_text(encoding='utf-8')
        bad = []
        for match in self.LABEL.finditer(html):
            attrs, inner = match.group(1), match.group(2)
            if 'for=' in attrs:
                continue
            # A label wrapping its own control needs no `for`.
            if re.search(r'<(input|select|textarea)\b', inner):
                continue
            text = re.sub(r'<[^>]+>', '', inner).strip()
            if text:
                bad.append(f'{path.name}: {text[:44]}')
        return bad

    def test_every_label_names_the_field_it_belongs_to(self):
        offenders = []
        for path in sorted(self.TEMPLATE_DIR.rglob('*.html')):
            offenders += self._unassociated(path)
        self.assertEqual(offenders, [], 'labels that announce nothing:\n  ' +
                         '\n  '.join(offenders))


class PagesDoNotPromiseMoreThanTheEngineDeliversTest(TestCase):
    """
    Two claims kept reappearing across the marketing pages, and both were false.

    "A fix for every finding" — twelve of the thirty-one checks ship a fix
    template. "Read-only access is all you need" — opening a pull request needs
    write, and `github_writer.require_push_access()` refuses without it, so a
    visitor who believed it would connect a read-only token, press the feature
    the headline sells, and get a permission error.

    A promise the product cannot keep costs more than the signup it won.
    """

    OVERCLAIMS = (
        'fix for every',
        'fix for each finding',
        'fix for each issue',
        'fix for every issue',
        'ready-to-use fix for each one',
        'read-only access only',
        'read-only personal access token',
    )

    def _engine_facts(self):
        from app.checks import run_all_checks
        from app.fix_templates import _FIXABLE
        from app.repo_client import StaticRepoClient
        results = run_all_checks(StaticRepoClient(
            {'README.md': '# x', 'Dockerfile': 'FROM python:3.11\n'}))
        ids = [c['check_id'] for c in results]
        return len(ids), sum(1 for i in ids if i in _FIXABLE)

    def test_the_premise_holds_only_some_checks_are_fixable(self):
        """If this ever fails the guard below can be relaxed — not before."""
        total, fixable = self._engine_facts()
        self.assertGreater(total, 0)
        self.assertLess(fixable, total,
                        'every check now ships a fix; the copy rule can change')

    def test_no_template_claims_a_fix_for_every_finding(self):
        offenders = []
        root = Path(__file__).resolve().parent / 'templates'
        for path in sorted(root.rglob('*.html')):
            text = path.read_text(encoding='utf-8')
            # Skip the comments that explain why these phrases are banned.
            body = re.sub(r'\{#.*?#\}|\{% comment %\}.*?\{% endcomment %\}', '',
                          text, flags=re.S)
            lowered = body.lower()
            for claim in self.OVERCLAIMS:
                if claim in lowered:
                    offenders.append(f'{path.name}: "{claim}"')
        self.assertEqual(offenders, [],
                         'pages promising what the engine does not do:\n  ' +
                         '\n  '.join(offenders))


class ConnectingASecondGithubAccountTest(TestCase):
    """
    Reported: "I made a token from another GitHub user and it connected my
    current account instead."

    The token link on the page is `github.com/settings/tokens/new`, and GitHub
    issues that token to whichever account the *browser* is signed in as — not
    the one the reader had in mind. The product then said nothing about which
    account it had actually connected: it redirected to the dashboard, the same
    account was there, and the second one had silently never arrived.
    """

    def setUp(self):
        self.user = make_user('multiacct')
        self.client = Client()
        self.client.login(username='multiacct', password='testpass123')

    @staticmethod
    def _gh(gid, login):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {'id': gid, 'login': login, 'avatar_url': ''}
        return resp

    def _connect(self, gid, login, token='ghp_x'):
        with patch('app.views.requests.get', return_value=self._gh(gid, login)):
            return self.client.post(reverse('connect_token'),
                                    {'provider': 'github', 'token': token}, follow=True)

    def test_two_different_accounts_both_connect(self):
        self._connect(111, 'acct-a')
        self._connect(222, 'acct-b')
        self.assertEqual(
            sorted(GithubProfile.objects.filter(user=self.user)
                   .values_list('github_login', flat=True)),
            ['acct-a', 'acct-b'])

    def test_the_page_says_which_account_was_connected(self):
        r = self._connect(111, 'acct-a')
        self.assertContains(r, 'acct-a')

    def test_a_token_for_an_account_already_connected_says_so(self):
        """
        The reported case. Silence here is what made it look like the product
        had connected the wrong account, when it had connected the account the
        token actually belonged to.
        """
        self._connect(111, 'acct-a')
        r = self._connect(111, 'acct-a', token='ghp_same_account_again')
        self.assertEqual(GithubProfile.objects.filter(user=self.user).count(), 1)
        body = r.content.decode()
        self.assertIn('acct-a', body)
        self.assertIn('already connected', body)

    def test_the_add_account_panel_explains_the_trap(self):
        self._connect(111, 'acct-a')
        r = self.client.get(reverse('connect'))
        self.assertContains(r, 'signed in to GitHub as that account')


class NothingLeavesForTheModelUnredactedTest(TestCase):
    """
    The AI suggestion feature sends the file a failed check is about to a
    third-party model. For "no secrets in code" the candidate files were
    settings.py, config.py, app.py and main.py — exactly where the credential
    the scanner had just found would be sitting.

    Reporting a leaked secret and forwarding it to Anthropic, OpenAI or Google
    in the same breath is not a trade any customer agreed to.
    """

    SECRETS = {
        'aws': 'AKIA2E0A8F3B244C9986',
        'github': 'ghp_abcdefghijklmnopqrstuvwxyz012345',
        'stripe': 'sk_live_abcdefghijklmnop1234',
        'dburl': 'sup3rs3cretpassword',
        'openai': 'sk-proj-abcdefghijklmnopqrstuvwxyz012345',
    }

    def test_the_scanner_rules_are_the_redaction_rules(self):
        """Anything the product will call a secret is something it will not forward."""
        from app.checks_secrets import redact
        blob = '\n'.join([
            f'AWS_KEY = "{self.SECRETS["aws"]}"',
            f'GH = "{self.SECRETS["github"]}"',
            f'STRIPE = "{self.SECRETS["stripe"]}"',
            f'DATABASE_URL = "postgres://u:{self.SECRETS["dburl"]}@db:5432/app"',
            f'OPENAI = "{self.SECRETS["openai"]}"',
        ])
        out = redact(blob)
        for label, value in self.SECRETS.items():
            with self.subTest(secret=label):
                self.assertNotIn(value, out)
        self.assertIn('REDACTED', out)

    def test_a_private_key_body_is_masked_not_just_its_header(self):
        from app.checks_secrets import redact
        pem = ('-----BEGIN RSA PRIVATE KEY-----\n'
               'MIIEowIBAAKCAQEAsecretkeymaterialhere\n'
               '-----END RSA PRIVATE KEY-----')
        self.assertNotIn('secretkeymaterialhere', redact(pem))

    def test_ordinary_configuration_survives_redaction(self):
        """A redactor that eats the whole file makes the suggestion worthless."""
        from app.checks_secrets import redact
        code = 'DEBUG = True\nALLOWED_HOSTS = ["example.com"]\nPORT = 8000\n'
        self.assertEqual(redact(code), code)

    def test_the_secret_check_never_asks_for_a_file(self):
        from app.ai_providers import _CHECK_FILES
        for key in _CHECK_FILES:
            with self.subTest(key=key):
                self.assertNotIn('secret', key.lower())
                self.assertNotIn('секрет', key.lower())

    def test_file_content_is_redacted_on_the_way_to_the_provider(self):
        """End to end: a secret in a sent file must not reach the provider call."""
        from app import ai_providers
        sent = {}

        def fake_call(provider, api_key, prompt):
            sent['prompt'] = prompt
            return 'ok'

        files = {'.gitignore': f'# deploy key\nDEPLOY_TOKEN="{self.SECRETS["github"]}"\n'}
        with patch.object(ai_providers, '_get_active_provider', return_value=('anthropic', 'k')), \
             patch.object(ai_providers, '_call_provider', side_effect=fake_call):
            ai_providers.get_ai_code_suggestions(
                [{'name': '.gitignore configured', 'check_id': 'ops.gitignore',
                  'description': 'd', 'recommendation': 'r'}],
                files.get, 'en',
            )
        self.assertIn('prompt', sent)
        self.assertNotIn(self.SECRETS['github'], sent['prompt'])
        self.assertIn('REDACTED', sent['prompt'])

    def test_the_stored_repository_context_carries_no_credentials(self):
        from app.repo_client import StaticRepoClient
        from app.repo_context import build
        client = StaticRepoClient({
            'README.md': f'# App\n\nRun with `export GH={self.SECRETS["github"]}`\n',
            'Dockerfile': f'FROM python:3.11\nEXPOSE 8000\nCMD ["sh","-c","TOKEN={self.SECRETS["stripe"]} ./run"]\n',
        })
        ctx = build(client)
        blob = json.dumps(ctx)
        for label, value in (('github', self.SECRETS['github']), ('stripe', self.SECRETS['stripe'])):
            with self.subTest(secret=label):
                self.assertNotIn(value, blob)


class AFailedAuditSaysWhatToDoTest(TestCase):
    """
    A failed audit used to report the exception's own text. Customers saw
    "User has no gitlab_profile." — Django's internal sentence — and
    "GitLab returned 401 for project 76017954", which says nothing about a token
    they could simply replace.
    """

    def setUp(self):
        self.user = make_user('failmsg')

    def _resp(self, code):
        r = MagicMock(status_code=code)
        r.headers = {}
        return r

    def test_a_missing_gitlab_connection_is_explained_not_raised(self):
        from app.repo_client import build_client_for_audit, RepoAccessError
        audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo::5', repo_url='u',
            source=Audit.SOURCE_GITLAB)
        with self.assertRaises(RepoAccessError) as ctx:
            build_client_for_audit(audit)
        message = str(ctx.exception)
        self.assertIn('No GitLab account is connected', message)
        self.assertNotIn('gitlab_profile', message)

    def test_a_missing_github_connection_is_explained(self):
        from app.repo_client import build_client_for_audit, RepoAccessError
        audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u',
            source=Audit.SOURCE_GITHUB)
        with self.assertRaises(RepoAccessError) as ctx:
            build_client_for_audit(audit)
        self.assertIn('No GitHub account is connected', str(ctx.exception))

    def test_each_github_status_gets_its_own_advice(self):
        from app.repo_client import _github_access_message
        expected = {
            401: 'expired or been revoked',
            403: 'not allowed to read',
            404: 'renamed, deleted or made',
        }
        for code, fragment in expected.items():
            with self.subTest(code=code):
                self.assertIn(fragment, _github_access_message(self._resp(code), 'org/repo'))
        self.assertIn('Could not reach GitHub', _github_access_message(None, 'org/repo'))

    def test_each_gitlab_status_gets_its_own_advice(self):
        from app.repo_client import _gitlab_access_message
        self.assertIn('read_api', _gitlab_access_message(self._resp(401), 5))
        self.assertIn('read_api', _gitlab_access_message(self._resp(403), 5))
        self.assertIn('renamed, deleted or moved', _gitlab_access_message(self._resp(404), 5))
        self.assertIn('self-hosted', _gitlab_access_message(None, 5))

    def test_no_message_leaks_an_internal_identifier(self):
        """A project id or an attribute name is not information the reader can use."""
        from app.repo_client import _github_access_message, _gitlab_access_message
        for code in (401, 403, 404, 500, None):
            resp = self._resp(code) if code else None
            with self.subTest(code=code):
                self.assertNotIn('76017954', _gitlab_access_message(resp, 76017954))
                self.assertNotIn('_profile', _github_access_message(resp, 'org/repo'))


class TheBuiltInSummaryReadsLikeItLookedAtTheRepositoryTest(TestCase):
    """
    Most audits land here: the AI providers are optional and with no key
    configured every summary is written by these rules. It used to end on
    "Top priority fix: Dependency manifest present" — naming the condition a
    check tests for as though it were the action — and it picked whichever
    failure came first in the list rather than the worst one.
    """

    CHECKS = [
        {'name': 'Dependency manifest present', 'severity': 'info', 'passed': False,
         'category': 'deps', 'applicable': True,
         'recommendation': 'Add requirements.txt so the build is reproducible.'},
        {'name': 'No secrets committed', 'severity': 'crit', 'passed': False,
         'category': 'security', 'applicable': True,
         'recommendation': 'Rotate the exposed credential, move it to a secret store, '
                           'and purge it from git history. Leaving it in history keeps it reachable.'},
        {'name': 'README present', 'severity': 'info', 'passed': True,
         'category': 'docs', 'applicable': True},
    ]
    CONTEXT = {'frameworks': ['Django'], 'languages': ['Python'],
               'docker': {'base_images': ['python:3.11-slim']}}

    def _summary(self, language='en', ctx=None):
        from app.ai_providers import _builtin_summary
        return _builtin_summary('acme/api', self.CHECKS, 33, language, ctx)

    def test_it_leads_with_the_worst_finding_not_the_first(self):
        text = self._summary()
        self.assertIn('No secrets committed', text)
        self.assertIn('Rotate the exposed credential', text)

    def test_it_gives_an_action_not_a_check_name(self):
        text = self._summary()
        self.assertNotIn('Top priority fix: Dependency manifest present', text)
        self.assertIn('Start here:', text)

    def test_it_names_the_stack_when_the_run_learned_it(self):
        text = self._summary(ctx=self.CONTEXT)
        self.assertIn('Django', text)
        self.assertIn('python:3.11-slim', text)

    def test_it_still_reads_properly_with_no_context(self):
        """Audits taken before the context existed must not read as broken."""
        text = self._summary(ctx={})
        self.assertTrue(text.startswith('Repository acme/api scored 33/100'))
        self.assertIn('Start here:', text)

    def test_counts_are_not_written_as_issue_s(self):
        self.assertIn('1 critical issue:', self._summary())
        self.assertNotIn('issue(s)', self._summary())

    def test_the_recommendation_is_trimmed_to_one_sentence(self):
        text = self._summary()
        self.assertNotIn('Leaving it in history', text)

    def test_russian_reads_as_russian(self):
        text = self._summary('ru', self.CONTEXT)
        self.assertIn('Django', text)
        self.assertIn('Начать стоит', text)


class AdviceIsNarrowedToTheStackTest(TestCase):
    """
    A recommendation has to serve every ecosystem, so it lists the command for
    each and ends with "depending on your stack". By the time it is read the run
    knows the stack — and offering somebody a choice you could have made for
    them is exactly what makes advice feel generic.
    """

    REC = ('Generate a lock file: `pip freeze > requirements.lock`, `npm install`, '
           '`poetry lock`, `go mod tidy` or `cargo build` depending on your stack.')

    def _narrow(self, languages):
        from app.ai_providers import _narrow_to_stack
        return _narrow_to_stack(self.REC, languages)

    def test_it_keeps_only_what_applies(self):
        self.assertEqual(self._narrow(['Go']), 'Generate a lock file: `go mod tidy`')
        self.assertEqual(self._narrow(['Rust']), 'Generate a lock file: `cargo build`')
        self.assertEqual(self._narrow(['JavaScript']), 'Generate a lock file: `npm install`')

    def test_cargo_build_is_not_read_as_a_go_command(self):
        """"cargo build" contains "go build"; substring matching offered Rust to Go."""
        self.assertNotIn('cargo', self._narrow(['Go']))

    def test_both_python_commands_survive(self):
        out = self._narrow(['Python'])
        self.assertIn('pip freeze', out)
        self.assertIn('poetry lock', out)
        self.assertNotIn('npm', out)

    def test_the_lead_in_is_kept(self):
        self.assertTrue(self._narrow(['Go']).startswith('Generate a lock file:'))

    def test_the_depending_on_your_stack_tail_goes(self):
        self.assertNotIn('depending on your stack', self._narrow(['Go']))

    def test_an_unknown_stack_changes_nothing(self):
        """Narrowing to the wrong ecosystem is worse than not narrowing."""
        for languages in (['Elixir'], [], None):
            with self.subTest(languages=languages):
                self.assertEqual(self._narrow(languages), self.REC)

    def test_a_single_option_recommendation_is_untouched(self):
        from app.ai_providers import _narrow_to_stack
        rec = 'Add a HEALTHCHECK instruction to the Dockerfile.'
        self.assertEqual(_narrow_to_stack(rec, ['Python']), rec)

    def test_the_summary_uses_it(self):
        from app.ai_providers import _builtin_summary
        checks = [{'name': 'Lock file present', 'severity': 'warn', 'passed': False,
                   'category': 'deps', 'applicable': True, 'recommendation': self.REC}]
        text = _builtin_summary('acme/api', checks, 70, 'en', {'languages': ['Go']})
        self.assertIn('go mod tidy', text)
        self.assertNotIn('npm install', text)
        self.assertNotIn('depending on your stack', text)


class TurningAIOffActuallyStopsItTest(TestCase):
    """
    Before this there was no way for an account to say no. If the deployment
    held a provider key, every customer's repository content was sent to a third
    party whether they wanted it or not — and whether repository content leaves
    is not a paid feature, it is the account owner's decision.
    """

    def setUp(self):
        self.user = make_user('privacy')
        self.profile = UserProfile.objects.create(user=self.user)
        self.client = Client()
        self.client.login(username='privacy', password='testpass123')

    def test_it_is_on_by_default(self):
        self.assertTrue(self.profile.ai_analysis_enabled)

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'server-side-key'})
    def test_a_server_key_is_refused_once_the_account_opts_out(self):
        from app.ai_providers import _get_active_provider
        self.assertEqual(_get_active_provider(self.user.id)[0], 'anthropic')
        UserProfile.objects.filter(pk=self.profile.pk).update(ai_analysis_enabled=False)
        self.assertEqual(_get_active_provider(self.user.id), (None, None))

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'server-side-key'})
    def test_the_users_own_key_is_refused_too(self):
        """Opting out means nothing leaves — not "nothing leaves on our bill"."""
        from app.models import UserAISettings
        from app.ai_providers import _get_active_provider
        UserAISettings.objects.create(user=self.user, provider='openai', api_key='sk-user')
        UserProfile.objects.filter(pk=self.profile.pk).update(ai_analysis_enabled=False)
        self.assertEqual(_get_active_provider(self.user.id), (None, None))

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'server-side-key'})
    def test_no_prompt_is_built_when_the_account_has_opted_out(self):
        from app import ai_providers
        UserProfile.objects.filter(pk=self.profile.pk).update(ai_analysis_enabled=False)
        with patch.object(ai_providers, '_call_provider') as called:
            text, provider = ai_providers.get_ai_summary(
                'acme/api', [{'name': 'X', 'severity': 'crit', 'passed': False,
                              'category': 'security', 'applicable': True,
                              'recommendation': 'Do the thing.'}],
                40, 'en', user_id=self.user.id)
        called.assert_not_called()
        self.assertEqual(provider, 'Built-in')
        self.assertTrue(text)

    @patch.dict('os.environ', {'ANTHROPIC_API_KEY': 'server-side-key'})
    def test_a_failure_to_read_the_preference_is_not_read_as_consent(self):
        from app import ai_providers
        with patch('app.models.UserProfile.objects') as broken:
            broken.filter.side_effect = RuntimeError('db down')
            self.assertEqual(ai_providers._get_active_provider(self.user.id), (None, None))

    def test_the_switch_is_reachable_and_works(self):
        r = self.client.post(reverse('update_ai_consent'), {'ai_analysis_enabled': '0'})
        self.assertEqual(r.status_code, 302)
        self.profile.refresh_from_db()
        self.assertFalse(self.profile.ai_analysis_enabled)
        self.client.post(reverse('update_ai_consent'), {'ai_analysis_enabled': '1'})
        self.profile.refresh_from_db()
        self.assertTrue(self.profile.ai_analysis_enabled)

    def test_the_switch_is_not_behind_a_paywall(self):
        """A free account can refuse just as a paid one can."""
        self.assertFalse(_get_subscription_is_pro(self.user))
        r = self.client.post(reverse('update_ai_consent'), {'ai_analysis_enabled': '0'})
        self.assertEqual(r.status_code, 302)
        self.profile.refresh_from_db()
        self.assertFalse(self.profile.ai_analysis_enabled)

    def test_the_page_states_what_leaves_and_what_never_does(self):
        r = self.client.get(reverse('connect'))
        self.assertContains(r, 'what leaves your repository')
        self.assertContains(r, 'Never sent')
        self.assertContains(r, 'Your source code')

    def test_it_is_post_only(self):
        self.assertEqual(self.client.get(reverse('update_ai_consent')).status_code, 405)


def _get_subscription_is_pro(user):
    from app.views import _get_subscription
    return _get_subscription(user).is_pro


class SigningInWithGithubConnectsGithubTest(TestCase):
    """
    "Continue with GitHub" is the widest entrance the product has. It
    authenticated the visitor and created a `SocialAccount` — and nothing else.
    Every dashboard, audit and repository list reads `GithubProfile`, so the new
    customer landed on an empty dashboard and had to go and paste a personal
    access token, having just been told connecting GitHub was one click.
    """

    def setUp(self):
        from allauth.socialaccount.models import SocialApp
        self.user = make_user('socialuser')
        self.app = SocialApp.objects.create(
            provider='github', name='GitHub', client_id='x', secret='y')

    def _account(self, provider='github', uid='4242', **extra):
        from allauth.socialaccount.models import SocialAccount
        data = {'id': uid, 'login': 'octocat', 'avatar_url': 'a'}
        data.update(extra)
        return SocialAccount.objects.create(
            user=self.user, provider=provider, uid=uid, extra_data=data)

    def _token(self, account, value='gho_social_token'):
        from allauth.socialaccount.models import SocialToken
        return SocialToken.objects.create(app=self.app, account=account, token=value)

    def test_a_social_account_with_a_token_becomes_a_github_profile(self):
        from app.signals import link_social_account
        account = self._account()
        self._token(account)
        self.assertTrue(link_social_account(account))
        profile = GithubProfile.objects.get(user=self.user)
        self.assertEqual(profile.github_id, 4242)
        self.assertEqual(profile.github_login, 'octocat')
        self.assertEqual(profile.access_token, 'gho_social_token')

    def test_the_dashboard_stops_being_empty(self):
        from app.signals import link_social_account
        account = self._account()
        self._token(account)
        link_social_account(account)
        self.assertTrue(GithubProfile.objects.filter(user=self.user).exists())

    def test_no_token_means_no_profile(self):
        """
        A profile that cannot answer is worse than none: the dashboard would
        show a connected account and then fail on every request.
        """
        from app.signals import link_social_account
        self.assertFalse(link_social_account(self._account()))
        self.assertFalse(GithubProfile.objects.filter(user=self.user).exists())

    def test_logging_in_links_an_account_that_signed_up_earlier(self):
        """
        On a first social sign-up allauth logs the user in without firing
        social_account_added — the brand-new customer is exactly the one it
        would have missed.
        """
        from django.contrib.auth.signals import user_logged_in
        account = self._account()
        self._token(account)
        user_logged_in.send(sender=User, request=None, user=self.user)
        self.assertTrue(GithubProfile.objects.filter(user=self.user, github_id=4242).exists())

    def test_signing_in_again_refreshes_the_token_rather_than_duplicating(self):
        from app.signals import link_social_account
        account = self._account()
        self._token(account)
        link_social_account(account)
        from allauth.socialaccount.models import SocialToken
        # (app, account) is unique — a re-login updates the token in place.
        SocialToken.objects.filter(account=account).update(token='gho_newer')
        link_social_account(account)
        profiles = GithubProfile.objects.filter(user=self.user)
        self.assertEqual(profiles.count(), 1)
        self.assertEqual(profiles.first().access_token, 'gho_newer')

    def test_a_sign_in_keeps_a_healthy_pasted_token(self):
        """`_on_login` (replace=False) must not swap a PAT for the OAuth token."""
        from app.signals import link_social_account
        GithubProfile.objects.create(user=self.user, github_id=4242, github_login='octocat',
                                     access_token='github_pat_finegrained')
        account = self._account()
        self._token(account)
        self.assertTrue(link_social_account(account, replace=False))
        self.assertEqual(GithubProfile.objects.get(user=self.user).access_token,
                         'github_pat_finegrained')

    def test_the_connection_is_marked_healthy(self):
        from app.signals import link_social_account
        account = self._account()
        self._token(account)
        link_social_account(account)
        self.assertTrue(GithubProfile.objects.get(user=self.user).is_healthy)

    def test_a_broken_social_account_never_breaks_the_login(self):
        from app.signals import link_social_account
        account = self._account(uid='not-a-number', id='not-a-number')
        self._token(account)
        self.assertFalse(link_social_account(account))

    def test_gitlab_is_linked_the_same_way(self):
        from app.signals import link_social_account
        from allauth.socialaccount.models import SocialApp
        SocialApp.objects.create(provider='gitlab', name='GitLab', client_id='x', secret='y')
        account = self._account(provider='gitlab', uid='77', username='glcat')
        self.app = SocialApp.objects.get(provider='gitlab')
        self._token(account, 'glpat_social')
        self.assertTrue(link_social_account(account))
        self.assertTrue(GitlabProfile.objects.filter(user=self.user, gitlab_id=77).exists())

    def test_the_plaintext_token_does_not_survive_the_login_it_authenticated(self):
        """
        allauth's own SocialToken.token is a plain TextField, not the
        EncryptedTextField GithubProfile.access_token is — copying the value
        across does nothing for a token that is also still sitting in
        plaintext three tables away. Confirmed nothing else in this codebase
        ever reads SocialToken again after this copy (grep for it), so it is
        blanked the moment our own encrypted copy is saved.
        """
        from app.signals import link_social_account
        from allauth.socialaccount.models import SocialToken
        account = self._account()
        token_row = self._token(account)
        self.assertTrue(link_social_account(account))

        self.assertEqual(GithubProfile.objects.get(user=self.user).access_token, 'gho_social_token')
        token_row.refresh_from_db()
        self.assertEqual(token_row.token, '')
        self.assertEqual(token_row.token_secret, '')

    def test_gitlab_plaintext_token_is_redacted_too(self):
        from app.signals import link_social_account
        from allauth.socialaccount.models import SocialApp
        SocialApp.objects.create(provider='gitlab', name='GitLab', client_id='x', secret='y')
        account = self._account(provider='gitlab', uid='77', username='glcat')
        self.app = SocialApp.objects.get(provider='gitlab')
        token_row = self._token(account, 'glpat_social')
        self.assertTrue(link_social_account(account))

        self.assertEqual(GitlabProfile.objects.get(user=self.user).access_token, 'glpat_social')
        token_row.refresh_from_db()
        self.assertEqual(token_row.token, '')

    def test_a_refresh_token_is_redacted_alongside_the_access_token(self):
        """
        token_secret is where allauth keeps a provider's refresh token for an
        OAuth2 connection — leaving it behind would defeat the point: the
        access token alone is what expires, the refresh token is what would
        let anyone who read it mint a new one indefinitely.
        """
        from app.signals import link_social_account
        from allauth.socialaccount.models import SocialToken
        account = self._account()
        token_row = self._token(account)
        token_row.token_secret = 'refresh-token-value'
        token_row.save(update_fields=['token_secret'])

        self.assertTrue(link_social_account(account))
        token_row.refresh_from_db()
        self.assertEqual(token_row.token_secret, '')

    def test_gitlabs_refresh_token_and_expiry_are_captured_before_redaction(self):
        """
        `_redact_token()` blanks token_secret and expires_at is never read
        again after this signal — so GitlabProfile.current_token would have
        nothing to refresh with unless _link_gitlab copies both across
        *before* the redaction, not after.
        """
        from django.utils import timezone as tz
        from app.signals import link_social_account
        from allauth.socialaccount.models import SocialApp
        SocialApp.objects.create(provider='gitlab', name='GitLab', client_id='x', secret='y')
        account = self._account(provider='gitlab', uid='77', username='glcat')
        self.app = SocialApp.objects.get(provider='gitlab')
        token_row = self._token(account, 'glpat_social')
        expires = tz.now() + timedelta(hours=2)
        token_row.token_secret = 'gitlab-refresh-token-value'
        token_row.expires_at = expires
        token_row.save(update_fields=['token_secret', 'expires_at'])

        self.assertTrue(link_social_account(account))

        profile = GitlabProfile.objects.get(user=self.user, gitlab_id=77)
        self.assertEqual(profile.refresh_token, 'gitlab-refresh-token-value')
        self.assertEqual(profile.token_expires_at, expires)

    def test_a_gitlab_account_with_no_refresh_token_leaves_the_field_blank(self):
        """
        A GitLab PAT connect path never goes through this signal at all, but
        an OAuth login whose token response genuinely carried no refresh
        token (would not currently happen against gitlab.com, but nothing
        here should assume it never will) must not leave a stale one behind
        or crash reading token_row.expires_at.
        """
        from app.signals import link_social_account
        from allauth.socialaccount.models import SocialApp
        SocialApp.objects.create(provider='gitlab', name='GitLab', client_id='x', secret='y')
        account = self._account(provider='gitlab', uid='88', username='glcat2')
        self.app = SocialApp.objects.get(provider='gitlab')
        self._token(account, 'glpat_social_2')

        self.assertTrue(link_social_account(account))

        profile = GitlabProfile.objects.get(user=self.user, gitlab_id=88)
        self.assertEqual(profile.refresh_token, '')
        self.assertIsNone(profile.token_expires_at)


class TheGuidePointsAtWhatIsActuallyOutstandingTest(TestCase):
    """
    The product has a dozen pages and no thread between them: a new customer
    signs up and has to guess which of GitHub, GitLab, Organization,
    Subscription and Profile moves them forward.

    Not a scripted tour — a tour tells everyone the same five things in the same
    order and is wrong for anyone who arrived in the middle. Each step knows how
    to check whether it is already done.
    """

    def setUp(self):
        self.user = make_user('guided')
        UserProfile.objects.create(user=self.user)
        self.client = Client()
        self.client.login(username='guided', password='testpass123')

    def _hint(self, page='dashboard'):
        from app.guide import hint_for
        return hint_for(self.user, page)

    def test_a_new_account_is_told_to_connect_something(self):
        hint = self._hint()
        self.assertEqual(hint['key'], 'connect')
        self.assertEqual(hint['position'], 1)

    def test_connecting_advances_it(self):
        GithubProfile.objects.create(
            user=self.user, github_id=1, github_login='x', access_token='t')
        self.assertEqual(self._hint()['key'], 'first_audit')

    def test_auditing_advances_it_again(self):
        GithubProfile.objects.create(
            user=self.user, github_id=1, github_login='x', access_token='t')
        Audit.objects.create(user=self.user, repo_full_name='o/r', repo_url='u',
                             source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=50)
        self.assertNotIn(self._hint()['key'], ('connect', 'first_audit'))

    def test_a_removed_repository_does_not_count_as_progress(self):
        """The quota and the guide have to agree on what "you have one" means."""
        GithubProfile.objects.create(
            user=self.user, github_id=1, github_login='x', access_token='t')
        Audit.objects.create(user=self.user, repo_full_name='o/r', repo_url='u',
                             source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=50)
        Audit.archive_repo(self.user, Audit.SOURCE_GITHUB, 'o/r')
        self.assertEqual(self._hint()['key'], 'first_audit')

    def test_it_disappears_once_everything_is_done(self):
        """A checklist that stays after it is finished is clutter on every page."""
        GithubProfile.objects.create(
            user=self.user, github_id=1, github_login='x', access_token='t')
        Audit.objects.create(user=self.user, repo_full_name='o/r', repo_url='u',
                             source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE,
                             score=50, is_public=True, public_token='tok')
        self.assertIsNone(self._hint())

    def test_skipping_one_step_moves_to_the_next(self):
        r = self.client.post(reverse('dismiss_guide_step'), {'step': 'connect'})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self._hint()['key'], 'first_audit')

    def test_hiding_it_hides_all_of_it(self):
        self.client.post(reverse('dismiss_guide_step'), {'step': 'all'})
        self.assertIsNone(self._hint())

    def test_a_hidden_guide_can_be_brought_back(self):
        self.client.post(reverse('dismiss_guide_step'), {'step': 'all'})
        self.client.post(reverse('restore_guide'))
        self.assertEqual(self._hint()['key'], 'connect')

    def test_an_unknown_step_key_is_ignored(self):
        self.client.post(reverse('dismiss_guide_step'), {'step': '../../etc/passwd'})
        self.assertEqual(self._hint()['key'], 'connect')
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.guide_dismissed, [])

    def test_it_renders_on_a_signed_in_page(self):
        r = self.client.get(reverse('billing'))
        self.assertContains(r, 'id="guide"')
        self.assertContains(r, 'Connect a repository host')

    def test_it_stays_off_the_public_surfaces(self):
        """A signed-in checklist has no business on the scanner or the rankings."""
        # (the landing redirects a signed-in visitor to the profile, so it is
        # not one of the pages this can appear on)
        for url in ('/scan/', '/rankings/'):
            with self.subTest(url=url):
                self.assertNotContains(self.client.get(url), 'id="guide"')

    def test_an_anonymous_visitor_never_sees_it(self):
        self.assertNotContains(Client().get('/pricing/'), 'id="guide"')

    def test_dismissing_is_post_only(self):
        self.assertEqual(self.client.get(reverse('dismiss_guide_step')).status_code, 405)

    def test_a_broken_guide_never_takes_a_page_down(self):
        from app.context_processors import guide as guide_ctx
        request = MagicMock(user=self.user, resolver_match=MagicMock(url_name='dashboard'))
        with patch('app.guide.hint_for', side_effect=RuntimeError('boom')):
            self.assertEqual(guide_ctx(request), {})


class TheProductDoesNotOfferAnActionItKnowsWillFailTest(TestCase):
    """
    Pull requests "not working" came down to this: the connection was already
    recorded as broken — `token_status` is written on every 401 — and the
    product offered the button anyway. Pressing it spent a round trip to GitHub
    to be told what the database could have said instantly, and left the reader
    looking at a failure instead of at the way out.
    """

    def setUp(self):
        self.user = make_user('prcap')
        self.audit = Audit.objects.create(
            user=self.user, repo_full_name='org/repo', repo_url='u',
            source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=50)

    def _cap(self):
        from app.views import _pr_capability
        return _pr_capability(self.user, self.audit)

    def test_a_healthy_connection_offers_the_button(self):
        GithubProfile.objects.create(
            user=self.user, github_id=1, github_login='octo', access_token='t')
        self.assertTrue(self._cap()['can_open_pr'])

    def test_a_broken_token_offers_the_way_out_instead(self):
        p = GithubProfile.objects.create(
            user=self.user, github_id=1, github_login='octo', access_token='t')
        p.mark_broken(GithubProfile.EXPIRED)
        cap = self._cap()
        self.assertFalse(cap['can_open_pr'])
        self.assertIn('octo', cap['pr_blocked'])
        self.assertIn('/profile/', cap['pr_blocked_url'])
        self.assertTrue(cap['pr_blocked_cta'])

    def test_no_connection_at_all_says_so(self):
        cap = self._cap()
        self.assertFalse(cap['can_open_pr'])
        self.assertIn('Connect a GitHub account', cap['pr_blocked'])

    def test_a_gitlab_audit_with_no_connection_says_so_in_gitlab_terms(self):
        """
        Was "simply out of scope" — no blocked message, no way out — before
        GitLab could open a merge request at all. Same shape as the GitHub
        case now: no connection means no button, with a reason and a link.
        """
        self.audit.source = Audit.SOURCE_GITLAB
        self.audit.save(update_fields=['source'])
        cap = self._cap()
        self.assertFalse(cap['can_open_pr'])
        self.assertIn('Connect a GitLab account', cap['pr_blocked'])

    def test_a_healthy_gitlab_connection_offers_the_button(self):
        GitlabProfile.objects.create(
            user=self.user, gitlab_id=1, gitlab_username='octo-gl', access_token='t')
        self.audit.source = Audit.SOURCE_GITLAB
        self.audit.save(update_fields=['source'])
        self.assertTrue(self._cap()['can_open_pr'])

    def test_a_broken_gitlab_token_offers_the_way_out_instead(self):
        p = GitlabProfile.objects.create(
            user=self.user, gitlab_id=1, gitlab_username='octo-gl', access_token='t')
        p.mark_broken(GitlabProfile.EXPIRED)
        self.audit.source = Audit.SOURCE_GITLAB
        self.audit.save(update_fields=['source'])
        cap = self._cap()
        self.assertFalse(cap['can_open_pr'])
        self.assertIn('octo-gl', cap['pr_blocked'])
        self.assertIn('/profile/', cap['pr_blocked_url'])

    def test_the_fix_response_carries_the_reason(self):
        p = GithubProfile.objects.create(
            user=self.user, github_id=1, github_login='octo', access_token='t')
        p.mark_broken(GithubProfile.EXPIRED)
        AuditCheck.objects.create(
            audit=self.audit, check_id='ci.security_scan', name='Security scanning',
            description='d', severity='warn', passed=False, severity_rank=1,
            recommendation='r', category='ci_cd')
        check = self.audit.checks.first()
        client = Client()
        client.login(username='prcap', password='testpass123')
        r = client.get(reverse('fix_generate', args=[self.audit.id, check.id]))
        data = r.json()
        self.assertFalse(data['can_open_pr'])
        self.assertIn('stopped working', data['pr_blocked'])


class TheTrendChartCanBeReadTest(TestCase):
    """
    The sparkline was drawn with `stroke-width=".8"` and
    `vector-effect="non-scaling-stroke"` — which means 0.8 of a CSS pixel, a
    hairline, whatever the container width. The trend was invisible. Its end
    marker was a `<circle>` in viewBox units under
    `preserveAspectRatio="none"`, so it rendered as a stretched ellipse.
    """

    def setUp(self):
        from app.charts import series
        self.spark = series([35, 40, 44, 50, 70])

    def test_every_reading_has_geometry_and_a_hit_column(self):
        self.assertEqual(len(self.spark['coords']), 5)
        for c in self.spark['coords']:
            with self.subTest(value=c['value']):
                self.assertIn('x', c)
                self.assertIn('y', c)
                self.assertIn('hit_x', c)
                self.assertIn('hit_w', c)

    def test_the_hit_column_is_wider_than_a_dot(self):
        """A 5px mark is a hard thing to hit; the target is the whole slot."""
        for c in self.spark['coords']:
            self.assertGreater(float(c['hit_w']), 5)

    def test_no_hit_column_hangs_off_the_canvas(self):
        """The first and last are half-columns; unclamped they overflow the page."""
        width = float(self.spark['width'])
        for c in self.spark['coords']:
            with self.subTest(value=c['value']):
                self.assertGreaterEqual(float(c['hit_x']), 0)
                self.assertLessEqual(float(c['hit_x']) + float(c['hit_w']), width + 0.01)

    def test_a_single_reading_still_produces_a_usable_column(self):
        from app.charts import series
        one = series([62])
        self.assertEqual(len(one['coords']), 1)
        self.assertGreater(float(one['coords'][0]['hit_w']), 0)

    def test_geometry_never_leaves_as_a_locale_formatted_float(self):
        """
        `viewBox="0 0 100,0 30,0"` makes a browser drop the whole chart, which
        is what every Russian reader used to see.
        """
        from django.utils import translation
        with translation.override('ru'):
            from app.charts import series
            spark = series([10, 90])
            for key in ('width', 'height', 'last_x', 'last_y'):
                self.assertNotIn(',', str(spark[key]))
            for c in spark['coords']:
                self.assertNotIn(',', c['x'] + c['y'] + c['hit_x'] + c['hit_w'])

    def test_the_page_draws_a_two_pixel_line_and_a_readable_scale(self):
        user = make_user('charted')
        UserProfile.objects.create(user=user)
        for i, score in enumerate((35, 50, 70)):
            Audit.objects.create(
                user=user, repo_full_name=f'o/r{i}', repo_url='u',
                source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE, score=score)
        client = Client()
        client.login(username='charted', password='testpass123')
        body = client.get(reverse('org_dashboard')).content.decode()
        self.assertIn('stroke-width="2"', body)
        self.assertNotIn('stroke-width=".8"', body)
        self.assertIn('spark-hit', body)
        self.assertIn('spark-scale', body)


# ── checks_cicd: CI/CD supply chain (roadmap 4.1) ─────────────────────────────

def _ci_client(files, public=False, provider='github'):
    from app.repo_client import StaticRepoClient
    client = StaticRepoClient(files, provider=provider)
    client.is_private = not public
    return client


def _by_check_id(checks):
    return {c['check_id']: c for c in checks}


class GithubActionsSupplyChainTest(TestCase):

    def _run(self, workflow, public=False, name='ci.yml'):
        from app.checks_cicd import check_github_actions
        return _by_check_id(check_github_actions(
            _ci_client({f'.github/workflows/{name}': workflow}, public=public)))

    # script injection
    def test_an_issue_title_inside_run_is_script_injection(self):
        wf = ('on: issues\npermissions: {}\njobs:\n  triage:\n    runs-on: ubuntu-latest\n'
              '    steps:\n      - run: echo "${{ github.event.issue.title }}"\n')
        c = self._run(wf)['actions.script_injection']
        self.assertFalse(c['passed'])
        self.assertEqual(c['severity'], 'crit')
        self.assertIn('github.event.issue.title', c['description'])
        self.assertIn('triage', c['description'])

    def test_a_branch_name_in_github_script_is_script_injection(self):
        wf = ('on: pull_request\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n'
              '      - uses: actions/github-script@v7\n        with:\n'
              '          script: console.log("${{ github.head_ref }}")\n')
        self.assertFalse(self._run(wf)['actions.script_injection']['passed'])

    def test_the_same_value_through_env_is_safe(self):
        wf = ('on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n'
              '      - env:\n          TITLE: ${{ github.event.issue.title }}\n'
              '        run: echo "$TITLE"\n')
        self.assertTrue(self._run(wf)['actions.script_injection']['passed'])

    def test_trusted_contexts_are_not_injection(self):
        wf = ('on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n'
              '      - run: echo "${{ github.sha }} ${{ github.event.pull_request.number }}"\n')
        self.assertTrue(self._run(wf)['actions.script_injection']['passed'])

    # pull_request_target / workflow_run
    def test_workflow_run_checking_out_the_pr_head_is_flagged(self):
        wf = ('on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\n'
              'jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n'
              '      - uses: actions/checkout@v4\n        with:\n'
              '          ref: ${{ github.event.workflow_run.head_sha }}\n')
        c = self._run(wf)['actions.pull_request_target']
        self.assertFalse(c['passed'])
        self.assertIn('workflow_run', c['description'])

    def test_gh_pr_checkout_under_pull_request_target_is_flagged(self):
        wf = ('on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n'
              '      - run: gh pr checkout ${{ github.event.pull_request.number }}\n')
        self.assertFalse(self._run(wf)['actions.pull_request_target']['passed'])

    def test_pull_request_target_without_checking_out_pr_code_passes(self):
        """The old text match flagged this: the trigger and head.sha in the same file."""
        wf = ('on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n'
              '      - uses: actions/labeler@v5\n'
              '      - env:\n          SHA: ${{ github.event.pull_request.head.sha }}\n'
              '        run: echo "$SHA"\n')
        self.assertTrue(self._run(wf)['actions.pull_request_target']['passed'])

    def test_pull_request_checking_out_its_own_head_is_fine(self):
        wf = ('on: pull_request\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n'
              '      - uses: actions/checkout@v4\n        with:\n'
              '          ref: ${{ github.event.pull_request.head.sha }}\n')
        self.assertTrue(self._run(wf)['actions.pull_request_target']['passed'])

    # permissions
    def test_job_level_contents_write_is_least_privilege_not_broad(self):
        """The old check flagged any `contents: write`, including a release job's."""
        wf = ('on: push\npermissions:\n  contents: read\njobs:\n  release:\n'
              '    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n    steps: []\n')
        self.assertTrue(self._run(wf)['actions.broad_permissions']['passed'])

    def test_no_permissions_anywhere_is_flagged(self):
        wf = 'on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []\n'
        c = self._run(wf)['actions.broad_permissions']
        self.assertFalse(c['passed'])
        self.assertIn('declares no permissions', c['description'])

    def test_a_reusable_workflow_inherits_its_callers_permissions(self):
        wf = 'on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []\n'
        self.assertTrue(self._run(wf)['actions.broad_permissions']['passed'])

    def test_job_level_write_all_is_flagged(self):
        wf = ('on: push\npermissions: read-all\njobs:\n  j:\n    runs-on: ubuntu-latest\n'
              '    permissions: write-all\n    steps: []\n')
        self.assertFalse(self._run(wf)['actions.broad_permissions']['passed'])

    # self-hosted
    def test_self_hosted_runner_in_a_public_repository_is_critical(self):
        wf = 'on: pull_request\npermissions: {}\njobs:\n  j:\n    runs-on: [self-hosted, linux]\n    steps: []\n'
        c = self._run(wf, public=True)['actions.self_hosted_public']
        self.assertFalse(c['passed'])
        self.assertEqual(c['severity'], 'crit')

    def test_self_hosted_runner_in_a_private_repository_passes(self):
        wf = 'on: push\njobs:\n  j:\n    runs-on: self-hosted\n    steps: []\n'
        self.assertTrue(self._run(wf, public=False)['actions.self_hosted_public']['passed'])

    def test_a_self_hosted_deploy_only_writers_can_start_is_fine(self):
        """tiangolo/full-stack-fastapi-template: workflow_dispatch deploy on self-hosted."""
        wf = 'on:\n  workflow_dispatch:\n  push:\njobs:\n  deploy:\n    runs-on: self-hosted\n    steps: []\n'
        self.assertTrue(self._run(wf, public=True)['actions.self_hosted_public']['passed'])

    def test_runner_group_labels_are_read(self):
        wf = ('on: pull_request\njobs:\n  j:\n    runs-on:\n      group: big\n      labels: [self-hosted]\n'
              '    steps: []\n')
        self.assertFalse(self._run(wf, public=True)['actions.self_hosted_public']['passed'])

    # OIDC
    def test_static_aws_keys_recommend_oidc(self):
        wf = ('on: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n'
              '      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n'
              '          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}\n'
              '          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n')
        c = self._run(wf)['actions.cloud_oidc']
        self.assertFalse(c['passed'])
        self.assertTrue(c.get('applicable', True))

    def test_oidc_passes(self):
        wf = ('on: push\npermissions:\n  id-token: write\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n'
              '    steps:\n      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n'
              '          role-to-assume: arn:aws:iam::1:role/x\n')
        c = self._run(wf)['actions.cloud_oidc']
        self.assertTrue(c['passed'])
        self.assertTrue(c.get('applicable', True))

    def test_no_cloud_at_all_is_not_applicable_not_a_free_pass(self):
        wf = 'on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []\n'
        self.assertFalse(self._run(wf)['actions.cloud_oidc']['applicable'])

    def test_unparseable_workflow_does_not_crash(self):
        checks = self._run('on: [push\n  jobs: : :\n')
        self.assertIn('actions.pinned_sha', checks)


class GitlabCiSupplyChainTest(TestCase):

    def _run(self, pipeline, extra=None):
        from app.checks_cicd import check_gitlab_ci
        files = {'.gitlab-ci.yml': pipeline}
        files.update(extra or {})
        return _by_check_id(check_gitlab_ci(_ci_client(files, provider='gitlab')))

    def test_no_pipeline_no_checks(self):
        from app.checks_cicd import check_gitlab_ci
        self.assertEqual(check_gitlab_ci(_ci_client({'README.md': 'x'})), [])

    # includes
    def test_project_include_without_ref_is_flagged(self):
        c = self._run('include:\n  - project: acme/ci\n    file: /build.yml\n')['gitlab_ci.pinned_includes']
        self.assertFalse(c['passed'])
        self.assertIn('acme/ci', c['description'])

    def test_project_include_on_a_branch_is_flagged(self):
        c = self._run('include:\n  project: acme/ci\n  ref: main\n  file: /b.yml\n')
        self.assertFalse(c['gitlab_ci.pinned_includes']['passed'])

    def test_remote_include_is_flagged_unless_it_has_integrity(self):
        self.assertFalse(self._run("include: 'https://example.com/ci.yml'\n")
                         ['gitlab_ci.pinned_includes']['passed'])
        self.assertTrue(self._run('include:\n  - remote: https://example.com/ci.yml\n'
                                  '    integrity: sha256-abc\n')['gitlab_ci.pinned_includes']['passed'])

    def test_component_at_latest_is_flagged_versioned_passes(self):
        self.assertFalse(self._run('include:\n  - component: gitlab.com/a/b@~latest\n')
                         ['gitlab_ci.pinned_includes']['passed'])
        self.assertTrue(self._run('include:\n  - component: gitlab.com/a/b@1.2.0\n')
                        ['gitlab_ci.pinned_includes']['passed'])

    def test_templates_local_and_tagged_project_includes_pass(self):
        pipeline = ('include:\n  - template: Security/SAST.gitlab-ci.yml\n  - local: /ci/build.yml\n'
                    '  - project: acme/ci\n    ref: v1.4.2\n    file: /b.yml\n')
        self.assertTrue(self._run(pipeline, {'ci/build.yml': 'build:\n  script: [make]\n'})
                        ['gitlab_ci.pinned_includes']['passed'])

    # images
    def test_untagged_and_latest_images_are_flagged(self):
        pipeline = ('image: node\nbuild:\n  image: python:latest\n  services: [postgres:16]\n'
                    '  script: [make]\n')
        c = self._run(pipeline)['gitlab_ci.pinned_images']
        self.assertFalse(c['passed'])
        self.assertIn('2 job image', c['description'])

    def test_tagged_digest_and_variable_images_pass(self):
        pipeline = ('default:\n  image: python:3.12-slim\nbuild:\n  image:\n    name: alpine@sha256:abc\n'
                    '  script: [x]\npush:\n  image: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA\n  script: [x]\n')
        self.assertTrue(self._run(pipeline)['gitlab_ci.pinned_images']['passed'])

    def test_registry_port_is_not_mistaken_for_a_tag(self):
        c = self._run('build:\n  image: registry.example.com:5000/team/tool\n  script: [x]\n')
        self.assertFalse(c['gitlab_ci.pinned_images']['passed'])

    def test_the_pages_job_is_a_job(self):
        """fdroid/fdroidserver: `pages: image: alpine:latest` was skipped as a keyword."""
        c = self._run('pages:\n  image: alpine:latest\n  script: [x]\n')
        self.assertFalse(c['gitlab_ci.pinned_images']['passed'])

    def test_a_credentials_file_path_is_not_a_static_key(self):
        """gitlab-org/cli: GOOGLE_APPLICATION_CREDENTIALS set up by OIDC federation."""
        c = self._run('release:\n  script:\n    - docker run -e GOOGLE_APPLICATION_CREDENTIALS=$GOOGLE_APPLICATION_CREDENTIALS x\n')
        self.assertFalse(c['gitlab_ci.cloud_oidc']['applicable'])

    def test_images_in_local_includes_are_read(self):
        c = self._run("include: '/ci/jobs.yml'\n", {'ci/jobs.yml': 'lint:\n  image: ruby\n  script: [x]\n'})
        self.assertFalse(c['gitlab_ci.pinned_images']['passed'])

    def test_reference_tags_parse(self):
        pipeline = ('.setup:\n  script: [echo hi]\ntest:\n  image: python:3.12\n'
                    '  script:\n    - !reference [.setup, script]\n')
        self.assertTrue(self._run(pipeline)['gitlab_ci.pinned_images']['passed'])

    # OIDC
    def test_static_cloud_key_is_flagged_id_tokens_pass_none_is_na(self):
        self.assertFalse(self._run('deploy:\n  script:\n    - aws configure set aws_secret_access_key '
                                   '$AWS_SECRET_ACCESS_KEY\n')['gitlab_ci.cloud_oidc']['passed'])
        c = self._run('deploy:\n  id_tokens:\n    T:\n      aud: https://gitlab.com\n  script: [x]\n')
        self.assertTrue(c['gitlab_ci.cloud_oidc']['passed'])
        self.assertFalse(self._run('build:\n  script: [make]\n')['gitlab_ci.cloud_oidc']['applicable'])


class CiSupplyChainInTheEngineTest(TestCase):
    """GitLab projects finally get CI supply-chain checks; GitHub ones keep theirs."""

    def test_gitlabs_own_sast_template_counts_as_a_scanner(self):
        """gitlab-org/cli includes Jobs/SAST and Secret-Detection and was told it had no scanner."""
        from app.checks import run_all_checks
        for include in ('template: Jobs/SAST.gitlab-ci.yml', 'template: Security/Secret-Detection.gitlab-ci.yml',
                        'component: gitlab.com/components/sast/sast@2.0'):
            checks = _by_check_id(run_all_checks(_ci_client(
                {'.gitlab-ci.yml': f'include:\n  - {include}\nbuild:\n  script: [make]\n'},
                provider='gitlab')))
            self.assertTrue(checks['ci.security_scan']['passed'], include)

    def _ids(self, files, provider):
        from app.checks import run_all_checks
        return {c['check_id'] for c in run_all_checks(_ci_client(files, provider=provider))}

    def test_a_gitlab_project_gets_gitlab_ci_checks(self):
        ids = self._ids({'.gitlab-ci.yml': 'build:\n  image: node\n  script: [x]\n'}, 'gitlab')
        self.assertIn('gitlab_ci.pinned_images', ids)
        self.assertFalse({i for i in ids if i.startswith('actions.')})

    def test_a_github_repository_gets_actions_checks(self):
        ids = self._ids({'.github/workflows/ci.yml': 'on: push\njobs: {}\n'}, 'github')
        self.assertIn('actions.script_injection', ids)
        self.assertIn('actions.self_hosted_public', ids)


class SocialSignInLandsSomewhereTest(TestCase):
    """
    A GitHub sign-in by the owner (whose account was made with Google) went
    GitHub → callback → /accounts/3rdparty/signup/ → a meta-refresh stub to
    /profile/ → the login page. No message, no account: the button looked
    broken. Seen in the prod nginx log on 2026-09-24.
    """

    def _provider_account(self, name='GitHub'):
        from types import SimpleNamespace
        provider = SimpleNamespace(name=name)
        return SimpleNamespace(get_provider=lambda: provider)

    def _signup_form(self, email_error=False):
        from django import forms

        class F(forms.Form):
            username = forms.CharField()
            email = forms.EmailField(required=False)

        form = F(data={'username': 'octo', 'email': 'me@example.com'})
        form.is_valid()
        if email_error:
            form.add_error('email', 'An account already exists with this email address.')
        return form

    def test_the_signup_step_is_a_page_not_a_redirect(self):
        from django.template.loader import render_to_string
        html = render_to_string('socialaccount/signup.html', {
            'form': self._signup_form(), 'account': self._provider_account()})
        self.assertNotIn('http-equiv="refresh"', html)
        self.assertIn('action="/accounts/3rdparty/signup/"', html)
        self.assertIn('name="username"', html)
        self.assertIn('GitHub', html)

    def test_an_email_already_here_is_explained_with_a_way_out(self):
        from django.template.loader import render_to_string
        html = render_to_string('socialaccount/signup.html', {
            'form': self._signup_form(email_error=True), 'account': self._provider_account('GitLab')})
        self.assertIn('An account with this email already exists here', html)
        self.assertIn('href="/login/?next=/profile/%23connect"', html)

    def test_a_failed_round_trip_says_what_happened(self):
        from allauth.socialaccount.models import SocialApp
        from django.contrib.sites.models import Site
        app = SocialApp.objects.create(provider='github', name='GitHub', client_id='x', secret='y')
        app.sites.add(Site.objects.get_current())
        r = self.client.get('/accounts/github/login/callback/?error=server_error')
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Sign-in did not go through')
        self.assertContains(r, 'href="/login/"')

    def test_allauths_login_url_keeps_next(self):
        from django.template.loader import render_to_string
        from django.test import RequestFactory
        html = render_to_string('account/login.html', {'request': RequestFactory().get('/', {'next': '/profile/'})})
        self.assertIn('url=/login/?next=/profile/', html)


class SocialSignupSaysTheEmailIsTakenUpFrontTest(TestCase):
    """A GitLab sign-in by an existing user used to be offered a duplicate account first."""

    def _form(self, email):
        from allauth.socialaccount.models import SocialAccount, SocialLogin
        from app.forms_social import SocialSignupForm
        user = User(email=email, username='gl-user')
        login = SocialLogin(user=user, account=SocialAccount(provider='gitlab', uid='1', extra_data={}))
        return SocialSignupForm(sociallogin=login)

    def test_an_email_that_already_has_an_account_is_flagged(self):
        make_user('dani', email='dani@example.com')
        self.assertTrue(self._form('DANI@example.com').email_taken)

    def test_a_new_email_is_not(self):
        self.assertFalse(self._form('new@example.com').email_taken)

    def test_the_page_explains_it_before_submit(self):
        from types import SimpleNamespace
        from django.template.loader import render_to_string
        make_user('dani', email='dani@example.com')
        provider = SimpleNamespace(name='GitLab')
        html = render_to_string('socialaccount/signup.html', {
            'form': self._form('dani@example.com'),
            'account': SimpleNamespace(get_provider=lambda: provider)})
        self.assertIn('An account with this email already exists here', html)


class SocialSignInByVerifiedEmailTest(TestCase):
    """The owner signs in with GitHub and lands in the account they made with Google."""

    def setUp(self):
        from allauth.account.models import EmailAddress
        from allauth.socialaccount.models import SocialApp
        from django.contrib.sites.models import Site
        self.app = SocialApp.objects.create(provider='github', name='GitHub', client_id='x', secret='y')
        self.app.sites.add(Site.objects.get_current())
        self.owner = make_user('owner', email='owner@example.com')
        self.address = EmailAddress.objects.create(
            user=self.owner, email='owner@example.com', verified=True, primary=True)

    def _github_login(self, email='owner@example.com', provider_verified=True):
        from allauth.account.models import EmailAddress
        from allauth.core import context
        from allauth.socialaccount.models import SocialAccount, SocialLogin, SocialToken
        from django.test import RequestFactory
        account = SocialAccount(provider='github', uid='4242',
                                extra_data={'id': 4242, 'login': 'owner-gh', 'avatar_url': ''})
        login = SocialLogin(user=User(), account=account,
                            token=SocialToken(app=self.app, account=account, token='gho_x'),
                            email_addresses=[EmailAddress(email=email, verified=provider_verified,
                                                          primary=True)])
        request = RequestFactory().get('/')
        request.user = AnonymousUser()
        with context.request_context(request):
            login.lookup()
        return login

    def test_a_verified_match_signs_in_to_the_existing_account(self):
        login = self._github_login()
        self.assertEqual(login.user, self.owner)

    def test_an_email_we_never_verified_is_not_enough(self):
        """register_view takes any email unconfirmed; do not hand that account to a GitHub login."""
        self.address.verified = False
        self.address.save()
        self.assertIsNone(self._github_login().user.pk)

    def test_an_email_the_provider_did_not_verify_is_not_enough(self):
        self.assertIsNone(self._github_login(provider_verified=False).user.pk)

    def test_the_owners_password_is_kept(self):
        self.owner.set_password('still-mine-123')
        self.owner.save()
        from allauth.core import context
        from django.test import RequestFactory
        login = self._github_login()
        request = RequestFactory().get('/')
        request.user = AnonymousUser()
        with context.request_context(request):
            login._accept_login(request)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.check_password('still-mine-123'))


class ProfileOffersOneClickConnectTest(TestCase):
    """The profile page never received the OAuth flags its template checks."""

    def setUp(self):
        self.user = make_user('btnuser')
        self.client.login(username='btnuser', password='testpass123')

    @override_settings(GITLAB_APP_ID='gl-app')
    def test_gitlab_has_a_one_click_connect(self):
        r = self.client.get(reverse('connect'))
        self.assertContains(r, 'href="/accounts/gitlab/login/?process=connect&amp;next=/profile/%23connect"')

    @override_settings(GITHUB_APP_SLUG='devops-audit')
    def test_the_github_app_install_is_offered_when_configured(self):
        with patch('app.github_app.is_configured', return_value=True):
            r = self.client.get(reverse('connect'))
        self.assertContains(r, reverse('github_app_install'))


# ── checks_ai_agents: AI agent safety (roadmap 4.3) ───────────────────────────

class AiAgentSafetyTest(TestCase):

    def _run(self, files, public=False, provider='github'):
        from app.checks_ai_agents import check_ai_agents
        return _by_check_id(check_ai_agents(_ci_client(files, public=public, provider=provider)))

    # MCP secrets
    def test_a_typed_in_token_in_mcp_env_is_critical(self):
        mcp = '{"mcpServers": {"github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@1.0.0"], "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_16C7e42F292c6912E7710c838347Ae178B4a"}}}}'
        c = self._run({'.mcp.json': mcp})['ai.mcp_secrets']
        self.assertFalse(c['passed'])
        self.assertEqual(c['severity'], 'crit')
        self.assertEqual(c['category'], 'ai_agents')
        self.assertIn('env.GITHUB_PERSONAL_ACCESS_TOKEN', c['description'])
        self.assertNotIn('ghp_16C7', c['description'] + c['recommendation'])  # never the value

    def test_low_entropy_literal_tokens_are_caught_by_name(self):
        """The generic scanner's entropy gate would let these through; the key name gives them away."""
        mcp = '{"servers": {"db": {"command": "uvx", "args": ["mcp-postgres==1.0"], "env": {"DB_PASSWORD": "postgres123"}}}}'
        self.assertFalse(self._run({'.vscode/mcp.json': mcp})['ai.mcp_secrets']['passed'])

    def test_bearer_header_and_url_query_are_caught(self):
        mcp = ('{"mcpServers": {"a": {"url": "https://mcp.example.com/sse", "headers": {"Authorization": "Bearer abcdef1234567890"}},'
               ' "b": {"url": "https://mcp.example.com/sse?api_key=abcdef1234567890"}}}')
        c = self._run({'.cursor/mcp.json': mcp})['ai.mcp_secrets']
        self.assertIn('headers.Authorization', c['description'])
        self.assertIn('?api_key=', c['description'])

    def test_environment_references_pass(self):
        mcp = ('{"mcpServers": {"gh": {"command": "npx", "args": ["-y", "pkg@1.2.3"], "env": {'
               '"GITHUB_TOKEN": "${env:GITHUB_TOKEN}", "API_KEY": "${API_KEY}", "X_TOKEN": "${input:tok}"},'
               ' "headers": {"Authorization": "Bearer ${env:TOKEN}"}}}}')
        self.assertTrue(self._run({'.mcp.json': mcp})['ai.mcp_secrets']['passed'])

    def test_vscode_jsonc_with_comments_parses(self):
        mcp = '{\n  // my servers\n  "servers": {"a": {"command": "npx", "args": ["pkg"], },},\n}'
        self.assertFalse(self._run({'.vscode/mcp.json': mcp})['ai.mcp_pinned']['passed'])

    def test_a_token_in_mcp_config_is_counted_once_not_twice(self):
        from app.checks import run_all_checks
        mcp = '{"mcpServers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": "ghp_16C7e42F292c6912E7710c838347Ae178B4a"}}}}'
        checks = _by_check_id(run_all_checks(_ci_client({'.mcp.json': mcp})))
        self.assertFalse(checks['ai.mcp_secrets']['passed'])
        self.assertTrue(checks['security.no_secrets']['passed'])

    def test_no_mcp_configs_is_not_applicable(self):
        c = self._run({'README.md': 'x'})
        self.assertFalse(c['ai.mcp_secrets']['applicable'])
        self.assertFalse(c['ai.mcp_pinned']['applicable'])

    # MCP pinning
    def test_npx_without_version_and_latest_are_unpinned(self):
        mcp = ('{"mcpServers": {"a": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},'
               ' "b": {"command": "npx", "args": ["-y", "some-server@latest"]}}}')
        c = self._run({'.mcp.json': mcp})['ai.mcp_pinned']
        self.assertFalse(c['passed'])
        self.assertIn('@modelcontextprotocol/server-github', c['description'])
        self.assertIn('some-server@latest', c['description'])

    def test_uvx_and_docker_pinning(self):
        pinned = ('{"mcpServers": {"a": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"]},'
                  ' "b": {"command": "uvx", "args": ["--from", "pkg==1.0", "tool"]},'
                  ' "c": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/github/github-mcp-server:v0.5.0"]},'
                  ' "d": {"command": "npx", "args": ["-y", "@scope/pkg@2.1.0"]}}}')
        self.assertTrue(self._run({'.mcp.json': pinned})['ai.mcp_pinned']['passed'])
        floating = '{"mcpServers": {"c": {"command": "docker", "args": ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server"]}}}'
        self.assertFalse(self._run({'.mcp.json': floating})['ai.mcp_pinned']['passed'])

    def test_remote_only_servers_have_nothing_to_pin(self):
        mcp = '{"mcpServers": {"a": {"type": "http", "url": "https://api.githubcopilot.com/mcp/"}}}'
        self.assertFalse(self._run({'.mcp.json': mcp})['ai.mcp_pinned']['applicable'])

    def test_a_locally_installed_binary_has_nothing_to_pin(self):
        """cli/cli: `gh aw mcp-server` is an installed extension, not a download."""
        mcp = '{"mcpServers": {"aw": {"type": "local", "command": "gh", "args": ["aw", "mcp-server"]}}}'
        self.assertFalse(self._run({'.github/mcp.json': mcp})['ai.mcp_pinned']['applicable'])

    # AI agents in CI
    def _wf(self, body):
        return {'.github/workflows/agent.yml': body}

    def test_an_agent_on_issue_comment_with_write_access_is_critical(self):
        wf = ('on: issue_comment\npermissions:\n  contents: write\njobs:\n  fix:\n    runs-on: ubuntu-latest\n'
              '    steps:\n      - uses: openai/codex-action@v1\n')
        c = self._run(self._wf(wf))['ai.agent_ci_exposed']
        self.assertFalse(c['passed'])
        self.assertEqual(c['severity'], 'crit')
        self.assertIn('issue_comment', c['description'])

    def test_an_agent_cli_in_run_counts_too(self):
        wf = ('on:\n  issues:\n    types: [opened]\njobs:\n  j:\n    runs-on: ubuntu-latest\n'
              '    steps:\n      - run: aider --yes --message "$BODY"\n')
        self.assertFalse(self._run(self._wf(wf))['ai.agent_ci_exposed']['passed'])

    def test_claude_code_action_gates_non_writers_by_default(self):
        wf = ('on: issue_comment\npermissions:\n  contents: write\njobs:\n  claude:\n    runs-on: ubuntu-latest\n'
              '    steps:\n      - uses: anthropics/claude-code-action@v1\n')
        self.assertTrue(self._run(self._wf(wf))['ai.agent_ci_exposed']['passed'])

    def test_opening_claude_code_action_to_everyone_is_flagged(self):
        wf = ('on: issue_comment\npermissions:\n  contents: write\njobs:\n  claude:\n    runs-on: ubuntu-latest\n'
              '    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: "*"\n')
        self.assertFalse(self._run(self._wf(wf))['ai.agent_ci_exposed']['passed'])

    def test_an_author_association_gate_is_respected(self):
        wf = ('on: issue_comment\npermissions:\n  contents: write\njobs:\n  j:\n'
              "    if: contains(fromJSON('[\"OWNER\",\"MEMBER\"]'), github.event.comment.author_association)\n"
              '    runs-on: ubuntu-latest\n    steps:\n      - uses: openai/codex-action@v1\n')
        self.assertTrue(self._run(self._wf(wf))['ai.agent_ci_exposed']['passed'])

    def test_read_only_or_fork_safe_triggers_pass(self):
        read_only = ('on: issue_comment\npermissions:\n  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n'
                     '    steps:\n      - uses: openai/codex-action@v1\n')
        self.assertTrue(self._run(self._wf(read_only))['ai.agent_ci_exposed']['passed'])
        fork_pr = ('on: pull_request\njobs:\n  review:\n    runs-on: ubuntu-latest\n'
                   '    steps:\n      - uses: qodo-ai/pr-agent@main\n')
        self.assertTrue(self._run(self._wf(fork_pr))['ai.agent_ci_exposed']['passed'])

    def test_a_read_only_agent_on_new_issues_is_the_safe_pattern(self):
        """cli/cli's gh-aw issue triage: outsider trigger, agent job read-only, writes elsewhere."""
        wf = ('on:\n  issues:\n    types: [opened]\npermissions: {}\njobs:\n  agent:\n    runs-on: ubuntu-latest\n'
              '    permissions:\n      contents: read\n      issues: read\n'
              '    steps:\n      - run: copilot --add-dir /tmp --prompt "$(cat prompt.txt)"\n')
        c = self._run(self._wf(wf))['ai.agent_ci_exposed']
        self.assertTrue(c.get('applicable', True))
        self.assertTrue(c['passed'])

    def test_an_open_triage_agent_that_can_only_label_is_a_warning(self):
        """anthropics/claude-code-action's own issue-triage.yml, as published."""
        wf = ('on:\n  issues:\n    types: [opened]\njobs:\n  triage-issue:\n    runs-on: ubuntu-latest\n'
              '    permissions:\n      contents: read\n      issues: write\n      id-token: write\n'
              '    steps:\n      - uses: anthropics/claude-code-action@main\n        with:\n'
              '          allowed_non_write_users: "*"\n')
        c = self._run(self._wf(wf))['ai.agent_ci_exposed']
        self.assertFalse(c['passed'])
        self.assertEqual(c['severity'], 'warn')
        self.assertIn('not change code', c['description'])

    def test_undeclared_permissions_count_as_able_to_change_code(self):
        wf = ('on: issue_comment\njobs:\n  j:\n    runs-on: ubuntu-latest\n'
              '    steps:\n      - uses: openai/codex-action@v1\n')
        self.assertEqual(self._run(self._wf(wf))['ai.agent_ci_exposed']['severity'], 'crit')

    def test_no_agent_in_ci_is_not_applicable(self):
        wf = 'on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps: []\n'
        self.assertFalse(self._run(self._wf(wf))['ai.agent_ci_exposed']['applicable'])

    # Instruction files
    def test_secrets_in_claude_md_are_critical(self):
        c = self._run({'CLAUDE.md': 'Deploy with key AKIA2E0A8F3B244C9986 and go.'})['ai.instructions_clean']
        self.assertFalse(c['passed'])
        self.assertEqual(c['severity'], 'crit')

    def test_internal_hostnames_are_a_warning(self):
        c = self._run({'AGENTS.md': 'Staging: https://api.staging.corp and http://10.0.3.7:8080/admin',
                       '.cursor/rules/deploy.mdc': 'see https://wiki.intranet.acme.com/runbook'})['ai.instructions_clean']
        self.assertFalse(c['passed'])
        self.assertEqual(c['severity'], 'warn')
        self.assertIn('api.staging.corp', c['description'])
        self.assertIn('10.0.3.7', c['description'])
        self.assertIn('wiki.intranet.acme.com', c['description'])

    def test_localhost_and_public_urls_are_fine(self):
        c = self._run({'CLAUDE.md': 'Run on http://localhost:8000 and read https://docs.djangoproject.com'})
        self.assertTrue(c['ai.instructions_clean']['passed'])

    def test_no_instruction_files_is_not_applicable(self):
        self.assertFalse(self._run({'README.md': 'x'})['ai.instructions_clean']['applicable'])

    def test_a_repository_with_no_ai_tooling_gets_no_ai_category_score(self):
        from app.checks import get_category_scores, run_all_checks
        scores = get_category_scores(run_all_checks(_ci_client({'README.md': 'x'})))
        self.assertNotIn('ai_agents', scores)


# ── Phase 4.2: secrets in git history + liveness ──────────────────────────────

_HIST_TOKEN = 'ghp_' + 'Q7fLm2Rx9TbW4kZp8NcV3hJy6DsA1eGu5oKi'


def _git_repo_with_deleted_secret(tmp):
    """A repository whose first commit added a token and whose second deleted it."""
    import subprocess
    repo = os.path.join(tmp, 'src')
    os.makedirs(repo)
    env = {**os.environ, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@t',
           'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@t',
           'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}

    def git(*args):
        subprocess.run(['git', '-C', repo, *args], env=env, check=True, capture_output=True)

    git('init', '-q', '-b', 'main')
    git('config', 'uploadpack.allowFilter', 'true')
    Path(repo, 'config.py').write_text(f'TOKEN = "{_HIST_TOKEN}"\n')
    Path(repo, 'README.md').write_text('hello\n')
    git('add', '-A')
    git('commit', '-q', '-m', 'add config')
    Path(repo, 'config.py').write_text('import os\nTOKEN = os.environ["TOKEN"]\n')
    git('commit', '-q', '-am', 'read token from env')
    return 'file://' + repo


class SecretHistoryTest(TestCase):
    def setUp(self):
        import shutil
        import tempfile
        if shutil.which('git') is None:
            self.skipTest('git not installed')
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.source = (_git_repo_with_deleted_secret(self.tmp), '', True)

    def _client(self, files=None):
        from app.repo_client import StaticRepoClient
        client = StaticRepoClient(files or {'config.py': 'import os\n', 'README.md': 'hello\n'})
        client.supports_deep_scan = True
        return client

    def test_a_secret_deleted_in_a_later_commit_is_found(self):
        from app.secret_history import scan_history
        result = scan_history(self._client(), source=self.source)
        self.assertTrue(result.scanned)
        [finding] = [f for f in result.findings if f['rule'] == 'github_pat']
        self.assertEqual(finding['file'], 'config.py')
        self.assertFalse(finding['in_head'])
        self.assertTrue(finding['commit'])
        self.assertRegex(finding['date'], r'^\d{4}-\d{2}-\d{2}$')

    def test_allow_secrets_paths_are_skipped_in_history_too(self):
        from app.secret_history import scan_history
        result = scan_history(self._client(), allow_paths=('config.py',), source=self.source)
        self.assertTrue(result.scanned)
        self.assertEqual(result.findings, [])

    def test_an_oversized_repository_is_not_cloned(self):
        from app.secret_history import scan_history
        client = self._client()
        client.size_kb = 10 ** 7
        with patch('app.secret_history.subprocess.run') as run:
            result = scan_history(client, source=self.source)
        run.assert_not_called()
        self.assertFalse(result.scanned)
        self.assertEqual(result.reason, 'too_large')

    def test_an_unreachable_remote_degrades_to_not_scanned(self):
        from app.secret_history import scan_history
        result = scan_history(self._client(), source=('file:///nonexistent/repo', '', True))
        self.assertFalse(result.scanned)
        self.assertEqual(result.reason, 'failed')

    def test_deep_scan_reports_history_and_a_live_key_without_ever_printing_it(self):
        from app.checks_secrets import scan_secrets
        with patch('app.secret_history.clone_source', return_value=self.source), \
             patch.dict('app.secret_liveness.CHECKERS',
                        {'github_pat': lambda value, **kw: 'active'}):
            checks = {c['check_id']: c for c in scan_secrets(self._client(), deep=True)}
        self.assertTrue(checks['security.no_secrets']['passed'])
        history = checks['security.no_secrets_in_history']
        self.assertFalse(history['passed'])
        self.assertEqual(history['severity'], 'crit')
        self.assertIn('config.py', history['description'])
        self.assertIn('deleted from the code later', history['description'])
        live = checks['security.secret_active']
        self.assertFalse(live['passed'])
        self.assertEqual(live['severity'], 'crit')
        for check in checks.values():
            for text in (check['description'], check['recommendation']):
                self.assertNotIn(_HIST_TOKEN, text)

    def test_a_revoked_key_in_history_is_reported_but_not_as_live(self):
        from app.checks_secrets import scan_secrets
        with patch('app.secret_history.clone_source', return_value=self.source), \
             patch.dict('app.secret_liveness.CHECKERS',
                        {'github_pat': lambda value, **kw: 'inactive'}):
            checks = {c['check_id']: c for c in scan_secrets(self._client(), deep=True)}
        self.assertFalse(checks['security.no_secrets_in_history']['passed'])
        self.assertIn('1 rejected', checks['security.no_secrets_in_history']['description'])
        self.assertNotIn('security.secret_active', checks)

    def test_a_secret_still_in_the_tree_is_not_reported_twice(self):
        from app.checks_secrets import scan_secrets
        client = self._client({'config.py': f'TOKEN = "{_HIST_TOKEN}"\n'})
        with patch('app.secret_history.clone_source', return_value=self.source), \
             patch.dict('app.secret_liveness.CHECKERS',
                        {'github_pat': lambda value, **kw: 'unknown'}):
            checks = {c['check_id']: c for c in scan_secrets(client, deep=True)}
        self.assertFalse(checks['security.no_secrets']['passed'])
        self.assertIn('could not be checked', checks['security.no_secrets']['description'])
        self.assertTrue(checks['security.no_secrets_in_history']['passed'])

    def test_the_public_scanner_never_clones_or_calls_a_provider(self):
        from app.checks import run_all_checks
        client = self._client({'config.py': f'TOKEN = "{_HIST_TOKEN}"\n'})
        with patch('app.secret_history.scan_history', side_effect=AssertionError('cloned')), \
             patch('app.secret_liveness.verify_findings', side_effect=AssertionError('called')):
            checks = run_all_checks(client)
        ids = {c['check_id'] for c in checks}
        self.assertNotIn('security.no_secrets_in_history', ids)
        self.assertNotIn('security.secret_active', ids)

    def test_a_test_client_is_never_deep_scanned_even_when_asked(self):
        from app.checks_secrets import scan_secrets
        from app.repo_client import StaticRepoClient
        with patch('app.secret_history.scan_history', side_effect=AssertionError('cloned')):
            checks = scan_secrets(StaticRepoClient({'a.py': ''}), deep=True)
        self.assertEqual({c['check_id'] for c in checks},
                         {'security.no_secrets', 'security.env_not_committed'})


class CloneSourceTest(TestCase):
    def test_token_goes_in_a_header_not_the_url(self):
        from app.repo_client import GithubRepoClient
        from app.secret_history import clone_source
        url, header, verify = clone_source(GithubRepoClient('acme/app', token='tok123'))
        self.assertEqual(url, 'https://github.com/acme/app.git')
        self.assertNotIn('tok123', url)
        self.assertEqual(header, 'Authorization: Basic ' + base64.b64encode(b'x-access-token:tok123').decode())
        self.assertTrue(verify)

    def test_gitlab_uses_the_instance_and_its_tls_setting(self):
        from app.repo_client import GitlabRepoClient
        from app.secret_history import clone_source
        client = GitlabRepoClient(7, 'tok', 'https://git.example.com/', verify_ssl=False)
        client.full_name = 'team/app'
        url, header, verify = clone_source(client)
        self.assertEqual(url, 'https://git.example.com/team/app.git')
        self.assertIn(base64.b64encode(b'oauth2:tok').decode(), header)
        self.assertFalse(verify)

    def test_custom_dns_gitlab_cannot_be_cloned(self):
        from app.repo_client import GitlabRepoClient
        from app.secret_history import clone_source
        self.assertIsNone(clone_source(GitlabRepoClient(7, 'tok', custom_dns='10.0.0.1')))

    def test_git_env_carries_the_header_only_in_the_environment(self):
        from app.secret_history import _git_env
        env = _git_env('Authorization: Basic abc', verify=False)
        self.assertEqual(env['GIT_CONFIG_KEY_0'], 'http.extraHeader')
        self.assertEqual(env['GIT_CONFIG_VALUE_0'], 'Authorization: Basic abc')
        self.assertEqual(env['GIT_CONFIG_KEY_1'], 'http.sslVerify')
        self.assertEqual(env['GIT_TERMINAL_PROMPT'], '0')


def _resp(status, body=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body or {}
    return r


class SecretLivenessTest(TestCase):
    def _finding(self, rule, value, file='config.py'):
        return {'rule': rule, 'value': value, 'file': file, 'label': rule, 'severity': 'crit'}

    def test_github_200_is_active_and_401_inactive(self):
        from app import secret_liveness as sl
        with patch('app.secret_liveness.requests.get', return_value=_resp(200)) as get:
            self.assertEqual(sl.check_github('ghp_x'), sl.ACTIVE)
        self.assertEqual(get.call_args.args[0], 'https://api.github.com/user')
        with patch('app.secret_liveness.requests.get', return_value=_resp(401)):
            self.assertEqual(sl.check_github('ghp_x'), sl.INACTIVE)
        with patch('app.secret_liveness.requests.get', return_value=_resp(403)):
            self.assertEqual(sl.check_github('ghp_x'), sl.UNKNOWN)

    def test_a_network_error_is_unknown_not_inactive(self):
        import requests as _requests
        from app import secret_liveness as sl
        with patch('app.secret_liveness.requests.get', side_effect=_requests.ConnectionError):
            self.assertEqual(sl.check_openai('sk-x'), sl.UNKNOWN)

    def test_slack_reads_the_error_code(self):
        from app import secret_liveness as sl
        with patch('app.secret_liveness.requests.post', return_value=_resp(200, {'ok': True})):
            self.assertEqual(sl.check_slack('xoxb-1'), sl.ACTIVE)
        with patch('app.secret_liveness.requests.post',
                   return_value=_resp(200, {'ok': False, 'error': 'token_revoked'})):
            self.assertEqual(sl.check_slack('xoxb-1'), sl.INACTIVE)
        with patch('app.secret_liveness.requests.post',
                   return_value=_resp(200, {'ok': False, 'error': 'ratelimited'})):
            self.assertEqual(sl.check_slack('xoxb-1'), sl.UNKNOWN)

    def test_a_restricted_stripe_key_without_balance_access_is_still_live(self):
        from app import secret_liveness as sl
        with patch('app.secret_liveness.requests.get', return_value=_resp(403)):
            self.assertEqual(sl.check_stripe('rk_live_x'), sl.ACTIVE)

    def test_telegram_and_anthropic(self):
        from app import secret_liveness as sl
        with patch('app.secret_liveness.requests.get', return_value=_resp(404)):
            self.assertEqual(sl.check_telegram('1:AA'), sl.INACTIVE)
        with patch('app.secret_liveness.requests.get', return_value=_resp(200)) as get:
            self.assertEqual(sl.check_anthropic('sk-ant-x'), sl.ACTIVE)
        self.assertEqual(get.call_args.kwargs['headers']['x-api-key'], 'sk-ant-x')

    def test_gitlab_is_checked_on_the_audited_instance(self):
        from app import secret_liveness as sl
        with patch('app.secret_liveness.requests.get', return_value=_resp(200)) as get:
            sl.check_gitlab('glpat-x', gitlab_url='https://git.example.com/', verify_ssl=False)
        self.assertEqual(get.call_args.args[0], 'https://git.example.com/api/v4/user')
        self.assertFalse(get.call_args.kwargs['verify'])

    def test_aws_key_id_alone_cannot_be_checked(self):
        from app import secret_liveness as sl
        findings = [self._finding('aws_access_key', 'AKIAIOSFODNN7EXAMPL1')]
        with patch('app.secret_liveness.requests.post') as post:
            sl.verify_findings(findings)
        post.assert_not_called()
        self.assertEqual(findings[0]['liveness'], sl.UNKNOWN)

    def test_aws_pair_is_checked_with_a_signed_sts_call(self):
        from app import secret_liveness as sl
        findings = [self._finding('aws_access_key', 'AKIAIOSFODNN7EXAMPL1'),
                    self._finding('aws_secret_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')]
        with patch('app.secret_liveness.requests.post', return_value=_resp(200)) as post:
            sl.verify_findings(findings)
        self.assertEqual(post.call_args.args[0], 'https://sts.amazonaws.com/')
        auth = post.call_args.kwargs['headers']['Authorization']
        self.assertTrue(auth.startswith('AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPL1/'))
        self.assertNotIn('wJalrXUtnFEMI', auth)
        self.assertEqual([f['liveness'] for f in findings], [sl.ACTIVE, sl.ACTIVE])

    def test_one_value_found_twice_is_asked_about_once(self):
        from app import secret_liveness as sl
        findings = [self._finding('github_pat', 'ghp_same', 'a.py'),
                    self._finding('github_pat', 'ghp_same', 'b.py'),
                    self._finding('jwt', 'eyJ.x.y')]
        calls = []
        with patch.dict('app.secret_liveness.CHECKERS',
                        {'github_pat': lambda v, **kw: calls.append(v) or sl.INACTIVE}):
            sl.verify_findings(findings)
        self.assertEqual(calls, ['ghp_same'])
        self.assertEqual([f['liveness'] for f in findings], [sl.INACTIVE, sl.INACTIVE, sl.UNKNOWN])

    def test_provider_calls_are_capped_per_audit(self):
        from app import secret_liveness as sl
        findings = [self._finding('github_pat', f'ghp_{i}') for i in range(sl.MAX_CHECKS + 5)]
        calls = []
        with patch.dict('app.secret_liveness.CHECKERS',
                        {'github_pat': lambda v, **kw: calls.append(v) or sl.ACTIVE}):
            sl.verify_findings(findings)
        self.assertEqual(len(calls), sl.MAX_CHECKS)
        self.assertEqual(sum(f['liveness'] == sl.UNKNOWN for f in findings), 5)

    def test_telegram_bot_tokens_are_found(self):
        from app.checks_secrets import scan_text
        found = scan_text('bot.py', 'TOKEN = "1234567890:AAH' + 'x7Kq2Lm9Pz4Rt6Wv8Yb1Nc3Df5Gh0Jk2"')
        self.assertEqual([f['rule'] for f in found], ['telegram_bot_token'])


# ── Phase 4.4: CVE reachability ───────────────────────────────────────────────

_CRIT_VULN = {'id': 'GHSA-crit', 'severity': [{'type': 'CVSS_V3', 'score': 'CRITICAL'}]}
_HIGH_VULN = {'id': 'GHSA-high', 'aliases': ['CVE-2024-1']}


def _osv(*per_package):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {'results': [{'vulns': list(v)} for v in per_package]}
    return resp


class ReachabilityTest(TestCase):
    def _analyse(self, files, ecosystem, pkgs):
        from app.reachability import analyse
        from app.repo_client import StaticRepoClient
        return analyse(StaticRepoClient(files), ecosystem, pkgs)

    def test_python_imports_and_distribution_names(self):
        files = {
            'app/main.py': 'import os, yaml\nfrom PIL import Image\nfrom rest_framework import views\n',
            'requirements.txt': 'pyyaml==5.1\npillow==8.0\ndjangorestframework==3.0\nparamiko==2.0\n',
        }
        self.assertEqual(
            self._analyse(files, 'PyPI', ['pyyaml', 'pillow', 'djangorestframework', 'paramiko']),
            {'pyyaml': 'imported', 'pillow': 'imported', 'djangorestframework': 'imported',
             'paramiko': 'not_imported'})

    def test_python_packages_loaded_by_name_count_as_used(self):
        files = {
            'config/settings.py': "INSTALLED_APPS = ['allauth.account']\n"
                                  "MIDDLEWARE = ['whitenoise.middleware.WhiteNoiseMiddleware']\n",
            'Procfile': 'web: gunicorn config.wsgi --worker-class uvicorn.workers.UvicornWorker\n',
        }
        result = self._analyse(files, 'PyPI', ['django-allauth', 'whitenoise', 'gunicorn', 'uvicorn', 'lxml'])
        self.assertEqual(result['django-allauth'], 'imported')
        self.assertEqual(result['whitenoise'], 'imported')
        self.assertEqual(result['gunicorn'], 'imported')
        self.assertEqual(result['uvicorn'], 'imported')
        self.assertEqual(result['lxml'], 'not_imported')

    def test_js_imports_requires_scripts_and_plugin_names(self):
        files = {
            'src/index.ts': "import express from 'express'\nconst _ = require('lodash/fp')\n"
                            "import { x } from '@scope/pkg/sub'\n",
            '.eslintrc.json': '{"plugins": ["react"]}',
            'package.json': json.dumps({'scripts': {'test': 'jest --ci'}}),
        }
        result = self._analyse(files, 'npm', ['express', 'lodash', '@scope/pkg', 'eslint-plugin-react',
                                              'jest', 'left-pad'])
        self.assertEqual(result, {'express': 'imported', 'lodash': 'imported', '@scope/pkg': 'imported',
                                  'eslint-plugin-react': 'imported', 'jest': 'imported',
                                  'left-pad': 'not_imported'})

    def test_vendored_code_does_not_count(self):
        files = {'src/a.js': "require('express')", 'node_modules/x/index.js': "require('left-pad')"}
        self.assertEqual(self._analyse(files, 'npm', ['left-pad'])['left-pad'], 'not_imported')

    def test_one_unreadable_source_file_makes_everything_unknown(self):
        files = {'a.py': 'import yaml\n', 'b.py': None}
        self.assertEqual(self._analyse(files, 'PyPI', ['paramiko']), {'paramiko': 'unknown'})

    def test_no_source_or_other_ecosystem_is_unknown(self):
        self.assertEqual(self._analyse({'README.md': 'x'}, 'PyPI', ['a']), {'a': 'unknown'})
        self.assertEqual(self._analyse({'main.go': 'import "x"'}, 'Go', ['x']), {'x': 'unknown'})

    def test_a_truncated_tree_is_unknown(self):
        from app.reachability import analyse
        from app.repo_client import StaticRepoClient
        client = StaticRepoClient({'a.py': ''})
        client.tree_truncated = True
        self.assertEqual(analyse(client, 'PyPI', ['x']), {'x': 'unknown'})

    def test_local_text_never_makes_a_request(self):
        from app.repo_client import GithubRepoClient
        client = GithubRepoClient('acme/app')
        client.files = {'a.py'}
        with patch.object(client, '_remote_content', side_effect=AssertionError('request')):
            self.assertIsNone(client.local_text('a.py'))


class CVEReachabilityTest(TestCase):
    def _check(self, files, *osv):
        from app.checks_extra import check_cve_vulnerabilities
        from app.repo_client import StaticRepoClient
        client = StaticRepoClient(files)
        with patch('app.checks_extra.requests.post', return_value=_osv(*osv)):
            [check] = check_cve_vulnerabilities(client.get_content, client=client)
        return check

    def test_a_critical_cve_in_an_unused_package_is_a_warning(self):
        check = self._check({'requirements.txt': 'paramiko==2.0\n', 'app.py': 'import os\n'},
                            [_CRIT_VULN])
        self.assertFalse(check['passed'])
        self.assertEqual(check['severity'], 'warn')
        self.assertIn('not imported', check['description'])
        self.assertIn('heuristic', check['description'])

    def test_a_critical_cve_in_an_imported_package_stays_critical(self):
        check = self._check({'requirements.txt': 'paramiko==2.0\n', 'app.py': 'import paramiko\n'},
                            [_CRIT_VULN])
        self.assertEqual(check['severity'], 'crit')
        self.assertNotIn('not imported', check['description'])

    def test_only_unused_non_critical_findings_are_informational(self):
        check = self._check({'requirements.txt': 'paramiko==2.0\n', 'app.py': 'import os\n'},
                            [_HIGH_VULN])
        self.assertFalse(check['passed'])
        self.assertEqual(check['severity'], 'info')

    def test_imported_packages_are_listed_first_in_the_fix(self):
        check = self._check(
            {'requirements.txt': 'aaa-unused==1.0\nzzz==2.0\n', 'app.py': 'import zzz\n'},
            [_HIGH_VULN], [_HIGH_VULN])
        self.assertLess(check['recommendation'].index('zzz'), check['recommendation'].index('aaa-unused'))
        self.assertEqual(check['severity'], 'warn')

    def test_without_a_client_nothing_is_lowered(self):
        from app.checks_extra import check_cve_vulnerabilities
        with patch('app.checks_extra.requests.post', return_value=_osv([_CRIT_VULN])):
            [check] = check_cve_vulnerabilities(lambda p: {'requirements.txt': 'paramiko==2.0\n'}.get(p))
        self.assertEqual(check['severity'], 'crit')


# ── Empty repositories and the "Reconnect" hint ──────────────────────────────

class EmptyRepositoryTest(TestCase):
    def test_github_pr_on_an_empty_repository_says_so_and_does_not_blame_the_token(self):
        from app.github_writer import GitHubWriteError, _Repo
        repo = _Repo('tok', 'acme/empty')
        with patch('app.github_writer.requests.get', return_value=_resp(409)):
            with self.assertRaises(GitHubWriteError) as ctx:
                repo.branch_from_default('fix')
        self.assertIn('empty', str(ctx.exception))
        self.assertFalse(ctx.exception.reconnect)

    def test_github_branch_failure_carries_the_status(self):
        from app.github_writer import GitHubWriteError, _Repo
        with patch('app.github_writer.requests.get', return_value=_resp(502)):
            with self.assertRaises(GitHubWriteError) as ctx:
                _Repo('tok', 'acme/app').branch_from_default('fix')
        self.assertIn('502', str(ctx.exception))
        self.assertFalse(ctx.exception.reconnect)

    def test_github_401_asks_for_a_reconnect(self):
        from app.github_writer import GitHubWriteError, _Repo
        with patch('app.github_writer.requests.get', return_value=_resp(401)):
            with self.assertRaises(GitHubWriteError) as ctx:
                _Repo('tok', 'acme/app').require_push_access()
        self.assertTrue(ctx.exception.reconnect)

    def test_gitlab_empty_project_is_refused_before_any_write(self):
        from app.gitlab_writer import GitlabWriteError, _Project
        project = _Project('tok', 7)
        body = {'empty_repo': True, 'default_branch': 'main',
                'permissions': {'project_access': {'access_level': 50}}}
        with patch('app.gitlab_writer.requests.request', return_value=_resp(200, body)):
            with self.assertRaises(GitlabWriteError) as ctx:
                project.require_push_access()
        self.assertIn('empty', str(ctx.exception))
        self.assertFalse(ctx.exception.reconnect)

    def test_auditing_an_empty_github_repository_fails_with_a_clear_message(self):
        from app.repo_client import GithubRepoClient, RepoAccessError
        meta = {'default_branch': 'main', 'private': False, 'size': 0}
        with patch.object(GithubRepoClient, '_get', side_effect=[_resp(200, meta), _resp(409)]):
            with self.assertRaises(RepoAccessError) as ctx:
                GithubRepoClient('acme/empty').load()
        self.assertIn('empty', str(ctx.exception))

    def test_auditing_an_empty_gitlab_project_fails_with_a_clear_message(self):
        from app.repo_client import GitlabRepoClient, RepoAccessError
        with patch.object(GitlabRepoClient, '_get', return_value=_resp(200, {'empty_repo': True})):
            with self.assertRaises(RepoAccessError) as ctx:
                GitlabRepoClient(7, 'tok').load()
        self.assertIn('empty', str(ctx.exception))


# ── Score v2: hygiene out of the score; AI routing by repository privacy ─────

class HygieneTest(TestCase):
    def test_hygiene_checks_are_reported_but_not_scored(self):
        from app.checks import HYGIENE_CHECKS, calculate_score, run_all_checks
        from app.repo_client import StaticRepoClient
        with patch('app.checks_extra.check_cve_vulnerabilities', return_value=[]):
            checks = run_all_checks(StaticRepoClient({'app.py': 'print(1)\n'}))
        hygiene = [c for c in checks if c['check_id'] in HYGIENE_CHECKS]
        self.assertTrue(hygiene)
        for c in hygiene:
            self.assertEqual(c['category'], 'hygiene')
            self.assertEqual(c['severity'], 'info')
        # Flipping every hygiene result leaves the score where it was.
        before = calculate_score(checks)
        for c in hygiene:
            c['passed'] = not c['passed']
        self.assertEqual(calculate_score(checks), before)

    def test_counted_queryset_leaves_hygiene_out(self):
        from app.models import AuditCheck
        user = User.objects.create_user('h', 'h@x.io', 'pw')
        audit = Audit.objects.create(user=user, repo_full_name='a/b', status='done')
        AuditCheck.objects.create(audit=audit, check_id='security.codeowners', name='c', description='',
                                  severity='info', passed=False, category='hygiene')
        AuditCheck.objects.create(audit=audit, check_id='deps.cve', name='d', description='',
                                  severity='crit', passed=False, category='deps')
        self.assertEqual([c.check_id for c in audit.checks.counted()], ['deps.cve'])
        self.assertEqual([c.check_id for c in audit.checks.hygiene()], ['security.codeowners'])


@override_settings()
class AIRoutingTest(TestCase):
    ENV = {'GEMINI_API_KEY': 'g', 'ANTHROPIC_API_KEY': 'a'}

    def _pick(self, env, is_private):
        from app.ai_providers import _get_active_provider
        with patch.dict(os.environ, env, clear=False):
            for k in ('AUDIT_AI_PROVIDER', 'OPENAI_API_KEY', 'GEMINI_FREE_TIER'):
                if k not in env:
                    os.environ.pop(k, None)
            return _get_active_provider(None, is_private=is_private)[0]

    def test_public_code_prefers_the_free_gemini_tier(self):
        self.assertEqual(self._pick(self.ENV, is_private=False), 'gemini')

    def test_private_code_never_goes_to_the_free_tier(self):
        self.assertEqual(self._pick(self.ENV, is_private=True), 'anthropic')
        self.assertIsNone(self._pick({'GEMINI_API_KEY': 'g', 'ANTHROPIC_API_KEY': ''}, is_private=True))

    def test_a_forced_free_gemini_is_ignored_for_private_code(self):
        env = {**self.ENV, 'AUDIT_AI_PROVIDER': 'gemini'}
        self.assertEqual(self._pick(env, is_private=True), 'anthropic')

    def test_a_paid_gemini_key_may_serve_private_code(self):
        env = {'GEMINI_API_KEY': 'g', 'ANTHROPIC_API_KEY': '', 'GEMINI_FREE_TIER': '0'}
        self.assertEqual(self._pick(env, is_private=True), 'gemini')

    def test_unknown_privacy_is_private(self):
        from app.ai_providers import _get_active_provider
        import inspect
        self.assertTrue(inspect.signature(_get_active_provider).parameters['is_private'].default)
        self.assertTrue(Audit._meta.get_field('repo_is_private').default)


class GeminiCallTest(TestCase):
    def test_key_in_header_and_fallback_past_a_retired_model(self):
        from app import ai_providers
        ok = _resp(200, {'candidates': [{'content': {'parts': [{'text': 'hi'}]}}]})
        with patch('app.ai_providers.requests.post', side_effect=[_resp(404), ok]) as post:
            self.assertEqual(ai_providers._call_gemini('KEY', 'p', 'gemini-2.5-flash'), 'hi')
        first, second = post.call_args_list
        self.assertNotIn('KEY', first.args[0])
        self.assertEqual(first.kwargs['headers']['x-goog-api-key'], 'KEY')
        self.assertIn('gemini-2.5-flash', first.args[0])
        self.assertIn(ai_providers.GEMINI_FALLBACK_MODELS[0], second.args[0])

    def test_thought_parts_are_not_returned_as_text(self):
        from app import ai_providers
        body = {'candidates': [{'content': {'parts': [{'text': 'thinking', 'thought': True},
                                                      {'text': 'answer'}]}}]}
        with patch('app.ai_providers.requests.post', return_value=_resp(200, body)):
            self.assertEqual(ai_providers._call_gemini('K', 'p', 'm'), 'answer')


# ── GitLab repositories get GitLab advice ─────────────────────────────────────

class GitlabAwareAdviceTest(TestCase):
    def test_gitlab_fix_templates_use_gitlab_paths(self):
        from app.fix_templates import get_fix
        expected = {
            'ci.pipeline': '.gitlab-ci.yml',
            'ci.security_scan': '.gitlab/ci/security.gitlab-ci.yml',
            'iac.scanning': '.gitlab/ci/terraform-scan.gitlab-ci.yml',
            'security.dependency_updates': 'renovate.json',
            'security.codeowners': '.gitlab/CODEOWNERS',
            'docs.templates': '.gitlab/merge_request_templates/Default.md',
        }
        for check_id, path in expected.items():
            filename, content = get_fix(check_id, 'python', 'team/app', host='gitlab')
            self.assertEqual(filename, path, check_id)
            self.assertNotIn('.github/', content, check_id)
            self.assertNotIn('uses: actions/', content, check_id)

    def test_github_templates_are_unchanged(self):
        from app.fix_templates import get_fix
        self.assertEqual(get_fix('ci.pipeline', 'python', 'a/b')[0], '.github/workflows/ci.yml')
        self.assertEqual(get_fix('security.dependency_updates', 'node', 'a/b')[0], '.github/dependabot.yml')

    def test_gitlab_ci_template_is_valid_yaml_with_a_test_job(self):
        import yaml
        from app.fix_templates import get_fix
        for eco in ('python', 'node', 'go', 'rust', 'unknown'):
            doc = yaml.safe_load(get_fix('ci.pipeline', eco, 'team/app', host='gitlab')[1])
            self.assertIn('script', doc['test'], eco)
        for check_id in ('ci.security_scan', 'iac.scanning'):
            doc = yaml.safe_load(get_fix(check_id, 'python', 'team/app', host='gitlab')[1])
            self.assertTrue(all('script' in job for job in doc.values()))

    def test_actions_pinning_has_no_fix_on_gitlab(self):
        from app.fix_templates import is_fixable
        self.assertTrue(is_fixable('actions.pinned_sha'))
        self.assertFalse(is_fixable('actions.pinned_sha', host='gitlab'))

    def test_recommendations_follow_the_host(self):
        from app.checks import run_all_checks
        from app.repo_client import StaticRepoClient
        with patch('app.checks_extra.check_cve_vulnerabilities', return_value=[]):
            gl = {c['check_id']: c for c in run_all_checks(StaticRepoClient({'a.py': ''}, provider='gitlab'))}
            gh = {c['check_id']: c for c in run_all_checks(StaticRepoClient({'a.py': ''}, provider='github'))}
        for cid in ('security.dependency_updates', 'security.codeowners', 'ci.pipeline',
                    'ci.branch_protection', 'docs.templates'):
            self.assertNotIn('.github', gl[cid]['recommendation'], cid)
            self.assertNotIn('Dependabot so', gl[cid]['recommendation'], cid)
        self.assertIn('.github/dependabot.yml', gh['security.dependency_updates']['recommendation'])
        self.assertIn('Protected branches', gl['ci.branch_protection']['recommendation'])

    def test_the_ai_is_told_where_the_repository_lives(self):
        from app.ai_providers import _make_suggestion_prompt
        from app.repo_context import to_prompt, with_host
        self.assertIn('GitLab', to_prompt(with_host({}, 'gitlab'), 'en'))
        self.assertIn('never suggest them', to_prompt({'host': 'gitlab'}, 'en'))
        self.assertIn('Dependabot', _make_suggestion_prompt('n', 'd', None, None, 'en', host='gitlab'))
        self.assertEqual(with_host({'host': 'github'}, 'gitlab')['host'], 'github')

    def test_github_only_builtin_suggestions_are_not_shown_on_gitlab(self):
        from app.ai_providers import get_ai_code_suggestions
        check = {'check_id': 'security.dependency_updates', 'name': 'Automated dependency updates',
                 'description': '', 'recommendation': 'Add renovate.json and enable Renovate.'}
        with patch('app.ai_providers._get_active_provider', return_value=(None, None)), \
             patch('app.ai_providers._get_builtin', return_value='Create .github/dependabot.yml'):
            gl = get_ai_code_suggestions([check], lambda p: None, 'en', host='gitlab')
            gh = get_ai_code_suggestions([check], lambda p: None, 'en', host='github')
        self.assertIn('renovate', gl['Automated dependency updates'])
        self.assertIn('dependabot', gh['Automated dependency updates'])


# ── AI review of build/deploy/CI files ────────────────────────────────────────

_COMPOSE_YML = 'services:\n  db:\n    image: postgres:16\n    ports:\n      - "0.0.0.0:5432:5432"\n'


class AIReviewTest(TestCase):
    def _client(self, files=None, provider='github'):
        from app.repo_client import StaticRepoClient
        c = StaticRepoClient(files or {'compose.yml': _COMPOSE_YML, 'Dockerfile': 'FROM python:3.12\n',
                                       'src/app.py': 'x=1', 'tests/Dockerfile': 'FROM x'},
                             full_name='acme/app', provider=provider)
        c.repo_url = 'https://github.com/acme/app' if provider == 'github' else 'https://gitlab.com/acme/app'
        c.head_sha = 'abc123'
        return c

    def test_only_build_deploy_ci_files_are_sent_and_redacted(self):
        from app.ai_review import select_files
        client = self._client({'Dockerfile': 'ENV TOKEN=ghp_' + 'Q7fLm2Rx9TbW4kZp8NcV3hJy6DsA1eGu5oKi\n',
                               'src/app.py': 'x', 'tests/Dockerfile': 'FROM x',
                               '.github/workflows/ci.yml': 'on: push\n'})
        files = dict(select_files(client))
        self.assertEqual(set(files), {'Dockerfile', '.github/workflows/ci.yml'})
        self.assertNotIn('ghp_Q7f', files['Dockerfile'])

    def test_a_finding_that_misquotes_its_line_is_dropped(self):
        from app.ai_review import verify
        files = [('compose.yml', _COMPOSE_YML)]
        raw = [
            {'file': 'compose.yml', 'line': 5, 'evidence': '- "0.0.0.0:5432:5432"', 'severity': 'high',
             'title': 'Database port published'},
            {'file': 'compose.yml', 'line': 3, 'evidence': 'privileged: true', 'severity': 'high',
             'title': 'Invented'},
            {'file': 'nope.yml', 'line': 1, 'evidence': 'services:', 'title': 'Unknown file'},
            {'file': 'compose.yml', 'line': 'x', 'evidence': 'services:', 'title': 'Bad line'},
        ]
        kept = verify(raw, files)
        self.assertEqual([f['title'] for f in kept], ['Database port published'])
        self.assertEqual(kept[0]['line'], 5)

    def test_a_line_number_a_little_off_is_corrected_to_the_quoted_line(self):
        from app.ai_review import verify
        kept = verify([{'file': 'compose.yml', 'line': 3, 'evidence': '- "0.0.0.0:5432:5432"',
                        'severity': 'weird', 'title': 'Port'}], [('compose.yml', _COMPOSE_YML)])
        self.assertEqual((kept[0]['line'], kept[0]['severity']), (5, 'medium'))

    def test_answer_in_code_fences_is_parsed(self):
        from app.ai_review import _parse
        self.assertEqual(_parse('```json\n[{"a": 1}]\n```'), [{'a': 1}])
        self.assertEqual(_parse('no json here'), [])

    def test_review_end_to_end_with_links_per_host(self):
        from app.ai_review import review
        answer = json.dumps([{'file': 'compose.yml', 'line': 5, 'evidence': '"0.0.0.0:5432:5432"',
                              'severity': 'high', 'title': 'DB port', 'why': 'w', 'fix': 'f'}])
        for host, sep in (('github', '/blob/'), ('gitlab', '/-/blob/')):
            with patch('app.ai_providers._get_active_provider', return_value=('gemini', 'k')), \
                 patch('app.ai_providers._call_provider', return_value=answer) as call:
                findings, provider = review(self._client(provider=host), [], 'en', is_private=False)
            self.assertEqual(provider, 'Google Gemini')
            self.assertTrue(findings[0]['url'].endswith(f'{sep}abc123/compose.yml#L5'), findings[0]['url'])
            self.assertIn('GitLab' if host == 'gitlab' else 'GitHub', call.call_args.args[2])

    def test_no_provider_means_no_review_and_no_request(self):
        from app.ai_review import review
        with patch('app.ai_providers._get_active_provider', return_value=(None, None)), \
             patch('app.ai_providers._call_provider') as call:
            self.assertEqual(review(self._client(), [], 'en'), ([], ''))
        call.assert_not_called()

    def test_private_repositories_follow_the_same_routing(self):
        from app.ai_review import review
        with patch('app.ai_providers._get_active_provider', return_value=(None, None)) as pick:
            review(self._client(), [], 'en', user_id=7, is_private=True)
        pick.assert_called_once_with(7, is_private=True)

    def test_run_ai_stores_findings_and_feeds_them_to_the_summary(self):
        from app import tasks
        user = User.objects.create_user('r', 'r@x.io', 'pw')
        audit = Audit.objects.create(user=user, repo_full_name='acme/app', status='running',
                                     commit_sha='abc123', repo_is_private=False)
        finding = {'file': 'compose.yml', 'line': 5, 'severity': 'high', 'title': 'DB port',
                   'evidence': 'x', 'why': '', 'fix': '', 'url': ''}
        with patch('app.ai_review.review', return_value=([finding], 'Google Gemini')), \
             patch('app.ai_providers.get_ai_summary', return_value=('s', 'Google Gemini')) as summ, \
             patch('app.ai_providers.get_ai_code_suggestions', return_value={}):
            tasks._run_ai(audit, [], self._client())
        audit.refresh_from_db()
        self.assertEqual(audit.ai_findings, [finding])
        self.assertEqual(summ.call_args.kwargs['ai_findings'], [finding])

    def test_a_rerun_on_a_moved_branch_keeps_the_old_findings(self):
        from app import tasks
        user = User.objects.create_user('m', 'm@x.io', 'pw')
        audit = Audit.objects.create(user=user, repo_full_name='acme/app', status='done',
                                     commit_sha='old000', ai_findings=[{'title': 'kept'}])
        with patch('app.ai_review.review') as rv, \
             patch('app.ai_providers.get_ai_summary', return_value=('s', 'x')), \
             patch('app.ai_providers.get_ai_code_suggestions', return_value={}):
            tasks._run_ai(audit, [], self._client())
        rv.assert_not_called()
        self.assertEqual(audit.ai_findings, [{'title': 'kept'}])


# ── Phase 5: pull request until green CI ─────────────────────────────────────

class _FakeGitHub:
    """Enough of fix_agent.GitHub to drive step() without a network."""
    def __init__(self, runs=(), state='open', merged=False, files=None):
        self.runs, self.state, self.merged = list(runs), state, merged
        self.files = dict(files or {})
        self.commits, self.comments = [], []

    def pull(self, number):
        return {'state': self.state, 'merged': self.merged, 'head': {'sha': 'sha1'}}

    def check_runs(self, sha):
        return self.runs

    def failed_logs(self, sha):
        return [('CI / test', 'ERROR: Could not open requirements file: requirements.txt')]

    def read_file(self, path, ref):
        return self.files.get(path), 'blob1'

    def commit_file(self, branch, path, content, message, sha):
        self.commits.append((path, content))
        self.files[path] = content
        return 'sha2'

    def comment(self, number, body):
        self.comments.append(body)


class FixAgentTest(TestCase):
    def setUp(self):
        from app.fix_templates import get_fix
        from app.models import FixAttempt
        self.user = User.objects.create_user('fx', 'fx@x.io', 'pw')
        GithubProfile.objects.create(user=self.user, github_id=1, github_login='fx', access_token='tok')
        self.audit = Audit.objects.create(user=self.user, repo_full_name='example-org/demo-repo', status='done',
                                          repo_is_private=False)
        self.ci_path, self.ci = get_fix('ci.pipeline', 'python', 'example-org/demo-repo')
        self.attempt = FixAttempt.objects.create(
            user=self.user, audit=self.audit, check_id='ci.pipeline', check_name='CI/CD pipeline configured',
            repo_full_name='example-org/demo-repo', branch='devops-audit/ci-1', pr_number=3,
            pr_url='https://github.com/example-org/demo-repo/pull/3', scope_files=[self.ci_path])

    def _step(self, gh, answers=()):
        from app import fix_agent
        answers = list(answers)
        with patch('app.fix_agent.GitHub', return_value=gh), \
             patch('app.ai_providers._get_active_provider', return_value=('gemini', 'k')), \
             patch('app.ai_providers._call_provider', side_effect=lambda *a, **k: answers.pop(0)):
            fix_agent.step(self.attempt)
        self.attempt.refresh_from_db()

    def _good_answer(self):
        fixed = self.ci.replace('pip install -r requirements.txt', 'pip install -e ".[test]"')
        return json.dumps({'explanation': 'The project uses pyproject.toml; install it with its test extra.',
                           'files': [{'path': self.ci_path, 'content': fixed}]})

    def test_a_failing_ci_gets_a_fix_pushed_to_the_same_branch(self):
        gh = _FakeGitHub(runs=[{'status': 'completed', 'conclusion': 'failure'}], files={self.ci_path: self.ci})
        self._step(gh, [self._good_answer()])
        self.assertEqual(self.attempt.state, 'ci_running')
        self.assertEqual(self.attempt.iterations, 1)
        self.assertIn('pip install -e ".[test]"', gh.commits[0][1])
        self.assertIn('pytest', gh.commits[0][1])
        self.assertIn('Pushed a fix', gh.comments[0])

    def test_disabling_the_tests_is_refused_and_never_pushed(self):
        cheat = json.dumps({'explanation': 'skip tests', 'files': [{'path': self.ci_path, 'content':
                            self.ci.replace('pytest --tb=short', 'echo ok')}]})
        cheat2 = json.dumps({'explanation': 'ignore', 'files': [{'path': self.ci_path, 'content':
                             self.ci.replace('run: pytest --tb=short', 'run: pytest --tb=short\n        continue-on-error: true')}]})
        gh = _FakeGitHub(runs=[{'status': 'completed', 'conclusion': 'failure'}], files={self.ci_path: self.ci})
        self._step(gh, [cheat, cheat2])
        self.assertEqual(gh.commits, [])
        self.assertEqual(self.attempt.state, 'gave_up')
        self.assertIn('guardrail', self.attempt.gave_up_reason)
        self.assertIn('stopped', gh.comments[-1])

    def test_a_file_outside_the_pull_request_is_refused(self):
        from app.fix_agent import guardrail
        self.assertTrue(guardrail({}, {'tests/test_core.py': 'x'}, [self.ci_path]))

    def test_green_ci_finishes_and_says_so_after_fixes(self):
        self.attempt.iterations = 1
        self.attempt.save()
        gh = _FakeGitHub(runs=[{'status': 'completed', 'conclusion': 'success'}])
        self._step(gh)
        self.assertEqual(self.attempt.state, 'green')
        self.assertIn('green after 1', gh.comments[0])

    def test_pending_ci_waits(self):
        gh = _FakeGitHub(runs=[{'status': 'in_progress', 'conclusion': None}])
        self._step(gh)
        self.assertEqual(self.attempt.state, 'ci_running')
        self.assertEqual(gh.comments, [])

    def test_three_fixes_then_it_stops(self):
        self.attempt.iterations = 3
        self.attempt.save()
        gh = _FakeGitHub(runs=[{'status': 'completed', 'conclusion': 'failure'}])
        self._step(gh)
        self.assertEqual(self.attempt.state, 'gave_up')
        self.assertIn('after 3', gh.comments[-1])

    def test_a_closed_pull_request_stops_tracking_and_records_merge(self):
        gh = _FakeGitHub(state='closed', merged=True)
        self._step(gh)
        self.assertEqual((self.attempt.state, self.attempt.merged), ('closed', True))

    def test_no_checks_after_the_grace_period_means_no_ci(self):
        from app.models import FixAttempt
        FixAttempt.objects.filter(pk=self.attempt.pk).update(created_at=timezone.now() - timedelta(minutes=30))
        self.attempt.refresh_from_db()
        self._step(_FakeGitHub(runs=[]))
        self.assertEqual(self.attempt.state, 'no_ci')

    def test_no_ai_for_this_repository_gives_up_with_a_reason(self):
        from app import fix_agent
        gh = _FakeGitHub(runs=[{'status': 'completed', 'conclusion': 'failure'}])
        with patch('app.fix_agent.GitHub', return_value=gh), \
             patch('app.ai_providers._get_active_provider', return_value=(None, None)):
            fix_agent.step(self.attempt)
        self.attempt.refresh_from_db()
        self.assertEqual(self.attempt.state, 'gave_up')
        self.assertIn('AI provider', self.attempt.gave_up_reason)

    def test_the_model_may_give_up_itself(self):
        gh = _FakeGitHub(runs=[{'status': 'completed', 'conclusion': 'failure'}], files={self.ci_path: self.ci})
        self._step(gh, [json.dumps({'give_up': 'the failing test is in the project code'})])
        self.assertEqual(self.attempt.state, 'gave_up')
        self.assertIn('project code', gh.comments[-1])

    def test_guardrail_lets_a_real_fix_through_and_catches_the_tricks(self):
        from app.fix_agent import guardrail
        scope = [self.ci_path]
        ok = self.ci.replace('pip install -r requirements.txt', 'pip install -e ".[test]"')
        self.assertEqual(guardrail({self.ci_path: self.ci}, {self.ci_path: ok}, scope), [])
        for trick in ('pytest --tb=short || true', 'pytest --tb=short -k "not slow"',
                      'pytest --tb=short\n        if: false'):
            bad = self.ci.replace('pytest --tb=short', trick)
            self.assertTrue(guardrail({self.ci_path: self.ci}, {self.ci_path: bad}, scope), trick)
        self.assertTrue(guardrail({self.ci_path: self.ci}, {self.ci_path: ''}, scope))

    def test_ci_status(self):
        from app.fix_agent import ci_status
        self.assertEqual(ci_status([]), 'none')
        self.assertEqual(ci_status([{'status': 'queued'}]), 'pending')
        self.assertEqual(ci_status([{'status': 'completed', 'conclusion': 'success'},
                                    {'status': 'completed', 'conclusion': 'skipped'}]), 'success')
        self.assertEqual(ci_status([{'status': 'completed', 'conclusion': 'failure'}]), 'failure')

    def test_log_excerpt_keeps_the_error(self):
        from app.fix_agent import excerpt
        log = '\n'.join([f'2026-09-26T10:00:00.0000000Z line {i}' for i in range(500)] +
                        ['2026-09-26T10:00:01.0Z ERROR: Could not open requirements file'] +
                        [f'2026-09-26T10:00:02.0Z tail {i}' for i in range(500)])
        text = excerpt(log)
        self.assertIn('ERROR: Could not open requirements file', text)
        self.assertNotIn('2026-09-26T', text)

    @override_settings(FIX_AGENT_REPOS='example-org/demo-repo')
    def test_only_allowlisted_github_repositories_are_tracked(self):
        from app.fix_agent import track
        from app.models import FixAttempt
        check = MagicMock(check_id='ci.pipeline', recommendation='r')
        check.name = 'CI'
        pr = {'url': 'u', 'number': 9, 'branch': 'b'}
        track(self.audit, check, pr, '.github/workflows/ci.yml')
        other = Audit.objects.create(user=self.user, repo_full_name='someone/else', status='done')
        track(other, check, pr, '.github/workflows/ci.yml')
        self.assertEqual(FixAttempt.objects.filter(pr_number=9).count(), 1)

    def test_admin_metrics(self):
        from app.admin import fix_agent_metrics
        from app.models import FixAttempt
        a = self.attempt
        a.state, a.iterations, a.merged = 'green', 1, True
        a.save()
        FixAttempt.objects.create(user=self.user, audit=self.audit, repo_full_name='r', branch='b',
                                  pr_number=4, state='gave_up', iterations=3, merged=False)
        m = fix_agent_metrics(list(FixAttempt.objects.all()))
        self.assertEqual((m['green_pct'], m['merged_pct'], m['avg_iterations']), (50, 50, 2.0))


# ── Phase 6: secret incidents and rotation ────────────────────────────────────

_LIVE = 'ghp_' + 'Z9yX8wV7uT6sR5qP4oN3mL2kJ1iH0gF9eD8c'


class SecretIncidentTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('si', 'si@x.io', 'pw')
        GithubProfile.objects.create(user=self.user, github_id=5, github_login='si', access_token='tok')
        self.audit = Audit.objects.create(user=self.user, repo_full_name='acme/app', status='done')

    def _finding(self, liveness, **kw):
        return {'rule': 'github_pat', 'label': 'GitHub token', 'value': _LIVE, 'file': 'deploy/config.py',
                'line': 3, 'in_head': True, 'liveness': liveness, **kw}

    def test_a_live_key_opens_one_incident_and_never_stores_the_key(self):
        from app.models import SecretIncident
        from app.secret_incidents import sync
        sync(self.audit, [self._finding('active'), self._finding('active', file='other.py')])
        [inc] = SecretIncident.objects.all()
        self.assertEqual((inc.status, inc.line, inc.in_head), ('open', 3, True))
        for field in SecretIncident._meta.fields:
            self.assertNotIn(_LIVE, str(getattr(inc, field.attname)))

    def test_an_inactive_or_unknown_key_opens_nothing(self):
        from app.models import SecretIncident
        from app.secret_incidents import sync
        sync(self.audit, [self._finding('inactive'), self._finding('unknown', value='ghp_x' * 8)])
        self.assertFalse(SecretIncident.objects.exists())

    def test_the_next_audit_confirms_rotation_when_the_provider_rejects_the_old_key(self):
        from app.models import SecretIncident
        from app.secret_incidents import sync
        sync(self.audit, [self._finding('active')])
        later = Audit.objects.create(user=self.user, repo_full_name='acme/app', status='done')
        sync(later, [self._finding('inactive', in_head=False, line=9, commit='abc1234', date='2025-01-02')])
        inc = SecretIncident.objects.get()
        self.assertEqual(inc.status, 'rotated')
        self.assertIsNotNone(inc.resolved_at)
        self.assertEqual((inc.in_head, inc.line, inc.commit), (False, None, 'abc1234'))

    def test_a_marked_rotated_key_that_still_works_reopens(self):
        from app.models import SecretIncident
        from app.secret_incidents import sync
        sync(self.audit, [self._finding('active')])
        SecretIncident.objects.update(status='marked_rotated')
        sync(self.audit, [self._finding('active')])
        self.assertEqual(SecretIncident.objects.get().status, 'open')

    def test_an_unknown_answer_does_not_close_anything(self):
        from app.models import SecretIncident
        from app.secret_incidents import sync
        sync(self.audit, [self._finding('active')])
        sync(self.audit, [self._finding('unknown')])
        self.assertEqual(SecretIncident.objects.get().status, 'open')

    def _incident(self, file='deploy/config.py', line=3, save=True):
        from app.models import SecretIncident
        from app.secret_incidents import fingerprint
        inc = SecretIncident(
            user=self.user, first_audit=self.audit, repo_full_name='acme/app', rule='github_pat',
            label='GitHub token', file=file, line=line, in_head=True,
            fingerprint=fingerprint('github_pat', _LIVE))
        if save:
            inc.save()
        return inc

    def test_rewrite_python_uses_the_existing_name_and_adds_import_os(self):
        from app.secret_incidents import rewrite
        text = f'"""Config."""\nDEBUG = False\nGH_TOKEN = "{_LIVE}"\n'
        new, var = rewrite(text, self._incident())
        self.assertEqual(var, 'GH_TOKEN')
        self.assertIn('GH_TOKEN = os.environ["GH_TOKEN"]', new)
        self.assertTrue(new.startswith('import os\n'))
        self.assertNotIn(_LIVE, new)

    def test_rewrite_finds_the_key_when_lines_moved_and_only_that_key(self):
        from app.secret_incidents import rewrite
        other = 'ghp_' + 'A' * 36
        text = f'import os\n\n\n\nOTHER = "{other}"\nTOKEN = "{_LIVE}"\n'
        new, _var = rewrite(text, self._incident(line=2))
        self.assertIn(other, new)
        self.assertIn('TOKEN = os.environ["TOKEN"]', new)
        self.assertEqual(new.count('import os'), 1)

    def test_rewrite_ci_and_compose_and_js(self):
        from app.secret_incidents import rewrite
        gha = rewrite(f'env:\n  GH_TOKEN: {_LIVE}\n', self._incident('.github/workflows/ci.yml', 2, save=False))[0]
        self.assertIn('GH_TOKEN: ${{ secrets.GH_TOKEN }}', gha)
        gl = rewrite(f'variables:\n  TOKEN: "{_LIVE}"\n', self._incident('.gitlab-ci.yml', 2, save=False))[0]
        self.assertIn('TOKEN: $TOKEN', gl)
        compose = rewrite(f'services:\n  a:\n    environment:\n      TOKEN: "{_LIVE}"\n',
                          self._incident('docker-compose.yml', 4, save=False))[0]
        self.assertIn('TOKEN: ${TOKEN}', compose)
        js = rewrite(f"const client = new Octokit({{ auth: '{_LIVE}' }})\n", self._incident('src/gh.js', 1, save=False))[0]
        self.assertIn('auth: process.env.AUTH', js)

    def test_rewrite_refuses_a_key_inside_a_larger_string(self):
        from app.secret_incidents import rewrite
        self.assertIsNone(rewrite(f'URL = "https://x:{_LIVE}@host"\n', self._incident(line=1)))

    def test_env_example_is_created_or_extended_once(self):
        from app.secret_incidents import env_example
        self.assertIn('GH_TOKEN=\n', env_example(None, 'GH_TOKEN'))
        self.assertEqual(env_example('A=1', 'GH_TOKEN'), 'A=1\nGH_TOKEN=\n')
        self.assertIsNone(env_example('GH_TOKEN=\n', 'GH_TOKEN'))

    def test_open_env_pr_commits_the_file_and_env_example_and_warns_to_rotate(self):
        from app.secret_incidents import open_env_pr
        inc = self._incident()
        repo = MagicMock()
        repo.read_file.side_effect = lambda path: ((f'TOKEN = "{_LIVE}"\n', 'b1') if path == 'deploy/config.py'
                                                   else (None, None))
        repo.branch_from_default.return_value = 'devops-audit/env-token-1'
        repo.open_pull_request.return_value = 'https://github.com/acme/app/pull/5'
        with patch('app.github_writer._Repo', return_value=repo):
            url = open_env_pr(inc, self.user)
        self.assertEqual(url, 'https://github.com/acme/app/pull/5')
        paths = [c.args[1] for c in repo.commit_file.call_args_list]
        self.assertEqual(paths, ['deploy/config.py', '.env.example'])
        for c in repo.commit_file.call_args_list:
            self.assertNotIn(_LIVE, c.args[2])
        self.assertIn('does not make the leaked key safe', repo.open_pull_request.call_args.args[2])
        inc.refresh_from_db()
        self.assertEqual(inc.fix_pr_url, url)

    def test_audit_page_shows_the_incident_with_playbook(self):
        self._incident()
        self.client.force_login(self.user)
        r = self.client.get(reverse('audit_detail', args=[self.audit.id]))
        self.assertContains(r, 'deploy/config.py:3')
        self.assertContains(r, 'github.com/settings/tokens')
        self.assertNotContains(r, _LIVE)

    def test_mark_rotated_only_for_the_owner(self):
        from app.models import SecretIncident
        inc = self._incident()
        other = User.objects.create_user('o', 'o@x.io', 'pw')
        self.client.force_login(other)
        self.assertEqual(self.client.post(reverse('incident_mark_rotated', args=[inc.id])).status_code, 404)
        self.client.force_login(self.user)
        self.client.post(reverse('incident_mark_rotated', args=[inc.id]))
        self.assertEqual(SecretIncident.objects.get().status, 'marked_rotated')

    def test_the_audit_task_syncs_and_drops_the_values(self):
        from app import tasks
        from app.repo_client import StaticRepoClient
        client = StaticRepoClient({'a.py': 'x'})
        client.head_sha = 'h'
        client.secret_findings = [self._finding('active')]
        audit = Audit.objects.create(user=self.user, repo_full_name='acme/app', status='pending')
        with patch('app.repo_client.build_client_for_audit', return_value=client), \
             patch('app.checks.run_all_checks', return_value=[]), \
             patch('app.tasks._ai_allowance', return_value=(False, False)), \
             patch('app.tasks._send_audit_email'):
            tasks.run_audit_task.run(audit.id)
        from app.models import SecretIncident
        self.assertEqual(SecretIncident.objects.count(), 1)
        self.assertIsNone(client.secret_findings)


# ── Phase 7: weekly CTO digest ────────────────────────────────────────────────

class WeeklyDigestTest(TestCase):
    def setUp(self):
        from app.models import AuditCheck, UserSubscription
        self.user = User.objects.create_user('cto', 'cto@x.io', 'pw')
        UserSubscription.objects.update_or_create(user=self.user, defaults={'plan': 'team'})
        old = timezone.now() - timedelta(days=10)
        before = Audit.objects.create(user=self.user, repo_full_name='acme/api', status='done', score=80)
        Audit.objects.filter(pk=before.pk).update(created_at=old)
        AuditCheck.objects.create(audit=before, check_id='deps.cve', name='CVE', description='',
                                  severity='crit', passed=True, category='deps')
        self.now_audit = Audit.objects.create(user=self.user, repo_full_name='acme/api', status='done', score=64)
        AuditCheck.objects.create(audit=self.now_audit, check_id='deps.cve', name='Known vulnerabilities',
                                  description='', severity='crit', passed=False, category='deps')

    def _settings(self, **kw):
        from app.models import DigestSettings
        return DigestSettings.objects.create(user=self.user, **kw)

    def test_build_reports_what_got_worse_and_what_to_do(self):
        from app.digest import build
        d = build(self.user)
        self.assertEqual(d['repo_count'], 1)
        [r] = d['worsened']
        self.assertEqual((r['before'], r['score'], r['new_findings']), (80, 64, ['Known vulnerabilities']))
        self.assertEqual(d['top_actions'][0]['text'], 'Known vulnerabilities')
        self.assertIsNone(d['compliance_pct'])

    def test_a_live_key_is_the_first_action_and_green_fix_prs_are_listed(self):
        from app.digest import build
        from app.models import FixAttempt, SecretIncident
        SecretIncident.objects.create(user=self.user, first_audit=self.now_audit, repo_full_name='acme/api',
                                      rule='github_pat', label='GitHub token', file='cfg.py', fingerprint='f' * 64)
        FixAttempt.objects.create(user=self.user, audit=self.now_audit, repo_full_name='acme/api', branch='b',
                                  pr_number=2, pr_url='https://github.com/acme/api/pull/2', state='green',
                                  check_name='CI')
        d = build(self.user)
        self.assertEqual(d['top_actions'][0]['kind'], 'incident')
        self.assertEqual([p['url'] for p in d['ready_prs']], ['https://github.com/acme/api/pull/2'])

    def test_compliance_plan_gets_control_coverage(self):
        from app.digest import build
        from app.models import UserSubscription
        UserSubscription.objects.filter(user=self.user).update(plan='compliance')
        self.assertIsNotNone(build(self.user)['compliance_pct'])

    def test_without_a_model_the_template_writes_the_opening(self):
        from app.digest import build, summary
        with patch('app.ai_providers._get_active_provider', return_value=(None, None)):
            text = summary(build(self.user), 'en')
        self.assertIn('80 → 64', text)

    def test_private_repositories_route_the_summary_as_private(self):
        from app.digest import build, summary
        with patch('app.ai_providers._get_active_provider', return_value=(None, None)) as pick:
            summary(build(self.user), 'en')
        self.assertTrue(pick.call_args.kwargs['is_private'])

    def test_send_has_one_click_unsubscribe_and_records_the_send(self):
        from app.digest import send
        ds = self._settings(recipients='a@x.io, b@x.io', language='ru')
        with patch('app.ai_providers._get_active_provider', return_value=(None, None)):
            self.assertTrue(send(self.user, ds))
        [msg] = mail.outbox
        self.assertEqual(msg.to, ['a@x.io', 'b@x.io'])
        self.assertIn(ds.unsubscribe_token, msg.extra_headers['List-Unsubscribe'])
        self.assertIn('Сделайте это на неделе', msg.alternatives[0][0])
        ds.refresh_from_db()
        self.assertIsNotNone(ds.last_sent_at)

    def test_task_sends_on_the_chosen_day_only_once_and_only_to_team(self):
        from app import tasks
        from app.models import DigestSettings, UserSubscription
        free = User.objects.create_user('free', 'free@x.io', 'pw')
        Audit.objects.create(user=free, repo_full_name='f/f', status='done', score=50)
        ds = self._settings(weekday=timezone.now().weekday())
        with patch('app.ai_providers._get_active_provider', return_value=(None, None)):
            tasks.send_weekly_digests()
            tasks.send_weekly_digests()
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['cto@x.io'])
        self.assertFalse(DigestSettings.objects.filter(user=free).exists())
        ds.refresh_from_db()
        ds.weekday = (timezone.now().weekday() + 1) % 7
        ds.last_sent_at = None
        ds.save()
        with patch('app.ai_providers._get_active_provider', return_value=(None, None)):
            tasks.send_weekly_digests()
        self.assertEqual(len(mail.outbox), 1)

    def test_unsubscribe_is_one_click_without_login_and_accepts_bare_post(self):
        from django.test import Client as C
        ds = self._settings()
        r = C(enforce_csrf_checks=True).post(reverse('digest_unsubscribe', args=[ds.unsubscribe_token]))
        self.assertEqual(r.status_code, 200)
        ds.refresh_from_db()
        self.assertFalse(ds.enabled)

    def test_settings_page_previews_without_a_model_call_and_validates(self):
        self.client.force_login(self.user)
        with patch('app.ai_providers._call_provider') as call:
            r = self.client.get(reverse('digest_settings'))
        call.assert_not_called()
        self.assertContains(r, 'srcdoc=')
        r = self.client.post(reverse('digest_settings'), {'recipients': 'not-an-email', 'weekday': '2',
                                                          'language': 'en', 'enabled': 'on', 'action': 'save'})
        self.assertContains(r, 'Not an email address')
        self.client.post(reverse('digest_settings'), {'recipients': 'x@y.io', 'weekday': '2', 'language': 'ru',
                                                      'enabled': 'on', 'action': 'save'})
        from app.models import DigestSettings
        ds = DigestSettings.objects.get(user=self.user)
        self.assertEqual((ds.recipients, ds.weekday, ds.language), ('x@y.io', 2, 'ru'))

    def test_settings_page_is_locked_below_team(self):
        from app.models import UserSubscription
        UserSubscription.objects.filter(user=self.user).update(plan='pro')
        self.client.force_login(self.user)
        r = self.client.get(reverse('digest_settings'))
        self.assertContains(r, 'Team plan')
        self.assertNotContains(r, 'srcdoc=')


# ── Accuracy spec, stage 1: evaluation harness ────────────────────────────────

class LocalDirClientTest(TestCase):
    def test_reads_a_directory_and_its_metadata(self):
        import tempfile
        from app.repo_client import LocalDirClient
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, 'src'))
            Path(d, 'src', 'a.py').write_text('x = 1\n')
            Path(d, 'metadata.yaml').write_text('provider: gitlab\npushed_at: "2026-01-02T00:00:00Z"\n'
                                                'branch_protected: true\n')
            Path(d, 'expected.yaml').write_text('checks: {}\n')
            c = LocalDirClient(d).load()
        self.assertEqual(c.files, {'src/a.py'})
        self.assertIn('src', c.dirs)
        self.assertEqual((c.provider, c.pushed_at.year, c.branch_is_protected()), ('gitlab', 2026, True))

    def test_an_empty_directory_is_an_empty_repository(self):
        import tempfile
        from app.repo_client import LocalDirClient, RepoAccessError
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RepoAccessError):
                LocalDirClient(d).load()


class EvaluationMetricsTest(TestCase):
    def test_precision_and_false_fail_rate(self):
        from app.evaluation import metrics
        pairs = [
            {'repo': 'a', 'check': 'ci.tests', 'expected': 'fail', 'actual': 'fail', 'ok': True},
            {'repo': 'b', 'check': 'ci.tests', 'expected': 'pass', 'actual': 'fail', 'ok': False},
            {'repo': 'c', 'check': 'ci.tests', 'expected': 'fail', 'actual': 'pass', 'ok': False},
            {'repo': 'd', 'check': 'ci.tests', 'expected': 'na', 'actual': 'na', 'ok': True},
        ]
        m = metrics(pairs, [], [])
        c = m['per_check']['ci.tests']
        self.assertEqual((c['fail_precision'], c['fail_recall'], c['false_fail']), (0.5, 0.5, 1))
        self.assertEqual((m['false_fail_rate'], m['accuracy']), (0.5, 0.5))

    def test_status_of(self):
        from app.evaluation import status_of
        self.assertEqual(status_of(None), 'na')
        self.assertEqual(status_of({'applicable': False, 'passed': True}), 'na')
        self.assertEqual(status_of({'passed': False}), 'fail')
        self.assertEqual(status_of({'status': 'unknown', 'passed': False}), 'unknown')


class SyntheticFixturesEvalTest(TestCase):
    """
    The synthetic fixtures (tests/fixtures/repos) on every run of the suite.

    Nothing that was right in eval-baseline.json may become wrong. Improving is
    free; to accept a new baseline, review `make eval` and run `make eval-baseline`.
    """

    def test_no_regression_against_the_baseline(self):
        from app import evaluation
        result = evaluation.evaluate(evaluation.synthetic_cases())
        self.assertTrue(result['metrics']['errors_ok'], result['errors'])
        baseline = evaluation.load_baseline().get('synthetic')
        self.assertIsNotNone(baseline, 'eval-baseline.json has no synthetic run — run make eval-baseline')
        diff = evaluation.compare(result, baseline)
        self.assertEqual(diff['broken'], [], 'these fixture expectations used to hold and no longer do')


class CheckStatusModelTest(TestCase):
    """Accuracy stage 2: four statuses, dependencies between checks, evidence."""

    def _run(self, files, protected=False):
        from app.checks import run_all_checks
        from app.repo_client import StaticRepoClient
        from django.utils import translation
        client = StaticRepoClient(files)
        client._protected = protected
        with translation.override('en'), patch('app.checks_extra.requests.post') as post:
            post.return_value.status_code = 200
            post.return_value.json.return_value = {'results': []}
            return {c['check_id']: c for c in run_all_checks(client)}

    def test_every_check_has_a_status_and_evidence(self):
        checks = self._run({'README.md': '# x', 'app.py': 'print(1)'})
        for cid, c in checks.items():
            self.assertIn(c['status'], ('pass', 'fail', 'na', 'unknown'), cid)
            self.assertTrue(c['evidence'], cid)

    def test_nothing_passes_or_fails_without_its_object(self):
        checks = self._run({'README.md': '# x', 'app.py': 'print(1)'})
        for cid in ('docker.dockerignore', 'docker.nonroot', 'docker.pinned_base',
                    'docker.multistage', 'docker.healthcheck', 'docker.resource_limits',
                    'deps.lockfile', 'deps.pinned', 'security.env_gitignored', 'ops.env_example'):
            self.assertEqual(checks[cid]['status'], 'na', cid)

    def test_unreadable_branch_protection_is_unknown_and_unscored(self):
        from app.checks import calculate_score
        files = {'README.md': '# x', 'app.py': 'print(1)'}
        checks = self._run(files, protected=None)
        bp = checks['ci.branch_protection']
        self.assertEqual(bp['status'], 'unknown')
        self.assertIn('admin', bp['evidence'])
        self.assertFalse(bp['applicable'])
        self.assertGreaterEqual(calculate_score(list(checks.values())),
                                calculate_score(list(self._run(files, protected=False).values())))

    def test_evidence_names_the_file_that_passed(self):
        checks = self._run({'Dockerfile': 'FROM python:3.12-slim\nUSER app\n',
                            '.github/workflows/ci.yml': 'jobs:\n  t:\n    steps:\n      - run: pytest -q\n'})
        self.assertEqual(checks['docker.dockerfile']['evidence'], 'Dockerfile')
        self.assertEqual(checks['ci.tests']['evidence'], '.github/workflows/ci.yml: pytest')
        self.assertIn('python:3.12-slim', checks['docker.pinned_base']['evidence'])

    def test_github_protection_falls_back_to_rulesets(self):
        from app.repo_client import GithubRepoClient
        c = GithubRepoClient('acme/demo')
        c.default_branch = 'main'
        branch = MagicMock(status_code=200); branch.json.return_value = {'protected': False}
        rules = MagicMock(status_code=200); rules.json.return_value = [{'type': 'pull_request'}]
        with patch.object(c, '_get', side_effect=[branch, rules]):
            self.assertIs(c.branch_is_protected(), True)
        with patch.object(c, '_get', return_value=MagicMock(status_code=403)):
            self.assertIsNone(c.branch_is_protected())


class DetectorsTest(TestCase):
    """Accuracy stage 5: look where maintainers actually put things."""

    def _run(self, files):
        from app.checks import run_all_checks
        from app.repo_client import StaticRepoClient
        with patch('app.checks_extra.requests.post') as post:
            post.return_value.status_code = 200
            post.return_value.json.return_value = {'results': []}
            return {c['check_id']: c for c in run_all_checks(StaticRepoClient(files))}

    def test_vendor_documentation_key_is_not_a_leak(self):
        from app.checks_secrets import find_secrets
        from app.repo_client import StaticRepoClient
        self.assertEqual(find_secrets(StaticRepoClient({'config.py': 'K = "AKIAIOSFODNN7EXAMPLE"'})), [])

    def test_changelog_under_other_names_and_places(self):
        for path in ('History.md', 'docs/en/docs/release-notes.md', 'docs/releases/5.0.txt',
                     'NEWS', '.changeset/config.json'):
            self.assertTrue(self._run({'README.md': '#', path: 'x'})['docs.changelog']['passed'], path)

    def test_dockerfile_in_a_subdirectory_is_audited(self):
        c = self._run({'apps/api/Dockerfile': 'FROM node:20-alpine\nUSER node\n',
                       'tests/Dockerfile': 'FROM node\n'})
        self.assertTrue(c['docker.dockerfile']['passed'])
        self.assertEqual(c['docker.dockerfile']['evidence'], 'apps/api/Dockerfile')
        self.assertTrue(c['docker.nonroot']['passed'])
        self.assertTrue(c['docker.pinned_base']['passed'])

    def test_floating_tags_and_stage_aliases(self):
        c = self._run({'Dockerfile': 'FROM python:slim AS base\nFROM base AS final\n'})
        self.assertFalse(c['docker.pinned_base']['passed'])
        c = self._run({'Dockerfile': 'FROM python:3.12-slim AS base\nFROM base AS final\nUSER root\nUSER app\n'})
        self.assertTrue(c['docker.pinned_base']['passed'])
        self.assertTrue(c['docker.nonroot']['passed'])

    def test_tests_behind_make_script_and_include(self):
        wf = '.github/workflows/ci.yml'
        self.assertTrue(self._run({wf: 'jobs:\n  a:\n    steps:\n      - run: make check\n',
                                   'Makefile': 'check: lint\n\tpython -m pytest\nlint:\n\truff .\n'})['ci.tests']['passed'])
        self.assertTrue(self._run({wf: 'jobs:\n  a:\n    steps:\n      - run: poetry run ./scripts/ci\n',
                                   'scripts/ci': 'set -e\ncoverage run -m pytest\n'})['ci.tests']['passed'])
        c = self._run({'.gitlab-ci.yml': 'include:\n  - local: /.gitlab/ci/unit.yml\n',
                       '.gitlab/ci/unit.yml': 'unit:\n  script:\n    - go test ./...\n'})['ci.tests']
        self.assertTrue(c['passed'])
        self.assertIn('.gitlab/ci/unit.yml', c['evidence'])


class KindApplicabilityTest(TestCase):
    """Accuracy stages 3-4: what the repository is decides what applies."""

    def _detect(self, files):
        from app.repo_client import StaticRepoClient
        from app.repo_kind import detect
        return detect(StaticRepoClient(files))

    def test_node_app_with_main_is_a_service(self):
        kind = self._detect({'package.json': '{"name": "x", "main": "server.js", "scripts": {"start": "node server"}}',
                             'server.js': 'x'})[0]
        self.assertEqual(kind, 'service')

    def test_helm_chart_repository_is_infrastructure(self):
        files = {f'charts/{n}/Chart.yaml': 'name: x' for n in ('a', 'b', 'c')}
        files.update({f'charts/{n}/templates/deploy.yaml': 'kind: Deployment' for n in ('a', 'b', 'c')})
        self.assertEqual(self._detect(files)[0], 'infrastructure')

    def test_workspace_with_root_dockerfile_is_a_service(self):
        self.assertEqual(self._detect({'nx.json': '{}', 'Dockerfile': 'FROM node:20', 'package.json': '{"private": true}',
                                       'apps/a/package.json': '{}', 'apps/b/package.json': '{}'})[0], 'service')

    def test_workspace_of_plugins_around_a_published_root_is_a_library(self):
        self.assertEqual(self._detect({'pnpm-workspace.yaml': 'packages: [extensions/*]',
                                       'package.json': '{"name": "cli", "main": "lib/index.js", "files": ["lib"]}',
                                       'lib/index.js': 'x', 'extensions/a/package.json': '{}'})[0], 'library')

    def test_nested_helper_modules_do_not_make_a_monorepo(self):
        self.assertEqual(self._detect({'go.mod': 'module x', 'main.go': 'package main',
                                       'helpers/a/go.mod': 'm', 'scripts/b/go.mod': 'm'})[0], 'service')

    def test_npm_library_lockfile_not_applicable(self):
        _, skipped, _, _ = self._detect({'package.json': '{"name": "x", "exports": "./i.js"}', 'i.js': 'x'})
        self.assertIn('deps.lockfile', skipped)

    def test_docs_repository_skips_tests_and_changelog(self):
        _, skipped, _, _ = self._detect({f'{n}.md': '# x' for n in 'abcdef'})
        self.assertTrue({'ci.tests', 'docs.changelog'} <= skipped)

    def test_devopscheck_yml_type_alias(self):
        from app import audit_config
        from app.repo_client import StaticRepoClient
        cfg = audit_config.load(StaticRepoClient({'.devopscheck.yml': 'type: iac\n'}))
        self.assertEqual(cfg.kind, 'infrastructure')
        self.assertEqual(cfg.errors, [])


class MethodologyV3Test(TestCase):
    def test_public_scan_on_old_methodology_is_requeued(self):
        from app.models import Audit, PublicScan
        from app.tasks import refresh_stale_public_scans
        old = PublicScan.objects.create(repo_full_name='a/old', repo_url='https://github.com/a/old',
                                        status=Audit.STATUS_DONE, score=50, score_version=2)
        from app.checks import SCORE_VERSION
        PublicScan.objects.create(repo_full_name='a/new', repo_url='https://github.com/a/new',
                                  status=Audit.STATUS_DONE, score=50, score_version=SCORE_VERSION)
        with patch('app.tasks.run_public_scan_task.delay') as delay, patch('app.views.LANDING_DEMO_REPOS', []):
            refresh_stale_public_scans()
        self.assertEqual([c.args[0] for c in delay.call_args_list], [old.id])


class FalsePositiveReportTest(TestCase):
    def setUp(self):
        from app.models import Audit, PublicScan
        self.scan = PublicScan.objects.create(
            repo_full_name='acme/demo', repo_url='https://github.com/acme/demo', status=Audit.STATUS_DONE,
            score=60, score_version=3, repo_kind='library',
            results=[{'check_id': 'ci.tests', 'name': 'Tests run in CI', 'description': 'd', 'severity': 'warn',
                      'passed': False, 'category': 'ci_cd', 'applicable': True, 'status': 'fail',
                      'evidence': 'Checked 2 CI file(s)'},
                     {'check_id': 'ci.branch_protection', 'name': 'Default branch is protected', 'description': 'd',
                      'severity': 'warn', 'passed': False, 'category': 'ci_cd', 'applicable': False,
                      'status': 'unknown', 'not_applicable_reason': 'needs admin'}])

    def test_report_is_stored_with_engine_evidence(self):
        from app.models import FalsePositiveReport
        r = self.client.post('/false-positive/', {'repo': 'acme/demo', 'check_id': 'ci.tests',
                                                  'comment': 'tox runs them', 'next': '/scan/acme/demo/',
                                                  'evidence': 'forged'})
        self.assertEqual(r.status_code, 302)
        self.assertIn('fp=sent', r['Location'])
        fp = FalsePositiveReport.objects.get()
        self.assertEqual((fp.check_id, fp.evidence, fp.comment, fp.score_version),
                         ('ci.tests', 'Checked 2 CI file(s)', 'tox runs them', 3))

    def test_only_a_failed_check_can_be_reported(self):
        from app.models import FalsePositiveReport
        r = self.client.post('/false-positive/', {'repo': 'acme/demo', 'check_id': 'ci.branch_protection',
                                                  'next': 'https://evil.example/'})
        self.assertEqual(r['Location'], '/?fp=invalid')
        self.assertFalse(FalsePositiveReport.objects.exists())

    def test_scan_page_shows_evidence_kind_unknown_and_button(self):
        with patch('app.rankings.standing', return_value=None):
            html = self.client.get('/scan/acme/demo/').content.decode()
        for text in ('Checked 2 CI file(s)', 'false positive', 'Could not be checked', 'needs admin', 'library'):
            self.assertIn(text, html)


class GoJvmLibraryKindTest(TestCase):
    def _kind(self, files):
        from app.repo_client import StaticRepoClient
        from app.repo_kind import detect
        return detect(StaticRepoClient(files))[0]

    def test_go_package_at_module_root_is_a_library(self):
        self.assertEqual(self._kind({'go.mod': 'module x', 'gin.go': 'package gin\n'}), 'library')
        self.assertEqual(self._kind({'go.mod': 'module x', 'main.go': 'package main\n'}), 'service')

    def test_jvm_build_that_publishes_is_a_library(self):
        self.assertEqual(self._kind({'build.gradle': "plugins { id 'java-library' }", 'src/A.java': 'x'}), 'library')
        self.assertEqual(self._kind({'build.gradle': "plugins { id 'application' }", 'src/A.java': 'x'}), 'service')

    def test_dockerfiles_in_test_resources_and_docs_are_not_the_project(self):
        from app.detectors import find_dockerfiles
        from app.repo_client import StaticRepoClient
        c = StaticRepoClient({'it/foo-integration-tests/src/dockerTest/resources/Dockerfile': 'FROM x',
                              'documentation/partials/dockerfile': 'x', 'app/Dockerfile': 'FROM y'})
        self.assertEqual(find_dockerfiles(c), ['app/Dockerfile'])


class CheckGuidesTest(TestCase):
    def test_every_guide_renders_with_fix_and_scan_form(self):
        from app.check_guides import GUIDES, catalog
        for cid in GUIDES:
            self.assertIn(cid, catalog(), cid)
            r = self.client.get(f'/checks/{cid}/')
            self.assertEqual(r.status_code, 200, cid)
            html = r.content.decode()
            self.assertIn(GUIDES[cid][0].split(' (')[0][:25].replace("'", '&#x27;'), html, cid)
            self.assertIn('scan/submit', html, cid)

    def test_index_sitemap_robots(self):
        self.assertContains(self.client.get('/checks/'), '/checks/docker.nonroot/')
        self.assertContains(self.client.get('/sitemap.xml'), '/checks/actions.pinned_sha/')
        self.assertContains(self.client.get('/robots.txt'), 'Allow: /checks/')
        self.assertEqual(self.client.get('/checks/nope/').status_code, 404)

    def test_russian_guide(self):
        self.client.cookies['django_language'] = 'ru'
        self.assertContains(self.client.get('/checks/docker.nonroot/'), 'Как запустить Docker-контейнер не от root')

    def test_guide_lists_public_repos_failing_it(self):
        from app.models import Audit, PublicScan
        PublicScan.objects.create(repo_full_name='acme/rooty', repo_url='https://github.com/acme/rooty',
                                  status=Audit.STATUS_DONE, score=50,
                                  results=[{'check_id': 'docker.nonroot', 'passed': False, 'applicable': True}])
        self.assertContains(self.client.get('/checks/docker.nonroot/'), '/scan/acme/rooty/')



class EarlyAccessTest(TestCase):
    """Until payments are live, customers leave interest instead of hitting a test checkout."""

    def setUp(self):
        self.user = User.objects.create_user('buyer', 'buyer@example.com', 'pw')
        self.client.force_login(self.user)

    @override_settings(PAYMENTS_LIVE=False, PAYMENT_MODE='test', LEMONSQUEEZY_API_KEY='k')
    def test_customer_sees_early_access_not_test_mode(self):
        html = self.client.get('/billing/').content.decode()
        self.assertIn('/billing/early-access/', html)
        self.assertNotIn('/billing/checkout/ls/', html)
        self.assertNotIn('TEST MODE', html)

    @override_settings(PAYMENTS_LIVE=False)
    def test_checkout_is_closed_and_interest_recorded_once(self):
        from app.models import PlanInterest
        with patch('app.views.requests.post') as post:
            r = self.client.post('/billing/checkout/ls/', {'plan': 'pro', 'period': 'annual'})
        self.assertEqual(r.status_code, 302)
        post.assert_not_called()
        for _ in range(2):
            self.client.post('/billing/early-access/', {'plan': 'team', 'period': 'annual'})
        pi = PlanInterest.objects.get()
        self.assertEqual((pi.email, pi.plan, pi.period), ('buyer@example.com', 'team', 'annual'))
        self.assertFalse(self.user.subscription.is_pro if hasattr(self.user, 'subscription') else False)

    @override_settings(PAYMENTS_LIVE=False, PAYMENT_MODE='test', LEMONSQUEEZY_API_KEY='k')
    def test_staff_keeps_the_test_checkout(self):
        self.user.is_staff = True
        self.user.save()
        html = self.client.get('/billing/').content.decode()
        self.assertIn('/billing/checkout/ls/', html)
        self.assertIn('TEST MODE', html)


class StorefrontConsistencyTest(TestCase):
    """B0: the score a visitor sees is the same everywhere it is shown."""

    def setUp(self):
        from app.checks import SCORE_VERSION
        from app.models import Audit, PublicScan
        from app.views import LANDING_DEMO_REPOS
        self.scores = {}
        for i, name in enumerate(LANDING_DEMO_REPOS):
            score = 61 + i * 7
            self.scores[name] = score
            PublicScan.objects.create(
                repo_full_name=name, repo_url=f'https://github.com/{name}', status=Audit.STATUS_DONE,
                score=score, score_version=SCORE_VERSION, category_scores={'security': score},
                results=[{'check_id': 'ci.tests', 'name': 'Tests run in CI', 'description': 'd', 'severity': 'warn',
                          'passed': False, 'category': 'ci_cd', 'applicable': True, 'status': 'fail'}])

    def test_landing_report_meta_and_badge_agree(self):
        import re
        from app.views_public import badge_markdown
        landing = self.client.get('/').content.decode()
        for name, score in self.scores.items():
            self.assertIn(name, landing)
            with patch('app.rankings.standing', return_value=None):
                page = self.client.get(f'/scan/{name}/').content.decode()
            meta = re.search(r'<meta name="description" content="([^"]*)"', page).group(1)
            self.assertIn(f'{score}/100', meta, name)
            self.assertIn(f'>{score}<', page, name)
            self.assertIn(str(score), badge_markdown(name, score))
            self.assertRegex(landing, rf'{re.escape(name)}[\s\S]{{0,2000}}\b{score}\b')

    def test_numbers_come_from_one_place(self):
        from app import site_facts
        html = self.client.get('/').content.decode()
        self.assertNotIn('30+', html)
        self.assertIn(f'{site_facts.CHECK_COUNT}', html)
        self.assertNotIn('Lock-файл', html)
        self.assertNotIn('GPT-4o', html)

    def test_check_count_matches_the_engine(self):
        import glob, re
        from app import site_facts
        ids = set()
        for path in glob.glob('app/checks*.py'):
            ids |= set(re.findall(r"'((?:security|ci|docker|docs|deps|ops|actions|gitlab_ci|iac|ai|k8s)"
                                  r"\.[a-z_]+)'", open(path).read()))
        self.assertEqual(len(ids), site_facts.CHECK_COUNT, sorted(ids))

    def test_every_public_page_has_an_absolute_og_image(self):
        import re
        for url in ('/', '/scan/', '/rankings/', '/trust/', '/pricing/', '/checks/'):
            html = self.client.get(url).content.decode()
            og = re.search(r'<meta property="og:image" content="([^"]*)"', html).group(1)
            self.assertTrue(og.startswith('http'), (url, og))
            self.assertNotIn('/og/scan/django/django.png', og, url)
        self.assertEqual(self.client.get('/og/page/scan.png')['Content-Type'], 'image/png')

    def test_rescan_is_rate_limited_per_repository(self):
        from app.models import PublicScan
        name = next(iter(self.scores))
        with patch('app.tasks.run_public_scan_task.delay') as delay:
            self.client.post(f'/scan/{name}/rescan/')
            delay.assert_not_called()                        # scanned just now
            PublicScan.objects.filter(repo_full_name=name).update(
                updated_at=timezone.now() - timezone.timedelta(minutes=11))
            self.client.post(f'/scan/{name}/rescan/')
            delay.assert_called_once()


class RussianUrlsTest(TestCase):
    """B1.10: Russian public pages have their own URLs a search engine can see."""

    def test_ru_prefix_serves_russian_with_hreflang_and_canonical(self):
        r = self.client.get('/ru/checks/docker.nonroot/')
        self.assertEqual(r.status_code, 200)
        html = r.content.decode()
        self.assertIn('<html lang="ru"', html)
        self.assertIn('Как запустить Docker-контейнер не от root', html)
        self.assertIn('rel="canonical" href="http', html)
        self.assertRegex(html, r'rel="canonical" href="[^"]*/ru/checks/docker\.nonroot/"')
        self.assertIn('hreflang="en"', html)
        self.assertEqual(r.cookies['django_language'].value, 'ru')

    def test_english_url_stays_english_for_a_crawler(self):
        html = self.client.get('/checks/docker.nonroot/').content.decode()
        self.assertIn('<html lang="en"', html)
        self.assertRegex(html, r'hreflang="ru" href="[^"]*/ru/checks/docker\.nonroot/"')

    def test_landing_and_private_paths(self):
        self.assertContains(self.client.get('/ru/'), 'hreflang="ru"')
        self.assertEqual(self.client.get('/ru').status_code, 301)
        self.assertEqual(self.client.get('/ru/billing/').status_code, 404)

    def test_sitemap_lists_russian_pages(self):
        body = self.client.get('/sitemap.xml').content.decode()
        self.assertIn('/ru/checks/', body)
        self.assertIn('/ru/scan/', body)


class LandingTrustPackTest(TestCase):
    """B1: scan from the first screen, FAQ, comparison, llms.txt, and a Trust page that matches the code."""

    def test_landing_has_scan_form_and_valid_faq_schema(self):
        import json, re
        html = self.client.get('/').content.decode()
        self.assertIn('action="/scan/submit/"', html)
        blocks = re.findall(r'<script type="application/ld\+json">([\s\S]*?)</script>', html)
        kinds = [json.loads(b)['@type'] for b in blocks]
        self.assertIn('FAQPage', kinds)
        faq = next(json.loads(b) for b in blocks if json.loads(b)['@type'] == 'FAQPage')
        for q in faq['mainEntity']:
            self.assertIn(q['name'].replace("'", '&#x27;'), html)   # schema matches visible text

    def test_compare_llms_and_guide_schema(self):
        import json, re
        self.assertContains(self.client.get('/compare/'), 'Where it is weaker')
        self.assertContains(self.client.get('/ru/compare/'), 'lang="ru"')
        txt = self.client.get('/llms.txt')
        self.assertEqual(txt['Content-Type'], 'text/plain; charset=utf-8')
        self.assertContains(txt, '/checks/docker.nonroot/')
        html = self.client.get('/checks/actions.pinned_sha/').content.decode()
        data = json.loads(re.search(r'<script type="application/ld\+json">([\s\S]*?)</script>', html).group(1))
        self.assertEqual({n['@type'] for n in data['@graph']}, {'TechArticle', 'BreadcrumbList'})

    def test_trust_page_states_the_ai_review_limits_in_code(self):
        from app import ai_review
        html = self.client.get('/trust/').content.decode()
        self.assertIn(f'up to {ai_review.MAX_FILES} configuration files', html)
        self.assertIn(f'{ai_review.MAX_FILE_CHARS:,}', html)
        self.assertIn(f'{ai_review.MAX_TOTAL_CHARS:,}', html)


class FunnelTest(TestCase):
    """B2: events, first-touch source, no personal data, UTM on outbound links."""
    UA = {'HTTP_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0'}

    def test_landing_visit_attributed_to_utm_and_counted_once(self):
        from app.models import FunnelEvent
        r = self.client.get('/?utm_source=habr', **self.UA)
        self.assertIn('dsrc', r.cookies)
        self.client.get('/', **self.UA)                     # reload: not a new visit
        ev = FunnelEvent.objects.get(name='visit_landing')
        self.assertEqual(ev.source, 'habr')
        self.assertEqual({f.name for f in FunnelEvent._meta.fields},
                         {'id', 'name', 'source', 'ref', 'user', 'created_at'})   # no IP, no UA

    def test_scan_from_referrer_keeps_the_first_source(self):
        from app.models import FunnelEvent
        self.client.get('/scan/', HTTP_REFERER='https://www.reddit.com/r/devops/', **self.UA)
        with patch('app.tasks.run_public_scan_task.delay'), patch('app.rankings.standing', return_value=None):
            self.client.get('/scan/acme/demo/', HTTP_REFERER='https://news.ycombinator.com/', **self.UA)
        self.assertEqual(FunnelEvent.objects.get(name='scan_started').source, 'reddit.com')

    def test_bots_are_not_counted(self):
        from app.models import FunnelEvent
        self.client.get('/', HTTP_USER_AGENT='Googlebot/2.1')
        self.assertFalse(FunnelEvent.objects.exists())

    def test_signup_and_paid(self):
        from app.models import FunnelEvent, UserSubscription
        from app.views import _activate_plan
        self.client.get('/?ref=badge', **self.UA)
        self.client.post('/register/', {'username': 'newbie', 'email': 'n@example.com',
                                        'password': 'Very-long-pass-123', 'password2': 'Very-long-pass-123'}, **self.UA)
        user = User.objects.get(username='newbie')
        self.assertEqual(FunnelEvent.objects.get(name='signup').source, 'badge')
        sub, _ = UserSubscription.objects.get_or_create(user=user)
        _activate_plan(sub, 'pro', 'monthly', provider='ls')
        self.assertEqual(FunnelEvent.objects.get(name='paid').source, 'badge')

    def test_outbound_links_are_tagged(self):
        from app.views_public import badge_markdown
        self.assertIn('utm_source=badge', badge_markdown('acme/demo', 80))

    @override_settings(ROOT_URLCONF='config.urls_admin')
    def test_metrics_page_for_staff_only(self):
        self.assertEqual(self.client.get('/admin/metrics/').status_code, 302)
        User.objects.create_user('boss', 'b@example.com', 'pw', is_staff=True)
        self.client.login(username='boss', password='pw')
        self.assertContains(self.client.get('/admin/metrics/'), 'Funnel, last 30 days')


class GoogleVerificationTest(TestCase):
    def test_file_is_served_exactly(self):
        r = self.client.get('/google9c61ce115925089c.html')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content.decode(), 'google-site-verification: google9c61ce115925089c.html')


class NoDeadDomainTest(TestCase):
    """devopsaudit.app does not exist (NXDOMAIN): nothing may point at it."""

    def test_no_reference_to_the_dead_domain(self):
        import glob
        hits = [p for p in glob.glob('app/**/*.py', recursive=True) + glob.glob('app/templates/**/*.html', recursive=True)
                + glob.glob('action/*') + ['config/settings.py']
                if 'devopsaudit.app' in open(p, encoding='utf-8').read() and not p.endswith('tests.py')]
        self.assertEqual(hits, [])
        self.assertIn('devopscheck.com', self.client.get('/.well-known/security.txt').content.decode())


class KeylessCIScanTest(TestCase):
    """B4: the Action works on a public repository without an account."""

    def test_start_poll_and_payload_shape(self):
        import json
        from app.models import CIScan
        with patch('app.tasks.run_ci_scan_task.delay') as delay:
            r = self.client.post('/api/v1/ci-scan/', json.dumps({'repo': 'acme/demo', 'ref': 'feature',
                                                                   'commit_sha': 'a' * 40, 'pr_number': 7}),
                                 content_type='application/json')
        self.assertEqual(r.status_code, 201)
        delay.assert_called_once()
        scan = CIScan.objects.get()
        self.assertEqual((scan.repo_full_name, scan.ref, scan.pr_number), ('acme/demo', 'feature', 7))
        prev = CIScan.objects.create(repo_full_name='acme/demo', commit_sha='b' * 40, status='done', score=70,
                                     results=[{'check_id': 'ci.tests', 'passed': False, 'applicable': True}])
        CIScan.objects.filter(id=prev.id).update(created_at=scan.created_at - timezone.timedelta(minutes=5))
        CIScan.objects.filter(id=scan.id).update(status='done', score=80, fail_under=75, results=[
            {'check_id': 'docker.nonroot', 'passed': False, 'applicable': True, 'severity': 'warn'}])
        data = self.client.get(f'/api/v1/ci-scan/{scan.id}/').json()
        self.assertEqual((data['score'], data['gate'], data['score_delta']), (80, True, 10))
        self.assertEqual((data['new_findings'], data['resolved_findings']), (['docker.nonroot'], ['ci.tests']))
        self.assertIn('utm_source=action', data['url'])

    def test_limits_and_validation(self):
        import json
        from app.models import CIScan
        self.assertEqual(self.client.post('/api/v1/ci-scan/', '{"repo": "not a repo"}',
                                          content_type='application/json').status_code, 400)
        for _ in range(20):
            CIScan.objects.create(repo_full_name='acme/busy')
        r = self.client.post('/api/v1/ci-scan/', json.dumps({'repo': 'acme/busy'}), content_type='application/json')
        self.assertEqual(r.status_code, 429)

    def test_worker_refuses_private_and_scores_public(self):
        from app.models import CIScan
        from app.repo_client import StaticRepoClient
        from app.tasks import run_ci_scan_task
        public = StaticRepoClient({'README.md': '# x', '.devopsaudit.yml': 'fail_under: 60\n'})
        public.is_private = False
        scan = CIScan.objects.create(repo_full_name='acme/demo')
        with patch('app.repo_client.GithubRepoClient.load', return_value=public), \
                patch('app.checks_extra.requests.post'):
            run_ci_scan_task(scan.id)
        scan.refresh_from_db()
        self.assertEqual((scan.status, scan.fail_under), ('done', 60))
        self.assertIsNotNone(scan.score)
        private = StaticRepoClient({'README.md': '#'})
        private.is_private = True
        scan2 = CIScan.objects.create(repo_full_name='acme/secret')
        with patch('app.repo_client.GithubRepoClient.load', return_value=private):
            run_ci_scan_task(scan2.id)
        scan2.refresh_from_db()
        self.assertEqual(scan2.status, 'failed')
        self.assertIn('private', scan2.error_message)

    def test_sarif_is_valid_shape(self):
        import importlib.util, os, tempfile
        spec = importlib.util.spec_from_file_location('sarif', '/app/action/sarif.py')
        sarif = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sarif)
        with tempfile.TemporaryDirectory() as ws:
            open(os.path.join(ws, 'Dockerfile'), 'w').write('FROM x\n')
            open(os.path.join(ws, 'README.md'), 'w').write('#\n')
            doc = sarif.build({'url': 'https://devopscheck.com/scan/a/b/', 'checks': [
                {'check_id': 'docker.nonroot', 'name': 'Container runs as a non-root user', 'passed': False,
                 'applicable': True, 'severity': 'warn', 'evidence': 'Runs as root: Dockerfile'},
                {'check_id': 'docker.pinned_base', 'passed': False, 'applicable': True, 'severity': 'crit',
                 'evidence': 'Dockerfile: FROM x'},
                {'check_id': 'ci.tests', 'passed': True},
                {'check_id': 'docs.changelog', 'passed': False, 'applicable': True, 'category': 'hygiene'},
                {'check_id': 'ops.observability', 'passed': False, 'applicable': False}]}, ws)
        run = doc['runs'][0]
        self.assertEqual(doc['version'], '2.1.0')
        self.assertEqual([r['ruleId'] for r in run['results']], ['docker.nonroot', 'docker.pinned_base'])
        self.assertEqual(run['results'][1]['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'Dockerfile')
        self.assertEqual(run['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'README.md')
        self.assertEqual(run['tool']['driver']['rules'][0]['helpUri'], 'https://devopscheck.com/checks/docker.nonroot/')


class OrgScanTest(TestCase):
    """B7: an organisation's public repositories at a glance."""

    def test_route_is_not_swallowed_by_repo_route_and_queues_once(self):
        from app.models import OrgScan
        with patch('app.tasks.run_org_scan_task.delay') as delay:
            r = self.client.get('/scan/org/acme/')
            self.client.get('/scan/org/acme/')
        self.assertEqual(r.status_code, 200)
        delay.assert_called_once()
        self.assertEqual(OrgScan.objects.get().org, 'acme')
        self.assertContains(r, 'noindex')

    def test_summary_average_worst_and_repeating_findings(self):
        from app.models import Audit, OrgScan, PublicScan
        names = []
        for i, score in enumerate((40, 70, 90)):
            n = f'acme/r{i}'
            names.append(n)
            PublicScan.objects.create(repo_full_name=n, repo_url='https://github.com/' + n, status=Audit.STATUS_DONE,
                                      score=score, results=[{'check_id': 'actions.pinned_sha', 'name': 'GitHub Actions pinned to a commit SHA',
                                                             'passed': False, 'applicable': True, 'category': 'ci_cd'}])
        OrgScan.objects.create(org='acme', status='done', repos=names, total_public=3)
        html = self.client.get('/scan/org/acme/').content.decode()
        self.assertIn('>67<', html)                                  # (40+70+90)/3
        self.assertLess(html.index('acme/r0'), html.index('acme/r2'))  # weakest first
        self.assertIn('/checks/actions.pinned_sha/', html)
        self.assertIn('index, follow', html)
        self.assertIn('/scan/org/acme/', self.client.get('/sitemap.xml').content.decode())

    def test_task_lists_repos_and_scans_most_starred(self):
        from app.models import OrgScan, PublicScan
        from app.tasks import run_org_scan_task
        row = OrgScan.objects.create(org='acme')
        listing = MagicMock(status_code=200)
        listing.json.return_value = [
            {'full_name': 'acme/small', 'stargazers_count': 1},
            {'full_name': 'acme/big', 'stargazers_count': 900},
            {'full_name': 'acme/fork', 'stargazers_count': 5000, 'fork': True},
        ]
        with patch('requests.get', return_value=listing), patch('app.tasks.run_public_scan_task') as scan:
            run_org_scan_task(row.id)
        row.refresh_from_db()
        self.assertEqual((row.status, row.repos, row.total_public), ('done', ['acme/big', 'acme/small'], 2))
        self.assertEqual(scan.call_count, 2)
        self.assertEqual(PublicScan.objects.count(), 2)

    def test_submit_accepts_url(self):
        r = self.client.post('/scan/org/', {'org': 'https://github.com/kubernetes/'})
        self.assertEqual(r['Location'], '/scan/org/kubernetes/')


class ContentFixesTest(TestCase):
    """B8: fixes that edit the workflows themselves."""

    WF = ('name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n'
          '      - uses: actions/checkout@v4\n'
          '      - uses: "actions/setup-python@v5"  # python\n'
          '      - uses: ./.github/actions/local\n'
          '      - uses: docker://alpine:3\n'
          '      - uses: some/unknown@v1\n'
          '      - uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9\n'
          '      - run: pytest\n')

    def _resolve(self, owner_repo, ref):
        return {('actions/checkout', 'v4'): 'a' * 40, ('actions/setup-python', 'v5'): 'b' * 40}.get((owner_repo, ref))

    def test_pin_actions_rewrites_only_resolvable_tags(self):
        from app.content_fixes import pin_actions
        r = pin_actions({'.github/workflows/ci.yml': self.WF}, self._resolve)
        new = r.changes['.github/workflows/ci.yml']
        self.assertIn('uses: actions/checkout@' + 'a' * 40 + ' # v4', new)
        self.assertIn('uses: "actions/setup-python@' + 'b' * 40 + '" # v5', new)
        self.assertIn('uses: ./.github/actions/local', new)
        self.assertIn('uses: docker://alpine:3', new)
        self.assertIn('uses: some/unknown@v1', new)                       # unresolved: untouched
        self.assertIn('actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9\n', new)
        self.assertEqual(len(r.done), 2)
        self.assertTrue(any('some/unknown@v1' in s for s in r.skipped))
        self.assertEqual(new.count('\n'), self.WF.count('\n'))           # no line added or lost

    def test_least_privilege_is_conservative(self):
        from app.content_fixes import least_privilege
        files = {
            '.github/workflows/ci.yml': self.WF,
            '.github/workflows/release.yml': 'on: push\njobs:\n  r:\n    steps:\n      - run: gh release create v1\n',
            '.github/workflows/done.yml': 'on: push\npermissions:\n  contents: read\njobs:\n  a: {}\n',
            '.github/workflows/perjob.yml': 'on: push\njobs:\n  a:\n    permissions:\n      contents: write\n',
        }
        r = least_privilege(files)
        self.assertEqual(list(r.changes), ['.github/workflows/ci.yml'])
        self.assertIn('permissions:\n  contents: read\n\njobs:', r.changes['.github/workflows/ci.yml'])
        self.assertEqual(len(r.skipped), 2)

    def test_both_are_offered_as_fixes_on_github_only(self):
        from app.fix_templates import is_fixable
        self.assertTrue(is_fixable('actions.broad_permissions', 'github'))
        self.assertFalse(is_fixable('actions.broad_permissions', 'gitlab'))


class GithubConnectTruthTest(TestCase):
    """The site describes the GitHub connection this deployment actually has."""

    @override_settings(GITHUB_APP_SLUG='')
    def test_without_the_app_nothing_promises_it(self):
        html = self.client.get('/').content.decode()
        self.assertNotIn('Install the GitHub App', html)
        self.assertNotIn('expire within the hour', html)
        self.assertIn('does not split into read and write', html)
        from app.models import OrgScan
        OrgScan.objects.create(org='acme', status='done')
        self.assertNotIn('/auth/github/app/install/', self.client.get('/scan/org/acme/').content.decode())

    def test_workflow_step_up_for_oauth_connections(self):
        from allauth.socialaccount.models import SocialAccount
        from app.content_fixes import WorkflowScopeError
        from app.models import Audit, AuditCheck, GithubProfile
        user = User.objects.create_user('u', 'u@example.com', 'pw')
        GithubProfile.objects.create(user=user, github_id=42, github_login='u', access_token='t')
        SocialAccount.objects.create(user=user, provider='github', uid='42')
        audit = Audit.objects.create(user=user, repo_full_name='u/r', repo_url='https://github.com/u/r',
                                     source=Audit.SOURCE_GITHUB, status=Audit.STATUS_DONE)
        check = AuditCheck.objects.create(audit=audit, name='x', description='d', severity='warn', passed=False,
                                          check_id='actions.pinned_sha')
        self.client.force_login(user)
        with patch('app.content_fixes.open_pull_request', side_effect=WorkflowScopeError('no workflow')):
            r = self.client.post(f'/audit/{audit.id}/fix/{check.id}/pr/')
        self.assertEqual(r.status_code, 403, r.content)
        url = r.json()['reauth_url']
        self.assertIn('scope=workflow', url)
        self.assertIn('process=connect', url)
