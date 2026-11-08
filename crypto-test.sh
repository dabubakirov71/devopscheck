#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# crypto-test.sh  — simulate a NOWPayments IPN webhook locally
#
# What it does:
#   Sends a fake "payment finished" IPN callback to your local Django server,
#   which activates Pro for the specified user.  No API key, no real money.
#
# Usage:
#   ./crypto-test.sh <user_id>
#
# Find your user_id:
#   docker compose -f docker/docker-compose.yml exec web \
#     python manage.py shell -c \
#     "from django.contrib.auth.models import User; [print(u.id, u.username) for u in User.objects.all()]"
# ──────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
COMPOSE_FILE="$SCRIPT_DIR/docker/docker-compose.yml"

# ── 1. Require user_id ───────────────────────────────────────────────────────
USER_ID="${1:-}"
if [[ -z "$USER_ID" ]]; then
  echo ""
  echo "  Usage: ./crypto-test.sh <user_id>"
  echo ""
  echo "  Find your user_id:"
  echo "    docker compose -f $COMPOSE_FILE exec web \\"
  echo "      python manage.py shell -c \\"
  echo "      \"from django.contrib.auth.models import User; [print(u.id, u.username) for u in User.objects.all()]\""
  echo ""
  exit 1
fi

# ── 2. Check Django is reachable ─────────────────────────────────────────────
if ! curl -sf http://localhost:8000/health/ >/dev/null 2>&1; then
  echo ""
  echo "  Django is not responding on localhost:8000."
  echo "  Start it: docker compose -f $COMPOSE_FILE up -d"
  echo ""
  exit 1
fi

echo ""
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │  Simulating NOWPayments crypto IPN webhook               │"
echo "  │                                                          │"
printf  "  │  User ID : %-46s│\n" "$USER_ID"
echo "  │  Status  : finished (payment complete)                   │"
echo "  │  Amount  : \$29 USD (test)                               │"
echo "  └──────────────────────────────────────────────────────────┘"
echo ""

# ── 3. Build payload, sign, and POST — all in Python ─────────────────────────
python3 - "$USER_ID" "$ENV_FILE" <<'PYEOF'
import sys, json, hmac, hashlib, datetime

try:
    import urllib.request, urllib.error
except ImportError:
    print("  Python 3 is required")
    sys.exit(1)

user_id  = sys.argv[1]
env_file = sys.argv[2]

# Parse .env file
env = {}
with open(env_file) as f:
    for line in f:
        line = line.strip()
        if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip()

ipn_secret  = env.get('NOWPAYMENTS_TEST_IPN_SECRET', '')
webhook_url = 'http://localhost:8000/billing/webhooks/crypto/'

now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')
data = {
    'actually_paid':    0.001,
    'created_at':       now,
    'order_description':'DevOps Audit Pro - 1 Month ($29) [TEST]',
    'order_id':         user_id,
    'outcome_amount':   29,
    'outcome_currency': 'usd',
    'pay_address':      '0xTEST1234567890ABCDEF',
    'pay_amount':       0.001,
    'pay_currency':     'eth',
    'payment_id':       '9999999999',
    'payment_status':   'finished',
    'price_amount':     29,
    'price_currency':   'usd',
    'purchase_id':      '8888888888',
    'updated_at':       now,
}

# Sort keys alphabetically — NOWPayments requires this for HMAC
sorted_body = json.dumps(data, sort_keys=True, separators=(',', ':'))
payload     = sorted_body.encode()

headers = {'Content-Type': 'application/json'}
if ipn_secret:
    sig = hmac.new(ipn_secret.encode(), payload, hashlib.sha512).hexdigest()
    headers['x-nowpayments-sig'] = sig
    print('  Signed with HMAC-SHA512 (NOWPAYMENTS_TEST_IPN_SECRET)')
else:
    print('  No NOWPAYMENTS_TEST_IPN_SECRET set — sending unsigned')
    print('  (signature check is skipped in code when no secret is configured)')

req = urllib.request.Request(webhook_url, data=payload, headers=headers, method='POST')
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        print(f'  ✓  Webhook accepted (HTTP {resp.status})')
        print(f'  ✓  User {user_id} Pro plan activated')
        print()
        print('  → Refresh /billing/ to confirm.')
except urllib.error.HTTPError as e:
    body = e.read().decode('utf-8', errors='replace')
    print(f'  ✗  Webhook returned HTTP {e.code}')
    if body:
        print(f'     Response: {body}')
    if e.code == 400:
        print()
        print('  Possible causes:')
        print('  • NOWPAYMENTS_TEST_IPN_SECRET is set but signature does not match')
        print('  • Leave NOWPAYMENTS_TEST_IPN_SECRET empty to skip signature check')
except urllib.error.URLError as e:
    print(f'  ✗  Could not connect: {e.reason}')
    print('  Is Django running? docker compose -f docker/docker-compose.yml up -d')

PYEOF
