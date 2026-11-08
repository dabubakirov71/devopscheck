#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# stripe-listen.sh  — one-command local Stripe webhook testing
#
# What it does:
#   1. Gets the current webhook signing secret from Stripe CLI
#   2. Auto-saves it to .env as STRIPE_TEST_WEBHOOK_SECRET
#   3. Restarts the Django container so the new secret is picked up
#   4. Starts forwarding Stripe events to your local server
#
# Requirements:
#   • Stripe CLI installed  → https://stripe.com/docs/stripe-cli#install
#   • Logged in             → stripe login
#   • Docker running        → docker compose -f docker/docker-compose.yml up -d
#
# Test card (after setup):
#   Number : 4242 4242 4242 4242
#   Expiry : any future date (e.g. 12/34)
#   CVC    : any 3 digits (e.g. 123)
# ──────────────────────────────────────────────────────────────────────────────

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
COMPOSE_FILE="$SCRIPT_DIR/docker/docker-compose.yml"

# ── 1. Check Stripe CLI is available ─────────────────────────────────────────
if ! command -v stripe &>/dev/null; then
  echo ""
  echo "  Stripe CLI not found. Install it first:"
  echo "    https://stripe.com/docs/stripe-cli#install"
  echo ""
  exit 1
fi

# ── 2. Get the signing secret for this session ────────────────────────────────
echo ""
echo "  Fetching webhook signing secret from Stripe CLI..."
SECRET=$(stripe listen --print-secret 2>/dev/null || true)

if [[ -z "$SECRET" || "$SECRET" != whsec_* ]]; then
  echo ""
  echo "  Could not get webhook secret. Are you logged in?"
  echo "    Run: stripe login"
  echo ""
  exit 1
fi

# ── 3. Save secret to .env ────────────────────────────────────────────────────
if grep -q "STRIPE_TEST_WEBHOOK_SECRET" "$ENV_FILE"; then
  # Replace existing line (works on Linux)
  sed -i "s|STRIPE_TEST_WEBHOOK_SECRET=.*|STRIPE_TEST_WEBHOOK_SECRET=$SECRET|" "$ENV_FILE"
else
  echo "STRIPE_TEST_WEBHOOK_SECRET=$SECRET" >> "$ENV_FILE"
fi

echo "  ✓  STRIPE_TEST_WEBHOOK_SECRET saved to .env"

# ── 4. Restart Django container so new secret is loaded ──────────────────────
if docker compose -f "$COMPOSE_FILE" ps --services 2>/dev/null | grep -q web; then
  echo "  Restarting Django container..."
  docker compose -f "$COMPOSE_FILE" restart web >/dev/null
  echo "  ✓  Django restarted"
fi

# ── 5. Start forwarding ───────────────────────────────────────────────────────
echo ""
echo "  ┌──────────────────────────────────────────────────────────┐"
echo "  │  Stripe webhook listener is running                      │"
echo "  │                                                          │"
echo "  │  Go to http://localhost:8000/billing/                    │"
echo "  │  Click \"Pay with Card\"                                   │"
echo "  │  Use test card: 4242 4242 4242 4242  12/34  123          │"
echo "  │                                                          │"
echo "  │  Press Ctrl+C to stop                                    │"
echo "  └──────────────────────────────────────────────────────────┘"
echo ""

stripe listen \
  --forward-to http://localhost:8000/billing/webhooks/stripe/ \
  --events checkout.session.completed,customer.subscription.updated,customer.subscription.deleted
