# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

All development runs inside Docker. The database and Redis are not available on the host.

```bash
# Start dev environment (first time or after dependency changes)
docker compose -f docker/docker-compose.yml up --build

# Subsequent starts
docker compose -f docker/docker-compose.yml up

# Run all tests
docker compose -f docker/docker-compose.yml exec web python manage.py test app --verbosity=2

# Run a single test class or method
docker compose -f docker/docker-compose.yml exec web python manage.py test app.tests.AuditModelTest
docker compose -f docker/docker-compose.yml exec web python manage.py test app.tests.AuditModelTest.test_score_label_none

# Apply migrations manually (normally auto-run by entrypoint)
docker compose -f docker/docker-compose.yml exec web python manage.py migrate

# i18n — after adding/changing translatable strings
docker compose -f docker/docker-compose.yml exec web python manage.py makemessages -l ru
docker compose -f docker/docker-compose.yml exec web python manage.py compilemessages

# Encrypt any provider tokens still stored as plaintext (safe to re-run)
docker compose -f docker/docker-compose.yml exec web python manage.py encrypt_tokens

# Reset local DB if volume is corrupted
docker compose -f docker/docker-compose.yml down
docker volume rm docker_pgdata
docker compose -f docker/docker-compose.yml up --build
```

Config is read via `python-decouple` from `.env`. Copy `.env.example` and fill in secrets before first run.

## Architecture

### Audit pipeline (the core product)

A user connects GitHub (one-click App install, OAuth, or PAT) or GitLab (PAT),
selects a repo, and triggers an audit. Anyone can also audit a public repository
with no account at `/scan/<owner>/<repo>/`.

1. `views._start_audit()` creates a **new** `Audit` row (status=pending) and dispatches
   `run_audit_task` (Celery). Audits are append-only — one row per run — which is what
   makes the score history and trend chart possible. Never reuse a row.
2. The task builds a `RepoClient` (`app/repo_client.py`) and calls `run_all_checks(client)`
   from `app/checks.py`. One engine serves both providers.
3. Checks return `{check_id, name, description, severity, passed, recommendation, category}`.
4. If the user is on a paid plan — or has a free monthly AI credit left — `get_ai_summary()`
   and `get_ai_code_suggestions()` run from `app/ai_providers.py`.
5. Results are bulk-created as `AuditCheck` rows; the `Audit` row gets score, category_scores,
   the dependency inventory for SBOM export, AI text, and status=done.
6. A PR-triggered run posts a score comment via `post_pr_comment`; otherwise an email goes out
   if `email_notifications=True`.

`regenerate_ai_task` re-runs only the AI step against existing DB rows.

### RepoClient: one archive instead of a request per file

`app/repo_client.py` is the single read path for both providers. It downloads the
repository as one tarball (`/tarball/{ref}` on GitHub, `/repository/archive.tar.gz`
on GitLab) and keeps the text files in memory, so:

- `exists(path)` is a set lookup, not an HTTP call
- `get_content(path)` is a dict lookup
- a full audit costs **3 API calls**, not ~90

Measured on gitlab-org/gitlab-ui (1774 files): 3 calls, 2.7s end to end. This is what
makes the free public scanner viable — unauthenticated GitHub allows 60 requests an hour.

Fallbacks are automatic: if the archive is too large (>40 MB) or the request fails,
the client goes back to per-file reads with `prefetch()` running them 8 at a time.
`StaticRepoClient` backs the test suite with an in-memory dict.

### check_id is the stable key

Display names are English source strings translated per audit, so **nothing may key off
a check name**. Every lookup — fix templates, built-in AI suggestions, compliance control
mapping — goes through `check_id` (e.g. `security.no_secrets`, `iac.open_ingress`).
`fix_templates._LEGACY_NAME_TO_ID` and `compliance._LEGACY` keep pre-`check_id` audit rows
working.

### GitLab repo identifier format

GitLab repos are stored as `"full_name::project_id"` (e.g. `myorg/myrepo::12345`). The `::`
separator is split in `views.py` and `repo_client.build_client_for_audit()`; use
`audit.repo_display` rather than splitting by hand. `checks_gitlab.py` is now a thin adapter
that builds a `GitlabRepoClient` and calls the shared engine.

### AI provider selection (`app/ai_providers.py`)

Priority: user's own key in `UserAISettings` DB record → `AUDIT_AI_PROVIDER` env override → first of Anthropic/OpenAI/Gemini with a populated env key → built-in rule-based fallback. The fallback (`_builtin_summary`, `_BUILTIN` dict) works without any API key and covers all check names in both EN and RU.

The model can be overridden per-deployment with `AUDIT_AI_MODEL` env var; defaults per provider are in `PROVIDERS` dict (`claude-haiku-4-5-20251001`, `gpt-4o-mini`, `gemini-2.5-flash`).

### Scoring

`calculate_score()` in `checks.py`: crit checks weight 30, warn=15, info=5. Score = earned / total × 100.

### Check modules

- `checks.py` — the engine plus security, CI/CD, Docker, docs, deps and ops checks
- `checks_secrets.py` — full-tree credential scan (provider patterns + entropy-gated generic rule)
- `secret_history.py` — secrets in git history: a bare, blob-size-filtered `git clone`
  into a temp dir (token in an env-set HTTP header, never the URL), every blob read once
  with the same rules. Bounded by repo size, blob size/count, bytes and time; any failure
  becomes a not-applicable `security.no_secrets_in_history`, never a failed audit
- `secret_liveness.py` — one read-only provider call per found key (GitHub, GitLab, Slack,
  Stripe, OpenAI, Anthropic, Telegram, AWS STS) → `active`/`inactive`/`unknown`; an active
  one adds the `security.secret_active` crit check with a "live key" badge. Only the status
  is kept, never the value
- `checks_iac.py` — Terraform: remote state, open ingress, encryption, public buckets, pinning
- `checks_extra.py` — CVE via OSV.dev, GitHub Actions supply chain, Kubernetes, observability

History and liveness run only with `run_all_checks(..., deep=True)`, which only
`run_audit_task` (repositories the owner connected) passes, and only for a client with
`supports_deep_scan` (the real GitHub/GitLab clients). The public scanner never clones
and never sends anyone's key to a provider — keep it that way.

### Plans and gating

`UserSubscription` has four plans: `free`, `pro`, `team`, `compliance`, each with a
`billing_period` of `monthly` or `annual`. Capability properties are cumulative:

- `is_pro` — any paid plan; gates AI, unlimited repos, PDF, fix pull requests
- `is_team` — Team and above; gates the organisation dashboard, weekly trends
  and org-wide `fail_under`. **Not** PR comments — those moved to `is_pro` for
  exposure; keep the plan tables in sync with the gate
- `is_compliance` — Compliance only; gates evidence export and SBOM

Free users get real quotas rather than a locked door: `FREE_REPO_LIMIT` private repos
(3), plus `FREE_AI_REPORTS_PER_MONTH` (1) and `FREE_PDF_PER_MONTH` (1) tracked in
`MonthlyUsage`. Public repository scans are unlimited and need no account.

The repository quota is **releasable**. `Audit.archived_at` marks a repository the
user has removed; it is set on every run of that repository at once and nothing is
deleted, so restoring brings the whole score history back. Read the count through
`views._tracked_repo_count()` and the queryset through `AuditQuerySet.active()` —
never re-derive it, or two surfaces will report different numbers. The limit is
enforced *per provider*, and the billing page shows one row per provider for that
reason. `latest_per_repo()` filters archived rows itself, so dashboards get this
for free; a report stays readable by direct link after removal.

### Fix pull request until green CI (`app/fix_agent.py`, roadmap phase 5)

After `fix_open_pr` opens a GitHub PR, `fix_agent.track()` creates a
`FixAttempt` — only for repositories in `FIX_AGENT_REPOS` (env, comma-separated;
empty by default, i.e. off; `*` for all). `tasks.poll_fix_attempts` runs
every minute (beat) and calls `step()`: check-runs on the PR head → green /
wait / no_ci / on failure read the failed Actions job logs, ask the model for
new content of the PR's own files (`scope_files`), run `guardrail()`, push to
the same branch, comment. Max 3 pushes, 6 model calls, 2 hours, then
`gave_up` with a comment. **Guardrail rules are the point of the feature:**
only scope files; the count of test/lint/scan commands may not drop; no
`continue-on-error`, `allow_failure`, `|| true`, `exit 0`, `if: false`, skip
markers, `-k not`/`--ignore`. Never loosen them to make a case pass. Metrics
(green %, merged %, avg iterations, model calls) are in the FixAttempt admin
list title. GitLab pipelines are not handled yet.

### The admin

**The admin is a separate process on its own port and is not routed on the
public site.** `ADMIN_SITE=1` swaps `ROOT_URLCONF` for `config/urls_admin.py`,
which serves `/admin/` and nothing else; `config/urls.py` does not route
`/admin/` at all, so the customer-facing domain returns 404 for it. It shares
the models and the database — it has to, that is what an admin is — but not the
URL space. In production both processes bind to loopback, and the admin port is
reached over an SSH tunnel (`DEPLOY.md`). Never add `admin.site.urls` back to
`config/urls.py`; `AdminIsNotOnThePublicSiteTest` fails the build if you do.

Admin tests must carry `@override_settings(ROOT_URLCONF='config.urls_admin')` —
`reverse('admin:...')` does not resolve on the public urlconf any more.

`app/admin.py` registers every model. Two rules it must keep:

- **No form may include an encrypted field.** `GithubProfile.access_token`,
  `GitlabProfile.access_token`, `UserAISettings.api_key`,
  `UserProfile.webhook_secret` and `api_token` are excluded and rendered as
  "set / not set" — a `ModelAdmin` that includes them decrypts them onto the page.
  `AdminNeverRendersACredentialTest` asserts this.
- **`AuditAdmin` has no add, no delete and no writable field.** Audits are
  append-only; a hand-edited score is indistinguishable from a measured one.

Plans are granted by admin action, which clears `stripe_subscription_id` —
`cancel_subscription` calls the Lemon Squeezy API on an `ls_` prefix and a granted
plan has nothing there to cancel.

### What may leave the customer's boundary

`UserProfile.ai_analysis_enabled` is the switch. When it is off,
`_get_active_provider()` returns `(None, None)` and every caller falls back to
the local rules — the feature stays, the tailoring goes. **It is not gated on a
plan**: whether repository content reaches a third party is the account owner's
decision, not a paid feature. A failure to read the preference is treated as
*off*, never as consent.

**Everything on its way to a provider goes through `checks_secrets.redact()`.**
The rules that define a secret are the rules that mask one, so anything the
product will call a credential is something it will never forward. PEM blocks
are masked as whole spans. `security.no_secrets` requests no file at all — its
candidate files used to be `settings.py`, `config.py`, `app.py`, `main.py`,
which is exactly where the credential it had just found would be.

`app/repo_context.py` collects the facts a prompt needs (languages, frameworks,
base images, ports, CI, Terraform, top-level tree, README head), redacts them,
and stores them on `Audit.repo_context`. The profile page states plainly what is
sent and what never is; keep that list true when the prompts change.

### Token encryption

`GithubProfile.access_token`, `GitlabProfile.access_token` and `UserAISettings.api_key`
use `crypto_utils.EncryptedTextField` (Fernet). The key comes from `TOKEN_ENCRYPTION_KEY`,
falling back to one derived from `SECRET_KEY` with a warning. Ciphertext carries an
`enc:v1:` prefix; values without it are read as legacy plaintext, and
`manage.py encrypt_tokens` rewrites them.

### `.devopsaudit.yml` — the repository's own say

`app/audit_config.py` reads an optional file from the repository being audited
(`.devopsaudit.yml`, `.devopsaudit.yaml` or `.github/devopsaudit.yml`):

```yaml
kind: library            # service | library | infrastructure — overrides detection
fail_under: 70           # the CI gate; Audit.gate compares the score to it
ignore:
  - id: docker.nonroot
    reason: the base image already runs as nobody
severity:
  deps.lockfile: info    # crit | warn | info
allow_secrets:
  - tests/fixtures/      # path prefixes the secret scanner skips
```

Two invariants keep this from becoming a way to fake a score:

- **An ignore needs a reason.** A bare id is refused and reported in
  `Audit.config_errors`, which the report and the PR comment both surface.
- **Nothing is hidden.** An ignored check stays in the report under "does not
  apply here" carrying the reason the repository gave.

`security.no_secrets` and `security.env_not_committed` cannot be ignored at all.
A broken config never breaks the audit — it runs and the errors are reported.

### Repository kind

`app/repo_kind.py` decides whether a repository is a `service` (the default),
a `library` or `infrastructure`, and names the checks it cannot act on. A
library loses the Docker family and `ops.observability`; infrastructure loses
the dependency checks too. Set-aside checks keep `applicable=False` and a
`not_applicable_reason`, stay in the report, and leave the score, the category
scores, the action plan and the compliance report.

The same flag covers checks with no input: `docker.healthcheck` and friends used
to *pass* when there was no Dockerfile, paying a repository sixty points for
shipping no container.

### What changed since the last run

`Audit.changed_findings()` returns `(appeared, resolved)` against
`previous_run()`, keyed on `check_id`. This is what the PR comment leads with —
a reviewer is looking at one change, not at the repository.

### Compliance and SBOM

`compliance.py` maps each `check_id` to SOC 2 Trust Services Criteria and ISO 27001:2022
Annex A controls. A control is satisfied only when **every** check mapped to it passes.
`sbom.py` emits CycloneDX 1.5 and SPDX 2.3 from `Audit.sbom_components`, captured during
the run so export never needs repository access again.

### Payments

Two providers controlled by `PAYMENT_MODE=test|live`:
- **Lemon Squeezy** — card payments via checkout redirect, webhook at `/billing/webhooks/ls/`
- **Cryptomus** — crypto checkout, webhook at `/billing/webhooks/crypto/`

Both webhooks use HMAC signature verification before granting Pro access.

### Key models

- `GithubProfile` — FK to User (a user can have several GitHub accounts); `installation_id`
  is set when connected through the GitHub App
- `GitlabProfile` — OneToOne to User; `gitlab_url`, `verify_ssl`, `custom_dns` for self-hosted
- `Audit` — one row per run, append-only. `source`, `trigger` (manual/webhook/api/pull_request),
  `commit_sha`, `pr_number`, `sbom_components`; `is_public` + `public_token` power shareable
  links and the SVG badge. `Audit.objects.latest_per_repo()` is what dashboards use;
  `previous_run()` and `score_delta` drive the trend
- `AuditCheck` — `check_id` is the stable key; `name`/`description` are display text
- `UserSubscription` — plan, billing period, payment provider, expiry reminder timestamp
- `MonthlyUsage` — per-month AI report and PDF counters for free-plan quotas
- `PublicScan` — cached audit of a public repository for the no-account scanner
- `UserAISettings` — optional per-user AI key (encrypted; overrides server-side keys)
- `UserProfile` — email notifications, webhook secret, REST API token, PR comment flag

### The badge, as a pull request

`github_writer.open_badge_pull_request()` puts the score badge in a
repository's README and opens the PR. `insert_badge()` is the part that matters:
it **must never stack a second badge**. An existing one is rewritten in place
(keeping the rest of its line — badges share a row); a marker it cannot parse
means the README is left alone and `NothingToChange` is raised.

`views_public.badge_markdown()` is the single source for the badge string — the
copy button and the commit both read it. Building it twice means the pull
request adds a badge the page never showed.

For an anonymous visitor the button routes through `/register/?next=…`.
"We will open the pull request" is the strongest reason to sign up the product
has; it is a finished job rather than a promise of one.

`open_fix_pull_request` and `open_badge_pull_request` share `_Repo` — permission
check, branch from the repository's **own** default branch, commit, PR. Nothing
is ever committed to the default branch.

### Keeping the visitor: `RepoWatch`

The public scanner is the top of the funnel and the emotional peak of the
product. `RepoWatch` (`models.py`, views in `views_public.py`, tasks in
`tasks.py`) captures an address on any finished scan page, sends the report, and
mails the reader when the score moves. It is not an account.

Three rules it must keep:

- **Double opt-in.** One report to an address someone typed is fine; recurring
  mail needs `confirmed_at`. Never send a recurring message to an unconfirmed or
  unsubscribed row.
- **Every message carries the one-click unsubscribe link.** No login, no
  confirmation step — the alternative is the spam button, which costs the
  sending domain more than the subscriber was worth.
- **Changes are measured against `last_score`** — what the reader was last told
  — not against the previous scan. Otherwise a dip that recovers between two
  messages mails them about nothing.

The subscribe form answers identically for a new, pending or already-watching
address: anything else lets a stranger test whether someone uses this product.

`refresh_watched_public_scans` (04:00) then `notify_watched_score_changes`
(05:00) — refresh first, compare an hour later.

### i18n

English and Russian. **English is the source language** — check names, descriptions and
recommendations in `checks*.py` are English strings wrapped in `gettext`, translated at
audit time into `audit.language`. The Russian catalogue is kept at 100%: add the translation
in the same change as the string.

`ai_providers._ID_TO_LEGACY_KEY` maps a `check_id` to the key the built-in suggestion tables
use, so the offline fallback keeps working now that names are translated.
`DefaultLanguageMiddleware` forces English for new visitors regardless of `Accept-Language`.

### GitHub Action (`action/`)

A composite action — `action.yml`, `audit.sh`, `report.py` — that audits the
commit under test and **fails the build** below the threshold. Nothing is built
and nothing is downloaded: it runs on `curl` and `python3`, both already on
every runner.

The exit code is the point. A report that can only be read on a website is one
people close; a check that fails a build is one the team has to talk about
before merging. Make the job a required status check and the score stops being
advice.

It fails when an explicit `fail-under` input is missed, when the repository's
own `fail_under` is missed, or when `fail-on-new: true` and this run introduced
a finding the previous run did not have. With no threshold anywhere it never
fails — most repositories start that way.

`app/views.api_audit_start` takes `ref`, `commit_sha` and `pr_number`; the same
`ref` reaches `RepoClient` so the audit reads the branch under test rather than
the default branch. Two branches of one repository run concurrently; the same
`(repo, ref)` twice joins the run already going rather than erroring.

### Provider connection health

`ProviderConnection` (abstract, on both profile models) carries `token_status`,
`token_broken_since` and `token_notified_at`. A 401 or 403 **records** the state
and keeps the connection — deleting it on one 401 loses the GitHub
`installation_id` with it. `check_provider_connections` runs daily and emails
once per outage.

`token_page_url` and `host` are instance-aware: a self-hosted GitLab customer is
sent to their own server, and the reconnect form prefills the instance URL it
already had rather than defaulting back to gitlab.com.

### REST API

Bearer token auth (`Authorization: Bearer <token>`) via `UserProfile.api_token`. Endpoints under `/api/v1/` in `config/urls.py`.

### PDF report

`pdf_report.py` renders for paper, not for a screen: light background, dark ink, colour
only on severity, a title block with repository and commit, and page numbers. Pass
`include_compliance=True` (the view does this for Compliance subscribers) to add the
control-coverage section that turns the file into audit evidence.

### Landing page

`landing.html` is a standalone template that does not extend `base.html`, so its `<head>`
carries its own description, canonical, Open Graph and Twitter tags. Keep them in sync
when the positioning changes. It used to be marked "final, never modify"; that rule was
removed — a frozen landing page means no way to fix SEO, no way to correct a claim, and
no conversion work.

## Billing Architecture

Two independent payment providers, both controlled by `PAYMENT_MODE=test|live` in `.env`.

### Cryptomus (crypto)

**Invoice creation** — `create_crypto_checkout` in `views.py` (`POST /billing/checkout/crypto/`):

1. Builds a JSON payload with `amount=str(PRO_PRICE_USD)` (string, not int — Cryptomus requirement), `currency='USD'`, `order_id=str(request.user.id)`, and callback/success/return URLs.
2. Signs the request: `MD5(base64(json_body) + CRYPTOMUS_API_KEY)` — sent as the `sign` header alongside `merchant: CRYPTOMUS_MERCHANT_ID`.
3. POSTs to `https://api.cryptomus.com/v1/payment`; redirects the user to `result.url` from the response. No local record is created at this point.

**Webhook / IPN** — `cryptomus_webhook` (`POST /billing/webhooks/crypto/`, `@csrf_exempt`):

Signature verification is Cryptomus-specific: the `sign` field is **inside the JSON body**, not in a header. To verify:
1. Extract `sign` from the parsed body.
2. Set `data['sign'] = None` (the key must stay, value becomes `null`).
3. Re-serialize with `json.dumps(data)` and compute `MD5(base64(that_json) + CRYPTOMUS_API_KEY)`.
4. Compare with the extracted sign using `hmac.compare_digest`.

If `CRYPTOMUS_API_KEY` is empty the verification block is skipped entirely — always set it in production.

**Activation** triggers when `status` is `'paid'` or `'paid_over'`. `order_id` encodes what was
bought — `{user_id}-{plan}-{period}-{timestamp}` — and is parsed by `_parse_crypto_order_id()`,
which also accepts a bare user id from invoices created before plans existed (read as monthly
Pro). `_activate_plan()` then sets the plan, period and expiry.

Cryptomus is a **one-time payment** — there is no cancellation flow, and nothing renews.
The `send_expiry_reminders` Celery beat job emails customers three days before access lapses;
without it, access simply stops and the customer never had a chance to renew.
`cancel_subscription` in `views.py` only calls the API for Lemon Squeezy
(`stripe_subscription_id.startswith('ls_')`).

**test vs live**: no URL switching — Cryptomus uses a single endpoint (`api.cryptomus.com`). Use a separate test merchant UUID/key pair for `PAYMENT_MODE=test`. Credentials come from `CRYPTOMUS_MERCHANT_ID` and `CRYPTOMUS_API_KEY` in `.env`.

### Lemon Squeezy (card)

Creates a checkout session via `POST https://api.lemonsqueezy.com/v1/checkouts`, passing
`user_id`, `plan` and `period` in `custom_data`. One variant per (plan, period) pair, mapped
in `settings.LS_VARIANTS` from `LS_VARIANT_*` env vars; `LEMONSQUEEZY_VARIANT_ID` is the
fallback. The webhook at `/billing/webhooks/ls/` activates the plan on
`subscription_created` / `order_created` / `subscription_payment_success` and deactivates on
`subscription_expired`. The LS subscription ID is stored in
`UserSubscription.stripe_subscription_id` prefixed with `ls_` (field reuse — the model
originally had Stripe fields).

### Rules

- **Audits are append-only.** Every run creates a new `Audit` row. Never `get_or_create`
  and overwrite one — that is what broke the score history before.
- **Never key logic off a check's display name.** Names are translated; use `check_id`.
- **Never order by `severity`.** It is a text column, so `-severity` sorts warn above
  crit. Order by `severity_rank` (0 = critical); `AuditCheck.save()` keeps it in sync and
  `bulk_create` callers must set it explicitly.
- **Public pages stay public.** `/pricing/` and `/scan/` must render for anonymous
  visitors — they are what `robots.txt` invites search engines to index.
- **Every template needs breakpoints and a focus state.** The base stylesheet supplies
  `:focus-visible`, the skip link and reduced-motion globally; page-level layouts supply
  their own media queries.
- `entrypoint.sh` uses the `RUN_MIGRATIONS=1` flag to prevent Celery race conditions.
- Prices live in `settings.PLAN_PRICES`; Cryptomus needs the amount cast to `str()` only in
  the checkout payload (`create_crypto_checkout`).
- English is the source language for all user-facing strings. Add the Russian translation
  in `locale/ru` in the same change — the catalogue is kept at 100%.
- pytest config: `testpaths = ["app"]` in pyproject.toml to avoid gevent collection.
- The public scanner needs `PUBLIC_SCAN_GITHUB_TOKEN` in production; without it GitHub
  allows 60 requests an hour per IP, which is about one scan.
