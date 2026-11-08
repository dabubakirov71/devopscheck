# Architecture Decision Records

Significant architectural decisions made in this project.
Format: context → decision → consequences.

---

## 2026-06-22 — Expand audit engine from 22 to 27 checks

**Context:**
The original 22 checks covered the basics but had two false-positive bugs (healthcheck always failed on repos without docker-compose; non-root check missed `USER 0`) and lacked several checks that DevOps engineers actively care about in production environments.

**Decision:**
- Fix two false positives: healthcheck passes when no docker-compose exists (N/A); non-root detection uses `re.search(r'USER\s+(root|0)\b')` to catch numeric root.
- Extend secrets scan from 6 hardcoded filenames to 20 paths including `config/local.py`, `config/production.py`, `src/settings/prod.py`, `secrets.py`, `credentials.py` variants.
- Add 5 new checks (27, 28 severity=warn): Docker base image pinned (no `:latest`), requirements.txt uses `==` not `>=`, docker-compose has resource limits, Dockerfile uses multi-stage build, CODEOWNERS file exists.
- All changes applied identically to both `checks.py` (GitHub) and `checks_gitlab.py` (GitLab) to keep parity.

**Consequences:**
- Repos without docker-compose no longer get false failures on healthcheck and resource limits checks.
- Existing audit scores may change slightly for repos with `USER 0` in Dockerfile (now correctly fails).
- The "22 checks" marketing copy in `landing.html` is now stale — it says "22 checks" but engine runs 27. Landing is marked as final (CLAUDE.md rule), so this needs a manual decision on whether to update the number.

---

## 2026-06-26 — Extend audit engine with CVE scanning, GitHub Actions security, Kubernetes, Observability

**Context:**
The 27 existing checks covered filesystem presence (does Dockerfile exist? does README exist?) but had no visibility into actual vulnerability data, supply-chain risks in CI, or Kubernetes workload security. Real DevOps engineers evaluate these factors daily. The product needed checks that produce non-obvious, actionable intelligence — not just "file exists" verdicts.

**Decision:**
Create a separate module `app/checks_extra.py` with four check groups, called from the end of both `run_all_checks()` (GitHub) and `run_gitlab_checks()` (GitLab):

1. **CVE scanning via OSV.dev** — `check_cve_vulnerabilities(get_content_fn)`.
   - Chosen OSV.dev (Google) because it is free, requires no API key, covers PyPI/npm/Go/crates.io/Maven, and uses a single `/v1/querybatch` endpoint supporting up to 1000 queries per request.
   - Parses `requirements.txt`, `package.json`, `go.mod`, `Cargo.toml` to extract `(name, version)` pairs, sends a batch POST, and maps results back. Capped at 100 packages per file to avoid abuse. Timeout 20s; failures degrade gracefully (check is skipped, not failed).
   - Severity mapping: CRITICAL CVE → `crit`, HIGH → `warn`, else clean → `info/passed`.

2. **GitHub Actions security** — `check_github_actions_security(get_content_fn, list_dir_fn)`.
   - Only called from `checks.py` (GitHub), not GitLab.
   - Three sub-checks: (a) actions pinned to 40-char SHA vs floating tag, (b) `permissions: write-all` or broad write scope, (c) `pull_request_target` + PR head checkout — a known RCE vector documented by GitHub Security Lab.
   - Reads up to 15 workflow files from `.github/workflows/`. Local actions (`./`) are excluded from pinning checks.

3. **Kubernetes security** — `check_kubernetes_security(get_content_fn, list_dir_fn)`.
   - Detects manifests in `k8s/`, `kubernetes/`, `deploy/`, `manifests/`, `helm/`, `charts/`, `.k8s/`, `kube/`.
   - Three checks: resource limits, `runAsNonRoot`/`privileged`, liveness+readiness probes.
   - Returns empty list when no workload manifests (kind: Deployment/Pod/StatefulSet/DaemonSet/Job/CronJob) found — not applicable.
   - Uses string/regex matching instead of a YAML parser to avoid adding a dependency.

4. **Observability** — `check_observability(get_content_fn)`.
   - Scans `requirements.txt`, `pyproject.toml`, `package.json`, `go.mod`, `Cargo.toml` for known monitoring libraries (sentry-sdk, prometheus-client, datadog, opentelemetry, structlog, etc.).
   - Severity `info` — advisory only, does not lower score dramatically.

**Why separate module instead of adding to checks.py directly:**
- `checks.py` and `checks_gitlab.py` are already 440 lines each. The extra checks need distinct callsites (GitHub gets Actions checks, GitLab doesn't). A separate module keeps both files from growing unwieldy and makes the extra checks independently testable.

**Logging:**
- Added `logging.getLogger(__name__)` to `checks.py`, `checks_gitlab.py`, `checks_extra.py`, `tasks.py`, `ai_providers.py`.
- Log levels: `info` for normal flow milestones (check count, provider selected), `warning` for degraded paths (API timeout, OSV non-200), `error` for unexpected exceptions.
- API keys and tokens are never logged — only provider names and HTTP status codes.

**Consequences:**
- Audit time increases by up to ~3s for repos with dependency files (one OSV.dev batch call per ecosystem, 20s timeout each). Celery task already has no hard timeout.
- Check count grows from 27 to up to 35 depending on repo contents (CVE: 1, Actions: 1–3, K8s: 0 or 3, Observability: 1).
- Score denominator grows, so existing Pro repos may see a slight score change on next re-audit.
- The "27 checks" copy anywhere in marketing is now stale (same issue as previous ADR re: 22→27).

---

## 2026-06-26 — One-click Fix feature

**Context:**
After adding intelligence checks (CVE, Actions, K8s), the audit report still only told users *what* was wrong without giving them a ready-made fix. Users had to Google how to create a `dependabot.yml` or a `SECURITY.md` from scratch. This was the top product priority discussed.

**Decision:**
Add a "One-click Fix" endpoint that returns a ready-to-use file for each fixable failed check.

- `app/fix_templates.py` — 17 static templates covering Dependabot, Renovate, CODEOWNERS, SECURITY.md, CONTRIBUTING.md, LICENSE, CHANGELOG, PR template, `.env.example`, `.dockerignore`, Dockerfile non-root, CI workflow, GitHub Actions SHA pinning script, K8s limits/probes/non-root patches. Each template function receives `(ecosystem, repo_name)` and returns `(filename, content)`.
- `detect_ecosystem(checks)` — infers Python/Node/Go/Rust from which dependency checks are in the audit (no extra API call).
- Endpoint: `GET /audit/<id>/fix/<check_id>/` → JSON `{ok, filename, content, language, is_ai}`.
- Free users: static template. Pro users: AI-customized version (calls `_generate_ai_fix` which prompts the AI with repo name, ecosystem, check description, and the base template).
- UI: "Get Fix" / "✨ AI Fix" button on each failed check card in `audit_detail.html`. Opens a modal with code block, Copy and Download buttons.
- `app/templatetags/app_extras.py` extended with `is_fixable` filter.
- `_guess_language(filename)` maps extension to highlight language for the code block.

**Consequences:**
- 10 new tests (6 view + 4 unit). Total test count: 91.
- Pro AI fix calls the same AI provider stack as the audit summary — no new provider setup needed.
- Templates are static strings in Python — no separate template files, no migrations.

---

## 2026-06-26 — Fix GitLab PAT connection: remove broken OAuth path, add scope validation

**Context:**
Two bugs were found in the GitLab integration:
1. The "Подключить →" button in `gitlab_dashboard.html` redirected to `/accounts/gitlab/login/` (allauth OAuth). No `SocialApp` record exists in DB → allauth threw "does not exist". The error looked like a server crash to the user.
2. `_connect_gitlab_pat` only validated the token against `/api/v4/user` (needs `read_user`), but `/api/v4/projects` requires `read_api`. A token with only `read_user` passed validation but then produced a silent 403 → empty project list with no explanation.

**Decision:**
- `gitlab_dashboard.html`: removed `connectSelfHosted()` JS function and the `{% block scripts %}` block entirely. Converted the self-hosted bar into a proper `<form method="POST" action="connect_token">` with URL + PAT token fields — exactly the same flow as the profile connect page.
- `_connect_gitlab_pat`: after validating `/api/v4/user`, now also tests `/api/v4/projects?per_page=1&membership=true`. If 403, returns error "Токен не имеет нужных прав. Добавьте scope: read_api" — prevents saving an unusable token.
- `gitlab_dashboard` view: now handles 403 (scope error), non-200 responses, and timeouts with explicit `projects_error` message passed to the template. Template shows a red banner with "Переподключить →" link.

**Consequences:**
- OAuth GitLab login (`/accounts/gitlab/login/`) is still in allauth URLs but no longer reachable from any UI element (it was only wired to the broken JS function). Can be removed entirely in a future cleanup.
- Tokens with insufficient scope are rejected at connection time instead of silently failing later.

---

## 2026-06-26 — Replace NowPayments with Cryptomus for crypto checkout

**Context:**
NowPayments was used as the crypto payment provider. It required maintaining four separate env vars (two API keys + two IPN secrets for test/live), used two different API hostnames for sandbox vs production, and signed webhooks with HMAC-SHA512 over a sorted JSON body sent in a header.

**Decision:**
Switch to Cryptomus. Single API endpoint (`api.cryptomus.com`), test vs live is handled by using a separate merchant account rather than a separate host. Two env vars instead of four (`CRYPTOMUS_MERCHANT_ID`, `CRYPTOMUS_API_KEY`). Webhook signature is MD5 of `base64(body with sign=null) + api_key`, delivered as the `sign` field inside the JSON body (not a header).

**Consequences:**
- `create_crypto_checkout` now sends `amount` as a string (Cryptomus requirement; NowPayments required an int).
- Webhook handler renamed `nowpayments_webhook` → `cryptomus_webhook`; successful statuses changed from `finished`/`confirmed` to `paid`/`paid_over`.
- Pro activation logic in `UserSubscription` unchanged — no migrations needed.
- `.env.example` and `config/settings.py` updated accordingly.

---

## 2026-07-12 — Fix `<nav>` CSS leak and invalid history JSON on audit detail page

**Context:**
User reported `/audit/<id>` looking visually broken. Two independent bugs were found:

1. `base.html`'s site header CSS used a bare tag selector: `nav { position:fixed; height:52px; display:flex; ... }`. Being unscoped, it matched *every* `<nav>` element on the page, not just the header — including `audit_detail.html`'s `.audit-sidebar` section-nav (Summary/AI/Categories/Issues/Passed/History links). That squashed the sidebar into a clipped 196×52px box showing only its first item.
2. `views.py:audit_detail` passed the audit-history list (containing `datetime` objects) into the template via `const historyData = {{ history|safe }};`. `|safe` only disables HTML-escaping — it does not JSON-encode. Django rendered Python's `repr()` of the list (single-quoted strings, `datetime.datetime(...)` literals), which is not valid JavaScript. Every audit with more than one completed run for the same repo (i.e. almost every real audit, since the query includes the current one) threw `ReferenceError: datetime is not defined` on page load, aborting the rest of the inline script — including the History modal's `let chartInst`, which was left in the temporal dead zone and crashed on click.

**Decision:**
- Scoped the header CSS to `.site-nav` (added the class to both the logged-in and logged-out `<nav>` markup in `base.html`) instead of the bare `nav` tag selector.
- `audit_detail` view now does `json.dumps(history, cls=DjangoJSONEncoder)` before passing `history` to the template, producing real JSON. Added a separate `history_count` context variable for the `{% if %}` gates that used to do `history|length` (that check breaks once `history` is a JSON string instead of a list).
- Added `test_audit_detail_history_is_valid_json` regression test.

**Consequences:**
- No other template currently pipes a Python value through `|safe` into a `<script>` block, but it's a footgun worth grepping for again if another data-into-JS pattern is added — `|safe` ≠ JSON-safe.
- Bare element-tag CSS selectors (`nav`, `button`, etc.) in `base.html` should be avoided going forward; scope to a class instead so new `<nav>`/`<button>` elements elsewhere don't inherit unrelated layout rules.

---

## 2026-07-12 — Backfill missing/fuzzy i18n translations

**Context:**
User asked to verify translations work correctly across the whole site. Auditing `locale/{en,ru}/LC_MESSAGES/django.po` found 139/388 English and 113/388 Russian entries with empty `msgstr`, plus ~30–35 entries per locale marked `fuzzy` (gettext auto-matched them to unrelated strings during a prior merge; `compilemessages` silently drops fuzzy entries, so they behaved as untranslated too). Net effect: Russian-language users were seeing raw English UI chrome across `audit_detail.html`, `connect.html` (profile/settings), and the `billing.html` FAQ — this predated the current session and had accumulated because templates were edited without re-running `makemessages`/`compilemessages`.

**Decision:**
Regenerated catalogs (`makemessages -l en -l ru --no-obsolete`) and backfilled every empty/fuzzy entry — ~108 real English→Russian translations, ~6 Russian→English translations, remainder identity-filled where the msgid already matched the target locale's language. Verified live in the browser (logged-in session) with `/i18n/setlang/` switching, confirming no raw-English leakage in the Russian version.

**Consequences:**
- No test asserts translation-catalog completeness — this can silently regress again. Recommended practice: run `makemessages -l en -l ru` and check `msgattrib --untranslated`/`--only-fuzzy` counts after any template text change, before considering it done.
- Also bumped the "22 checks" marketing copy to "35" (actual engine capability, per the 2026-06-22 and 2026-06-26 entries above) across `landing.html`, `billing.html`, and `base.html`'s meta description — `landing.html` is normally frozen per project rules, edited this time on the user's explicit in-session request, not a standing policy change.

---

## 2026-08-22 — Global launch: unify the engine, make audits append-only, and restructure pricing

**Context:**
A product review found six blockers to selling outside the region, one structural bug that
made retention impossible, and a pricing structure with no way to grow the average contract.
This ADR records the whole set, because the pieces depend on each other.

### 1. Audits are append-only

`start_audit_for_repo` used `get_or_create` on (user, repo, source) and then wiped the row.
Exactly one `Audit` existed per repository, forever — so `audit_history_json`, which filters
by the same repository, could only ever return one point. The score trend was structurally
impossible to draw.

**Decision:** every run creates a new `Audit` row. `Audit.objects.latest_per_repo()` gives
dashboards the newest run per repository; `previous_run()` and `score_delta` give the trend.
`run_audit` (re-run) returns the new audit id and the report page follows it. The free-plan
limit counts *distinct repositories*, so re-auditing never burns quota.

**Consequences:** the history chart works; audit rows grow with usage (indexed on
`(user, source, repo_full_name, -created_at)`); the webhook and API paths create rows the
same way. A retention policy per plan is the obvious follow-up.

### 2. One engine, one read path

`checks.py` and `checks_gitlab.py` were two 450-line near-copies that drifted whenever a
check was added to one and not the other. Both answered "does this file exist?" with one
HTTP request per candidate path — around 90 sequential calls per audit, each with a 10s
timeout, with `.gitignore` and `Dockerfile` fetched twice.

**Decision:** `app/repo_client.py` provides one read interface for both providers. It pulls
the repository as a single tarball (`/tarball/{ref}` on GitHub,
`/repository/archive.tar.gz` on GitLab) and holds the text files in memory, so existence is
a set lookup and content is a dict lookup. `checks.py` is now provider-agnostic and
`checks_gitlab.py` is a nine-line adapter.

**Measured** on gitlab-org/gitlab-ui (1774 files): 23 API calls and 14.0s before the change
in this direction, **3 API calls and 2.7s** after. That difference is what makes the free
public scanner possible at all — unauthenticated GitHub allows 60 requests per hour per IP,
which the old engine spent on a single audit.

Fallbacks are automatic: an archive over 40 MB, or a failed request, drops back to per-file
reads with `prefetch()` issuing eight at a time. Binary and oversized members still
contribute their *path* to the index, so `bun.lockb` is detected without being read.
`StaticRepoClient` backs the tests with a plain dict.

### 3. check_id, not the display name

Names are now English source strings translated per audit, so keying anything off a name
would break the moment a user switched language. Every check carries a stable `check_id`
(`security.no_secrets`, `iac.open_ingress`). Fix templates, built-in AI suggestions and
compliance mapping all look up by it; `_LEGACY_NAME_TO_ID` tables keep pre-`check_id` rows
working.

### 4. New checks that are worth paying for

The engine was ~25 "does this file exist" checks — which OpenSSF Scorecard does for free.
Added:

- **`checks_secrets.py`** — the old scanner matched one regex against twenty hardcoded
  paths. It now walks the whole tree with provider-specific patterns (AWS, GitHub, GitLab,
  Stripe, OpenAI, Anthropic, SendGrid, npm, private key blocks, database URLs) plus one
  generic rule gated on Shannon entropy and a placeholder filter, so `your-password-here`
  and `os.environ[...]` do not fire. A `.env` under `examples/` or `tests/` is sample
  material, not a leak, and is not counted.
- **`checks_iac.py`** — Terraform: state without locking, ingress from 0.0.0.0/0 on
  sensitive ports, unencrypted RDS/EBS/S3, publicly accessible databases, public bucket
  ACLs, hardcoded provider credentials, unconstrained provider versions, no IaC scanner in
  CI. Returns nothing when a repository has no Terraform.
- `ci.security_scan`, `docs.readme_quality` — practice checks rather than presence checks.

**False positives fixed:** the `.env` rules now only apply to projects that actually use a
`.env` file (evidence: a committed one, a `.env.example`, or a dotenv dependency).
Changelog, contributing, licence and readme tables gained `.rst` and other real-world names
— reStructuredText projects were being failed for files they do have.

### 5. Encryption at rest

The billing page told users "tokens are stored in an encrypted database" while
`access_token` was a plain `CharField`. Now `crypto_utils.EncryptedTextField` (Fernet)
covers both provider tokens and user AI keys, keyed from `TOKEN_ENCRYPTION_KEY` and falling
back to an HKDF derivation from `SECRET_KEY` with a logged warning. Ciphertext carries an
`enc:v1:` prefix; anything without it is read as legacy plaintext, and
`manage.py encrypt_tokens` rewrites those rows. The billing copy now describes what the code
actually does.

### 6. Pricing: four plans, annual billing, real free quotas

One $29 plan gave no way to grow the contract value, and the free tier locked AI entirely —
so nobody ever saw the thing they were being asked to pay for.

- Free: unlimited public scans, 3 private repos, **1 AI report and 1 PDF per month**
- Pro $19 — the individual engineer
- Team $99 per organisation, **seats included** — org dashboard, PR comments
- Compliance $299 — SOC 2 / ISO 27001 evidence, SBOM

Annual billing at −20% turns month-thirty-one revenue into month-one cash. Crypto payments
are one-off, so `send_expiry_reminders` (Celery beat, daily) warns three days out; without
it access simply stopped and every crypto customer churned by default.

### 7. Growth surfaces

- **`/scan/<owner>/<repo>/`** — audit any public repository with no account. Demo, viral
  hook and SEO surface in one: every scanned repository becomes an indexable page, listed in
  the sitemap. Rate-limited to ten new repositories per hour per IP; results cached for a
  week and refreshed by a nightly job.
- **Social cards** — `og_image.py` renders a 1200×630 PNG with the score and category bars,
  served at `/og/scan/<owner>/<repo>.png`. A shared report now unfurls as a result rather
  than a bare URL.
- **Landing SEO** — `landing.html` does not extend `base.html` and had no description, no
  canonical, no Open Graph at all. All added. The "never modify landing.html" rule was
  removed: a frozen landing page cannot be corrected or optimised.
- **Invented testimonials removed.** Three named endorsements with roles and cities, none of
  them real — an FTC Endorsement Guides problem in the US and a credibility problem
  everywhere. Replaced with live scans of real repositories.

### 8. Workflow integration

- **One-click fix → pull request** (`github_writer.py`): the 17 fix templates were
  copy-paste only. A button now creates a branch, commits the file and opens a PR, with a
  clear message when the token is read-only.
- **PR comments** (`post_pr_comment`): a `pull_request` webhook audits the PR and posts the
  score with the delta against the previous run. Team plan and above.
- **GitHub App** (`github_app.py`): one-click install replacing the PAT flow — organisation
  coverage, short-lived credentials, and the permission needed to comment. Falls back to
  PAT when unconfigured.
- **Organisation dashboard**: every repository ranked by score, with weekly trend. The
  screen a manager buys.

### 9. Accessibility and correctness

`--muted: #4a6070` on the app background is 3.09:1 — below the 4.5:1 WCAG AA threshold, and
it carried nearly all secondary text. Now `#8aa3b2` (6.5–7.7:1). `--dim` went from 1.39:1 to
`#748c9e`. Also: `TIME_ZONE` UTC instead of `Asia/Almaty`; "35 checks" corrected to "30+"
(the engine runs 28–35 depending on what a repository contains); the broken favicon data URI
in `base.html` that had swallowed a duplicate `<meta charset>` fixed.

### 10. No charting CDN

`audit_detail.html` loaded Chart.js from jsDelivr on a floating `@4` tag — an unpinned
third-party script, in a product whose own check tells users to pin their supply chain.
Sparklines are now server-rendered inline SVG (`charts.py`).

**Consequences overall:**
- Tests: 92 → 249, all passing.
- Russian catalogue kept at 100% (745 msgids, 0 untranslated).
- Dependencies: added `cryptography`, `PyJWT`, `Pillow`; removed `PyGithub`, which nothing
  imports now that the client talks to the REST API directly.
- Migrations 0009 and 0010.
- New env vars, all optional with sane fallbacks: `TOKEN_ENCRYPTION_KEY`, `GITHUB_APP_*`,
  `PUBLIC_SCAN_GITHUB_TOKEN`, `LS_VARIANT_*`.

---

## 2026-08-22 — Pre-launch review: severity ordering, public pricing, mobile, print

**Context:**
A full functional and visual pass over the running application before promoting
it. Authorisation, data isolation between users, CSRF and the scanner's edge
cases all held — no security holes. Eight functional defects and nine visual
ones did not.

### Severity ordering was reversed

`AuditCheck.Meta.ordering = ['passed', '-severity']` sorts a *text* column, so
reversed alphabetical order yields warn → ok → info → crit. Critical findings
were last everywhere: the audit email's "top three issues", the pull request
comment's top five, the PDF, and the report page.

Measured on live data: the email contained two warnings and one informational
note and **zero** critical findings, while the repository held a committed
secret and four vulnerable packages.

**Decision:** add `severity_rank`, a small denormalised integer column kept in
sync by `save()`, and order by it. A column rather than a `Case/When`
expression specifically so `Meta.ordering` covers callers that do not order
explicitly — the failure mode here was a caller trusting the default.
`bulk_create` bypasses `save()`, so `_apply_checks` sets it directly; migration
0012 backfills.

Note for future reference: the free public scan page was never affected because
it sorts through an explicit `{'crit': 0, 'warn': 1, 'info': 2}` mapping. The
bug lived only in the paid paths, which is the harder place to notice it.

### /pricing/ was behind the login wall

The route pointed at `billing_view`, which is `@login_required`, so every
visitor clicking "Pricing" met a sign-in form — while `robots.txt` explicitly
invited search engines to index that redirect.

**Decision:** a separate public `pricing_page` with its own template: four
plans, a monthly/annual toggle, a capability matrix, and the five questions
people ask before paying. `billing_view` keeps the checkout buttons for
signed-in users. Both build their cards from `_plan_rows()` so prices cannot
drift apart.

### The app had no mobile layout at all

`base.html`, the shell every signed-in page renders inside, contained **zero**
media queries: eleven controls in a fixed 52px row, a 1040px container, no
mobile menu. Seven other templates had none either.

**Decision:** collapse the bar into a labelled menu below 900px with 44px touch
targets, and give every page real breakpoints. The landing page went from one
breakpoint to three — it is the acquisition surface, and a large share of first
visits arrive from a link opened on a phone.

### Nothing had a focus state

`focus-visible` appeared in none of the seventeen templates — a WCAG 2.4.7
failure, and a question on every enterprise procurement form. Also: eight
`<div onclick>` controls unreachable by keyboard, no `aria-live` on regions that
swap during polling, and 24 animations against one `prefers-reduced-motion`.

**Decision:** one focus rule in the base stylesheet, a skip link, live regions
announced, pseudo-buttons converted to real `<button>`s, Escape closes modals
(a keyboard user cannot click a backdrop), and a global reduced-motion block.

### The PDF was a screenshot of a dark UI

Generated one and read it page by page. White sheets with near-black blocks,
the score wrapping mid-fraction into "/10" above a stray "0", the passed
section stranded across a three-quarter-empty page, no title block, no page
numbers, no controls.

**Decision:** rewrite `pdf_report.py` for paper — dark ink on white, colour
only for severity, a title block naming repository, commit, audit date and
scope, findings numbered and ordered by severity, a running header and page
numbers. Compliance subscribers get a control-coverage section; that section is
what makes the file evidence rather than a summary.

### The landing page showed a product that does not exist

The hero was an animated terminal session for a command-line tool the product
does not ship, with invented findings for an invented repository — and no image
of the actual interface anywhere on the page.

**Decision:** replace it with the real report rendered inline, populated from an
actual `PublicScan`: repository, score, category bars and the top findings,
linking to the full report. Better than a screenshot — it is responsive, crisp,
and cannot go stale. Falls back to an invitation when nothing has been scanned
yet. The stats band's "35 checks / 6 categories" was corrected to "30+ / 8".

### Smaller fixes

- `Audit.error_message` was written on every failure and never displayed. Now
  surfaced, and turned into a specific next step per failure kind.
- A public scan whose job never ran left a row queued forever and its page
  spinning for every visitor. Timed out on view and by a quarter-hourly job.
- No `Content-Security-Policy` or `Permissions-Policy`. Added via middleware
  rather than nginx so development matches production; badges and social cards
  opt out because they exist to be hot-linked.
- The shared public report still used the old standalone design with its own
  copy of the palette and no social card. Rebuilt on the shared layout.

**Consequences:** 271 tests, up from 249. Russian catalogue back to 100%.
Migrations 0011–0013. The functional sweep now reports zero findings.

## 2026-08-23 — Make the checkout reachable, and stop shipping two source languages

**Context:** Nobody could pay. Clicking "Pay by card" or "Pay with crypto" did
nothing at all — no error, no navigation, the billing page simply sat there.
A full pass over every page in both languages and both viewports, with a real
browser, turned up the reason and a good deal else besides.

### Four separate faults sat between a buyer and a payment page

**The Content-Security-Policy aborted the checkout.** `form-action 'self'`,
added with the other security headers, applies to the *whole redirect chain* in
Chrome. Both checkouts are a POST to our own URL that answers with a 302 to the
provider, so the browser killed the navigation with `ERR_ABORTED` and left the
buyer on the billing page. Every card and crypto payment had been impossible
since the header landed, and nothing logged it.

**Decision:** name the payment hosts in `form-action`. The directive is worth
keeping — it is what stops an injected form posting elsewhere — but it has to
list where our own checkouts legitimately go.

**An account with no email got a 422.** `checkout_data.email` was sent as
`request.user.email or ''`, and Lemon Squeezy rejects an empty string. Email is
optional at registration; three of the four accounts in the local database had
none. Those users could never pay by card.

**Decision:** omit the key when there is no address and let the checkout page
ask for one. Sending a placeholder or forcing email at registration both cost a
conversion that this does not.

**Every plan resolved to the variant that sells Pro.** No `LS_VARIANT_*` was
configured, so `LS_VARIANTS.get(...) or LEMONSQUEEZY_VARIANT_ID` handed the
single legacy variant to Team, to Compliance and to every annual period. A
Compliance buyer would have been charged the Pro monthly price and granted
Compliance by the webhook's `custom_data`.

**Decision:** the legacy variant answers for `(pro, monthly)` only — that is the
one thing it was created to sell. Anything else needs its own variant, and
without one the billing page offers to invoice instead of showing a button that
charges the wrong amount.

**Failures were logged nowhere.** Both checkout views ended in a bare
`except Exception` that set a message and swallowed the cause. Diagnosing the
422 meant adding logging first.

**Decision:** log the exception with the provider's response body. A checkout
that fails silently is a checkout nobody can fix.

### Advertised prices did not match the ones being charged

`manage.py check_payments --live` was added to ask the providers directly, and
it reports what no page ever said out loud:

- the store is in **test mode** — real cards are declined;
- the only variant is **$29.00/month** while every surface advertises $19;
- that variant's status is `pending`, not `published`;
- Cryptomus has no credentials at all, so the crypto button could only ever
  show an error;
- `PAYMENT_MODE` was `lemonsqueezy`, which is not one of the two values the
  code understands.

The last of those is corrected in `.env`. The rest live in the Lemon Squeezy
dashboard and are the operator's to fix; the command exists so they are visible
before a customer finds them. Dead buttons are gone: crypto is hidden unless
configured, plans without a variant offer `SUPPORT_EMAIL` instead, and the
pricing page no longer promises a crypto option that does not exist.

**Consequences:** the card checkout now reaches Lemon Squeezy and renders a
payment form. It still charges $29 for a $19 plan and still declines real cards
until the store leaves test mode — code cannot fix either.

### English is now genuinely the source language

The rule existed; nine templates and `views.py` had not followed it. 107 `trans`
tags and 18 `_()` calls carried Russian source text, translated *into* English
by `locale/en`. So the English pages depended on a catalogue, and a stale entry
there would silently rewrite them — `'Password'` → `'Passed'` was sitting in the
file, held back only by a fuzzy flag anyone could clear.

**Decision:** rewrite every Russian source string to its English translation,
move the Russian into `locale/ru` under the new key, and **empty
`locale/en` entirely** — 791 entries cleared. A translation of the source
language can only ever be wrong.

Separately, the Russian catalogue was not at 100% as claimed: a `makemessages`
run had left 111 entries fuzzy or empty, every one falling back to English for a
Russian reader, and the fuzzy matches were nonsense (`.gitignore configured` →
"Платежи не настроены."). All 111 were written by hand. Three tests now hold the
invariant: no Russian in source, Russian catalogue complete, English catalogue
empty.

### The sparkline was blank in Russian

`viewBox="0 0 {{ spark.width }} {{ spark.height }}"` with float values renders
as `0 0 100,0 30,0` under a locale with a decimal comma, and the browser
discards the element. The organisation trend and the score history had no chart
for any Russian user.

**Decision:** `charts.py` emits geometry as pre-formatted text. Coordinates are
not numbers to be presented, and no template should be able to localise them.

### Layout and copy

- **Every report page scrolled sideways on a phone.** `.chk` / `.check-item` are
  grids whose `1fr` column defaults to `min-width: auto`, so one unbreakable
  token — a commit SHA inside a recommendation — set the column's minimum and
  pushed the document to 577px in a 390px viewport. `min-width: 0` on the grid
  children; the code block scrolls inside itself instead.
- **The landing's plan CTAs did not line up**: `.btn-plan` declared
  `margin-top: auto` and then overrode it with `margin-top: 20px` on the next
  line.
- **The landing said $19 and the pricing page said $15** — the same plan, two
  surfaces, because one defaults to monthly and the other to annual. The landing
  now shows both, and builds its cards from `_plan_rows()` so the numbers cannot
  drift apart again. A test asserts it.
- **The payment success page congratulated everyone on Pro**, whatever they
  bought, and sent them to `/dashboard/`, which bounces a fresh buyer straight
  back to `/profile/`. It now names the real plan and points at the step that
  actually comes next.
- **The profile sidebar showed `PRO` for a Compliance subscriber** — it read
  `is_pro`, which is true for any paid plan.
- Two invented statistics on the landing ("68% of teams…", "Average detection
  time: 197 days") were replaced with claims that are true and need no source.
- The Free plan card on `/billing/` had no call to action at all; standalone
  templates (sign-in, 403/404/429/500) had no favicon.

**Consequences:** 286 tests, up from 271. All 56 page renders — 14 pages × two
languages × desktop and mobile — come back with no HTTP error, no horizontal
overflow and no console error. The Russian catalogue is at 100% and a test keeps
it there.

## 2026-08-23 — Two findings that were wrong on well-run repositories

**Context:** Auditing `psf/requests` and `fastapi/fastapi` — two of the best-run
Python projects there are — to judge whether the engine's output is worth
paying for. `psf/requests` scored **44/100** with a critical finding.

**`security.no_secrets` reported "3 credentials committed"** for
`tests/certs/*/server.key`. Those are TLS fixtures the library's own test suite
needs. Every HTTP or TLS project on the platform would have tripped this, and a
false critical on the security check is the one finding a reader will not
forgive.

**Decision:** a private-key block under a test, example, docs or certs path is
reported as a fixture rather than a leak, and does not fail the check. Only
`private_key` is softened this way — a live API key in a test directory is
still a live API key. A key anywhere else is still critical.

**`ci.tests` reported "no tests in CI"** for a repository whose
`.github/workflows/run-tests.yml` runs eight Python versions across three
operating systems. The check searched workflow text for `pytest` and friends;
this project reaches pytest through a Makefile.

**Decision:** recognise the task runners that stand in front of the test
command (`make test`, `nox`, `tox`, `hatch test`, `just test`, …), and treat a
workflow that calls itself a test run as one — its steps are often a shell
script we cannot read. A workflow that only publishes still fails the check.

**Consequences:** `psf/requests` 44 → 88, `fastapi/fastapi` 41 → 79. 291 tests,
up from 286. Five of them pin these two behaviours, including the cases that
must still fail.

**Still open — the score does not know what kind of repository it is reading.**
`psf/requests` is marked down for having no Dockerfile, no `.dockerignore` and
no non-root container user. It is a library; it will never have any of them.
Three of its five remaining findings are unreachable by design, and the same
will be true of every library on the platform. Fixing it means detecting the
repository type and scoring against the checks that apply — which changes the
number on every audit ever run, so it is a decision to take deliberately rather
than a patch to slip in.

## 2026-08-23 — The score grades a repository on what it could have done

**Context:** `psf/requests` was marked down for shipping no Dockerfile, no
`.dockerignore` and no non-root container user. It is a library; it will never
have any of them. Three of its five remaining findings were unreachable by
design, and the same held for every library on the platform.

This is a commercial problem before it is a technical one. The score is the
product: it goes in a README badge, in a pull request comment and in front of an
auditor. A number that penalises a repository for not being a different kind of
repository is a number nobody will publish, and an unpublished badge is a
funnel that does not run.

**Decision:** `app/repo_kind.py` classifies a repository and names the checks it
cannot act on.

- **library** — packaging metadata that declares something published, and no
  deployment artefact anywhere (Dockerfile, compose, k8s, Procfile, Helm, a
  platform config). Loses the Docker family and `ops.observability`.
- **infrastructure** — Terraform or equivalent with no meaningful application
  source. Also loses the dependency checks; there is no manifest to read.
- **service** — everything else, and the default. When the evidence is thin
  every check applies: nothing is quietly forgiven.

A library that also ships a Dockerfile is a service. The Docker checks have
something to read, so they are asked.

Set-aside checks are **kept in the report** under "does not apply here", with
the reason. A check that simply vanished would read as one that was quietly
failed, and a reader who disagrees with the classification needs to see what was
put aside. They are excluded from the score, from the category scores, from the
action plan and from the compliance report — counting a library's missing
container hardening as a SOC 2 gap would put a finding in front of an auditor
that nobody can ever close.

### The same defect, in the other direction

Auditing the change turned up its mirror image: `docker.healthcheck`,
`docker.pinned_base`, `docker.multistage` and `docker.resource_limits` were
recorded as **passes** when there was no Dockerfile or compose file to read.
Sixty warn-weight points for shipping no container at all — enough to put a
repository with no Docker above one with a mediocre Dockerfile.

**Decision:** a check with no input is not applicable, not a pass. A service with
no Dockerfile now fails `docker.dockerfile` and `docker.dockerignore` and is
scored on the rest, instead of being paid for the four it never ran.

**Consequences:** `psf/requests` 88 → **96**, one actionable finding instead of
five. `fastapi/fastapi` 79 → 84. A service with a Dockerfile now scores above an
otherwise identical repository with none, which was not previously true.
Migrations 0014–0015 add `Audit.repo_kind`, `PublicScan.repo_kind`,
`AuditCheck.applicable` and `AuditCheck.not_applicable_reason`; existing rows
default to applicable, so historical audits keep the score they were given.
303 tests, up from 291.

One pre-existing test asserted the old behaviour — `docker.healthcheck` passing
with no compose file — and was rewritten to state the intent it had always
carried in its name.

## 2026-08-23 — Give the repository a say, and answer the reviewer's question

**Context:** Market research on what engineers actually complain about in this
category, to decide what to build rather than guess.

Two findings dominate, and both are about trust rather than coverage:

1. **False positives are the reason tools get muted.** Untuned scanners report
   40–80% false positives; teams learn to tune out all findings, and the whole
   process breaks down. A scanner that cannot be argued with gets ignored
   wholesale.
2. **Nobody opens another dashboard.** Developers want the feedback inside the
   workflow — the pull request — and they want it about *their change*. A
   whole-repository score in a PR comment answers a question the reviewer did
   not ask.

There is a third, specific to this category. The direct free competitor,
OpenSSF Scorecard, is criticised for applying "a singular set of criteria
regardless of package function" and for grading GitHub features rather than
security properties. The repository-kind work earlier today already answers the
first half of that; this answers the rest.

### `.devopsaudit.yml` — the repository answers back

**Decision:** a repository can ship a config that the audit obeys.

```yaml
kind: library
fail_under: 70
ignore:
  - id: docker.nonroot
    reason: the base image already runs as nobody
severity:
  deps.lockfile: info
allow_secrets:
  - tests/fixtures/
```

Two invariants keep this from becoming a way to fake a score, which is the
obvious failure mode and the one that would destroy the Compliance tier:

- **An ignore needs a reason.** A bare id is refused and reported as a config
  error. An auditor, or the next engineer, has to be able to see why a check was
  set aside.
- **Nothing is hidden.** An ignored check stays in the report under "does not
  apply here", carrying the reason the repository gave — the same treatment as a
  check the engine set aside itself.

`security.no_secrets` and `security.env_not_committed` cannot be ignored at all.
A report that can switch off the secret scanner and still print a number is not
evidence of anything. `kind:` overrides detection, because a heuristic nobody
can correct is one people work around instead of using. A broken config never
breaks the audit: it runs, and the errors appear in the report and the PR
comment, because a config that silently does nothing is worse than none.

`fail_under` is what turns a report into something CI can block on. Most
repositories will set none, so `Audit.gate` returns `None` rather than inventing
a threshold and failing everyone.

### The pull request comment leads with what changed

**Decision:** `Audit.changed_findings()` compares failing `check_id`s against
`previous_run()` and returns what appeared and what was resolved. The comment
now opens with **"7 new since the last run"**, then the gate verdict, then the
new findings — with the standing total collapsed into a `<details>` block
underneath.

A check that stops applying counts as resolved, not as still-broken. Ignoring a
finding should read as a decision, not as a fix that never happened.

**Consequences:** 324 tests, up from 303. Migration 0016 adds
`Audit.fail_under` and `Audit.config_errors`. PyYAML is a new dependency —
parsing a user's config by regex is exactly the fragility this product tells
other people not to ship. All 56 page renders stay clean.

**Sources for the research above:** OX Security and Praetorian on false-positive
rates and alert fatigue; Snyk, Datadog and Endor Labs documentation on
pull-request-native feedback; Andrew Nesbitt's "The Mismeasure of Open Source"
on what Scorecard actually measures.

## 2026-08-23 — A connection that dies has to say so

**Context:** A connected GitLab account, and clicking through to the dashboard
did nothing — the page appeared to reload. The token had expired; GitLab was
answering 401 and `gitlab_dashboard` was redirecting to `/profile/` without a
word. From the profile page, that redirect is indistinguishable from a refresh.

The GitHub path was worse. A single 401 **deleted the connection**, taking the
`installation_id` with it and turning a token refresh into a full GitHub App
re-install.

Both are the same failure: the product stops working and says nothing. Every
audit for that account silently stops, the score history stops growing, and the
first thing the customer concludes is that the product is broken. That is a
cancellation, not a support ticket.

**Decision:** a `ProviderConnection` abstract base carries health on both
profile models — `token_status` (ok / expired / forbidden / unreachable),
`token_checked_at`, `token_broken_since`, `token_notified_at`.

- A 401 or 403 **records** the state; nothing is deleted. Reconnecting is one
  step rather than a re-setup, and the audit history stays attached.
- `token_broken_since` is set once per outage, not on every check — the outage
  started when it started.
- The profile page opens with what happened, which account, since when, and a
  button that goes straight to reconnecting.
- `check_provider_connections` runs daily and emails the owner **once per
  outage**. `token_notified_at` clears only when the connection recovers, so a
  fixed-then-broken-again account can alert again.
- Someone who turned email notifications off is left alone.

**Consequences:** 335 tests, up from 324. Migration 0017. Eleven of the new
tests cover this, including the two behaviours that were wrong: an expired
GitLab token is now recorded rather than swallowed, and a GitHub 401 no longer
deletes the connection.

This is retention work as much as correctness work. A tool that tells you it
stopped working is one you keep paying for; one that dies quietly is one you
cancel without ever filing a bug.

## 2026-08-23 — Red is for a committed secret, not for an expired token

**Context:** The connection notice shipped an hour earlier was a full red panel:
red border, red tint, red uppercase heading, red outlined button. It read as an
incident. An expired personal access token is routine maintenance.

**Decision:** amber, and quiet. The product already uses red for `crit` — a
committed credential, a security group open to the world. Spending the alarm
colour on upkeep is how people stop reading the alarm colour. The notice is now
a single line of plain language, one row per account, and a secondary button;
the panel is a left rule rather than a filled box.

### The page contradicted itself

Fixing the colour exposed something worse. Below the notice, the connected
account cards still wore a **green tick** — the same two accounts the notice
said had stopped working. And each offered "Open Dashboard", the link that had
appeared to do nothing in the first place.

**Decision:** one state, told the same way everywhere. A card for an account
that needs a token turns amber with the same icon as the notice, the dashboard
link is replaced by a line saying what to do, and the token field it points at
is **already open** — a hint that points at a collapsed form is not a fix.

**Consequences:** 337 tests, up from 335. Four of them hold the coherence:
a broken account does not wear a green tick, is not offered the dead link, and
a healthy one shows nothing at all.

Two of the new tests were initially written against page text and passed on the
wrong evidence — the stylesheet ships inline, so its comments satisfy a naive
substring search of the rendered HTML. They assert on markup now.

## 2026-08-23 — A check that fails a build, and a reconnect that lands somewhere useful

**Context:** `fail_under` existed in `.devopsaudit.yml` and showed in the
report, but nothing could act on it. A threshold nobody enforces is a number in
a file.

### The Action

**Decision:** `action/` ships a composite GitHub Action — `action.yml`,
`audit.sh`, `report.py`. Composite rather than Docker or JavaScript: a Docker
action costs an image build on every run, and a JS one means shipping
`node_modules` to the marketplace. `curl` and `python3` are on every runner, so
the step starts immediately.

The exit code is the whole point. A report that can only be read on a website is
a report people close; a check that fails a build is one the team has to talk
about before merging. It fails when an explicit `fail-under` is missed, when the
repository's own `fail_under` is missed, or with `fail-on-new: true` when this
run introduced a finding the last run did not have. With no threshold anywhere
it never fails — most repositories start there, and a gate set above the current
score on day one gets removed by Friday.

**It audits the commit under test.** `RepoClient` grew a `ref`, threaded from
`Audit.ref` and the API. Grading the default branch and calling it a check on a
pull request would report on code the change has not touched, which is how a
required check becomes one people learn to re-run until it passes.

Two supporting changes came out of thinking about what CI does:

- The "already running" 409 now only applies to the same `(repo, ref)`, and
  answers with the run already going instead of an error. Two branches of one
  repository is a normal Tuesday; failing the second job would fail a check for
  a reason its author cannot see.
- `api_audit_detail` returns `check_id`, `applicable`, `gate`, `fail_under`,
  `repo_kind`, `config_errors`, `score_delta`, `new_findings` and
  `resolved_findings` — everything a job needs to decide and to explain itself,
  in one request.

The snippet sits on the profile page directly beneath the API token, because
that is what most people want the token for.

### Reconnecting, on the right server

Fixing the connection notice exposed the rest of the path. **The reconnect form
defaulted the GitLab instance URL back to `https://gitlab.com`** — so a
self-hosted customer reconnecting would silently point the account at the wrong
server. The "create token" link had the same problem, and the two GitLab forms
on the page shared element ids, so `getElementById` always answered with the
first: typing a self-hosted URL into the second form updated the first one's
link and never revealed its own options.

**Decision:** `token_page_url` and `host` on both profile models, instance-aware.
The notice links each account straight to the server that issued its token. The
reconnect form comes back with the instance, the DNS and the SSL setting it
already had. The two forms no longer share ids, and the JavaScript scopes itself
to the form the input belongs to.

The self-hosted token path was also wrong — `/-/profile/personal_access_tokens`,
which modern GitLab has moved. One path now, `/-/user_settings/…`, on both.

"Reconnect" was an `#connect` anchor, and the tabs are switched in JavaScript,
so it landed on whichever tab happened to be open. It now switches the tab,
scrolls to the token field and focuses it. The first version of that focused
nothing: `input[name$="token"]` also matches `csrfmiddlewaretoken`, which is
hidden.

**Consequences:** 356 tests, up from 348. Migration 0018 adds `Audit.ref`.
All 56 page renders stay clean.

## 2026-08-23 — Two payment buttons, on every plan, on both periods

**Context:** Monthly could be bought and annual said "talk to us". A plan you
cannot click reads as a plan that is not for sale.

**First, what was measured.** Lemon Squeezy's `custom_price` looked like it
would let one variant sell all six prices. It does not: the checkout shows the
custom amount as the **first** charge and keeps the variant's own recurring
line underneath.

```
custom_price 1900  →  "$19.00"   then  "$29.00 billed every month"
custom_price 18200 →  "$182.00"  then  "$29.00 billed every month"
```

An annual button would have taken $182 once and then $29 every month. Variants
cannot be created through the API either — `POST /v1/variants` answers 405. So
card genuinely needs six variants made by hand in the dashboard, and no amount
of code changes that.

**The useful half of the same measurement:** Cryptomus is a **one-off** charge
for the exact `PLAN_PRICES[plan][period]`. It needs no variants at all — crypto
sells every plan and every period the moment the two keys are set.

**Decision:** both buttons on every card, in the same weight, both posting to a
real checkout. When a provider cannot take that combination it says so on the
way back. One behaviour to understand rather than two, and no button that looks
different because of a configuration the buyer cannot see.

An earlier version of this routed the un-sellable combinations through an
invoice request — a model, a form and a modal. It was removed the same day:
the product sells by card and crypto, and a third path is a branch to maintain
for a customer who was never asked for.

### The visual pass

Every page, both languages, desktop and mobile — 68 renders. No HTTP error, no
horizontal overflow, no console error anywhere.

What it did turn up was **touch targets**. The copy button on a code block was
12px tall; the section toggles 22–23px. Both are under the 24px floor, and far
under the 44px this product committed to when it grew a mobile layout. Fixed
across ten templates under `@media (pointer: coarse)`.

Links that sit inside a sentence — "No account? *Sign up for free*", a
breadcrumb tail, a hint pointing at a token page — are deliberately left alone.
WCAG 2.5.8 exempts them, and padding them out breaks the line they belong to.

**Consequences:** 361 tests. Migrations 0019 and 0020 add and then drop the
invoice model, which is the honest record of a thing tried and taken out.

---

## 2026-08-24 — A pass over every page with a browser, and what it found

**Context:**
Every page had been checked for defects before, but never *looked at* end to
end with the funnel in mind. A scripted sweep drove Chrome over 21 pages × two
viewports × two languages × signed-in and anonymous — 168 renders — recording
HTTP status, console errors, horizontal overflow and the controls present, then
resolved every in-app link and clicked through the interactive ones.

The interesting findings were not layout. They were places where the product
told the reader something untrue, hid the thing it was selling, or offered to
charge a card that was already being charged.

**Decision:**

*Money*

- **The current plan is no longer for sale.** `billing_view` now marks a plan
  `renews` when the subscription is recurring (a Lemon Squeezy id, not
  cancelled) and `extendable` when it is a one-off. A recurring plan shows its
  renewal date and a cancel link instead of two pay buttons — pressing "Pay
  $2870 by card" on the plan you already subscribe to opened a second
  subscription and charged again. A Cryptomus one-off can still be extended,
  and says "Extend" rather than "Pay".
- **The showcase on the landing page can no longer prove nothing.** It drew
  three pinned repositories and rendered "No score yet" for any without a
  finished scan; two of three cards were empty. It now fills every slot from
  the scans that exist, most-viewed first, and `refresh_stale_public_scans`
  keeps the pinned repositories scanned instead of waiting for a visitor to
  happen upon them.
- **The compliance report leads with the gaps and the export.** Controls were
  ordered by id, so the two gaps sat below five satisfied controls, and the
  evidence export — the artefact the plan is bought for — was below all of
  them. Gaps first on the page; the export keeps canonical id order.
- **The free scanner and the shared report fold what passed.** 23 green rows
  and 8 not-applicable rows were four fifths of the page, pushing the single
  finding and the sign-up out of view. Folded, the scanner page went 3019px →
  1140px with the counts still visible on the summary.
- **Onboarding offers the thing its own lede promises.** The copy said a public
  repository could be scanned right now with nothing connected; the only
  actions were "connect a token" and "skip".

*Counting*

- **A check the engine set aside is neither a finding nor a pass.** The report
  page and the score already knew this. The organisation dashboard, the
  notification email, both Open Graph cards, the landing showcase and the AI
  prompt did not — so one audit reported a different number of problems
  depending on where it was read, and the AI wrote advice about a Dockerfile a
  library was never going to have. All of them filter on `applicable` now.
- **"Needs attention" was `min(5, repo_count)`** — `sorted(rows)[:5]` rendered
  as a count. It is the number of repositories under 60 now.

*Broken*

- **`connect.html` threw on load.** `const GITLAB_TOKEN_PATH` was declared
  below its first use, so the initialiser hit the temporal dead zone and every
  statement after it was dead: the GitLab token link was never built and the
  error-state sections never opened. Declaration moved above the call.
- **Sign out did not sign you out.** The profile page linked to allauth's
  `account_logout`, which answers a GET with an unstyled confirmation page
  carrying allauth's own menu and leaves the session signed in until that page
  is posted. Both controls use the product's `logout` now, and the nav's
  `<button>` nested inside an `<a>` — invalid, two tab stops for one control —
  is a styled anchor.
- **Recommendations were cut off mid-sentence.** `white-space: pre` on the
  recommendation block hid everything past the right edge behind a scrollbar
  with no affordance, on the report, the shared report and the free scanner.
  `pre-wrap` keeps the newlines in the multi-line snippets and wraps the prose.
- **Every copy button failed silently.** Six call sites used
  `navigator.clipboard.writeText(...).then(feedback)` with no `.catch()`. When
  the write was refused the promise rejected unhandled, nothing was copied and
  the confirmation never ran — including on the API token. One `window.copyText`
  helper in `base.html` falls back to `execCommand` and resolves either way.
- **The error pages spoke only English**, `lang="en"` hardcoded, in a product
  that keeps its Russian catalogue at 100%. The 429 page is what a rate-limited
  anonymous visitor sees.
- **`makemessages` fuzzy-matched thirteen new strings onto unrelated
  translations** — the GitLab button was given "Войти через GitHub", and a
  `%(n)s` string was given a translation carrying `%(since)s`. Django ignores
  fuzzy entries, so nothing shipped wrong, but the catalogue was not the 100%
  it reported. All written by hand; 0 fuzzy, 0 untranslated.

*Self-inflicted, and guarded*

- Three of the comments written during this pass used `{# … #}` across several
  lines. Django's hash comment is single-line: written that way it is not a
  comment, the text renders, and the `<button>` inside one of them became a
  real element in the site header. `TemplatesDoNotLeakTheirOwnSyntaxTest` now
  renders fourteen pages and asserts no template syntax reaches the body, and
  greps the template sources for multi-line hash comments. The guard was
  verified by reintroducing the bug and watching it fail.

**Consequences:**
- 378 tests pass, up from 361. The new ones cover the double-charge guard, the
  applicable-only counts, the dashboard surviving a dead token, the showcase,
  the translated error pages, sign-out, and the template-syntax guard.
- Scores do not move: nothing here changes `calculate_score`. What changes is
  how many problems a surface *reports*, which now agrees everywhere.
- The sweep and link-audit scripts live in the session scratchpad, not the
  repository. A page-level visual check is still a manual act.
- Still outstanding and not code: the Lemon Squeezy store is in test mode with
  one $29 variant, and Cryptomus has no credentials. Email remains optional at
  registration, which means the expiry reminder — the only thing standing
  between a one-off crypto customer and silent lapse — has nowhere to go for
  those accounts. That is a conversion trade-off worth a deliberate decision.

---

## 2026-08-24 — The corpus, and turning a scanner into a reference

**Context:**
A target was set: roughly a thousand users in about two months. That deadline
rules out SEO as the primary channel — indexing and ranking take three to six —
so the question became what the product can produce *now* that is worth
linking to.

The free scanner had six repositories in it. Every one is an indexable page and
the sitemap already holds five thousand, but nothing was filling them. And a
score of 76 on its own says nothing: without a distribution behind it, the
number is arbitrary, which is exactly why it is not shareable.

**Decision:**

- **Discovery is separated from scanning.** `seed_public_scans` walks GitHub's
  search endpoint in descending star bands (the endpoint caps any one query at
  1000 results) and only *records* what it finds, with `queued_at` unset.
  `scan_pending_public_repos` drains that backlog on the hour at
  `PUBLIC_SCAN_BATCH` a run. An audit costs three API calls against a budget of
  5000 an hour, so queueing everything on discovery would burn the hour in a
  minute and leave nothing for the visitors who came to scan something
  themselves — they are the point; the corpus is the by-product.
- **`PublicScan.queued_at` distinguishes waiting from dying.** Without it
  `expire_stuck_public_scans` would have closed the entire seeded backlog as
  failed fifteen minutes after it was recorded. A row that was genuinely handed
  to a worker and never came back is still closed out.
- **`app/rankings.py` is what the corpus knows about itself** — score histogram,
  percentile, per-language leaderboards, and how often each check fails. All
  cached for fifteen minutes and computed with grouped queries, because it is
  read on the busiest page in the product. Keyed on `check_id`, never on the
  display name.
- **Nothing is claimed from too little.** `standing()` returns None below
  `MIN_SAMPLE` (40) and falls back from a thin language to the whole corpus
  rather than inventing a per-language ranking from three repositories.
  Listing a language leaderboard asks less of the data than claiming a
  percentile does, so it has its own lower threshold (`MIN_LANGUAGE`, 25).
- **`/rankings/` and `/rankings/<language>/`** publish the distribution, the
  leaderboards, and the check-prevalence table. In `robots.txt` and the
  sitemap, one page per language the corpus can rank. An unknown slug redirects
  to the index rather than dead-ending in a 404.
- **Every scan page now shows where the repository stands** — "Better than 98%
  of the 50 Python repositories scanned", linked to the ranking it came from.
  That line is the shareable unit; the bare score never was.

**Consequences:**
- 394 tests pass, up from 378. The new ones cover the percentile thresholds and
  the tie case, prevalence counting only applicable checks, the page's
  below-threshold state, the backlog surviving the stuck-scan sweep, and the
  drain claiming a row so a second tick cannot double-queue it.
- **This does nothing until `PUBLIC_SCAN_GITHUB_TOKEN` is set.** Unauthenticated
  search allows ten requests a minute; the seeder says so and keeps going, but
  a real corpus needs the token. With it, roughly 1600 repositories an hour.
- The check-prevalence table is the launch artefact: "one in three of the
  most-starred repositories has no lockfile" is a finding, and a finding travels
  where a tool does not.
- "Most room to improve" names real repositories with low scores on a public
  page. It is factual, reproducible and framed constructively, and the same
  thing OpenSSF Scorecard does — but it puts the engine's accuracy in public,
  so a false finding now costs more than it did.

---

## 2026-08-25 — A repository quota you can spend down, and an admin that can be trusted with tokens

**Context:**
Two things had been asked for and not started.

The first was reported as "the connected-repository counter does not go down".
The free plan allows `FREE_REPO_LIMIT` (3) private repositories, and the count
was derived from append-only `Audit` rows: *distinct repositories ever audited*.
It could only grow. A free user who tried three repositories in their first
week and abandoned them was locked out of the product permanently, with no
control anywhere in the interface to change that — there was no way to remove a
repository at all. That is not a quota, it is a one-way door.

The second was a Django admin. `/admin/` was routed and `app/admin.py` did not
exist, so granting a plan, inspecting a run or re-queuing a public scan needed a
shell on the container.

**Decision:**

*Releasable slots.* `Audit.archived_at` marks a repository the user has taken
off their list. Removal is expressed on **every run** of that repository at once,
never on a single run, and nothing is deleted:

- `AuditQuerySet.active()` / `.archived()` / `.tracked_repo_count()` are the one
  place the rule lives. `latest_per_repo()` filters archived rows itself rather
  than leaving it to each call site — there are more dashboards than there are
  places to remember.
- `Audit.archive_repo()` / `.restore_repo()` / `.removed_repos()` are the
  operations. `views._tracked_repo_count()` is what every "x of 3" surface reads,
  so the dashboard, the profile page and the billing page cannot disagree.
- `POST /repo/remove/` and `POST /repo/restore/`, both login-required and scoped
  to `request.user`. Restoring re-checks the quota: removing three and restoring
  three would otherwise be a free upgrade to unlimited.
- Re-auditing a removed repository restores it rather than starting a second
  history beside the first. Two disjoint histories for one repository is exactly
  the bug append-only rows exist to prevent.

*The dead-token gap, found by looking at the page.* The dashboard lists
repositories from the live GitHub API. A repository that is audited but no
longer in that list — dead token, or renamed, transferred or deleted on GitHub —
appeared only in a fallback shown when the *whole* list failed to load, and that
fallback was one big anchor with no controls in it. So the slot could be held by
something the customer could not see and therefore could not release. The
dashboard now computes those orphans explicitly and gives each one a remove
control.

*Per-provider quota display.* The quota is enforced per provider, but the
billing page summed both against the same limit, so three GitHub and three
GitLab repositories read as "6 / 3". Each provider now gets its own row. Whether
the limit *should* be per provider or total is a pricing question, not an
engineering one — it is in `BACKLOG.md` for the operator, and nothing about who
can do what was changed here.

*The billing usage meter had never rendered.* Its markup referenced
`.usage-bar`, `.usage-bar-wrap`, `.usage-label` and `.usage-fill`; none of the
four was declared anywhere in the project. The section had always been a bare
line of text — the number was there, the meaning was not. Found by screenshotting
the page, not by reading a status code.

*The admin.* `app/admin.py` registers every model, under two rules:

- **Nothing may leak a token.** `GithubProfile.access_token`,
  `GitlabProfile.access_token` and `UserAISettings.api_key` are Fernet-encrypted
  at rest, and a `ModelAdmin` that includes the field decrypts it straight onto
  the change page — which would make the admin the easiest place in the system
  to read a customer's credentials. They are excluded from every form and shown
  as "set / not set". `UserProfile.webhook_secret` and `api_token` authenticate
  requests and are treated the same way. Four tests assert the literal secret
  does not appear on the changelist or the change page.
- **Audits stay append-only.** `AuditAdmin` has no add and no delete, and every
  field is read-only: a score edited by hand would be indistinguishable from one
  the engine produced. What it *can* do is remove and restore a repository.

Plans are granted by action (Pro/Team/Compliance, monthly or annual), which also
clears `stripe_subscription_id` — `cancel_subscription` calls the Lemon Squeezy
API on an `ls_` prefix, and a hand-granted plan has no subscription there to
cancel. `expire_in_two_days` puts an account in the state
`send_expiry_reminders` is meant to pick up. `UserAdmin` carries the
subscription and profile as inlines, because the plan is an attribute of the
account and belonged on the account's page.

`Audit.STATUS_CHOICES` labels were hardcoded Russian strings. Nothing but the
admin reads them — customer-facing status text comes from the templates — so an
English admin was printing Russian at itself. They are English now, like every
other source string.

**Consequences:**
- 421 tests pass, up from 394. The new ones cover removal freeing a slot,
  removal keeping every run and its score, a removed repository leaving every
  dashboard while its report stays readable by link, restore being refused past
  a full quota, cross-user isolation, re-audit restoring rather than splitting,
  the per-provider quota rows, and the four credential-leak assertions.
- Migrations `0022` (`archived_at` + a `(user, source, archived_at)` index) and
  `0023` (the status labels).
- The Russian catalogue is at 100% — 895 translated, zero fuzzy.
- `.repo-actions`, `.btn-remove`, the removed-repositories strip and the
  confirmation dialog live in `base.html` with the markup in
  `app/templates/app/_repo_removal.html`, shared by both dashboards. The
  confirmation is the app's own dialog, not `window.confirm()`, which blocks the
  page and cannot be translated. Escape closes it, handled once in `base.html`.
- **Free-plan behaviour is now strictly more generous, never less.** Nobody
  loses access; a user who was permanently stuck gets a way out.

---

## 2026-08-25 — The admin leaves the public domain; the scanner starts keeping people

**Context:**

Two separate problems, one session.

*The admin.* It was routed at `/admin/` on the customer-facing domain. An admin
login form reachable from the internet is the highest-value target this product
has: one session behind it reads every customer's account and the audit data for
every repository they connected. The request was to "put it on another port
because it feels like they depend on each other".

*The scanner.* `/scan/<owner>/<repo>/` is the top of the funnel, the SEO surface
and the emotional peak of the product — the moment a visitor reads "44/100, two
critical". There was nothing to do with that moment. No email capture anywhere
public, and a single call to action that assumed the reader had private
repositories they cared about. A launch spike with nothing to keep it is a spike
that leaves, and the target is revenue in two months.

**Decision:**

*Separate the exposure, not the code.* The admin cannot be decoupled from the
application in the way it first looks like it should be — it works on the same
models and the same database, and that is what an admin is. What can be
separated is which URL space it lives in:

- `ADMIN_SITE=1` → `ROOT_URLCONF = 'config.urls_admin'`, which serves `/admin/`
  and nothing else. No landing page, no signup, no OAuth callback, no webhook.
- `config/urls.py` no longer routes `/admin/` at all, so the public domain
  returns 404 for it. Nginx returns 404 for it too, before Gunicorn is woken.
- Its own container on 8001, bound to loopback in production and reached over an
  SSH tunnel. WhiteNoise serves its static files inside that process, so it does
  not depend on the public site's Nginx `/static/` block.
- A root route on the admin port, because without one Django serves its "install
  worked successfully" placeholder whenever DEBUG is on — the framework version,
  to anyone who asks.
- The production `web` service published 8000 on `0.0.0.0`, putting Gunicorn on
  the internet beside Nginx where a request to `http://<ip>:8000` skipped TLS,
  the auth rate limit and every security header. Loopback now.

*`RepoWatch`: an address, one report, mail when the score moves.* Deliberately
not an account — no password, no profile, no consent to anything but mail about
one repository.

- **Double opt-in.** Sending one report to an address a visitor typed is
  ordinary; signing that address up for standing mail is not, and doing it
  without confirmation is how a product becomes a way to mail strangers. The
  first message carries the report *and* the confirm link; `confirmed_at` gates
  everything recurring.
- **One-click unsubscribe on every message**, no login and no confirmation step.
  The alternative to an easy unsubscribe is the spam button, which costs the
  sending domain far more than the subscriber was worth.
- **The form answers the same way for a new address, a pending one and one
  already watching.** Anything else turns it into a way to test whether somebody
  uses this product.
- **Rate limited per IP, and it fails closed** if the cache is unavailable — a
  scan still runs without the cache because scanning is cheap and public;
  sending mail on someone else's behalf is neither.
- **Changes are measured against `last_score` — what the reader was told — not
  against the previous scan.** A score that dips and recovers between two
  messages is not a change they ever saw, and mailing them about it would be
  mailing them about nothing.
- `refresh_watched_public_scans` at 04:00 and `notify_watched_score_changes` at
  05:00: refresh first, compare an hour later, so the scans have finished before
  anything is sent. A repository someone asked about is by definition worth
  re-reading on a shorter cycle than the weekly sweep.
- An old confirm link cannot resurrect a subscription the reader ended. Coming
  back through the form can, because that is the one place that proves it is
  them.

**Consequences:**
- 456 tests pass, up from 428. Russian at 100% (930 messages).
- Migration `0024` (`RepoWatch`).
- The email counts use labelled values — "Findings: 1 · Checks passed: 23" —
  rather than a sentence. "1 findings, 1 checks passed" was wrong in English and
  would have needed three plural forms in Russian to say something this simple.
- `.visually-hidden` added to `base.html`. The project had no such class, so the
  email field's label had nowhere to live that a screen reader would read and a
  sighted reader would not.
- **Admin tests must carry `@override_settings(ROOT_URLCONF='config.urls_admin')`.**
  `reverse('admin:...')` no longer resolves on the public urlconf.
- Known and unchanged: a Russian reader sees English check names on a public
  scan page and in these emails, because `PublicScan.results` is captured at
  scan time in English. The email is at least consistent with the page it links
  to. Recorded in `BACKLOG.md`.
- This captures nothing until there is traffic, and converts nothing until
  payments are live. It is the piece that has to exist *before* a launch push,
  not after — which is the only reason it was built ahead of the badge loop.

---

## 2026-08-25 — Close the badge loop, and stop hiding the most visible feature

**Context:**

The target is $1000 a month in about two months. Two things in the product were
working against that.

*The badge was a dead end.* `github_writer.py` has opened pull requests for
fixes since it was written, and the README badge was offered as markdown to copy
by hand. They were never connected. A badge in a README is a backlink, an
impression on every visitor to that repository, and an entry point for the next
reader — the loop shields.io, Codecov and Snyk all grew on — and copying
markdown by hand is a step most people do not take.

*The pull-request comment was priced out of sight.* It was gated on `is_team`
($99). It is the most visible surface the product has: every engineer on the
team reads it on every pull request. Behind the $99 tier, almost nobody ever
did.

**Decision:**

*One click, and the badge arrives as a pull request.* `open_badge_pull_request`
reads the README, inserts the badge, and opens a PR on a fresh branch. Nothing
is ever committed to the default branch.

- **`insert_badge` never stacks a duplicate.** A pull request that adds a second
  badge beside the first is worse than no pull request at all. An existing badge
  is rewritten where it stands, keeping the rest of its line intact — badges
  usually share a row. If the marker is present in a shape the rewrite cannot
  parse, the README is left alone and no PR opens.
- **Placement follows what the README already does**: onto the badge row under
  the title if there is one, otherwise on its own line under the title,
  otherwise at the top.
- **The markdown shown and the markdown committed are one string**
  (`views_public.badge_markdown`). Built in two places they drift, and the pull
  request starts adding a badge the page never showed.
- **The anonymous path is the signup.** A visitor without an account is sent to
  register and back. "We will open the pull request" is a far better reason to
  make an account than "track your score over time" — it is a finished job, not
  a promise of one.
- The writer's branch/commit/PR machinery is now shared with the fix pull
  request rather than duplicated, and the branch is cut from the repository's
  *own* default branch, not from `main`.

*The comment moves from Team to Pro.* Exposure on the cheapest paid plan is
worth more than the handful of upgrades the gate was buying. The organisation
dashboard, weekly trends and org-wide `fail_under` stay on Team. Three plan
tables and the billing feature matrix printed it under Team; all four were
moved, because a price page that contradicts the code is worse than either
version of the rule.

**Consequences:**
- 488 tests pass, up from 456. Russian at 100% (938 messages).
- The writer's HTTP sequence is now tested against a stubbed GitHub — the view
  tests mock the writer away, so the requests it actually sends were untested,
  and that is the part that breaks against the real API. Covered: the branch is
  cut from the repository's own default branch, the commit carries the existing
  blob SHA, the README keeps its content, nothing is committed to the default
  branch, a read-only token is refused before anything is written, and a
  repository with no README gets a message rather than a failure.
- A repository with no README is refused. Creating one would be a far larger
  change to somebody else's repository than they asked for.
- `PullRequestCommentIsSoldWhereItIsGivenTest` asserts the plan tables and the
  gate agree, so the next pricing edit cannot quietly split them again.

---

## 2026-08-25 — A rendering pass over every page, and two guards so it stays fixed

**Context:**
A sweep of 68 page/viewport/language/session combinations, checking what is
actually *rendered* rather than what returns 200. Two of the findings were
things no status-code check could have seen.

**What it found, and what was done:**

*The landing page's own call to action was unreachable on a phone.* `nav` hides
`.nav-links` below 768px but keeps the logo, the language switcher, "Sign in"
and "Get started free →" on one 52px row. At 390px that is about 450px of
content: "Sign in" wrapped to two lines and the button ran off the right edge.
The primary CTA, on the page every visitor arrives at, could not be tapped —
and Russian was wider still. Fixed with a short label (`Start free`) swapped in
below 620px plus tightened metrics, verified at 360px and 390px in both
languages. The nav stays one row on purpose: it is `position: fixed` and the
hero below is padded for exactly 52px, so wrapping would have hidden the
headline instead.

*The audit report's section nav was clipped shut on mobile.* The mobile rule
sets `overflow-x: auto`, but the desktop rule is declared **later in the same
sheet with the same specificity** and its `overflow: hidden` won. "Issues" was
half cut and "Passed" was entirely off-screen with no way to reach it. Fixed by
raising the mobile rule's specificity (`nav.audit-sidebar`) — the same cascade
trap this file already documents once for `.repo-card`. The scrollbar is hidden
there by design, so a fade at the right edge now says there is more, and lifts
when the row is scrolled to the end.

*Twenty-two labels announced nothing.* `<label class="form-label">Password</label>`
with no `for=` and not wrapping its input is a caption: it looks correct and a
screen reader reads a bare edit box. Both password fields, the API token, the
webhook secret, every provider token field and the account username were in that
state. All associated.

*Eleven touch targets under 32px* — "View on GitHub", "New token on <host>", the
landing sign-in and the language switcher (26px). The last one is instructive:
the coarse-pointer rule said `.lang-btn`, which is `base.html`'s class name, and
the landing page calls it `.lang-sw-btn` — so the rule had always matched
nothing there.

*One self-inflicted regression, caught by looking.* Making the CTA
`inline-flex` for its touch target turned the whitespace before its arrow into
an anonymous flex item, and flex strips it: the button read `Начать→`. A `gap`
fixed it.

**Two guards, because both classes of bug will recur:**

- `FormLabelsAreAssociatedWithTheirFieldTest` scans every template for a label
  that neither carries `for=` nor wraps its control. It found fourteen more than
  the browser sweep did — the browser check had excused fields that carry a
  `placeholder`, and a placeholder is not a label.
- The sweep script itself now walks *ancestors* for `overflow-x` before calling
  an element clipped, so a table inside its own scroll container stops reporting
  as broken. (Note for the next run: `<svg>` computes `overflow: hidden` on
  itself, which makes an icon inside a scrollable row look clipped. It is not.)

**Consequences:**
- 489 tests pass, up from 488. Russian at 100% (941 messages).
- The four error pages were checked directly rather than through the server:
  with `DEBUG=True` Django serves its own debug page, and the "404 overflows on
  mobile" finding was that page, not `404.html`. All four are clean at 390px and
  1280px.
- The remaining sweep output is empty apart from that debug-page artifact and a
  decorative glow div that its parent clips on purpose.

---

## 2026-08-25 — The landing page leads with the fix, not with the finding

**Context:**
The headline read "Know the truth about your repository in 30 seconds". That is
the promise every free scanner in this category already makes — OpenSSF
Scorecard, Snyk's free tier, Trivy, gitleaks, checkov, GitHub's own Dependabot
and secret scanning. A team that cares already has most of it, for nothing.

The one thing this product does that they do not is open the pull request. It
was in the subhead, as a clause.

**Decision:**
The first thing the page says is the difference: *Every scanner finds problems.
This one opens the pull request.*

- The lead-in is small and quiet, the payoff carries the accent colour. Reading
  order and visual weight now agree; before, the middle line was the loudest
  thing on the page while the punchline sat in muted grey at 75% size.
- **The claim is bounded, because it has to be true.** Twelve of the thirty-one
  checks ship a fix template, so the subhead says "where a fix can be written"
  rather than "for every finding". The old meta description claimed "a fix for
  every issue" outright; that was false and is gone.
- Title, description, Open Graph and Twitter tags were re-synced with the
  positioning, as `CLAUDE.md` requires whenever it changes.

**A contradiction the rewrite surfaced.** Step 2 of "how it works" promised
"Read-only access only". Opening a pull request needs write, and
`github_writer.require_push_access()` refuses without it — so a visitor who
believed the landing page would connect a read-only token, press the feature the
headline sells, and get a permission error. The step now says which scope buys
which capability: read to audit, write to fix.

**Consequences:**
- 489 tests pass. Russian at 100% (943 messages).
- The call to action stays above the fold at 1280×900 and 390×844 in both
  languages — checked, because a three-line headline is exactly the kind of
  change that quietly pushes it under.
- The social-proof separators became `::before` marks on the following item.
  As standalone elements they could wrap to the end of a line and dangle there
  with nothing after them.
- This is a positioning change, not a copy tidy. It is reversible in one commit
  if the framing turns out to be wrong.

---

## 2026-08-25 — Stop the pages promising what the engine will not do

**Context:**
Rewriting the landing headline turned up one false claim, and looking for its
siblings turned up four more. Two claims, repeated across five templates:

- **"A fix for every finding."** Twelve of the thirty-one checks ship a fix
  template. It was in the landing meta description, `base.html`'s default meta
  description, the onboarding third step, and the scanner's sign-up panel.
- **"Read-only access is all you need."** Opening a pull request needs write and
  `github_writer.require_push_access()` refuses without it. So a visitor who
  believed the page connected a read-only token, pressed the feature the
  headline sells, and got a permission error — the worst possible moment to
  discover the copy was wrong.

**Decision:**
Every occurrence now says what is true: fixes arrive as pull requests *for the
findings that have one*, and read access audits while write opens pull requests.

`PagesDoNotPromiseMoreThanTheEngineDeliversTest` guards both. It first asserts
the premise — that not every check is fixable — so the day that changes the rule
can be relaxed deliberately rather than silently. Then it scans every template
for the banned phrasings, ignoring template comments so the comments explaining
the ban do not trip it.

**Consequences:**
- 491 tests pass. Russian at 100% (943 messages).
- The organisation dashboard hides its sort control when it has no rows. A page
  whose only control does nothing reads as a page that failed to load.
- The `{# … #}` guard earned its keep again: it caught a multi-line comment
  added in this very change.

---

## 2026-08-25 — Say which GitHub account was connected, and delete the callback that could have taken one over

**Context:**
Reported: "I made a token from another GitHub user and it connected my current
account instead."

The mechanism was fine — `_connect_github_pat` keys on `(user, github_id)` and a
test confirms two different accounts both attach. What was missing was the
sentence. `github.com/settings/tokens/new` issues a token to whichever account
the **browser** is signed in as. Open that link while signed in as your main
account and you get a token for your main account, however many other accounts
you meant to add. The product then said nothing at all: it redirected to the
dashboard, the same account was sitting there, and the second one had silently
never arrived.

**Decision:**
- Connecting names the account: *GitHub account @acct-b connected.* When the
  token turns out to belong to an account already connected, it says so and
  explains the cause: create the token while signed in to GitHub as the account
  you want to add. Same for GitLab.
- The "+ Add GitHub account" panel now carries that warning up front, and offers
  the GitHub App install as well as a token — GitHub asks which account or
  organisation to install on, which makes it the reliable route for a second
  account. The panel had only ever offered a token.
- **Messages are rendered in `base.html`.** Only `billing.html` had a message
  block, so `github_app_callback`'s "GitHub connected — <name>" had been
  speaking into the void: the one-click install gave no confirmation at all.

**Four dead views deleted.** `github_login`, `github_callback`, `gitlab_login`
and `gitlab_callback` sat in `views.py` routed by nothing — `/accounts/<provider>/login/`
belongs to django-allauth, and `{% url 'github_login' %}` resolves there.
`github_callback` in particular was a sign-in flow wearing a connect flow's
name: it ignored `request.user` entirely, so a signed-in customer who ever
reached it would have been logged into whichever account already owned that
GitHub id, or into a brand-new user created on the spot. Dead code that
dangerous is worth deleting rather than leaving for someone in a hurry to wire
up.

**Consequences:**
- 495 tests pass, up from 491. Russian at 100% (950 messages).
- `ConnectingASecondGithubAccountTest` covers both accounts attaching, the
  account being named, the already-connected case, and the panel carrying the
  explanation.
- Note for later: allauth's social login creates a `SocialAccount` and **no
  `GithubProfile`**, so signing up with "Continue with GitHub" still leaves the
  dashboard empty until a token or App install is added. Recorded in
  `BACKLOG.md`.

---

## 2026-08-25 — Stop shipping the customer's secrets to the model, and give the model the repository

**Context:**
Two complaints, one root: the AI step was working almost blind, and what little
it did read, it read from the worst possible place.

*It had nothing to work with.* `get_ai_summary` received a repository **name**,
a score and a list of failed check titles. Asked to analyse a repository from
that, a model has no repository to analyse, so it writes the only thing it can:
advice that would fit any project. `_generate_ai_fix` was worse — it told the
model to "customise this template for the project" while showing it nothing
about the project.

*And it leaked.* `get_ai_code_suggestions` sends the file a failed check is
about. For `security.no_secrets` the candidate files were `settings.py`,
`config.py`, `app.py`, `main.py` — exactly where the credential the scanner had
just found would be sitting. So at the moment the product told a customer they
had a hardcoded secret, it shipped that secret to Anthropic, OpenAI or Google.
Nobody agreed to that trade.

**Decision:**

*Nothing leaves unredacted.* `checks_secrets.redact()` masks every match of the
rules the scanner already reports on, and every piece of repository content on
its way to a provider goes through it. The rules that define a secret are the
rules that mask one, so anything the product is willing to *call* a credential
is something it will never *forward*. Redaction keeps the surrounding line —
`API_KEY = "«REDACTED:Stripe secret key»"` is as useful for advice as the real
value and safe to send. A PEM block is masked as a whole span, because the rule
that finds one matches only its `BEGIN` line and would have forwarded the key
body.

*`security.no_secrets` asks for no file at all.* The advice for a leaked
credential — rotate it, move it to a secret store, purge the history — does not
need to be written while looking at the credential.

*`app/repo_context.py` gives the model the repository.* Languages, frameworks,
dependency files, Docker base images and exposed ports, the container user and
start command, compose services, CI workflows, Terraform providers, Kubernetes
manifests, the top level, and the first 400 characters of the README. Built
from the archive already in memory, so it costs no extra API calls, redacted
before it is stored, and kept on `Audit.repo_context` for the same reason
`sbom_components` is: the fix view runs long after the token that read the
repository may have been revoked.

Both prompts now carry those facts and both are told the same thing: *invent
nothing — if a fact is not listed, do not mention it.*

*The 401 says what to do about it.* `require_push_access` answered a failed
pull request with "GitHub returned 401 for the repository", which tells a
customer nothing about a token they could simply replace. 401, 403, 404 and
"can read but not write" are now four distinct sentences, each naming the scope
or the action that fixes it.

**Consequences:**
- 501 tests pass, up from 495. Migration `0025` (`Audit.repo_context`).
- `NothingLeavesForTheModelUnredactedTest` asserts end to end that a secret
  placed in a file the AI step sends does not appear in the provider call, that
  a private key body is masked and not just its header, that ordinary
  configuration survives redaction untouched, and that the stored repository
  context carries no credentials.
- Audits taken before this ship with an empty `repo_context`; `to_prompt({})`
  returns an empty string, so their prompts are exactly what they were rather
  than padded with "unknown", which reads to a model as something to guess at.

---

## 2026-08-25 — The audit explains itself: real error messages, and a summary that looked at the repository

**Context:**
Walking the product turned up what "the audit doesn't work the way I want"
actually meant. Three findings, from the audit rows themselves:

- Failed audits reported the exception's own text. Customers saw
  **"User has no gitlab_profile."** — Django's internal sentence for a missing
  reverse one-to-one — and **"GitLab returned 401 for project 76017954"**, which
  names an id they cannot use and says nothing about a token they could replace.
- `ai_provider: Built-in` on real audits. **The AI providers are optional, and
  with no key configured every summary is written by the rule-based fallback.**
  So the filler complaint was not about the model at all — it was about the
  default path most people actually get.
- That fallback ended on **"Top priority fix: Dependency manifest present"** —
  naming the *condition a check tests for* as though it were the action — and it
  picked `failed[0]`, whichever failure happened to be first in the list, rather
  than the most severe one.

**Decision:**

*Every access failure is a sentence about what to do.* `_github_access_message`
and `_gitlab_access_message` map 401, 403, 404, unreachable and everything else
to advice naming the scope or the step that fixes it. No message carries a
project id or an attribute name — neither is something the reader can use. A
missing connection raises a `RepoAccessError` saying so, rather than letting
Django's `RelatedObjectDoesNotExist` become the customer-facing explanation.

*The built-in summary reads like it looked at the repository.* It sorts failures
by severity and leads with the worst; it gives the **recommendation**, trimmed
to its first sentence, instead of the check's title; and where the run learned
what the repository is, it opens with that — "acme/api is a Django project built
on python:3.11-slim, scoring 33/100" is a sentence about a repository, where
"Repository acme/api scored 33/100" is a sentence about a database row.

`repo_context` therefore improves the default experience, not only the paid one.

**Consequences:**
- 513 tests pass, up from 501. Russian at 100% (962 messages).
- Audits taken before `repo_context` existed fall back to the old opening rather
  than reading as broken; a test covers that.
- "1 critical issue(s)" is gone. A count written with "(s)" is a developer
  writing for themselves.
- **Advice is narrowed to the stack.** A recommendation has to serve every
  ecosystem, so it lists the command for each and ends with "depending on your
  stack" — and by the time it is read, the run knows the stack. Offering
  somebody a choice you could have made for them is exactly what makes advice
  feel generic. `_narrow_to_stack` keeps only the applicable options and drops
  that tail. It only ever *removes* options: an unknown ecosystem leaves the
  recommendation exactly as written, because narrowing to the wrong one is
  worse than not narrowing at all. Matching is on word boundaries — `cargo
  build` contains `go build`, and substring matching offered a Go repository
  the Rust command.

---

## 2026-08-25 — Let the account say no, and say plainly what leaves

**Context:**
"Customers must not fear for their repositories." They had reason to. There was
**no way for an account to refuse AI analysis**: `_get_active_provider` looked
for the user's own key, then for a server-side one, and if the deployment held a
key every customer's repository content was sent to Anthropic, OpenAI or Google
whether they wanted it or not. Nowhere did the product say what was being sent.

**Decision:**
- `UserProfile.ai_analysis_enabled`, default on. Off means `(None, None)` from
  `_get_active_provider`, and every caller already falls back to the local
  rules — so refusing costs the tailoring and keeps the feature. That only
  became an acceptable trade once the built-in summary stopped reading like
  filler, which is why the two changes belong together.
- **Not gated on a plan.** Whether repository content reaches a third party is
  the account owner's decision, not something to sell them.
- **A failure to read the preference is treated as off.** A database hiccup must
  not be read as consent.
- Opting out refuses the customer's *own* key too. "Nothing leaves" has to mean
  nothing leaves, not "nothing leaves on our bill".
- The profile page states it in plain words: three things that are sent, three
  that never are, next to the switch that stops it.

**Consequences:**
- 530 tests pass, up from 521. Russian at 100% (979 messages). Migration `0026`.
- The claims on that card are load-bearing. When a prompt changes, the list
  changes with it.

---

## 2026-08-25 — Sign-in with GitHub connects GitHub, and the product says where to go next

**Context:**
Two things a new customer hits in their first two minutes.

*The widest entrance led nowhere.* "Continue with GitHub" is the primary signup
button. allauth authenticated the visitor and created a `SocialAccount` — and
nothing else. Every dashboard, audit and repository list reads `GithubProfile`,
so the new customer landed on an **empty dashboard** and had to go and paste a
personal access token, having just been told that connecting GitHub was one
click. Most people do not do the second step.

*And nothing said where to go.* A dozen pages, no thread between them: GitHub,
GitLab, Organization, Subscription, Profile. A new account has to guess which
one moves them forward.

**Decision:**

*`app/signals.py` bridges the social account to the profile.* On
`social_account_added`, `social_account_updated` **and `user_logged_in`** —
the last because a first social sign-up logs the user in without firing
`social_account_added`, so the brand-new customer is precisely the one the
obvious two receivers would have missed. Keyed on `(user, github_id)` like
every other connect path, so several accounts still work. No token means no
profile: a row that cannot answer is worse than none, because the dashboard
would show a connected account and then fail on every request. A failure here
never takes down the login it is attached to.

*`app/guide.py` is a guide, not a tour.* A tour tells everyone the same five
things in the same order and is wrong for anyone who arrived in the middle.
Each step knows how to check whether it is already done, so the guide always
points at the first thing genuinely outstanding — and **disappears entirely**
once there is nothing left to say, which is the part tours never do.

- Fixed to the corner and collapsed by default, so it travels with the reader
  across pages and is an offer rather than an interruption. Open/closed is
  remembered per browser: re-collapsing on every navigation would make the
  reader open it again on every page.
- "Skip this" advances one step; "Hide the guide" ends it; a hidden guide can be
  restored.
- It counts the step you are *on*, not the number behind you — "Step 0 of 5" is
  a progress bar pretending to be an instruction.
- A **removed** repository does not count as progress, so the guide and the
  quota agree on what "you have one" means.
- It never appears for anonymous visitors or on the public surfaces, and a
  failure computing it returns an empty context rather than a 500 — a guide is
  a convenience and must never be the reason a page breaks.

**Consequences:**
- 552 tests pass, up from 530. Russian at 100% (993 messages). Migration `0027`.
- `app/apps.py` now exists so the receivers are connected on startup;
  `INSTALLED_APPS` points at `app.apps.AppConfig_`.
- `app/context_processors.py` supplies the hint, because `base.html` has no view
  behind it and a dozen views would otherwise each have to remember.

---

## 2026-08-25 — Do not offer an action you already know will fail; and a navigation of three things, not five

**Context:**
"Pull requests still don't work." They did work — the failure was that the
product **already knew** they would not.

`ProviderConnection.token_status` is written on every 401, and the demo account
was sitting at `expired` with an empty token. The report offered "Open pull
request" anyway. Pressing it spent a round trip to GitHub to be told what the
database could have answered instantly, and left the reader looking at a
failure instead of at the way out. The failure message was also set in 11px —
the size a developer uses for their own console output, on the one sentence
that decides whether the reader knows what to do next.

Separately: the signed-in navigation carried five flat items of three different
kinds. GitHub and GitLab are repository *sources* — and are already tabs on the
repositories page — while Organization, Subscription and Profile are sections.
The words did not help either: "Organization" is not where anyone looks for an
overview of their repositories.

**Decision:**

*`_pr_capability()` answers three states, not two.* Can open; cannot because
nothing is connected; cannot because the connection is recorded as broken. The
last two carry the sentence **and the link that fixes it**, and the modal shows
"Reconnect GitHub" in place of the button that would have failed. The error
message is 13px in a bordered block with a link to the reconnect page, because
every one of those messages ends by naming a page and telling somebody to go and
find it is not the same as taking them there.

*Three destinations and an account menu.* Repositories, Overview, Free scanner —
then the account behind one control carrying Profile and connections, Plan and
billing, and Sign out. On mobile the account items expand inline instead of
opening a dropdown over a menu that is already a stack.

**Consequences:**
- 557 tests pass, up from 552. Russian at 100% (997 messages).
- `nav_repo_pages` in a context processor keeps the Repositories tab lit across
  the GitHub page, the GitLab page, a report and a compliance report — one part
  of the product, one tab.
- The account menu closes on an outside click and on Escape. A menu that only
  closes by pressing its own button is a menu people leave open.

---

## 2026-08-25 — Raise the type floor, and stop the form controls rendering as operating-system widgets

**Context:**
"Small fonts in places, ugly in places, nothing catches the eye." Measured
rather than guessed: every visible text node across six signed-in pages, by
computed size.

**Over a hundred nodes below 12px**, carrying real meaning — the CRIT/WARN
severity badges on a report at **9px**, form labels at 10px, KPI captions at
10px, table headers at 10px, one label at **8px**. The distribution also had
almost nothing between 18px and 24px, so the hierarchy had a body and a
headline and nothing in between.

And every `<select>` in the product was rendering as a **light grey
operating-system widget on a dark page** — the "unstyled" look that makes a
whole page read as unfinished. `appearance` was never reset, so Chrome drew its
own control regardless of the colours the rule asked for.

**Decision:**
- One pass over every template raising the floor: 8→11, 9→11, 10→11.5,
  10.5→12. The mono face and the letter-spacing stay, so the technical register
  survives — it is legible now rather than decorative. 123 rules across 22
  templates; **zero visible text under 11px** afterwards, verified the same way
  it was measured.
- The email template was left alone. Mail clients render at fixed widths under
  their own rules, and it is the one surface where these sizes were deliberate.
- `select` is styled once in `base.html` with `appearance: none` and an arrow
  drawn from two gradients.
- **Page-level select rules had to stop using the `background` shorthand**,
  which resets `background-image` and erased that arrow — leaving a control that
  looked like a button and gave no sign it opened. The same cascade trap as the
  audit sidebar, in a different costume.
- The Overview page is called Overview. The navigation had been renamed and the
  page still said "Organization".

**Consequences:**
- 557 tests pass. The rendering sweep is unchanged: no new overflow anywhere, in
  either language, at either width.

---

## 2026-08-25 — A trend you can read, and a scale with a middle

**Context:**
The trend chart on Overview was "almost invisible", and the type scale had no
level between a page title and a caption.

The chart's line was `stroke-width=".8"` with `vector-effect="non-scaling-stroke"`
— which means **0.8 of a CSS pixel**, a hairline at any container width. Its end
marker was a `<circle>` in viewBox units under `preserveAspectRatio="none"`, so
it rendered as a stretched ellipse. There was no y reference of any kind, so a
height on the chart meant nothing, and there was no way to read a value: a line
chart with no readable value is a decoration.

**Decision (following the dataviz method):**
- Lines are 2px. The end marker is a zero-length round-capped line with a
  non-scaling stroke, which draws a true circle at any width where a `<circle>`
  cannot.
- Reference lines at 0 / 50 / 100 with the labels in HTML beside the SVG — text
  inside a `preserveAspectRatio="none"` canvas is stretched with everything else.
- The area fill is a gradient rather than a flat 10% wash.
- **Hover and keyboard focus on every reading**, with a tooltip naming the week
  and the score. The hit target is the whole column, not the 5px dot — and each
  column is clamped to the canvas, because the first and last are half-columns
  and an unclamped one hangs off the edge of the page. The sweep caught exactly
  that.
- The scale is kept at 0–100. A score chart that auto-scales turns a two-point
  drift into a cliff.

*The type scale gets a middle.* Page title 28, section 18, sub 15, label 11.5
mono. Before, a page title was 24px and everything below it was an 11.5px
uppercase caption — so a major section and a minor one were announced at exactly
the same volume, and no page had a shape you could read at a glance.

**Consequences:**
- 563 tests pass, up from 557. The chart tests cover the geometry, the clamped
  hit columns, and that no coordinate ever leaves as a locale-formatted float —
  `viewBox="0 0 100,0 30,0"` makes a browser drop the entire chart, which is
  what every Russian reader used to see.

---

## 2026-08-25 — Put the actionable part of the report first

**Context:**
The report is the product's most important page, and its first screen showed —
in this order — a breadcrumb, a metadata line, five equally weighted buttons, a
small score ring, and then a **340px sharing panel**: the report URL, a badge
preview and a markdown snippet. The findings began below the fold.

The panel was open because the template said
`class="share-card {% if audit.is_public %}open{% endif %}"`, so every visit to
a public report led with sharing. Being public is a *state* — the Share button
already shows it — not a reason to occupy the top of the page forever.

Below that, the order was AI paragraph → stat tiles → category bars → **Start
here** → findings. The one block that says what to *do* was fourth, after three
that only describe.

**Decision:**
- The share panel is closed by default, always. The Share button opens it, which
  is what a Share button is for.
- "Start here" leads. It arrives at **302px** instead of roughly 1700 — the
  first screen now carries the repository, the score, the projected score, and
  the three findings worth fixing first with their point values, their effort,
  and a Fix button on the one-click one.
- The section list is reordered to match the page. It had Summary above AI while
  the page had AI above Summary; a table of contents in a different order from
  the document is a table of contents that has to be read twice.

**Consequences:**
- 563 tests pass. The rendering sweep is unchanged.
- Note for the next sweep: `<svg>` computes `overflow: hidden` on itself, so an
  icon inside a horizontally scrollable row reports as clipped when it is not.
  Adding an icon to the section list produced three more of those; all were
  verified against the page's own scroll width, which is unchanged.
