# Backlog

What is next, why, and what it depends on. Newest planning session first.
Decisions already taken live in `DECISIONS.md`; this file is what has *not*
been done yet.

---

## Target

**~1000 users by late October 2026** (set 2026-08-24).

The deadline is what shapes the order below. SEO is the right long game — every
public scan is an indexable page and the sitemap holds 5000 — but indexing and
ranking take three to six months. It cannot be the primary channel for a
two-month target. Build the corpus anyway, for what it produces *now*: a
distribution that makes the score mean something, and a finding worth linking
to.

---

## Blocked on the operator — no code will move these

1. **Lemon Squeezy is in test mode.** Real cards are declined. One variant
   exists (`1756008`) at $29/month against an advertised $19, status `pending`.
   Six variants must be created by hand — $19/$182, $99/$950, $299/$2870 —
   published, and set in `.env` as `LS_VARIANT_PRO_MONTHLY` …
   `LS_VARIANT_COMPLIANCE_ANNUAL`. Variants cannot be created through the API
   (`POST /v1/variants` → 405) and `custom_price` only changes the first charge.
2. **Cryptomus has no credentials.** `CRYPTOMUS_MERCHANT_ID` and
   `CRYPTOMUS_API_KEY` are absent. It is a one-off charge for the exact amount,
   so crypto sells all six plan/period combinations the moment those two keys
   exist. **This is the fastest route to taking money at all.**
3. **`PUBLIC_SCAN_GITHUB_TOKEN` is not set.** Unauthenticated GitHub search
   allows ten requests a minute; with a token, roughly 1600 repositories an
   hour. Everything in "the corpus" below is built and tested but produces
   nothing without it. A classic token with no scopes is enough.
4. **The user's own GitLab PAT is expired.** Reconnect at `/profile/` with a
   token carrying `read_api`.

Run `manage.py check_payments --live` before claiming payments work.

---

## Asked for, not yet done

- **"Continue with GitHub" does not connect a repository.** allauth's social
  login creates a `SocialAccount`; the product reads `GithubProfile`, and
  nothing bridges the two. So signing up through the GitHub button lands on an
  empty dashboard until a token or an App install is added. Either bridge it on
  `social_account_added`, or stop offering the button as if it connected
  anything.

*(Both 2026-08-24 items are done — see the 2026-08-25 ADR in `DECISIONS.md`.)*

- **Is the private-repository limit per provider, or three in total?** It is
  enforced per provider today, so a free account can hold three GitHub *and*
  three GitLab repositories, while the pricing page advertises "3 private
  repositories". The billing page used to sum them against the same limit and
  display "6 / 3"; it now shows a row per provider, which is at least honest
  about the rule being applied. Which rule is *right* is a pricing decision.
  Tightening it to three in total would put existing free accounts over the
  line — survivable now that a repository can be removed, but it is a call for
  the operator, not a refactor.

---

## Next, in the order I would take them

### 1. Fill the corpus *(built — needs the token)*

`manage.py seed_public_scans --languages Python,JavaScript,Go,… --per-language 800`
then let `scan_pending_public_repos` drain it hourly. 10–50k repositories is
one night to a weekend. Everything below depends on this having run.

### 2. The launch artefact

Once the corpus is real, `/rankings/` carries the check-prevalence table — "one
in three of the most-starred repositories has no lockfile". Write that up as a
post and take it to Show HN, r/devops, r/programming, dev.to, Product Hunt.
This is the channel that can actually move a thousand people in two months; the
SEO pages compound behind it.

### 3. Email capture on the public pages *(done 2026-08-25)*

Shipped: `RepoWatch`, the form on every finished scan page, double opt-in,
one-click unsubscribe, and a daily refresh-then-compare pair that mails watchers
when a score moves. See the 2026-08-25 ADR. What remains is traffic to point at
it — and payments, so the traffic can convert.

**Known gap, not fixed:** a Russian reader sees English check names on a public
scan page and in the watch emails. `PublicScan.results` is captured at scan time
in English, so fixing it means either translating at render time from
`check_id`, or re-scanning the corpus per language. The email is at least
consistent with the page it links to.

### 3b. The original note, for context *(superseded)*

The emotional peak is the moment someone sees "44/100, two critical". Right now
there is no way to keep that person: no email capture anywhere public, and the
only CTA assumes they have private repositories they care about.

- "Send me this report" — a contact without an account.
- "Watch this repository" — mail when the score changes. Returning traffic with
  no token and no signup.

**Do this before any launch push, not after.** A spike with no capture is a
spike that leaves.

### 4. The badge as a one-click pull request *(done 2026-08-25)*

Shipped. `open_badge_pull_request` inserts the badge into the README and opens
the PR; it never stacks a duplicate, and it rewrites a stale badge in place. For
a visitor without an account the button routes through signup — "we will open
the pull request" is the strongest reason to register the product has.

### 4b. The original note, for context *(superseded)*

The README badge exists; `github_writer.py` already opens pull requests for
fixes. They are not connected — the badge is offered as text to copy by hand.
Wiring them closes the loop shields.io, Codecov and Snyk all grew on: badge in
a README is a backlink, an impression, and an entry point for the next person.

### 5. Move the pull-request comment from Team to Pro *(done 2026-08-25)*

Shipped. Gate is `is_pro`; the organisation dashboard, weekly trends and
org-wide `fail_under` stay on Team. Three plan tables and the billing matrix
were moved to match, with a test that keeps them agreeing.

### 5b. The original note, for context *(superseded)*

`views.py:1786` gates PR comments on `is_team` ($99). It is the most visible
surface the product has — every developer on the team sees it on every pull
request — and almost no one will. Basic comment (score + what changed) belongs
in Pro at $19; keep the organisation dashboard, weekly trends and org-wide
`fail_under` for Team. This trades a little revenue for a lot of exposure.

### 6. Publish the Action to the GitHub Marketplace

`action/` is written, tested end to end, and unpublished. Needs brand assets, a
README with examples, a `v1` tag and the listing. A discovery channel with
intent already attached.

### 7. Narrow wedges, each with its own landing page

The same engine, a sharper pitch, and a concentrated audience to launch into:

- **GitHub Actions supply chain** (`checks_extra.py`) — unpinned actions,
  `pull_request_target`, over-broad permissions.
- **Terraform misconfiguration** (`checks_iac.py`) — remote state, ingress open
  to 0.0.0.0/0, unencrypted storage, public buckets.
- **SOC 2 readiness for small teams** (`compliance.py`) — narrow, high pain,
  highest willingness to pay.

---

## Standing risks

- **Database backup and restore does not exist.** No `pg_dump`, no restore
  script, no beat job, nothing in `docker/`. Verified absent twice. Cheap now,
  impossible after the first real user. The one thing I would not launch
  without.
- **Retention policy.** Audit rows grow with every run and nothing prunes them.
- **The public "most room to improve" list names real repositories.** Factual,
  reproducible, and the same thing OpenSSF Scorecard does — but it puts the
  engine's accuracy in public, so a false finding now costs more than it did.
- **Email is optional at registration.** `send_expiry_reminders` is the only
  thing between a one-off crypto customer and silent lapse, and it has nowhere
  to send for those accounts. Making it required trades signup conversion for
  renewal — a deliberate decision, not a bug.

---

## Notes for whoever picks this up

- Django's `{# … #}` is a **single-line** comment. Across several lines it is
  not a comment: the text renders and markup inside it becomes real elements.
  Use `{% comment %}`. `TemplatesDoNotLeakTheirOwnSyntaxTest` guards this.
- `makemessages` fuzzy-matches new strings onto unrelated translations — it
  gave the GitLab button "Войти через GitHub" and gave a `%(n)s` string a
  translation carrying `%(since)s`. Always read the fuzzy entries before
  compiling.
- Celery does not auto-reload. Restart it after changing `tasks.py`.
- `DEBUG=True` locally, so `/nope/` serves Django's debug page rather than
  `404.html`. Render the error templates directly to review them.
- Three `msgfmt --check` errors on plural forms pre-date all of this and are
  Django's own convention; `compilemessages` succeeds.
