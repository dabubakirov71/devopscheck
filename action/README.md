# DevOpsCheck — GitHub Action

A DevOps and security score for the commit under test: committed secrets,
known CVEs in dependencies, GitHub Actions supply chain, Docker, Kubernetes and
Terraform. Findings land in the pull request, the job summary and
**Security → Code scanning**. Free for public repositories — no account, no token.

```yaml
name: DevOpsCheck
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write     # the PR comment
  security-events: write   # the Code scanning upload

jobs:
  devopscheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devopscheck/scan-action@v1
        id: scan
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && steps.scan.outputs.sarif-file != ''
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

That is the whole setup for a public repository. Pin both third-party actions
to a commit SHA in your own workflow — DevOpsCheck will tell you to anyway.

**Private repositories** need an API token from **Profile → Notifications & API**
on your DevOpsCheck account, stored as a repository secret:

```yaml
      - uses: devopscheck/scan-action@v1
        with:
          token: ${{ secrets.DEVOPSCHECK_TOKEN }}
```

## What it does

It audits the **head commit of the pull request**, not the default branch —
grading `main` and calling it a check on a change nobody has merged yet would
report on code the change has not touched.

On a pull request it leaves one comment: what this push introduced first, the
gate verdict, and the standing findings folded away underneath. The same thing
goes into the job summary, so the answer is on the run page whether or not the
comment was allowed.

The step **fails the build** when:

- the score is below `fail-under`, if you passed one; or
- the score is below `fail_under` in the repository's `.devopsaudit.yml`; or
- `fail-on-new: true` and this run introduced a finding the previous run
  did not have.

With no threshold anywhere, the step never fails. Most repositories start that
way and turn the gate on once they know their number.

## Inputs

| Input | Default | What it is |
|---|---|---|
| `token` | — | API token. Optional for public repositories (free scanner, 20 scans per repository per hour); required for private ones. |
| `repository` | this repository | `owner/name` to audit. |
| `ref` | the commit under test | Branch, tag or sha. |
| `fail-under` | — | Minimum score, 0–100. Overrides `.devopsaudit.yml`. |
| `fail-on-new` | `false` | Fail when a finding appears that the last run did not have. |
| `comment` | `true` | Post the result as a pull request comment. |
| `sarif` | `devopscheck.sarif` | Where to write findings as SARIF for Code scanning. Empty to skip. |
| `api-url` | `https://devopscheck.com` | Change only for a self-hosted instance. |
| `timeout` | `300` | Seconds to wait for the audit. |

## Outputs

| Output | What it is |
|---|---|
| `score` | 0–100. |
| `gate` | `true`, `false`, or empty when no threshold applies. |
| `new-findings` | How many findings this run introduced. |
| `report-url` | Link to the full report. |
| `audit-id` | Id of the audit that ran. |

## Tuning it from the repository

The gate and the checks belong next to the code, not in the workflow. Add
`.devopsaudit.yml` to the repository root:

```yaml
kind: library            # service | library | infrastructure
fail_under: 70

ignore:
  - id: docker.nonroot
    reason: the base image already runs as nobody

severity:
  deps.lockfile: info

allow_secrets:
  - tests/fixtures/
```

An `ignore` needs a reason, and the check stays in the report carrying it —
so the next person, or an auditor, can see what was set aside and why. The
secret scanner cannot be switched off.

## Blocking a merge on it

Turn the job into a required status check: **Settings → Branches → Branch
protection rules → Require status checks to pass**, then select `audit`. From
then on the score is not advice.

## Not failing on day one

Start without a threshold, let it run for a week, then set `fail_under` just
below where you already are and raise it as you go. A gate set above the
current score on the first day fails every pull request and gets removed by
Friday.

## Examples

**Only block on regressions, never on the standing total:**

```yaml
- uses: devops-audit/action@v1
  with:
    token: ${{ secrets.DEVOPS_AUDIT_TOKEN }}
    fail-on-new: true
```

**Stricter in CI than the file asks for:**

```yaml
- uses: devops-audit/action@v1
  with:
    token: ${{ secrets.DEVOPS_AUDIT_TOKEN }}
    fail-under: 85
```

**Use the score in a later step:**

```yaml
- uses: devops-audit/action@v1
  id: audit
  with:
    token: ${{ secrets.DEVOPS_AUDIT_TOKEN }}
- run: echo "Scored ${{ steps.audit.outputs.score }} — ${{ steps.audit.outputs.report-url }}"
```

## Self-hosted

```yaml
- uses: devops-audit/action@v1
  with:
    token: ${{ secrets.DEVOPS_AUDIT_TOKEN }}
    api-url: https://audit.internal.example.com
```

## Requirements

`curl` and `python3`, both already on every GitHub-hosted runner. Nothing is
built and nothing is downloaded, so the step starts immediately.
