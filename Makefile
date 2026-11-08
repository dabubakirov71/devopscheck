DC := docker compose -f docker/docker-compose.yml

.PHONY: golden golden-write test eval eval-live eval-baseline

# Regression check for the audit engine and repo_kind classifier against a
# corpus of real, recorded repositories (tests/golden/). Run this before
# merging any change that touches checks.py, checks_extra.py, checks_iac.py,
# checks_secrets.py, or repo_kind.py — a false reading on a well-known
# repository is exactly what this catches.
golden:
	$(DC) run --rm web python tests/golden/run_golden.py

# Regenerate tests/golden/expected/ from the engine's current output. Only
# after reviewing the new result by hand and confirming it is correct — never
# to make a `make golden` failure go away without looking at why it moved.
golden-write:
	$(DC) run --rm web python tests/golden/run_golden.py --write

test:
	$(DC) exec web python manage.py test app --verbosity=2

# Accuracy of the checks against known right answers (docs/accuracy/spec.md).
# `eval`: synthetic fixtures, no network — also run by the test suite.
# `eval-live`: pinned real repositories; snapshots cached in .eval-cache/.
eval:
	$(DC) exec web python manage.py eval_checks --set synthetic

eval-live:
	$(DC) exec web python manage.py eval_checks --set live

# Only after reviewing the run: the baseline is what the next run is compared to.
eval-baseline:
	$(DC) exec web python manage.py eval_checks --set all --write-baseline
