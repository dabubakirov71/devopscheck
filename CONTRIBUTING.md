# Contributing to DevOpsCheck

Thanks for helping! Bug reports, new checks, translations and docs are all welcome.

## How to contribute

1. **Open an issue first** for anything bigger than a small fix, so we can agree on the approach.
2. Fork the repository and create a branch: `git checkout -b feat/my-check`.
3. Start the stack and make your change:
   ```bash
   cp .env.example .env   # see README → Quick start
   docker compose -f docker/docker-compose.yml up --build
   ```
4. Add tests next to the change and run them:
   ```bash
   docker compose -f docker/docker-compose.yml exec web python manage.py test app --verbosity=2
   make golden   # if you touched checks*.py or repo_kind.py
   ```
5. Open a pull request that explains **what** changed and **why**.

## Project rules

These keep the product honest. The reasoning is in [`CLAUDE.md`](CLAUDE.md) and [`DECISIONS.md`](DECISIONS.md).

- **Key logic off `check_id`, never off a check's display name.** Names are translated.
- **Audits are append-only.** Every run creates a new `Audit` row.
- **English is the source language.** Add the Russian translation in `locale/ru` in the same change.
- **Nothing that reaches an AI provider skips `checks_secrets.redact()`.**
- **The fix agent's guardrails are never loosened** to make a case pass.
- **No real credentials in the repository**, not even in tests. Use obviously fake values.

## Good first contributions

- A new check: see [`docs/checks-inventory.md`](docs/checks-inventory.md) for what exists.
- A false positive or false negative on a real repository, reported as an issue with a link.
- Translations and documentation.

## Licensing of contributions

DevOpsCheck is published under the [Functional Source License 1.1 (FSL-1.1-ALv2)](LICENSE.md).
Every version becomes Apache-2.0 two years after its release.

By submitting a contribution (code, documentation or any other material) you agree that:

1. you wrote it, or otherwise have the right to submit it under these terms;
2. you license it to the project maintainer under the
   [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0). This lets
   the maintainer distribute it as part of DevOpsCheck under the project's current or
   any future license and run DevOpsCheck as a hosted service;
3. it is distributed to everyone else under the project's license.

You keep the copyright to your contribution. If you can't agree to this, for example
because your employer owns your work, please say so in the pull request before it is merged.

## Security issues

Please **do not** open a public issue for a vulnerability. Use GitHub's
**Security → Report a vulnerability** button on this repository instead.
