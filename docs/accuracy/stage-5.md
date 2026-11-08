# Этап 5 — исправление детекторов (выполнен раньше 3–4)

Порядок изменён сознательно: все ложные FAIL, которые чинятся без знания типа
репозитория, починены здесь; оставшиеся — вопрос применимости (этапы 3–4).

## Что изменено (`app/detectors.py`)
- changelog: CHANGELOG/CHANGES/HISTORY/NEWS/RELEASES/release-notes любого регистра и
  расширения в корне, `.github/`, `docs/`, `.gitlab/`; `docs/**/release-notes*`,
  `docs/releases/`; `.changeset/`, `newsfragments/`, release-please, goreleaser, towncrier, git-cliff.
- security policy / contributing / license: любой регистр, `.md/.rst/.txt/.adoc`, те же каталоги.
- Dockerfile: поиск по всему дереву (`Dockerfile`, `Dockerfile.*`, `*.Dockerfile`), кроме
  тестов, примеров, vendor, devenv/scripts/tools/.github. Зависимые проверки — по всем
  найденным (до 8): non-root — у каждого, последний `USER` решает; pinned — у каждого.
- pinned base: имена стадий (`FROM base AS final`) и `${ARG}` не считаются образами;
  тег без версии (`python:slim`, `node:lts-alpine`) — плавающий.
- tests in CI: на один уровень вглубь — GitLab `include: local` (2 уровня), локальные
  reusable workflows и composite actions, цели Makefile (с пререквизитами), `npm/pnpm/yarn run`
  скрипты, shell-скрипты (`scripts/test`, `*.sh`), tox/nox/just/Taskfile; GitLab job в
  стадии `test` или с именем `*test*`. Evidence — файл, где найдена команда.
- секреты: документационные ключи вендоров (`AKIAIOSFODNN7EXAMPLE`, `…EXAMPLEKEY` и т. п.)
  не находятся. Тесты, использовавшие этот ключ как «настоящий», переведены на
  синтетический `AKIA2E0A8F3B244C9986`.

## Метрики
| Набор | Ложных FAIL: база → этап 2 → этап 5 | Верно |
|---|---|---|
| synthetic | 9/12 → 8/11 → **2/5** | 79.2% → **95.8%** |
| live | 15/30 → 14/29 → **7/24** | 79.6% → **90.8%** |

Оставшиеся 9 ложных FAIL — все про применимость по типу (docs-only / awesome:
ci.tests и changelog; helm-charts, Ghost-CLI: docker и observability; express: lockfile).

Golden: changelog теперь pass у cli, django, express, fastapi, kit, full-stack-fastapi;
contributing у terraform-aws-vpc; fdroidserver 66 → 57 — найден и проверен его
`buildserver/Dockerfile` (раньше docker-проверки были na).
