# Этап 1 — эталонный набор и прогон (базовая линия)

Логика проверок НЕ менялась. Добавлено только то, что нужно, чтобы её измерить.

## Что сделано
- `app/repo_client.py: LocalDirClient` — источник файлов из локальной директории
  (+ `metadata.yaml` для того, чего в директории нет: провайдер, SHA, protection).
- 18 синтетических фикстур `tests/fixtures/repos/<name>/` с `expected.yaml`.
- Живой набор `tests/golden/golden-set.yaml`: 18 репозиториев на закреплённых SHA
  (8 из затравки ТЗ + 10 небольших реальных проектов с настоящими проблемами).
  Все `verified: false` — проверяет владелец.
- `app/evaluation.py` + `manage.py eval_checks` (`make eval`, `make eval-live`,
  `make eval-baseline`): матрица expected×actual, precision/recall FAIL,
  список расхождений с evidence, сравнение с `eval-baseline.json`.
- Синтетический прогон входит в `manage.py test` (CI на каждый PR).
- Снапшоты: `scripts/eval-fetch.sh` (качает на проде, копирует scp в `.eval-cache/`).

## Базовая линия (текущая логика)
| Набор | Пар | Верно | FAIL выдано | Ложных FAIL | Доля ложных | Тип верно |
|---|---|---|---|---|---|---|
| synthetic | 48 | 38 (79%) | 12 | 9 | 75% | 100% |
| live | 98 | 78 (80%) | 30 | 15 | 50% | 61% |

Ложные FAIL по проверкам (оба набора): `docs.changelog` 7, `docker.dockerfile` 5,
`ci.tests` 5, `ops.observability` 2, `docker.dockerignore` 2, `security.no_secrets` 1,
`ops.license` 1, `deps.lockfile` 1.

Найденный ложный PASS: `docker.pinned_base` у miguelgrinberg/microblog (`FROM python:slim`
считается закреплённым тегом).

Цель ТЗ: доля ложных FAIL ≤ 3%, precision FAIL ≥ 95% по каждой проверке.
