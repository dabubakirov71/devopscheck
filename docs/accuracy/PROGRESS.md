# Точность проверок (ТЗ `docs/accuracy/spec.md`) — журнал и контекст

Читать первым после перерыва. Обновляется в конце каждого шага.

## Правила, о которых нельзя забыть
- Этап 1 (эталонный прогон + `eval-baseline.json`) — ДО любых правок логики проверок.
- Каждый этап — своя ветка `accuracy-stage-N-*`, описание «MR» в `docs/accuracy/stage-N.md`
  (метрики до/после). MR через API создать нельзя (нет glab/токена) — пушим ветку,
  GitLab даёт ссылку на MR; мерж + деплой по правилу владельца.
- Владелец (2026-09-26): «сразу после прогона выкатывай в прод» — каждый этап: eval → merge → деплой на прод.
- Противоречия ТЗ и кода — записывать (см. `docs/checks-inventory.md` §6), не обходить молча.
- `verified: false` в живом наборе проверяет владелец, не агент.
- Владелец раньше вынес «гигиену» (CODEOWNERS/CHANGELOG/SECURITY.md/лицензию…) из балла —
  перед этапом 4 спросить, как это совместить с матрицей применимости.

## Статус этапов
| Этап | Статус | Ветка / коммит | Заметки |
|---|---|---|---|
| 0 Инвентаризация | готово | accuracy-stage-0-inventory | `docs/checks-inventory.md`, 58 проверок, маппинг имён, 9 противоречий |
| 1 Эталон и прогон | готово | accuracy-stage-1-eval | см. `stage-1.md`; synthetic false FAIL 9/12, live 15/30, тип live 61% |
| 2 Статусы/зависимости/evidence | готово | accuracy-stage-2-statuses | см. `stage-2.md` |
| 3 Тип репозитория | готово | accuracy-stage-3-4-kind | см. `stage-3-4.md`; тип live 100% |
| 4 Матрица применимости | готово | accuracy-stage-3-4-kind | владелец: гигиена вне балла (вариант а) |
| 5 Детекторы | готово | accuracy-stage-5-detectors | см. `stage-5.md`; live false FAIL 7/24 |
| 6 Score v3 + пересканирование | готово | accuracy-stage-6-score-v3 | SCORE_VERSION=3, PublicScan.score_version (0037), пунктир на графике, пересчёт устаревших |
| 7 UI отчёта | готово | accuracy-stage-7-report-ui | evidence под проверкой, «Не удалось проверить», тип + «Неверно? Изменить», кнопка «Это ложное срабатывание» → FalsePositiveReport (0038, в админке) |

## Факты, найденные по ходу
- Уже есть: `repo_kind` (типы + confidence + `.devopsaudit.yml kind:`), `na` через
  `applicable=False` с причиной, `StaticRepoClient`, golden из 9 репо (частичное
  содержимое, без SHA), `SCORE_VERSION`, гигиена вне балла.
- Ложные FAIL уже видны в текущем golden: `docs.changelog` у fastapi/express/django,
  `iac.remote_state` у terraform-aws-vpc (модуль), `ci.branch_protection` у всех публичных
  (нет прав → fail вместо unknown), `ops.activity` плывёт от даты.
- «Пустота→pass»: `deps.pinned`, `security.env_gitignored`, `ops.env_example`.
  `docker.dockerignore`, `deps.lockfile` не зависят от своего объекта.
- В проде 8 публичных сканов — мало для «реальных репо с проблемами».

## Этап 1 — рабочие заметки
- Синтетический базовый прогон (текущая логика): 48 пар, верно 38; FAIL выдано 12, ложных 9.
  Ложные: changelog (History.md, docs/release-notes.md, docs-only), ci.tests (Makefile,
  GitLab include:, docs-only), docker.dockerfile в apps/api (монорепо), dockerignore без
  Dockerfile, AKIAIOSFODNN7EXAMPLE в config.example.py.
- В seed ТЗ была невалидная YAML-строка (`notes: ... include: ...`) — взята в кавычки.
- С dev-хоста GitHub отдаёт ~30 КБ/с. Снапшоты качаются на проде и копируются scp:
  `scripts/eval-fetch.sh ubuntu@87.199.130.66` (curl с таймаутом; раньше завис на django).
  Кеш: `.eval-cache/` (gitignored; создаётся контейнером от root → chown).
- Живой набор: 8 из seed (SHA на 2026-09-26) + 10 небольших проектов агента с `checks: {}` —
  разметить по снапшоту после загрузки (verified: false).
