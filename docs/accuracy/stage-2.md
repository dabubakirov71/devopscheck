# Этап 2 — четыре статуса, зависимости, evidence

## Что изменено
- У каждого результата `status` (pass / fail / na / unknown) и `evidence`
  (`checks.finalize_statuses`, последним шагом после repo_kind и .devopsaudit.yml).
  Хранится в `AuditCheck.status` / `.evidence` (миграция 0036).
- `unknown` хранится как `applicable=False` + флаг: все существующие пути подсчёта
  score/findings исключают его без изменений; причина показывается там же, где у `na`.
- Зависимости («нет объекта → na, никогда pass»):
  `docker.dockerignore` ← Dockerfile; `deps.lockfile` ← манифест; `deps.pinned` ←
  requirements.txt; `security.env_gitignored`, `ops.env_example` ← проект использует .env.
- `ci.branch_protection`: GitHub — classic protection, иначе rulesets
  (`/rules/branches/<b>`, публичный); не удалось прочитать → `unknown`
  (было: fail у всех публичных). GitLab: 401/403/5xx → `unknown`.
- Evidence: путь к найденному файлу, `файл: команда` для тестов в CI, список FROM,
  «искали в … — не найдено» для отсутствующих.

## Метрики
| Набор | Ложных FAIL до | после | Верно до | после |
|---|---|---|---|---|
| synthetic | 9/12 | 8/11 | 79.2% | 81.2% |
| live | 15/30 | 14/29 | 79.6% | 80.6% |

Golden (9 репо): сдвиг score на −3…+1 — только из-за снятых «pass по пустоте»
(deps.pinned, env_gitignored, env_example, dockerignore). Перезаписан осознанно.
SCORE_VERSION не поднят: поднимется один раз на этапе 6 (v3) вместе с пересканированием.

Готово по ТЗ: фикстура `no-dockerfile-service` проходит; тест
`CheckStatusModelTest.test_nothing_passes_or_fails_without_its_object`.
