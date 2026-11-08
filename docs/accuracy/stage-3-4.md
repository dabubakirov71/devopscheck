# Этапы 3–4 — тип репозитория и применимость

Решение владельца (2026-09-26, вариант «а»): гигиена (CHANGELOG, LICENSE, SECURITY.md,
CODEOWNERS…) остаётся вне балла; тип решает только, применима ли она (показывать или «na»).

## Тип (`app/repo_kind.py`)
- package.json: одного `"main"` мало (его пишет `npm init` в любое приложение). Библиотека —
  `exports/module/types/typings/publishConfig/peerDependencies`, либо `main` + `files`/`bin`.
- Репозиторий Helm-чартов (≥2 Chart.yaml, нет Dockerfile, мало кода) → infrastructure.
- Workspace (nx/lerna/pnpm/go.work) с Dockerfile в корне → service (grafana).
- Workspace вокруг публикуемого корневого пакета → library (Ghost-CLI с extensions/).
- Без workspace-маркера вложенные манифесты при корневом манифесте — не монорепо
  (gitlab-runner: helpers/, scripts/).
- `.devopscheck.yml` принимается наравне с `.devopsaudit.yml`; `type:` — синоним `kind:`,
  `iac` — синоним `infrastructure`; допустимы также cli / monorepo / docs.

## Применимость (единый источник — `SKIPPED_BY_KIND` + `detect()`)
- docs: + `ci.tests`, `docs.changelog` → na.
- library/cli на npm/Python: `deps.lockfile` → na со своей причиной (lock-файл не доходит
  до пользователей пакета). Go/Rust — остаётся.
- Противоречие ТЗ: матрица говорит «lockfile: recommended (info)» для библиотек, а затравка
  эталона — `na` для express. Выбрано `na` (info-FAIL всё равно FAIL в отчёте).

## Метрики
| Набор | Ложных FAIL | Верно | Тип верно |
|---|---|---|---|
| synthetic | 2/5 → **0/3** | 95.8% → **100%** | 100% |
| live | 7/24 → **0/19** | 90.8% → **100%** | 61% → **100%** |

Оговорка: живой набор размечен агентом (`verified: false`), 18 репо — меньше цели 30+.
100% здесь — верхняя оценка; настоящая проверка — кнопка «ложное срабатывание» (этап 7).

Golden: django/express/fastapi — lockfile na; fdroidserver monorepo → library (78);
full-stack-fastapi-template monorepo → service.
