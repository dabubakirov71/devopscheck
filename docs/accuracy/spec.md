# ТЗ: точность проверок DevOps Audit (методика v2)

## Контекст и цель

Публичный отчёт по `fastapi/fastapi` на главной странице содержит ложные срабатывания, которые видны любому разработчику:

- «Tests run in CI» → FAIL, хотя тесты запускаются в GitHub Actions на каждый PR;
- «Dockerfile present» → FAIL, но при этом «Healthcheck defined», «Base image is pinned», «Dockerfile uses a multi-stage build», «Resource limits set in compose» → PASS (проверки проходят «по пустоте», когда объекта проверки нет);
- от библиотеки-фреймворка требуются Dockerfile, non-root-контейнер и observability (Sentry/Prometheus), хотя для библиотеки это неприменимо;
- CHANGELOG, SECURITY.md, CONTRIBUTING ищутся только в одном месте и с одним именем.

**Цель:** отчёт не должен содержать FAIL, который инженер может опровергнуть за минуту. Метрика — precision статуса FAIL по каждой проверке на эталонном наборе ≥ 95%, общая доля ложных FAIL ≤ 3%.

## Правила работы для агента

1. Сначала изучи кодовую базу. Не угадывай стек, имена модулей и ID проверок — найди их.
2. Работай по этапам ниже. Каждый этап — отдельная ветка и отдельный PR с описанием: что изменено, метрики эталонного прогона до и после.
3. Не меняй логику проверок, пока не готов эталонный прогон (этап 1): каждое изменение должно быть измеримо.
4. Если что-то в ТЗ противоречит устройству кода, остановись и опиши противоречие в PR, а не обходи его молча.
5. Имена проверок в этом документе (`tests_in_ci`, `dockerfile_present` и т. д.) условные. На этапе 0 сопоставь их с реальными ID.

---

## Этап 0. Инвентаризация

Создай `docs/checks-inventory.md` — таблицу всех существующих проверок:

| ID | Название | Категория | Severity | Что именно ищет (файлы, паттерны, API) | Зависит от наличия чего | Известные слабости |

Отдельно перечисли, как сейчас считается score (формула, веса категорий) и где хранится история score.

**Готово, когда:** таблица покрывает 100% проверок, есть соответствие условных имён из этого ТЗ реальным ID.

---

## Этап 1. Эталонный набор и прогон (сделать ДО правок логики)

### 1.1. Абстракция источника файлов

Сканер должен уметь работать не только с API GitHub/GitLab, но и с локальной директорией. Если сейчас чтение файлов жёстко завязано на API — выдели интерфейс источника (`list_files`, `read_file`, `repo_metadata`) с реализациями для GitHub, GitLab и локального пути. Метаданные, которых нет в локальной директории (branch protection, releases, звёзды), — через фикстурный `metadata.yaml`.

### 1.2. Синтетические фикстуры (детерминированные, без сети)

`tests/fixtures/repos/<name>/` + `tests/fixtures/repos/<name>/expected.yaml`. Минимальный набор:

| Фикстура | Что проверяет |
|---|---|
| `lib-python-tox` | pyproject.toml, тесты через `tox` в workflow → `tests_in_ci: pass`, все docker-проверки `na`, observability `na` |
| `tests-via-makefile` | в workflow `run: make check`, в Makefile цель `check` вызывает pytest → `pass` |
| `tests-via-script` | в workflow `run: bash scripts/test.sh`, в скрипте `pytest` → `pass` |
| `tests-via-reusable-workflow` | `uses: ./.github/workflows/_test.yml` → `pass` |
| `gitlab-ci-include` | тесты в файле, подключённом через `include:` в `.gitlab-ci.yml` → `pass` |
| `no-tests-anywhere` | CI есть, только lint и build → `fail` |
| `service-docker-root` | Dockerfile без `USER` → `container_nonroot: fail` |
| `service-docker-good` | multi-stage, `USER app`, pinned base → всё `pass` |
| `no-dockerfile-service` | сервис без Dockerfile → `dockerfile_present: fail`, ВСЕ зависимые docker-проверки `na` |
| `changelog-history-md` | `History.md` (как у express) → `changelog: pass` |
| `changelog-in-docs` | `docs/release-notes.md` → `pass` |
| `security-in-github-dir` | `.github/SECURITY.md` → `pass` |
| `readme-rst` | `README.rst`, `CONTRIBUTING.rst` → `pass` |
| `docs-only` | только markdown (awesome-list) → почти всё `na`, score по оставшимся |
| `terraform-module` | `.tf` файлы, без `.terraform.lock.hcl` → lock-файл `na` для модуля, docker `na` |
| `monorepo-pnpm` | `pnpm-workspace.yaml`, Dockerfile в `apps/api/` → docker-проверки выполняются по нему |
| `aws-example-key` | в README документационный ключ `AKIAIOSFODNN7EXAMPLE` → секрет НЕ находится (или `info`, не `critical`) |
| `empty-repo` | пустой репозиторий → нет падения, score не вычисляется, понятное сообщение |

Формат `expected.yaml`:

```yaml
expected_type: library   # library | service | iac | docs | monorepo
checks:                  # перечислены только утверждаемые проверки
  tests_in_ci: pass
  dockerfile_present: na
```

### 1.3. Живой эталонный набор

Файл `tests/golden/golden-set.yaml` (затравка приложена отдельно: `golden-set.seed.yaml`). Правила:

- каждый репозиторий закреплён на commit SHA (`ref`), иначе ожидания «уплывут»;
- снапшот репозитория на этом SHA скачивается один раз (tarball) и кешируется — прогон не должен упираться в rate limit;
- записи с `verified: false` участвуют в прогоне, но в отчёте помечаются отдельно; их надо проверить руками (это делает владелец продукта, не агент);
- цель — 30+ репозиториев. Добавь 10–15 небольших реальных репозиториев с НАСТОЯЩИМИ проблемами из истории сканирований в базе (если доступ есть) — иначе набор будет перекошен в сторону «хороших» проектов и не поймает ложные PASS.

### 1.4. Команда прогона

`make eval` (или аналог в принятом в проекте стиле) выводит:

- для каждой проверки: матрицу `expected × actual` по статусам, precision и recall для FAIL;
- список расхождений: репозиторий, проверка, ожидалось, получено, evidence;
- итоговые метрики и сравнение с предыдущим прогоном (сохраняй `eval-baseline.json`).

Прогон на синтетических фикстурах — в CI на каждый PR. Прогон на живом наборе — вручную или по расписанию.

**Готово, когда:** базовый прогон на текущей логике зафиксирован в `eval-baseline.json` и описан в PR (ожидаемо много расхождений — это нормально).

---

## Этап 2. Модель результата: четыре статуса и зависимости

### 2.1. Статусы

- `pass` — требование выполнено;
- `fail` — требование применимо и не выполнено (с severity: critical / warn / info);
- `na` — неприменимо к этому репозиторию (тип проекта или отсутствует объект проверки);
- `unknown` — не удалось проверить (нет прав, API недоступен, таймаут).

`na` и `unknown` не входят в знаменатель score. `unknown` показывается в отчёте с причиной («нужен токен с правами admin, чтобы прочитать branch protection»).

### 2.2. Зависимости между проверками

Каждая проверка объявляет, от чего зависит, например:

```
container_nonroot       requires: dockerfile
dockerfile_multistage   requires: dockerfile
base_image_pinned       requires: dockerfile
dockerignore            requires: dockerfile
healthcheck             requires: compose OR dockerfile
compose_resource_limits requires: compose
lockfile_present        requires: dependency_manifest
```

Если зависимость не выполнена — `na`, никогда не `pass`.

### 2.3. Evidence

Каждый результат обязан содержать evidence: где искали и что нашли.
- `pass`: файл и строка (`.github/workflows/test.yml:42 — pytest`);
- `fail`: где искали (`проверено 4 workflow, Makefile, scripts/*.sh — команд запуска тестов не найдено`);
- `na`: причина (`тип репозитория: library`, `Dockerfile не найден`).

Evidence показывается в отчёте под каждой проверкой (свёрнуто). Это главный инструмент доверия: инженер видит, почему вывод такой, и может сам найти ошибку.

**Готово, когда:** фикстура `no-dockerfile-service` проходит; ни одна проверка не даёт `pass` при отсутствии своего объекта.

---

## Этап 3. Определение типа репозитория

Типы: `library`, `service`, `iac`, `docs`, `monorepo` (монорепо дополнительно содержит список подпроектов со своими типами).

Эвристики (с весами, итог — тип + confidence):

- **library:** `pyproject.toml` с `[project]`/`[tool.poetry]` и без признаков приложения; `package.json` с `main`/`exports`/`types` и без `"private": true`; `go.mod` без `package main` в корне и `cmd/`; `Cargo.toml` с `[lib]`; `setup.py`; workflow с публикацией в PyPI/npm/crates; topics репозитория (`library`, `framework`, `sdk`).
- **service:** Dockerfile, docker-compose, k8s/helm/nomad-манифесты для самого приложения, `Procfile`, `"private": true`, `cmd/<name>/main.go`, `manage.py` в корне (Django-проект, а не сам Django), workflow с деплоем.
- **iac:** преобладание `.tf`/`.hcl`, `Chart.yaml`, `kustomization.yaml`, Ansible-роли (`tasks/main.yml`, `playbooks/`), `*.nomad.hcl`.
- **docs:** > 80% файлов — `.md/.rst/.adoc`, нет манифестов зависимостей.
- **monorepo:** `pnpm-workspace.yaml`, `workspaces` в package.json, `go.work`, `nx.json`, `turbo.json`, `lerna.json`, несколько манифестов в поддиректориях.

Переопределение:
- в настройках репозитория в интерфейсе (для приватных);
- файлом `.devopscheck.yml` в корне репозитория (`type: service`, `ignore: [changelog]`, `paths: [apps/api]`).

В отчёте показывается определённый тип и ссылка «Неверно? Изменить».

**Готово, когда:** на эталонном наборе тип определяется верно в ≥ 90% случаев; ошибки перечислены в PR.

---

## Этап 4. Матрица применимости

Создай единый источник правды (конфиг или код, не разбросанные `if`): проверка × тип → `required` / `recommended` / `na`. Отправная точка (уточни по реальному списку проверок):

| Проверка | library | service | iac | docs |
|---|---|---|---|---|
| tests_in_ci | required | required | recommended (validate/lint/tflint/terratest) | na |
| dockerfile_present | na | required | na | na |
| docker-зависимые | na | по requires | na | na |
| observability | na | recommended | na | na |
| lockfile_present | recommended (npm/py — info) | required | na для модулей | na |
| dependency_manifest | required | required | na | na |
| changelog | recommended | recommended | recommended | na |
| security_policy | required | recommended | recommended | na |
| contributing | recommended | info | recommended | recommended |
| codeowners | recommended | recommended | recommended | info |
| secrets_in_code | required | required | required | required |
| workflow_permissions | required | required | required | required |
| actions_pinned_sha | required | required | required | required |
| license | required | info | required | recommended |

`recommended` при несоблюдении даёт максимум `warn`, `info` — только `info`.

---

## Этап 5. Исправление детекторов

### tests_in_ci
- Разбирать ВСЕ workflow в `.github/workflows/`, включая reusable (`uses: ./.github/workflows/...`) и composite actions (`uses: ./.github/actions/...`).
- Искать в `run:` команды: `pytest`, `python -m pytest`, `tox`, `nox`, `coverage run`, `go test`, `cargo test`, `npm|yarn|pnpm|bun test`, `npm run test*`, `jest`, `vitest`, `mocha`, `mvn test|verify`, `gradle test|check`, `make test|check`, `dotnet test`, `phpunit`, `rspec`, `bundle exec rake`.
- Следовать на один уровень вглубь: `bash scripts/*.sh`, цели Makefile, `scripts` в package.json, `tox.ini`/`noxfile.py`, `justfile`, `Taskfile.yml`.
- Эвристика-подстраховка: job или workflow с именем, содержащим `test`, и шагом `run` → `pass` с пометкой в evidence «по имени job».
- GitLab: `include:` (local, project, template), `extends:`, стадии `test`; CircleCI, Jenkinsfile, Drone, Azure Pipelines, Woodpecker — хотя бы по ключевым командам.

### changelog
Искать без учёта регистра и расширения: `CHANGELOG*`, `CHANGES*`, `HISTORY*`, `NEWS*`, `RELEASES*`, `RELEASE_NOTES*`; в `docs/**` файлы и каталоги `release-notes*`, `changelog*`, `releases/`; конфиги `.changeset/`, `towncrier` (newsfragments), `release-please-config.json`, `.goreleaser.yml`. Если ничего нет — GitHub/GitLab Releases с непустым описанием за последний год → `pass`.

### security_policy, contributing, codeowners, readme
- Расширения `.md`, `.rst`, `.txt`, `.adoc`, без учёта регистра.
- Расположения: корень, `.github/`, `docs/`, для GitLab — `.gitlab/`.
- Наследование от организации: на GitHub SECURITY.md и CONTRIBUTING из репозитория `<org>/.github` применяются ко всем репозиториям организации → `pass` с evidence «унаследовано от org/.github».
- security_policy: также `pass`, если включён private vulnerability reporting (если доступно через API).

### branch_protection
Без прав администратора правила защиты не читаются. Попробовать rulesets API (`/repos/{owner}/{repo}/rules/branches/{branch}`), иначе — `unknown`, а не `pass` и не `fail`.

### secrets_in_code
- Исключать известные документационные ключи (`AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` и подобные), файлы в `test/`, `tests/`, `fixtures/`, `examples/` понижать до `info` с пометкой.
- Учитывать энтропию и контекст (`example`, `dummy`, `xxx`, `<your-key>`).

### docker-проверки в монорепо
Искать все Dockerfile (`Dockerfile`, `*.Dockerfile`, `Dockerfile.*`), кроме каталогов тестов и примеров; проверки выполняются по каждому, в отчёте — результат по файлу.

**Готово, когда:** precision FAIL ≥ 95% по каждой проверке на эталонном наборе; все синтетические фикстуры зелёные.

---

## Этап 6. Score v2 и миграция

- Score = взвешенное среднее только по применимым проверкам (`pass`/`fail`), severity влияет на вес.
- Категория, в которой все проверки `na`, не показывается и не влияет на score (сейчас такие категории, вероятно, дают 100 или 0 — проверь).
- Версия методики хранится с каждым результатом (`methodology: v2`). На графике истории — отметка «смена методики», чтобы скачок score не выглядел как изменение репозитория.
- Пересканировать все публичные страницы `/scan/*` и rankings после выката; OG-картинки перегенерировать.
- Бейджи в чужих README автоматически покажут новый score — это ожидаемо.

---

## Этап 7. Отчёт (UI)

- Под заголовком: определённый тип репозитория и «Неверно? Изменить».
- Проверки со статусом `na` — в свёрнутом блоке «Неприменимо (N)» с причиной.
- `unknown` — отдельно, с объяснением, что нужно для проверки.
- У каждой проверки — раскрывающийся evidence.
- Кнопка «Это ложное срабатывание» у каждого FAIL: сохраняет репозиторий, SHA, проверку и комментарий. Эти записи — главный источник новых кейсов для эталонного набора.

---

## Критерии приёмки всего ТЗ

1. Отчёт по `fastapi/fastapi` не содержит FAIL по tests_in_ci, dockerfile_present, container_nonroot, observability, changelog.
2. Ни одна проверка не даёт `pass`, если объекта проверки нет.
3. Синтетические фикстуры гоняются в CI на каждый PR.
4. На живом наборе (30+ репозиториев) precision FAIL ≥ 95% по каждой проверке, общая доля ложных FAIL ≤ 3%.
5. Все публичные страницы пересканированы по методике v2.
