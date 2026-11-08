# Инвентаризация проверок (этап 0 ТЗ `docs/accuracy/spec.md`)

Состояние на `main` = `8a00a00` (2026-09-26). 58 проверок в 7 модулях.
Все проверки возвращают словарь `_c(...)`: `check_id, name, description,
severity, passed (bool), category, recommendation, applicable, not_applicable_reason`.
Статуса `unknown` и поля evidence сейчас **нет** (см. «Противоречия»).

Обозначения в колонке «Зависит от»: что должно существовать, чтобы проверка
имела смысл. «**пустота→pass**» — сейчас проверка даёт `pass`, когда объекта нет
(нарушает требование 2 ТЗ). «**na**» — сейчас корректно уходит в неприменимые.

## 1. Соответствие условных имён ТЗ реальным ID

| Имя в ТЗ | Реальный `check_id` |
|---|---|
| tests_in_ci | `ci.tests` |
| dockerfile_present | `docker.dockerfile` |
| container_nonroot | `docker.nonroot` |
| dockerfile_multistage | `docker.multistage` |
| base_image_pinned | `docker.pinned_base` |
| dockerignore | `docker.dockerignore` |
| healthcheck | `docker.healthcheck` |
| compose_resource_limits | `docker.resource_limits` |
| observability | `ops.observability` |
| lockfile_present | `deps.lockfile` |
| dependency_manifest | `deps.manifest` |
| changelog | `docs.changelog` |
| security_policy | `security.security_policy` |
| contributing | `docs.contributing` |
| codeowners | `security.codeowners` |
| readme | `docs.readme` |
| license | `ops.license` |
| secrets_in_code | `security.no_secrets` |
| workflow_permissions | `actions.broad_permissions` |
| actions_pinned_sha | `actions.pinned_sha` |
| branch_protection | `ci.branch_protection` |

Типы репозиториев: ТЗ `library/service/iac/docs/monorepo` ↔ код
`library/service/infrastructure/docs/monorepo` + дополнительно `cli` и `unknown`
(`app/repo_kind.py`). `iac` = `infrastructure`.

## 2. Таблица проверок

### checks.py — security

| ID | Название | Кат. | Sev | Что ищет | Зависит от | Известные слабости |
|---|---|---|---|---|---|---|
| security.env_gitignored | .env is ignored by git | security | crit | строка `.env` в `.gitignore` (regex `^\s*!?\*?\.env`) | проект использует .env (`uses_dotenv`: .env/.env.example/python-dotenv и т.п.) | **пустота→pass**: без dotenv даёт pass, а не na |
| security.dependency_updates | Automated dependency updates | security | warn | `.github/dependabot.y(a)ml`, `renovate.json`, `.renovaterc*`, `.github/renovate.json` | манифест зависимостей | нет `renovate.json5`, `.gitlab/renovate.json`, `package.json#renovate`; для docs/iac без зависимостей всё равно требуется |
| security.security_policy | Security policy (SECURITY.md) | hygiene¹ | info | `SECURITY.md` в корне, `.github/`, `docs/` | — | только `.md`, регистр важен; нет `.gitlab/`, `.rst/.txt/.adoc`; нет наследования от `<org>/.github`; нет private vulnerability reporting |
| security.codeowners | CODEOWNERS is configured | hygiene¹ | info | `.github/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS`, `.gitlab/CODEOWNERS` | — | ок по путям; регистр важен |

### checks_secrets.py

| ID | Название | Кат. | Sev | Что ищет | Зависит от | Слабости |
|---|---|---|---|---|---|---|
| security.no_secrets | No secrets committed to the repository | security | crit/warn | 17 правил (AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI, Anthropic, SendGrid, Twilio, npm, Telegram, PEM, JWT, DB URL, generic+энтропия) по ≤45 файлам с приоритетом; плейсхолдеры отсеиваются; PEM/generic в test/example → fixture | — | `AKIAIOSFODNN7EXAMPLE` (документационный ключ AWS) **не исключён**: провайдерские правила не смягчаются в `examples/`/README; только 45 файлов дерева |
| security.env_not_committed | .env file is not committed | security | crit | `.env`/`*/.env` вне example/test/docs/template | — | ок |
| security.no_secrets_in_history | No secrets in git history | security | crit/warn | те же правила по всем blob'ам истории (partial clone) | только аудиты владельца (`deep=True`) | в публичном скане отсутствует |
| security.secret_active | No live credentials in the repository | security | crit | проверка активности у провайдера | найденный секрет + `deep=True` | появляется только при fail |

### checks.py — CI/CD

| ID | Название | Кат. | Sev | Что ищет | Зависит от | Слабости |
|---|---|---|---|---|---|---|
| ci.pipeline | CI/CD pipeline configured | ci_cd | warn | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `.circleci/config.yml`, `Jenkinsfile`, `.drone.yml` | — | нет Azure Pipelines, Woodpecker, Bitbucket, Buildkite |
| ci.tests | Tests run in CI | ci_cd | warn | подстрока из 35 слов (`pytest`, `tox`, `make test`, `uv run`…) в объединённом тексте CI-файлов (≤15 workflow); подстраховки: имя workflow/`name:` содержит test; `run: *test*.sh`; `uses: …workflows/*test*.yml` | CI | **не следует** в Makefile/скрипты/package.json scripts/tox.ini/локальные reusable/composite actions/GitLab `include: local`; подстрока без границ слов (`uv run` даёт pass на что угодно); для docs-репо не na |
| ci.branch_protection | Default branch is protected | ci_cd | warn | GitHub `GET /branches/{b}` → `protected`; GitLab `/protected_branches/{b}` | права API | **без прав возвращает fail**, а не unknown; публичный скан без токена всегда fail; rulesets не смотрим |
| ci.linter | Linter or formatter configured | ci_cd | info | конфиги из `LINTER_FILES` (включая `pyproject.toml`!) | — | `pyproject.toml` сам по себе считается линтером → ложный pass |
| ci.security_scan | Security scanning in the pipeline | ci_cd | warn | 20 слов сканеров в тексте CI (+GitLab шаблоны SAST/secret-detection) | CI | не видит сканеры в подключаемых файлах/скриптах; CodeQL default setup (без workflow) не виден |

### checks.py — Docker

| ID | Название | Кат. | Sev | Что ищет | Зависит от | Слабости |
|---|---|---|---|---|---|---|
| docker.dockerfile | Dockerfile present | docker | warn | первый из `Dockerfile`, `docker/Dockerfile`, `build/Dockerfile`, `deploy/Dockerfile` | тип service | нет `*.Dockerfile`, `Dockerfile.*`, `Containerfile`, `apps/*/Dockerfile` (монорепо) |
| docker.dockerignore | .dockerignore configured | docker | info | `.dockerignore` в корне | Dockerfile | **не зависит от Dockerfile**: без Dockerfile даёт fail (если тип не library/cli/infra/docs) |
| docker.healthcheck | Healthcheck defined | docker | warn | `healthcheck` в compose или `HEALTHCHECK` в Dockerfile | compose OR Dockerfile | **na** при отсутствии обоих ✔ |
| docker.nonroot | Container runs as a non-root user | docker | warn | `USER ` в Dockerfile и не `USER root/0` | Dockerfile | **na** ✔; последний `USER` не учитывается (USER app → USER root) |
| docker.pinned_base | Base image is pinned (not :latest) | docker | warn | каждый `FROM` имеет тег и не `:latest` | Dockerfile | **na** ✔; `FROM stage-name` (ссылка на стадию) считается непиннутым образом |
| docker.multistage | Dockerfile uses a multi-stage build | docker | warn | >1 `FROM` | Dockerfile | **na** ✔ |
| docker.resource_limits | Resource limits set in compose | docker | warn | `mem_limit` или `deploy`+`limits` в compose | compose | **na** ✔; проверяет весь файл, а не каждый сервис |

### checks.py — docs (все кроме readme_quality — hygiene¹)

| ID | Название | Кат. | Sev | Что ищет | Слабости |
|---|---|---|---|---|---|
| docs.readme | README exists | hygiene¹ | info | 8 путей (`README.md/.rst/.txt/README/readme.md/Readme.md/docs/README.md/docs/index.md`) | регистр (`ReadMe.md`, `README.MD`), `.adoc` |
| docs.readme_quality | README explains how to run the project | hygiene¹ | info | >500 символов и слово install/setup/usage/… | эвристика |
| docs.changelog | CHANGELOG maintained | hygiene¹ | info | 12 точных путей (`CHANGELOG.md`, `HISTORY.md`, `NEWS.rst`…) | **регистр** (`History.md` у express), нет `docs/**/release-notes*` (fastapi), `docs/releases/` (django), `.changeset/`, towncrier, release-please, goreleaser, GitHub Releases |
| docs.contributing | CONTRIBUTING guide | hygiene¹ | info | 5 путей | нет `.gitlab/`, `docs/CONTRIBUTING.rst`, регистр, наследование от org |
| docs.templates | Pull request / issue templates | hygiene¹ | info | `.github/pull_request_template.md`, `ISSUE_TEMPLATE/`, `.gitlab/*_templates` | — |

### checks.py — deps

| ID | Название | Кат. | Sev | Что ищет | Зависит от | Слабости |
|---|---|---|---|---|---|---|
| deps.manifest | Dependency manifest present | deps | crit | 14 корневых манифестов | тип с кодом | только корень |
| deps.lockfile | Lock file present | deps | warn | 13 lock-файлов в корне | манифест | **не зависит от манифеста** (без манифеста — fail); npm/py-библиотеки обычно не коммитят lock → fail |
| deps.pinned | Dependencies pinned to exact versions | deps | warn | `==`/`~=` в каждой строке `requirements.txt` | requirements.txt | **пустота→pass**: без requirements.txt даёт pass |
| deps.cve | Known vulnerabilities in dependencies | deps | crit/warn/info | OSV.dev по ≤100 пакетам из корневых `requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`; reachability понижает (этап 4.4 roadmap) | манифест | проверки нет, если манифестов нет (ок); сеть в прогоне |

### checks.py — ops (все кроме observability — hygiene¹)

| ID | Название | Кат. | Sev | Что ищет | Слабости |
|---|---|---|---|---|---|
| ops.gitignore | .gitignore configured | hygiene¹ | info | непустой `.gitignore` | — |
| ops.env_example | .env.example documents required variables | hygiene¹ | info | `.env` в .gitignore → нужен `.env.example`… | **пустота→pass**, когда `.env` не упомянут |
| ops.license | License specified | hygiene¹ | info | 9 имён в корне | регистр, `LICENSE-*`, `COPYING.*` |
| ops.activity | Repository is actively maintained | hygiene¹ | info | `pushed_at` < 180 дней | **зависит от текущей даты** → эталон «плывёт» (сейчас все фикстуры fail) |
| ops.observability | Observability / monitoring (checks_extra) | ops | warn | библиотеки Sentry/Prometheus/OTel/… в 5 корневых манифестах | для library na ✔ (repo_kind); для service только корень |

### checks_extra.py — Kubernetes (возвращает [] без манифестов)

| ID | Кат. | Sev | Что ищет | Слабости |
|---|---|---|---|---|
| k8s.resource_limits | ops | warn | `resources:…limits:` хоть где-то в YAML из 8 каталогов | «хоть где-то», а не в каждом контейнере; Helm-шаблоны не рендерятся |
| k8s.nonroot | ops | warn/crit | `runAsNonRoot: true`; `privileged: true` → crit | то же |
| k8s.probes | ops | warn | `livenessProbe:` и `readinessProbe:` | Job/CronJob не нуждаются в пробах, но учитываются |

### checks_iac.py — Terraform (возвращает [] без `.tf`)

| ID | Кат. | Sev | Что ищет | Слабости |
|---|---|---|---|---|
| iac.remote_state | iac | crit/warn | `backend "s3|gcs|…"` + locking | **модуль** (как terraform-aws-vpc) не должен иметь backend → ложный crit fail |
| iac.open_ingress | iac | crit | ingress 0.0.0.0/0 на чувствительные порты | `examples/` исключены ✔ |
| iac.encryption_at_rest | iac | warn | S3/RDS/EBS без шифрования | только при наличии ресурсов ✔ |
| iac.private_database | iac | crit | `publicly_accessible = true` | ✔ |
| iac.no_public_buckets | iac | crit | `acl = "public-read…"` | ✔ |
| iac.no_hardcoded_credentials | iac | crit | литералы ключей в .tf | ✔ |
| iac.pinned_providers | iac | warn | `required_providers` + `version =` | ✔ |
| iac.scanning | iac | warn | tfsec/checkov/trivy config в CI | как ci.security_scan |

### checks_cicd.py — GitHub Actions (возвращает [] без workflow)

| ID | Sev | Что ищет |
|---|---|---|
| actions.pinned_sha | warn | `uses: owner/repo@ref`, ref не 40-hex SHA |
| actions.script_injection | crit | `${{ github.event.* }}` недоверенных полей в `run:` |
| actions.pull_request_target | crit | `pull_request_target` + checkout head |
| actions.broad_permissions | warn | нет `permissions:` или `write-all` |
| actions.self_hosted_public | crit | `runs-on: self-hosted` в публичном репо |
| actions.cloud_oidc | warn | статические облачные ключи в workflow без OIDC |

### checks_cicd.py — GitLab CI (возвращает [] без `.gitlab-ci.yml`)

| ID | Sev | Что ищет |
|---|---|---|
| gitlab_ci.pinned_includes | warn | `include: project/remote` без `ref`/SHA |
| gitlab_ci.pinned_images | warn | `image:`/`services:` без тега/с `:latest` |
| gitlab_ci.cloud_oidc | warn | статические облачные ключи без `id_tokens` |

### checks_ai_agents.py (возвращает [] без соответствующих файлов)

| ID | Sev | Что ищет |
|---|---|---|
| ai.mcp_secrets | crit | литеральные токены в MCP-конфигах |
| ai.mcp_pinned | warn | `npx/uvx` MCP-серверы без версии |
| ai.agent_ci_exposed | crit/warn | AI-агент в CI на внешних событиях с правом записи |
| ai.instructions_clean | warn | секреты/внутренние URL в CLAUDE.md/AGENTS.md/.cursorrules |

¹ `hygiene` — с методики score v2 (коммит `1b3ca5c`) эти проверки показываются
отдельным блоком и **не входят в балл** (`checks.HYGIENE_CHECKS`).

## 3. Как считается score

- `checks.calculate_score()`: веса по severity `crit=30, warn=15, info=5`;
  `score = round(Σвес(pass) / Σвес(все учитываемые) × 100)`.
- Учитываются только `counts(c)`: `applicable=True` и категория не `hygiene`.
  `na` (applicable=False) уже не входит в знаменатель ✔.
- Категории: `get_category_scores()` — та же формула внутри категории;
  категория без учитываемых проверок **не появляется** в словаре ✔ (ТЗ этап 6
  опасался, что даёт 100 или 0 — не даёт).
- Весов категорий нет: все категории равноправны через веса проверок.
- `SCORE_VERSION = 2` (`app/checks.py`); v1 → v2 при выносе гигиены из балла.

## 4. Где хранится история

- `Audit` — одна строка на запуск (append-only): `score`, `category_scores`,
  `score_version`, `repo_kind`, `kind_confidence`, `commit_sha`; строки
  `AuditCheck` (passed/severity/applicable/not_applicable_reason, без evidence).
- `PublicScan` — **одна** строка на публичный репозиторий, перезаписывается при
  пересканировании (`results` JSON, `score`, `category_scores`, `repo_kind`);
  истории у публичных сканов нет.
- `/badge/` и OG-картинки читают эти же строки.

## 5. Источники файлов (к этапу 1.1)

`app/repo_client.py`: `RepoClient` (индекс путей + кеш содержимого) с
реализациями `GithubRepoClient`, `GitlabRepoClient` (архив одним запросом) и
`StaticRepoClient` (словарь в памяти, тесты/golden). Интерфейс уже есть:
`files`, `exists`, `list_dir`, `get_content`, `local_text`, метаданные
(`pushed_at`, `stars`, `is_private`, `default_branch`, `branch_is_protected()`).
Нет только реализации «локальная директория + metadata.yaml».

## 6. Противоречия ТЗ и кода (правило 4 ТЗ)

1. **MR на каждый этап.** Нет доступа к API GitLab (нет `glab`/токена). Ветки
   пушатся, описание MR — в `docs/accuracy/stage-N.md` и в merge-коммите;
   мерж и деплой — по постоянному правилу владельца (self-review → merge →
   deploy).
2. **«CI на каждый PR».** У самого проекта нет `.gitlab-ci.yml`; прогон
   фикстур делается через `manage.py test` (как `GoldenCorpusTest`). Добавить
   `.gitlab-ci.yml` можно, но shared runners gitlab.com требуют верификации
   аккаунта — нужно решение владельца.
3. **Гигиена вне балла vs матрица применимости (этап 4).** Владелец 2026-09-25
   вынес CODEOWNERS/CHANGELOG/SECURITY.md/лицензию и т.п. из балла. Матрица ТЗ
   делает `security_policy` и `license` `required` для library. Решение нужно
   от владельца перед этапом 4 (предложение: severity из матрицы применять,
   но оставить эти проверки вне балла, т.е. матрица управляет na/severity
   внутри блока гигиены).
4. **`.devopscheck.yml` vs существующий `.devopsaudit.yml`** (`kind:`,
   `ignore:` с обязательной причиной, `allow_secrets:`). Предложение: читать
   оба имени, `type:` — синоним `kind:`, `ignore:` без причины по-прежнему
   отклонять (иначе балл можно «накрутить»).
5. **«Score v2»** — номер уже занят (гигиена). Методика ТЗ станет
   `SCORE_VERSION = 3`.
6. **Статусы `unknown` и evidence** требуют новых полей `AuditCheck`
   (миграция) и нового формата `PublicScan.results`.
7. **Эталонный набор**: существующий golden (9 репозиториев) хранит частичное
   содержимое без SHA. ТЗ требует SHA + кешированный tarball. Живой набор
   делается заново по `golden-set.yaml`; старый golden остаётся регрессией
   до замены.
8. **«10–15 реальных репозиториев с проблемами из истории сканов»**: в базе
   прода всего 8 публичных сканов (баллы 67–78). Кандидатов придётся
   подбирать вне базы.
9. **`ops.activity` зависит от текущей даты** — для детерминированного прогона
   нужен фиксированный «now» (дата снапшота) в eval.
