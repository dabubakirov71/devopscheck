"""
Public guide pages, one per check: /checks/ and /checks/<check_id>/.

Each page answers the question an engineer types into a search engine
("run docker container as non-root", "pin github actions to sha") and ends
with the scanner, which checks their own repository for it. The fix text is
the same built-in advice the report gives (ai_providers._BUILTIN) or the
check's own recommendation, so a guide never says something the product
does not.

Titles and "why" are written per language here rather than through gettext:
they are long-form copy for search, not UI strings.
"""
import json
from functools import lru_cache
from pathlib import Path

# check_id: (title_en, title_ru, why_en, why_ru)
GUIDES = {
    'security.no_secrets': (
        'How to find and remove secrets committed to a Git repository',
        'Как найти и убрать секреты, закоммиченные в Git-репозиторий',
        'An API key or password in the source is readable by everyone who can clone the repository — '
        'and, for a public one, by the bots that scan GitHub for keys within minutes of a push. '
        'Deleting the line is not enough: the value stays in history until it is rotated.',
        'API-ключ или пароль в исходниках видит каждый, кто может склонировать репозиторий, а у публичного — '
        'боты, которые сканируют GitHub на ключи в течение минут после push. Удалить строку мало: значение '
        'остаётся в истории, пока ключ не перевыпущен.'),
    'security.env_gitignored': (
        'Why .env must be in .gitignore (and how to check it is not already committed)',
        'Почему .env должен быть в .gitignore (и как проверить, что он уже не закоммичен)',
        'A .env file collects every secret the application needs in one place. Without a .gitignore rule, '
        'one `git add .` publishes all of them at once.',
        'Файл .env собирает все секреты приложения в одном месте. Без правила в .gitignore один `git add .` '
        'публикует их все сразу.'),
    'security.env_not_committed': (
        'A .env file is committed to the repository: what to do',
        'Файл .env закоммичен в репозиторий: что делать',
        'A tracked .env file is a leak even if the repository is private today: every clone, fork and CI '
        'cache carries it. Remove it from the index, rewrite history if it held real values, and rotate them.',
        'Отслеживаемый .env — это утечка, даже если репозиторий сегодня приватный: он есть в каждом клоне, '
        'форке и кеше CI. Уберите его из индекса, перепишите историю, если там были реальные значения, и '
        'перевыпустите их.'),
    'security.dependency_updates': (
        'Automated dependency updates with Dependabot or Renovate',
        'Автообновление зависимостей: Dependabot или Renovate',
        'Most breaches through dependencies use vulnerabilities that already had a patch. A bot that opens '
        'the update as a pull request the day the patch ships closes that window without anyone remembering to.',
        'Большинство взломов через зависимости используют уязвимости, для которых уже был патч. Бот, который '
        'открывает обновление pull request’ом в день выхода патча, закрывает это окно без чьей-то памяти.'),
    'security.security_policy': (
        'How to add a SECURITY.md security policy to a repository',
        'Как добавить политику безопасности SECURITY.md в репозиторий',
        'Without a stated way to report a vulnerability privately, researchers open a public issue — and the '
        'details are out before a fix exists. GitHub shows SECURITY.md in the Security tab.',
        'Без указанного способа сообщить об уязвимости приватно исследователь откроет публичный issue — и '
        'детали окажутся в открытом доступе до исправления. GitHub показывает SECURITY.md во вкладке Security.'),
    'security.codeowners': (
        'How to set up CODEOWNERS for required reviews',
        'Как настроить CODEOWNERS для обязательного ревью',
        'CODEOWNERS requests review from the right people automatically, and with branch protection it makes '
        'their approval required for the paths they own — CI config and infrastructure included.',
        'CODEOWNERS автоматически назначает ревьюеров, а вместе с защитой ветки делает их одобрение '
        'обязательным для их путей — включая конфигурацию CI и инфраструктуру.'),
    'ci.pipeline': (
        'Setting up a CI/CD pipeline for every push',
        'Как настроить CI/CD-пайплайн на каждый push',
        'A pipeline is the one reviewer that never skips a step: build, tests, linters and scanners run on '
        'every change, not only when someone remembers.',
        'Пайплайн — единственный ревьюер, который никогда не пропускает шаг: сборка, тесты, линтеры и сканеры '
        'запускаются на каждом изменении, а не когда кто-то вспомнил.'),
    'ci.tests': (
        'How to run tests in CI on every pull request',
        'Как запускать тесты в CI на каждый pull request',
        'Tests that only run on a laptop protect nothing: the regression reaches the main branch the first '
        'time someone forgets. DevOpsCheck follows Makefile targets, package scripts, shell scripts and '
        'GitLab includes to find the test command, not only the workflow file.',
        'Тесты, которые запускаются только на ноутбуке, ничего не защищают: регрессия попадает в основную '
        'ветку, как только кто-то забыл. DevOpsCheck находит команду тестов через цели Makefile, скрипты '
        'package.json, shell-скрипты и include в GitLab, а не только в самом workflow.'),
    'ci.branch_protection': (
        'How to protect the main branch on GitHub and GitLab',
        'Как защитить основную ветку на GitHub и GitLab',
        'An unprotected default branch accepts a force-push or a direct commit from anyone with write '
        'access — or anyone holding their token. Protection (or a ruleset) requires review and green CI first.',
        'Незащищённая основная ветка принимает force-push и прямой коммит от любого с правом записи — или от '
        'любого, у кого его токен. Защита (или ruleset) требует ревью и зелёный CI.'),
    'ci.linter': (
        'Adding a linter or formatter to your project',
        'Как добавить линтер или форматтер в проект',
        'An enforced style removes a whole class of review comments and catches simple bugs — unused '
        'variables, shadowed names — before a human reads the diff.',
        'Единый обязательный стиль убирает целый класс замечаний на ревью и ловит простые ошибки — '
        'неиспользуемые переменные, затенённые имена — до того, как человек прочтёт diff.'),
    'ci.security_scan': (
        'Adding security scanning (Trivy, gitleaks, CodeQL) to CI',
        'Как добавить сканирование безопасности (Trivy, gitleaks, CodeQL) в CI',
        'A scanner in the pipeline catches a vulnerable dependency, a leaked key or a dangerous pattern in '
        'the pull request — where fixing it costs one commit, not an incident.',
        'Сканер в пайплайне ловит уязвимую зависимость, утёкший ключ или опасный паттерн в pull request’е — '
        'там, где исправление стоит один коммит, а не инцидент.'),
    'docker.dockerfile': (
        'Writing a production Dockerfile',
        'Как написать Dockerfile для продакшена',
        'A Dockerfile makes the runtime reproducible: the image you tested is the image that runs. For a '
        'library this check does not apply — DevOpsCheck detects the repository type first.',
        'Dockerfile делает окружение воспроизводимым: запускается ровно тот образ, который тестировали. К '
        'библиотеке эта проверка не применяется — DevOpsCheck сначала определяет тип репозитория.'),
    'docker.dockerignore': (
        'What to put in .dockerignore',
        'Что добавить в .dockerignore',
        'Without .dockerignore the whole directory — .git, node_modules, local .env files — is sent to the '
        'build and can end up inside the image.',
        'Без .dockerignore в сборку уходит весь каталог — .git, node_modules, локальные .env — и всё это может '
        'оказаться внутри образа.'),
    'docker.healthcheck': (
        'How to add a Docker healthcheck',
        'Как добавить healthcheck в Docker',
        'Without a healthcheck the orchestrator only knows the process is alive, not that it answers. A hung '
        'container keeps receiving traffic instead of being restarted.',
        'Без healthcheck оркестратор знает только, что процесс жив, но не что он отвечает. Зависший '
        'контейнер продолжает получать трафик вместо перезапуска.'),
    'docker.nonroot': (
        'How to run a Docker container as a non-root user',
        'Как запустить Docker-контейнер не от root',
        'A process running as root inside the container is root on the host the moment it escapes — through '
        'a kernel bug, a mounted socket or a misconfigured volume. A USER line costs nothing.',
        'Процесс от root внутри контейнера становится root на хосте, как только выберется наружу — через баг '
        'ядра, примонтированный сокет или неверный volume. Строка USER ничего не стоит.'),
    'docker.pinned_base': (
        'Why pin Docker base images (and not use :latest or python:slim)',
        'Зачем закреплять базовый образ Docker (а не :latest или python:slim)',
        'A floating tag — :latest, or a tag with no version like python:slim — resolves to a different image '
        'on every build, so two builds of the same commit can behave differently in production.',
        'Плавающий тег — :latest или тег без версии вроде python:slim — на каждой сборке указывает на другой '
        'образ, и две сборки одного коммита могут вести себя в проде по-разному.'),
    'docker.multistage': (
        'Docker multi-stage builds: smaller and safer images',
        'Multi-stage сборка в Docker: меньше и безопаснее образ',
        'A multi-stage build leaves compilers, package managers and build secrets in a stage that is thrown '
        'away, so the shipped image carries only what runs.',
        'Multi-stage сборка оставляет компиляторы, пакетные менеджеры и секреты сборки в промежуточной стадии, '
        'и в итоговый образ попадает только то, что нужно для запуска.'),
    'docker.resource_limits': (
        'Setting memory and CPU limits in docker-compose',
        'Как задать лимиты памяти и CPU в docker-compose',
        'One service with a memory leak takes the whole host down with every other container on it. A limit '
        'turns that into one restarted container.',
        'Один сервис с утечкой памяти роняет весь хост вместе с остальными контейнерами. Лимит превращает это '
        'в перезапуск одного контейнера.'),
    'deps.manifest': (
        'Why every project needs a dependency manifest',
        'Зачем проекту файл зависимостей',
        'Without requirements.txt, pyproject.toml, package.json or go.mod nobody can rebuild the environment, '
        'and no scanner can tell you which dependency is vulnerable.',
        'Без requirements.txt, pyproject.toml, package.json или go.mod окружение невозможно воспроизвести, а '
        'сканер не скажет, какая зависимость уязвима.'),
    'deps.lockfile': (
        'Should you commit a lock file?',
        'Нужно ли коммитить lock-файл?',
        'For an application, yes: the lock file makes the build you tested the build you ship. For an npm or '
        'Python library it is never shipped to users, so DevOpsCheck does not require one there.',
        'Для приложения — да: lock-файл делает сборку в проде той же, что тестировали. У npm- или '
        'Python-библиотеки он не доходит до пользователей, поэтому DevOpsCheck его там не требует.'),
    'deps.pinned': (
        'Pinning Python dependencies to exact versions',
        'Как закрепить версии Python-зависимостей',
        'A range such as requests>=2 means two builds of the same commit can install different code — '
        'including a release published by someone who took over the package.',
        'Диапазон вроде requests>=2 означает, что две сборки одного коммита могут поставить разный код — в '
        'том числе релиз, опубликованный тем, кто перехватил пакет.'),
    'deps.cve': (
        'Finding known vulnerabilities (CVE) in your dependencies',
        'Как найти известные уязвимости (CVE) в зависимостях',
        'DevOpsCheck looks every dependency up in OSV.dev and, for Python and npm, checks whether the '
        'vulnerable package is actually imported — so the list starts with what is reachable.',
        'DevOpsCheck проверяет каждую зависимость по базе OSV.dev, а для Python и npm смотрит, импортируется '
        'ли уязвимый пакет на самом деле, — список начинается с достижимых.'),
    'docs.readme': (
        'What a good README contains',
        'Что должно быть в хорошем README',
        'The README is the first thing a new developer, a user and an auditor read. Without one, every '
        'question lands on the maintainer.',
        'README — первое, что читают новый разработчик, пользователь и аудитор. Без него каждый вопрос идёт '
        'мейнтейнеру.'),
    'docs.readme_quality': (
        'Writing a README that explains how to run the project',
        'Как написать README, по которому проект можно запустить',
        'A README without setup steps costs every new developer their first day. Prerequisites, install, run '
        'and test commands are enough.',
        'README без инструкции по запуску стоит каждому новому разработчику первого дня. Достаточно '
        'требований, установки, запуска и команды тестов.'),
    'docs.changelog': (
        'Keeping a CHANGELOG: formats and tools',
        'Как вести CHANGELOG: форматы и инструменты',
        'A changelog tells users what changed before they upgrade. DevOpsCheck accepts CHANGELOG, CHANGES, '
        'HISTORY or NEWS in any case, release notes under docs/, and tools like changesets or release-please.',
        'Changelog говорит пользователям, что изменилось, до обновления. DevOpsCheck засчитывает CHANGELOG, '
        'CHANGES, HISTORY или NEWS в любом регистре, release notes в docs/ и инструменты вроде changesets или '
        'release-please.'),
    'docs.contributing': (
        'How to write a CONTRIBUTING guide',
        'Как написать CONTRIBUTING',
        'A contribution guide answers the questions every first-time contributor asks — how to run tests, '
        'which branch, what a good pull request looks like.',
        'Руководство для контрибьюторов отвечает на вопросы каждого новичка — как запустить тесты, в какую '
        'ветку, каким должен быть pull request.'),
    'docs.templates': (
        'Pull request and issue templates',
        'Шаблоны pull request и issue',
        'Templates make every bug report arrive with versions and steps, and every pull request with a '
        'description and a checklist — less back-and-forth for reviewers.',
        'Шаблоны заставляют каждый баг-репорт приходить с версиями и шагами, а каждый pull request — с '
        'описанием и чек-листом: меньше переписки у ревьюеров.'),
    'ops.gitignore': (
        'Why every repository needs a .gitignore',
        'Зачем репозиторию .gitignore',
        'Without .gitignore, build output, editor files and local secrets end up committed sooner or later.',
        'Без .gitignore артефакты сборки, файлы редактора и локальные секреты рано или поздно попадают в коммит.'),
    'ops.env_example': (
        'Documenting environment variables with .env.example',
        'Как описать переменные окружения в .env.example',
        'When .env is ignored and nothing documents it, nobody new can start the project without asking.',
        'Когда .env скрыт и нигде не описан, новый человек не запустит проект, не спросив.'),
    'ops.license': (
        'Choosing and adding a LICENSE',
        'Как выбрать и добавить LICENSE',
        'Code without a license is all rights reserved: nobody may legally use, modify or redistribute it, '
        'whatever the repository settings say.',
        'Код без лицензии — «все права защищены»: никто не может законно использовать, менять или '
        'распространять его, что бы ни стояло в настройках репозитория.'),
    'ops.activity': (
        'Is this repository still maintained?',
        'Поддерживается ли ещё репозиторий?',
        'A dependency nobody commits to will not get a fix when the next vulnerability is found in it.',
        'Зависимость, в которую никто не коммитит, не получит исправление, когда в ней найдут следующую '
        'уязвимость.'),
    'ops.observability': (
        'Adding logging, metrics and error tracking to a service',
        'Логи, метрики и трекинг ошибок в сервисе',
        'Without monitoring you learn about incidents from your users. Structured logs, metrics and error '
        'tracking are how a team finds out first. Libraries are exempt — they have no runtime of their own.',
        'Без мониторинга об инцидентах узнают от пользователей. Структурные логи, метрики и трекинг ошибок — '
        'способ узнать первыми. К библиотекам не применяется: у них нет своего рантайма.'),
    'actions.pinned_sha': (
        'How to pin GitHub Actions to a commit SHA',
        'Как закрепить GitHub Actions на commit SHA',
        'A tag like @v4 can be moved by whoever controls the action — which is how the tj-actions/changed-files '
        'compromise reached thousands of pipelines. A full commit SHA cannot be moved.',
        'Тег вроде @v4 может перенести тот, кто контролирует action, — так компрометация tj-actions/changed-files '
        'дошла до тысяч пайплайнов. Полный commit SHA перенести нельзя.'),
    'actions.broad_permissions': (
        'Least-privilege GITHUB_TOKEN permissions in workflows',
        'Минимальные права GITHUB_TOKEN в workflow',
        'Without a permissions block the workflow token may have write access to the whole repository. Any '
        'step that is compromised — a dependency, an action — inherits it.',
        'Без блока permissions токен workflow может иметь права записи во весь репозиторий. Любой '
        'скомпрометированный шаг — зависимость, action — получает их.'),
    'actions.pull_request_target': (
        'The pull_request_target trap in GitHub Actions',
        'Ловушка pull_request_target в GitHub Actions',
        'pull_request_target runs with the repository secrets. Checking out and running the pull request’s '
        'code there hands those secrets to anyone who opens a pull request.',
        'pull_request_target запускается с секретами репозитория. Если там собрать код из pull request’а, '
        'секреты получает любой, кто откроет pull request.'),
    'actions.script_injection': (
        'Script injection in GitHub Actions and how to prevent it',
        'Инъекции в скриптах GitHub Actions и как их избежать',
        'An issue title or branch name pasted into run: with ${{ }} is executed as shell. Passing it through an '
        'environment variable makes it data again.',
        'Заголовок issue или имя ветки, вставленные в run: через ${{ }}, исполняются как shell. Передача через '
        'переменную окружения снова делает их данными.'),
    'actions.self_hosted_public': (
        'Self-hosted runners in public repositories',
        'Self-hosted раннеры в публичных репозиториях',
        'In a public repository a pull request from a stranger can run on your self-hosted runner — your '
        'network, your credentials, your machine.',
        'В публичном репозитории pull request от постороннего может запуститься на вашем self-hosted '
        'раннере — в вашей сети, с вашими учётными данными.'),
    'actions.cloud_oidc': (
        'Deploying from GitHub Actions with OIDC instead of stored cloud keys',
        'Деплой из GitHub Actions через OIDC вместо хранимых облачных ключей',
        'A long-lived cloud key in repository secrets works for anyone who extracts it, forever. OIDC issues '
        'a short-lived credential per run, scoped to the repository and branch.',
        'Долгоживущий облачный ключ в секретах репозитория работает для любого, кто его достанет, навсегда. '
        'OIDC выдаёт короткоживущие учётные данные на каждый запуск, ограниченные репозиторием и веткой.'),
    'gitlab_ci.pinned_images': (
        'Pinning images in GitLab CI',
        'Закрепление образов в GitLab CI',
        'An image: without a tag or digest pulls whatever is current, so the pipeline you reviewed is not '
        'the pipeline that runs.',
        'image: без тега или digest тянет то, что сейчас актуально, и запускается не тот пайплайн, который '
        'проверяли.'),
    'gitlab_ci.pinned_includes': (
        'Pinning GitLab CI includes from other projects',
        'Закрепление include из других проектов в GitLab CI',
        'An include from another project’s default branch runs whatever that project merges next — in your '
        'pipeline, with your variables.',
        'include из default-ветки чужого проекта выполняет то, что там смержат следующим, — в вашем '
        'пайплайне, с вашими переменными.'),
    'gitlab_ci.cloud_oidc': (
        'GitLab CI deploys with OIDC (id_tokens) instead of stored keys',
        'Деплой из GitLab CI через OIDC (id_tokens) вместо хранимых ключей',
        'A cloud key in CI/CD variables is readable by every job that can print it. id_tokens gives each job '
        'a short-lived credential instead.',
        'Облачный ключ в переменных CI/CD доступен любому job, который может его напечатать. id_tokens выдаёт '
        'каждому job короткоживущие учётные данные.'),
    'iac.remote_state': (
        'Terraform remote state and state locking',
        'Удалённый state и блокировки в Terraform',
        'Local state means two people applying at once overwrite each other, and the state file — which '
        'holds secrets — lives on a laptop.',
        'Локальный state означает, что два одновременных apply перезаписывают друг друга, а файл state — с '
        'секретами внутри — лежит на ноутбуке.'),
    'iac.open_ingress': (
        'Security groups open to 0.0.0.0/0 in Terraform',
        'Security group, открытые на 0.0.0.0/0, в Terraform',
        'SSH, RDP or a database port open to the whole internet is found by scanners within hours of apply.',
        'SSH, RDP или порт базы данных, открытые всему интернету, сканеры находят за часы после apply.'),
    'iac.no_hardcoded_credentials': (
        'Removing hardcoded credentials from Terraform',
        'Как убрать захардкоженные ключи из Terraform',
        'A provider key in a .tf file is committed with the code and copied into every state file and plan.',
        'Ключ провайдера в .tf-файле попадает в коммит вместе с кодом и копируется в каждый state и plan.'),
    'iac.pinned_providers': (
        'Constraining Terraform provider versions',
        'Как ограничить версии провайдеров Terraform',
        'Without a version constraint the next init can pull a major provider release that changes '
        'resources under you.',
        'Без ограничения версии следующий init может подтянуть мажорный релиз провайдера, который изменит '
        'ресурсы.'),
    'iac.scanning': (
        'Scanning Terraform in CI with Checkov, tfsec or Trivy',
        'Сканирование Terraform в CI: Checkov, tfsec, Trivy',
        'An IaC scanner catches a public bucket or an open port in review, before apply makes it real.',
        'Сканер IaC ловит публичный бакет или открытый порт на ревью — до того, как apply сделает их реальными.'),
    'ai.instructions_clean': (
        'Keeping secrets out of CLAUDE.md, AGENTS.md and other agent instructions',
        'Как не допустить секретов в CLAUDE.md, AGENTS.md и других инструкциях агентов',
        'Agent instruction files are read by every tool and every contributor — and often committed to public '
        'repositories. Credentials and internal hostnames in them leak like any other file.',
        'Файлы инструкций для агентов читают все инструменты и все участники — и они часто лежат в публичных '
        'репозиториях. Ключи и внутренние адреса в них утекают, как из любого файла.'),
    'ai.mcp_pinned': (
        'Pinning MCP server versions',
        'Как закрепить версии MCP-серверов',
        'npx some-mcp-server@latest runs whatever was published last, with the access your agent has.',
        'npx some-mcp-server@latest запускает то, что опубликовали последним, с доступом вашего агента.'),
    'ai.mcp_secrets': (
        'Keeping credentials out of MCP configs',
        'Как убрать ключи из конфигов MCP',
        'An MCP config committed with a token in it publishes that token. Reference an environment variable '
        'instead.',
        'Конфиг MCP, закоммиченный с токеном, публикует этот токен. Ссылайтесь на переменную окружения.'),
    'ai.agent_ci_exposed': (
        'AI agents in CI that outsiders can steer',
        'AI-агенты в CI, которыми могут управлять посторонние',
        'An agent triggered by any issue or comment, with write tools and secrets, does what a stranger’s '
        'text tells it to — prompt injection with repository access.',
        'Агент, который запускается на любой issue или комментарий и имеет права записи и секреты, делает то, '
        'что велит текст постороннего, — prompt injection с доступом к репозиторию.'),
}


@lru_cache(maxsize=1)
def catalog() -> dict:
    """check_id -> {name, category, severity, description, recommendation} (English source)."""
    path = Path(__file__).with_name('check_catalog.json')
    return json.loads(path.read_text(encoding='utf-8'))


def guide(check_id: str, language: str = 'en') -> dict | None:
    if check_id not in GUIDES:
        return None
    from django.utils.translation import gettext as _
    from app.ai_providers import _get_builtin, _lookup_key
    title_en, title_ru, why_en, why_ru = GUIDES[check_id]
    ru = (language or '').startswith('ru')
    meta = catalog().get(check_id, {})
    fix = _get_builtin(_lookup_key({'check_id': check_id, 'name': meta.get('name', '')}),
                       'ru' if ru else 'en')
    return {
        'check_id': check_id,
        'title': title_ru if ru else title_en,
        'why': why_ru if ru else why_en,
        'name': _(meta['name']) if meta.get('name') else check_id,
        'category': meta.get('category', ''),
        'severity': meta.get('severity', ''),
        'fix_markdown': fix,
        'recommendation': '' if fix else (_(meta['recommendation']) if meta.get('recommendation') else ''),
    }


def all_guides(language: str = 'en') -> list[dict]:
    return [g for g in (guide(cid, language) for cid in GUIDES) if g]
