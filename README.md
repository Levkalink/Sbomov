# SBOM Automation

Автоматизация генерации, валидации и экспорта **Software Bill of Materials** в формате **CycloneDX** для C/C++ проектов.

Включает веб-интерфейс с браузером файловой системы сервера, реалтайм-логами и интеграцией инструментов ИСПРАН.

## Возможности

| Функция | Описание |
|---|---|
| **Генерация SBOM** | cdxgen (OWASP) или Syft; поддержка Conan, vcpkg, CMake |
| **Фильтрация шума** | Автоматическое удаление системных pkg:deb/rpm/apk пакетов |
| **Обогащение** | sbom-updater: GOST-поля, externalReferences, метаданные продукта |
| **Валидация схемы** | sbom-checker (ИСПРАН): PURL, VCS-ссылки, source-distribution |
| **Quality Check** | CISA 2025 + NTIA minimum elements, score 0-100 |
| **BDU ФСТЭК** | Импорт 89 898 уязвимостей, CVE/vendor+name matching, VEX-отчёт |
| **Экспорт** | JSON (CycloneDX), CSV, ODT (перечень для документации) |
| **CI/CD** | Готовые конфиги для GitLab CI и GitHub Actions |
| **Веб-интерфейс** | Браузер папок сервера, загрузка архивов, SSE-логи реального времени |

## Быстрый старт

### 1. Установка зависимостей

```bash
# Системные
apt-get install -y jq nodejs npm python3 python3-pip

# cdxgen (OWASP официальный)
npm install -g @cyclonedx/cdxgen

# Syft (бинарный анализ)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Python зависимости
pip3 install -r webapp/requirements.txt
```

### 2. Запуск веб-интерфейса

```bash
cd webapp
bash start.sh
# → http://localhost:8000
```

### 3. CLI (без веб-интерфейса)

```bash
# Полный pipeline
SBOM_PROJECT_NAME=myapp SBOM_VERSION=1.0.0 \
  bash scripts/run_pipeline.sh /path/to/c-project

# Только генерация
bash scripts/generate_sbom.sh /path/to/c-project

# Только валидация существующего SBOM
SBOM_APP_NAME=myapp bash scripts/check_and_enrich.sh sbom.json
```

## Структура проекта

```
sbomsauto/
├── webapp/
│   ├── main.py              # FastAPI бэкенд
│   ├── bdu_parser.py        # Импорт vulxml.zip → SQLite (потоковый, без RAM)
│   ├── bdu_matcher.py       # Matching SBOM-компонентов с уязвимостями БДУ
│   ├── templates/index.html # Веб-интерфейс (SPA), вкладка BDU ФСТЭК
│   ├── start.sh             # Скрипт запуска
│   └── requirements.txt
├── sbom-checker-master/     # ИСПРАН SDL-Tools
│   ├── sbom-checker.py      # Валидация CycloneDX JSON
│   ├── sbom-updater.py      # Обогащение метаданными
│   ├── sbom-to-csv.py       # Экспорт в CSV
│   ├── sbom-to-odt.py       # Экспорт в ODT (ГОСТ-таблица)
│   └── sbom-unifier.py      # Слияние нескольких SBOM
├── scripts/
│   ├── setup.sh             # Установка инструментов
│   ├── generate_sbom.sh     # Генерация (cdxgen + syft)
│   ├── check_and_enrich.sh  # Валидация + обогащение
│   └── run_pipeline.sh      # Полный pipeline
├── config/
│   └── sbom.config.yaml     # Конфигурация
└── ci/
    ├── gitlab-ci.yml        # GitLab CI
    └── github-actions.yml   # GitHub Actions
```

## Борьба с шумом в C-проектах

C/C++ проекты — главная проблема для SBOM-сканеров: при наивном сканировании системы обнаруживаются сотни системных пакетов (libc6, bash, dpkg и т.д.), которые не являются зависимостями вашего проекта.

**Решение, применённое в этом проекте:**

1. `cdxgen` запускается с `--filter pkg:deb --filter pkg:rpm --filter pkg:apk`
2. `syft` запускается с `--override-default-catalogers binary-cataloger,conan-cataloger` — **dpkg-db-cataloger отключён**
3. Финальный `jq`-фильтр удаляет системные пакеты по имени и PURL-типу
4. Исключаются пути `/usr/share`, `/var`, `/etc`, `/boot`

## Стандарты и соответствие

- **CISA 2025 Minimum Elements** — 4 новых обязательных поля: Component Hash, License, Tool Name, Generation Context
- **NTIA Minimum Elements** — Supplier, Name, Version, Unique ID, Dependencies, Author, Timestamp
- **CycloneDX 1.6 / 1.7** — официальная схема с валидацией
- **ГОСТ / ИСПРАН SDL** — GOST:attack_surface, GOST:security_function через sbom-updater

## Интеграция БДУ ФСТЭК

Банк данных угроз ФСТЭК содержит **89 898 уязвимостей** (по состоянию на 2025 год).

### Импорт

1. Скачайте `vulxml.zip` с [bdu.fstec.ru/vul](https://bdu.fstec.ru/vul)
2. Откройте вкладку **🛡️ BDU ФСТЭК** в веб-интерфейсе
3. Укажите путь к файлу и нажмите **Импортировать** — прогресс отображается в реальном времени
4. Для запуска из CLI: `python3 webapp/bdu_parser.py /path/to/vulxml.zip`

### Стратегия сопоставления

| Стратегия | Приоритет | Описание |
|---|---|---|
| CVE cross-reference | 1 (наиболее точная) | CVE ID из SBOM → `cve_mapping` → уязвимость BDU |
| Vendor + Name + Version | 2 | Нормализованные строки + фильтрация версий |
| Name-only fallback | 3 | Только имя компонента, если vendor неизвестен |

### Нормализация версий

BDU описывает версии в виде «до X.X.X» и «X.X и ниже» — matcher корректно их интерпретирует, используя `packaging.version` при наличии.

## Инструменты

| Инструмент | Назначение |
|---|---|
| [cdxgen](https://github.com/cdxgen/cdxgen) | Официальный генератор OWASP CycloneDX |
| [Syft](https://github.com/anchore/syft) | Бинарный анализ и Conan |
| [sbom-checker](https://gitlab.community.ispras.ru/sdl-tools/sbom-checker) | Валидация (ИСПРАН SDL-Tools) |
| [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) | Слияние и конвертация |
