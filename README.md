# SBOM Automation

Платформа автоматизации генерации, валидации и анализа **Software Bill of Materials** в формате **CycloneDX** для проектов на любом языке программирования.

Включает интеграцию с базой уязвимостей **БДУ ФСТЭК** (89 898 записей), оценку качества по стандартам CISA 2025 и NTIA, а также веб-интерфейс с потоковыми логами в реальном времени.

---

## Возможности

| Функция | Описание |
|---|---|
| **Автодетектирование языков** | Определяет Python, Go, Node.js, Java, Rust, .NET, Ruby, PHP, C/C++ из файлов-манифестов |
| **Полиглот-проекты** | Один запуск `cdxgen` со всеми обнаруженными типами (`--type py --type go --type c`) |
| **Глубокий анализ C/C++** | `--deep` для бинарного анализа, поддержка Conan, vcpkg, CMake, Meson |
| **Фильтрация шума** | Автоматическое удаление системных `pkg:deb/rpm/apk` пакетов через `jq` |
| **Обогащение** | sbom-updater (ИСПРАН): GOST-поля, externalReferences, метаданные продукта |
| **Валидация схемы** | sbom-checker (ИСПРАН): PURL, VCS-ссылки, source-distribution |
| **Оценка качества** | CISA 2025 + NTIA minimum elements, score 0–100 |
| **БДУ ФСТЭК** | 89 898 уязвимостей, CVE/vendor+name/name-only matching, VEX-совместимый отчёт |
| **Экспорт** | CycloneDX JSON, CSV (таблица), ODT (перечень для документации по ГОСТ) |
| **Персистентность** | Jobs хранятся в SQLite — история не теряется при перезапуске сервера |
| **CI/CD** | Готовые конфиги для GitLab CI и GitHub Actions |

---

## Быстрый старт

### 1. Зависимости

```bash
# Системные пакеты
apt-get install -y jq nodejs npm python3 python3-pip

# cdxgen — официальный генератор CycloneDX (OWASP)
npm install -g @cyclonedx/cdxgen

# Python зависимости
pip3 install -r webapp/requirements.txt
```

### 2. Запуск

```bash
cd webapp
bash start.sh
# → http://localhost:8000
```

### 3. CLI (без веб-интерфейса)

```bash
# Полный pipeline: генерация → обогащение → валидация → экспорт
SBOM_PROJECT_NAME=myapp SBOM_VERSION=1.0.0 \
  bash scripts/run_pipeline.sh /path/to/project

# Только генерация
bash scripts/generate_sbom.sh /path/to/project

# Только валидация существующего SBOM
SBOM_APP_NAME=myapp bash scripts/check_and_enrich.sh sbom.json
```

---

## Структура проекта

```
sbomsauto/
├── webapp/
│   ├── main.py              # FastAPI бэкенд — pipeline, API, генерация
│   ├── job_store.py         # SQLite-хранилище задач (персистентность)
│   ├── bdu_parser.py        # Потоковый импорт vulxml.zip → SQLite (без RAM)
│   ├── bdu_matcher.py       # 3-стратегийный matching SBOM ↔ БДУ
│   ├── templates/index.html # Веб-интерфейс (SPA, AdminLTE 3 + dark theme)
│   ├── start.sh             # Скрипт запуска uvicorn
│   └── requirements.txt
├── sbom-checker-master/     # ИСПРАН SDL-Tools
│   ├── sbom-checker.py      # Валидация CycloneDX JSON
│   ├── sbom-updater.py      # Обогащение метаданными (ГОСТ-поля)
│   ├── sbom-to-csv.py       # Экспорт в CSV
│   ├── sbom-to-odt.py       # Экспорт в ODT (таблица для документации)
│   └── sbom-unifier.py      # Слияние нескольких SBOM
├── scripts/
│   ├── setup.sh             # Установка инструментов
│   ├── generate_sbom.sh     # Генерация через cdxgen
│   ├── check_and_enrich.sh  # Валидация + обогащение
│   └── run_pipeline.sh      # Полный pipeline одной командой
├── config/
│   └── sbom.config.yaml     # Параметры по умолчанию
└── ci/
    ├── gitlab-ci.yml        # GitLab CI pipeline
    └── github-actions.yml   # GitHub Actions workflow
```

---

## Как работает генерация SBOM

### Определение языков проекта

Сканер автоматически определяет все экосистемы по файлам-манифестам:

| Экосистема | Маркерные файлы |
|---|---|
| **Go** | `go.mod` |
| **Python** | `requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.py` |
| **Node.js** | `package.json`, `package-lock.json`, `yarn.lock` |
| **Java/Maven** | `pom.xml` |
| **Gradle** | `build.gradle`, `build.gradle.kts` |
| **Rust** | `Cargo.toml` |
| **.NET** | `*.csproj`, `*.sln`, `*.fsproj` |
| **PHP** | `composer.json` |
| **Ruby** | `Gemfile` |
| **C/C++** | `CMakeLists.txt`, `conanfile.txt/py`, `vcpkg.json`, `meson.build`, `*.c/*.cpp` |

### Pipeline генерации

```
Проект
  ↓
1. Автодетект языков (сканирование файлов-манифестов)
  ↓
2. cdxgen --type go --type python --type js --type c
          --deep (если C/C++)
          --evidence --recurse
  ↓
3. Фильтрация: удаление pkg:deb/rpm/apk (системные пакеты)
  ↓
4. Обогащение: sbom-updater (ГОСТ-поля, метаданные, externalReferences)
  ↓
5. Валидация: sbom-checker (схема, PURL, VCS)
  ↓
6. Оценка качества: CISA 2025 + NTIA (score 0-100)
  ↓
7. Экспорт: JSON + CSV + ODT
```

### Полиглот-проекты

Если проект содержит несколько языков (например, C-библиотека с Python-обёрткой и Node.js CLI), `cdxgen` запускается **один раз** с несколькими флагами `--type`. Это:
- быстрее, чем N отдельных запусков
- даёт единый граф зависимостей
- избегает дублирования компонентов

Пример реального теста на полиглот-проекте (C + Python + Node.js + Go):
```
✓ cdxgen: 89 компонентов [conan:4, golang:2, npm:78, pypi:4]
```

---

## Борьба с шумом в C/C++ проектах

C/C++ проекты — главная проблема для SBOM-сканеров: при наивном сканировании системы обнаруживаются сотни системных пакетов (libc6, bash, dpkg и т.д.), не являющихся зависимостями проекта.

**Решение:**

1. `cdxgen` запускается с `--filter pkg:deb --filter pkg:rpm --filter pkg:apk`
2. Финальный `jq`-фильтр удаляет системные пакеты по имени и PURL-типу
3. Исключаются пути `/usr/share`, `/var`, `/etc`, `/boot`
4. Для Conan-проектов: библиотеки берутся из `conanfile.txt/py` напрямую

---

## Стандарты и соответствие

### CISA 2025 Minimum Elements

| Поле | Описание |
|---|---|
| `metadata.tools` | Наименование и версия инструмента генерации |
| `metadata.timestamp` | Дата и время создания SBOM |
| `metadata.manufacture` | Поставщик/производитель |
| `components[*].hashes` | Хэш SHA-256 каждого компонента |
| `components[*].licenses` | Лицензия каждого компонента |
| `metadata.component` | Информация о сканируемом продукте |

### NTIA Minimum Elements

| Поле | Описание |
|---|---|
| Supplier | `metadata.supplier` или `component.supplier` |
| Component Name | `components[*].name` |
| Version | `components[*].version` |
| Unique Identifier | `components[*].purl` (Package URL) |
| Dependency Relationship | `dependencies[]` |
| Author | `metadata.authors` |
| Timestamp | `metadata.timestamp` |

### CycloneDX версии

- По умолчанию: **1.6** (полная поддержка всех полей)
- Поддерживается: 1.4, 1.5, 1.6, 1.7

---

## Интеграция БДУ ФСТЭК

Банк данных угроз ФСТЭК содержит **89 898 уязвимостей** (2025 год).

### Импорт базы

1. Скачайте `vulxml.zip` с [bdu.fstec.ru/vul](https://bdu.fstec.ru/vul)
2. Откройте вкладку **🛡️ BDU ФСТЭК** в веб-интерфейсе
3. Укажите путь к файлу → **Импортировать** (потоковый импорт ~30 сек)
4. CLI: `python3 webapp/bdu_parser.py /path/to/vulxml.zip`

### Стратегии сопоставления

| Приоритет | Стратегия | Описание |
|---|---|---|
| 1 (точная) | CVE cross-reference | CVE ID из SBOM → таблица `cve_mapping` → уязвимость БДУ |
| 2 | Vendor + Name + Version | Нормализованные строки, проверка "до версии X" |
| 3 (fallback) | Name-only | По имени компонента, если vendor неизвестен |

### Технические детали

- Парсинг XML потоковый (streaming) — не загружает 500+ МБ в RAM
- SQLite с индексами по `cve_id`, `name_norm`, `vendor_norm`, `severity`, `has_exploit`
- Нормализация версий: понимает «до X.X.X», «X.X и ниже», диапазоны
- Поле `has_exploit` = 1 если эксплойт существует в открытом доступе

---

## Веб-интерфейс

### Страницы

| Страница | Функция |
|---|---|
| **Dashboard** | Сводная статистика: задачи, качество, БДУ, эксплойты |
| **Генерация** | Запуск pipeline: путь к проекту, параметры, детектированные языки |
| **Валидация** | Проверка готового SBOM-файла через sbom-checker |
| **Результаты** | Список компонентов, оценка качества, скачивание файлов |
| **BDU ФСТЭК** | Импорт базы, сканирование, поиск уязвимостей |
| **История** | Все задачи (сохраняются в SQLite между перезапусками) |

### Технологии

- **Backend**: FastAPI + SSE (Server-Sent Events) для потоковых логов
- **Frontend**: AdminLTE 3 + Bootstrap 4 + Font Awesome 6
- **Тема**: Dark zinc (zinc-950 фон, red-600 акцент — в стиле Red-Lycoris)
- **Хранение jobs**: SQLite (`webapp/jobs.db`) — история задач не теряется при перезапуске

---

## Установка и настройка

### requirements.txt

```
fastapi>=0.111
uvicorn[standard]>=0.29
aiofiles>=23.0
python-multipart>=0.0.9
packaging>=24.0
```

### start.sh

```bash
#!/bin/bash
cd "$(dirname "$0")"
exec uvicorn main:app --host 0.0.0.0 --port 8000
```

### Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `HOST` | `0.0.0.0` | Адрес привязки |
| `PORT` | `8000` | Порт |

---

## Инструменты

| Инструмент | Назначение | Источник |
|---|---|---|
| **cdxgen** | Официальный генератор CycloneDX OWASP | [github.com/cdxgen/cdxgen](https://github.com/cdxgen/cdxgen) |
| **sbom-checker** | Валидация CycloneDX JSON (ИСПРАН) | [gitlab.community.ispras.ru/sdl-tools/sbom-checker](https://gitlab.community.ispras.ru/sdl-tools/sbom-checker) |
| **sbom-updater** | Обогащение SBOM метаданными (ИСПРАН) | В составе sbom-checker-master |
| **jq** | Фильтрация шума, слияние SBOM | Системный пакет |

---

## Лицензия

MIT
