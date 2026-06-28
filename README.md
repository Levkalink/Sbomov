# SBOM Automation Platform

Платформа автоматизации генерации, валидации и анализа **Software Bill of Materials** в формате **CycloneDX** для проектов на любом языке программирования.

Включает интеграцию с базой уязвимостей **БДУ ФСТЭК** (89 898 записей), импорт результатов внешних SCA-сканеров, оценку качества по стандартам CISA 2025 и NTIA, генерацию VEX-документов и веб-интерфейс с потоковыми логами в реальном времени.

---

## Возможности

| Функция | Описание |
|---|---|
| **Автодетектирование языков** | Python, Go, Node.js, Java, Gradle, Rust, .NET, Ruby, PHP, C/C++ — рекурсивный поиск манифестов |
| **Полиглот-проекты** | Один запуск cdxgen со всеми найденными типами (`--type py --type go --type c`) |
| **Глубокий анализ C/C++** | `--deep` для бинарного анализа, Conan, vcpkg, CMake, Meson |
| **Фильтрация шума** | Автоматическое удаление `pkg:deb/rpm/apk` через jq |
| **Обогащение** | sbom-updater (ИСПРАН): GOST-поля, externalReferences, метаданные |
| **Валидация схемы** | sbom-checker (ИСПРАН): PURL, VCS, source-distribution |
| **Оценка качества** | CISA 2025 + NTIA minimum elements, score 0–100 |
| **БДУ ФСТЭК** | 89 898 уязвимостей, 3-стратегийный matching, приоритизация |
| **Priority Score** | Формула: CVSS×0.30 + exploit×0.30 + BDU×0.15 + recency×0.15 + public_exploit×0.10 |
| **VEX-документы** | Встраивание уязвимостей в секцию `vulnerabilities` CycloneDX SBOM (VEX embedding) |
| **Импорт сканеров** | Grype JSON, Trivy JSON, OSV-Scanner JSON, SARIF 2.1.0, Generic JSON |
| **Триаж уязвимостей** | Статусы: open / confirmed / resolved / risk\_accepted / false\_positive |
| **Экспорт** | CycloneDX JSON + VEX, CSV, ODT (ГОСТ-таблица), **XLSX** (3 листа: сводка, уязвимости, компоненты) |
| **Персистентность** | Jobs и история в SQLite (не теряется при перезапуске сервера) |
| **CI/CD** | GitLab CI и GitHub Actions конфиги |

---

## Быстрый старт

### 1. Зависимости

```bash
# Системные
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

# Валидация + обогащение
SBOM_APP_NAME=myapp bash scripts/check_and_enrich.sh sbom.json
```

---

## Дополнительные SCA-сканеры

Платформа принимает результаты популярных SCA/vulnerability сканеров через `/api/import`.

### Grype (Anchore)

```bash
# Установка
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Сканирование готового SBOM
grype sbom:./sbom.json -o json > grype-results.json

# Загрузка результатов в платформу
curl -X POST http://localhost:8000/api/import -F "file=@grype-results.json"
```

### Trivy (Aqua Security)

```bash
# Установка
apt-get install -y trivy
# или
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Генерация SBOM
trivy fs --format cyclonedx --output sbom.cdx.json ./my-project

# Сканирование уязвимостей в готовом SBOM
trivy sbom --format json --output trivy-vulns.json sbom.cdx.json

# Загрузка в платформу
curl -X POST http://localhost:8000/api/import -F "file=@trivy-vulns.json"
```

### OSV-Scanner (Google)

```bash
# Установка
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Сканирование SBOM
osv-scanner --sbom sbom.cdx.json --format json > osv-results.json

# Загрузка в платформу
curl -X POST http://localhost:8000/api/import -F "file=@osv-results.json"
```

### Поддерживаемые форматы импорта

| Формат | Авто-определение | Описание |
|---|---|---|
| **Grype JSON** | `descriptor.name = "grype"` | Anchore Grype CVE-matching |
| **Trivy JSON** | `SchemaVersion` + `Results` | Aqua Trivy multi-target scanner |
| **OSV-Scanner JSON** | `results[].packages` | Google OSV database |
| **SARIF 2.1.0** | `runs[].results` | Универсальный формат SAST/SCA |
| **Generic JSON** | array с `cve`/`vulnerability` | Произвольные форматы |

---

## Структура проекта

```
sbomsauto/
├── webapp/
│   ├── main.py              # FastAPI бэкенд — pipeline, API, генерация
│   ├── job_store.py         # SQLite-хранилище задач (персистентность)
│   ├── bdu_parser.py        # Потоковый импорт vulxml.zip → SQLite
│   ├── bdu_matcher.py       # 3-стратегийный matching + Priority Score
│   ├── vuln_importer.py     # Парсеры Grype/Trivy/OSV/SARIF результатов
│   ├── vex_generator.py     # CycloneDX VEX embedding
│   ├── xlsx_exporter.py     # XLSX экспорт (3 листа)
│   ├── templates/index.html # Веб-интерфейс (SPA, AdminLTE 3 + dark theme)
│   ├── start.sh             # Запуск uvicorn
│   └── requirements.txt
├── sbom-checker-master/     # ИСПРАН SDL-Tools
│   ├── sbom-checker.py      # Валидация CycloneDX JSON
│   ├── sbom-updater.py      # Обогащение (ГОСТ-поля)
│   ├── sbom-to-csv.py       # Экспорт в CSV
│   ├── sbom-to-odt.py       # Экспорт в ODT
│   └── sbom-unifier.py      # Слияние SBOM
├── scripts/                 # Bash-скрипты pipeline
├── config/sbom.config.yaml
└── ci/                      # GitLab CI, GitHub Actions
```

---

## Pipeline генерации SBOM

### Алгоритм детектирования языков (рекурсивный)

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

### Этапы pipeline

```
Проект
  ↓
1. Автодетект языков (рекурсивный поиск манифестов)
  ↓
2. cdxgen --type go --type python --type c --deep --evidence --recurse
  ↓
3. Фильтрация шума (jq: pkg:deb/rpm/apk, системные пакеты)
  ↓
4. Обогащение: sbom-updater (ГОСТ-поля, supplier, externalReferences)
  ↓
5. Валидация: sbom-checker (схема, PURL, VCS)
  ↓
6. Оценка качества: CISA 2025 + NTIA (score 0-100)
  ↓
7. [Опционально] BDU ФСТЭК сканирование + Priority Score
  ↓
8. [Опционально] VEX embedding → sbom-vex.json
  ↓
9. Экспорт: JSON + CSV + ODT + XLSX
```

---

## Priority Score (приоритизация уязвимостей)

Формула вдохновлена подходом [Red-Lycoris ASOC Platform](https://github.com/Nefrit0n/Red-Lycoris):

```
priority_score = CVSS_base × 0.30
               + exploit_bonus × 0.30      # 7.0 если эксплойт, 10.0 если публичный
               + bdu_in_database × 0.15    # 5.0 если в базе БДУ
               + recency × 0.15            # 10 × exp(-days/730)
               + public_exploit × 0.10     # дополнительный бонус публичности

Результат: 0.0 – 10.0 (нормализован к максимальному теоретическому значению)
```

---

## VEX (Vulnerability Exploitability eXchange)

После BDU-сканирования можно встроить уязвимости прямо в CycloneDX SBOM:

```bash
# Через API
curl -X POST http://localhost:8000/api/bdu/scan/{task_id}/vex \
  -H 'Content-Type: application/json' \
  -d '{"job_id": "abc123"}'

# Результат: sbom-vex.json с секцией "vulnerabilities"
```

Статусы VEX (по CycloneDX спецификации):

| Статус триажа | VEX state | Описание |
|---|---|---|
| `open` | `in_triage` | Анализируется |
| `confirmed` | `affected` | Подтверждено, требует исправления |
| `resolved` | `resolved` | Исправлено |
| `risk_accepted` | `not_affected` | Риск принят |
| `false_positive` | `not_affected` | Ложное срабатывание |

---

## Стандарты и соответствие

### CISA 2025 Minimum Elements

| Поле | Описание |
|---|---|
| `metadata.tools` | Инструмент генерации (cdxgen + версия) |
| `metadata.timestamp` | Дата и время создания |
| `metadata.manufacture` | Производитель/поставщик |
| `components[*].hashes` | Хэш SHA-256 каждого компонента |
| `components[*].licenses` | Лицензия каждого компонента |
| `metadata.component` | Описание сканируемого продукта |

### NTIA Minimum Elements

| Поле | Описание |
|---|---|
| Supplier | `metadata.supplier` / `component.supplier` |
| Component Name | `components[*].name` |
| Version | `components[*].version` |
| Unique Identifier | `components[*].purl` (Package URL) |
| Dependency Relationship | `dependencies[]` |
| Author | `metadata.authors` |
| Timestamp | `metadata.timestamp` |

### CycloneDX версии

- По умолчанию: **1.6** (рекомендуется)
- Поддерживается: 1.4, 1.5, 1.6, 1.7

---

## Интеграция БДУ ФСТЭК

### Импорт базы

```bash
# Скачайте vulxml.zip с https://bdu.fstec.ru/vul
# Через веб-интерфейс: вкладка "BDU ФСТЭК" → Импортировать
# Через CLI:
python3 webapp/bdu_parser.py /path/to/vulxml.zip
```

Импорт ~90 000 записей занимает ~30 секунд. Потоковый XML-парсер не загружает файл в RAM.

### Стратегии сопоставления

| Приоритет | Стратегия | Описание |
|---|---|---|
| 1 | CVE cross-reference | CVE ID из SBOM → `cve_mapping` → уязвимость БДУ |
| 2 | Vendor + Name + Version | Нормализованные строки, версионные диапазоны |
| 3 (fallback) | Name-only | Только имя компонента |

---

## API

### SBOM Generation

```bash
POST /api/run              # Запуск pipeline
GET  /api/job/{id}         # Статус задачи
GET  /api/stream/{id}      # SSE-поток логов в реальном времени
GET  /api/download/{id}/{filename}  # Скачать файл
GET  /api/jobs             # История задач
GET  /api/detect?path=...  # Детектировать языки в директории
```

### Import & Analysis

```bash
POST /api/import           # Импорт результатов Grype/Trivy/OSV/SARIF (multipart)
POST /api/quality          # Проверка качества SBOM файла
GET  /api/tools            # Статус доступных инструментов
POST /api/triage           # Обновить статус уязвимости (триаж)
```

### BDU ФСТЭК

```bash
GET  /api/bdu/status       # Статус базы (записей, источник, дата)
POST /api/bdu/import       # Запуск импорта vulxml.zip
GET  /api/bdu/import/{id}/stream  # SSE-прогресс импорта
POST /api/bdu/scan         # Сканирование SBOM против БДУ
GET  /api/bdu/scan/{id}    # Результаты сканирования (пагинация: ?page=1&limit=50)
POST /api/bdu/scan/{id}/vex    # Генерация VEX-файла
POST /api/bdu/scan/{id}/xlsx   # Экспорт в XLSX
GET  /api/bdu/search?q=...     # Поиск по базе уязвимостей
```

---

## Инструменты

| Инструмент | Назначение | Источник |
|---|---|---|
| **cdxgen 12.x** | Генератор CycloneDX (OWASP) — полиглот, --deep, --evidence | [github.com/cdxgen/cdxgen](https://github.com/cdxgen/cdxgen) |
| **sbom-checker** | Валидация CycloneDX (ИСПРАН SDL-Tools) | [gitlab.community.ispras.ru](https://gitlab.community.ispras.ru/sdl-tools/sbom-checker) |
| **sbom-updater** | Обогащение метаданными (ИСПРАН) | в составе sbom-checker-master |
| **Grype** (опц.) | CVE-сканирование SBOM/образов (Anchore) | [github.com/anchore/grype](https://github.com/anchore/grype) |
| **Trivy** (опц.) | Универсальный scanner — SBOM+CVE+secrets (Aqua) | [trivy.dev](https://trivy.dev) |
| **OSV-Scanner** (опц.) | Сканирование против OSV.dev (Google) | [github.com/google/osv-scanner](https://github.com/google/osv-scanner) |
| **jq** | Фильтрация шума, слияние SBOM | системный пакет |

---

## Архитектура (вдохновлена Red-Lycoris ASOC Platform)

Проект использует концепции из [Red-Lycoris](https://github.com/Nefrit0n/Red-Lycoris):

- **Finding data model** — структурированная модель уязвимости с severity/status/priority_score
- **Priority Score** — формула приоритизации на основе CVSS + exploit + BDU + recency
- **Triage statuses** — open/confirmed/resolved/risk\_accepted/false\_positive
- **SHA256 fingerprint** — дедупликация уязвимостей при повторных сканированиях
- **Multi-format import** — Grype/Trivy/OSV/SARIF парсеры с авто-определением формата
- **VEX embedding** — встраивание уязвимостей в CycloneDX SBOM (секция `vulnerabilities`)
- **SSE real-time logs** — потоковые логи без polling

Основные отличия: наш проект фокусируется на **генерации SBOM** и **БДУ ФСТЭК**, тогда как Red-Lycoris — ASOC-платформа для хранения и дедупликации результатов сканирования.

---

## Требования

```
Python >= 3.11
Node.js >= 18 (для cdxgen)
jq (системный)
```

### requirements.txt

```
fastapi>=0.111
uvicorn[standard]>=0.29
aiofiles>=23.0
python-multipart>=0.0.9
packaging>=24.0
openpyxl>=3.1
```

---

## Лицензия

MIT
