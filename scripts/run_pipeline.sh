#!/usr/bin/env bash
# Полный SBOM-pipeline: генерация → фильтрация → обогащение → валидация
# Точка входа для ручного и CI/CD запуска
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${1:-$(pwd)}"

# Настройки (переопределяются через env или .env файл)
[ -f "${PROJECT_DIR}/.sbom.env" ] && source "${PROJECT_DIR}/.sbom.env"

export SBOM_PROJECT_NAME="${SBOM_PROJECT_NAME:-$(basename "${PROJECT_DIR}")}"
export SBOM_VERSION="${SBOM_VERSION:-$(git -C "${PROJECT_DIR}" describe --tags --abbrev=0 2>/dev/null || echo "0.0.0")}"
export SBOM_OUTPUT_DIR="${SBOM_OUTPUT_DIR:-${PROJECT_DIR}/sbom-output}"
export SBOM_APP_NAME="${SBOM_APP_NAME:-${SBOM_PROJECT_NAME}}"
export SBOM_APP_VERSION="${SBOM_APP_VERSION:-${SBOM_VERSION}}"
export SBOM_MANUFACTURER="${SBOM_MANUFACTURER:-}"
export SBOM_FORMAT="${SBOM_FORMAT:-oss}"
export SBOM_CHECK_VCS="${SBOM_CHECK_VCS:-false}"
export SBOM_CHECK_SOURCES="${SBOM_CHECK_SOURCES:-false}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[PIPELINE]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}     $*"; }
err()  { echo -e "${RED}[ERR]${NC}      $*"; }

log "============================================================"
log "SBOM Pipeline — ${SBOM_PROJECT_NAME} v${SBOM_VERSION}"
log "Проект: ${PROJECT_DIR}"
log "Вывод:  ${SBOM_OUTPUT_DIR}"
log "============================================================"

# ─── Шаг 1: Генерация SBOM ──────────────────────────────────────────────────
log ""
log "▶ ШАГ 1/3: Генерация SBOM"
bash "${SCRIPT_DIR}/generate_sbom.sh" "${PROJECT_DIR}"

# Находим итоговый SBOM
FINAL_SBOM=$(find "${SBOM_OUTPUT_DIR}" -name "sbom-${SBOM_PROJECT_NAME}-*.json" \
    ! -name "*-filtered*" ! -name "*-enriched*" \
    -newer "${SBOM_OUTPUT_DIR}/sbom-generate.log" \
    2>/dev/null | head -1)

if [ -z "${FINAL_SBOM}" ]; then
    # Fallback: любой json который не filtered/enriched
    FINAL_SBOM=$(find "${SBOM_OUTPUT_DIR}" -name "sbom-*-filtered.json" 2>/dev/null | head -1)
fi

if [ -z "${FINAL_SBOM}" ] || [ ! -f "${FINAL_SBOM}" ]; then
    err "Не найден итоговый SBOM после генерации"
    exit 1
fi

log "Итоговый SBOM после генерации: ${FINAL_SBOM}"

# ─── Шаг 2: Обогащение и валидация ──────────────────────────────────────────
log ""
log "▶ ШАГ 2/3: Обогащение и валидация (sbom-checker ИСПРАН)"
ENRICHED_SBOM=$(bash "${SCRIPT_DIR}/check_and_enrich.sh" "${FINAL_SBOM}" 2>&1 | tail -1)

# Если check_and_enrich вернул путь к файлу
if [ ! -f "${ENRICHED_SBOM:-}" ]; then
    ENRICHED_SBOM="${FINAL_SBOM}"
fi

# ─── Шаг 3: Итоговый отчёт ──────────────────────────────────────────────────
log ""
log "▶ ШАГ 3/3: Итоговый отчёт"

TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
REPORT_FILE="${SBOM_OUTPUT_DIR}/pipeline-report-${TIMESTAMP}.txt"

{
    echo "========================================"
    echo "SBOM Pipeline Report"
    echo "Проект:   ${SBOM_PROJECT_NAME} v${SBOM_VERSION}"
    echo "Дата:     ${TIMESTAMP}"
    echo "========================================"
    echo ""
    echo "Файлы:"
    for f in "${SBOM_OUTPUT_DIR}"/sbom-*.json; do
        [ -f "$f" ] || continue
        count=$(jq '.components | length' "$f" 2>/dev/null || echo "?")
        printf "  %-50s  %s компонентов\n" "$(basename "$f")" "${count}"
    done
    echo ""
    echo "Итоговый SBOM: ${ENRICHED_SBOM}"
    echo ""
    if command -v jq &>/dev/null && [ -f "${ENRICHED_SBOM}" ]; then
        echo "Статистика компонентов:"
        jq -r '
        "  Всего:              " + (.components | length | tostring),
        "  С PURL:             " + ([.components[] | select(.purl != null)] | length | tostring),
        "  С версией:          " + ([.components[] | select(.version != null and .version != "")] | length | tostring),
        "  С лицензией:        " + ([.components[] | select(.licenses != null and (.licenses | length) > 0)] | length | tostring),
        "  С externalRefs:     " + ([.components[] | select(.externalReferences != null)] | length | tostring)
        ' "${ENRICHED_SBOM}" 2>/dev/null
    fi
} | tee "${REPORT_FILE}"

log ""
log "============================================================"
log "Pipeline завершён успешно"
log "Финальный SBOM:  ${ENRICHED_SBOM}"
log "Отчёт pipeline:  ${REPORT_FILE}"
log "============================================================"
