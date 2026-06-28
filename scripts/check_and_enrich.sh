#!/usr/bin/env bash
# Шаг 2: Валидация и обогащение SBOM через sbom-checker (ИСПРАН)
# Запускается ПОСЛЕ generate_sbom.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SBOM_FILE="${1:?Укажите путь к SBOM-файлу: $0 <sbom.json> [options]}"
OUTPUT_DIR="$(dirname "${SBOM_FILE}")"

APP_NAME="${SBOM_APP_NAME:-TODO}"
APP_VERSION="${SBOM_APP_VERSION:-TODO}"
MANUFACTURER="${SBOM_MANUFACTURER:-TODO}"
CHECK_VCS="${SBOM_CHECK_VCS:-false}"
FORMAT="${SBOM_FORMAT:-oss}"         # oss | container
MAX_ERRORS="${SBOM_MAX_ERRORS:-0}"   # 0 = все ошибки

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[CHECK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()  { echo -e "${RED}[ERR]${NC}   $*"; }
info() { echo -e "${BLUE}[INFO]${NC}  $*"; }

check_tool() { command -v "$1" &>/dev/null; }

# ─── Шаг 1: Обогащение через sbom-updater ───────────────────────────────────
enrich_sbom() {
    local input="$1"
    local enriched="${OUTPUT_DIR}/$(basename "${input%.json}")-enriched.json"

    if ! check_tool sbom-updater; then
        warn "sbom-updater не найден. Запустите scripts/setup.sh"
        cp "$input" "$enriched"
        echo "$enriched"
        return
    fi

    log "Обогащение SBOM через sbom-updater..."

    # --fix-all: добавляет все поля которые нужны для валидации
    # --props:   добавляет GOST-поля attack_surface и security_function
    # --ref:     добавляет externalReferences из purl (VCS-ссылки)
    sbom-updater \
        --fix-all \
        --props \
        --ref \
        ${APP_NAME:+--app-name "${APP_NAME}"} \
        ${APP_VERSION:+--app-version "${APP_VERSION}"} \
        ${MANUFACTURER:+--manufacturer "${MANUFACTURER}"} \
        "${input}" \
        "${enriched}" \
        && log "Обогащённый SBOM: ${enriched}" \
        || { warn "sbom-updater завершился с ошибками, использую исходный файл"; cp "$input" "$enriched"; }

    echo "$enriched"
}

# ─── Шаг 2: Валидация через sbom-checker ────────────────────────────────────
validate_sbom() {
    local sbom="$1"
    local exit_code=0

    if ! check_tool sbom-checker; then
        warn "sbom-checker не найден. Запустите scripts/setup.sh"
        return 0
    fi

    log "Валидация SBOM через sbom-checker (ИСПРАН)..."
    info "  Файл:   $(basename "${sbom}")"
    info "  Формат: ${FORMAT}"
    info "  VCS-проверка: ${CHECK_VCS}"
    echo ""

    local vcs_flag=""
    if [ "${CHECK_VCS}" = "true" ]; then
        # --check-vcs-leaf-only быстрее чем --check-vcs (только leaf-узлы)
        vcs_flag="--check-vcs-leaf-only"
    fi

    # Базовая валидация: PURL, структура CycloneDX JSON
    sbom-checker \
        --purl-validation yes \
        --format "${FORMAT}" \
        --errors "${MAX_ERRORS}" \
        ${vcs_flag} \
        "${sbom}" \
        && log "sbom-checker: PASSED" \
        || { exit_code=$?; warn "sbom-checker обнаружил проблемы (код ${exit_code})"; }

    return ${exit_code}
}

# ─── Шаг 3: Проверка source-distribution URL ────────────────────────────────
validate_sources() {
    local sbom="$1"

    if ! check_tool sbom-checker; then return 0; fi

    log "Проверка source-distribution URL..."
    sbom-checker \
        --check-source-distribution \
        --purl-validation no \
        --errors "${MAX_ERRORS}" \
        "${sbom}" \
        && log "source-distribution: OK" \
        || warn "Некоторые source-distribution URL недоступны"
}

# ─── Шаг 4: Дополнительная jq-валидация ─────────────────────────────────────
validate_structure() {
    local sbom="$1"

    if ! check_tool jq; then return 0; fi

    log "Структурная проверка CycloneDX SBOM..."

    local errors=0

    # Проверка обязательных полей верхнего уровня
    for field in "bomFormat" "specVersion" "version" "metadata" "components"; do
        if ! jq -e ".${field}" "$sbom" &>/dev/null; then
            warn "Отсутствует обязательное поле: .${field}"
            errors=$((errors+1))
        fi
    done

    # Компоненты без purl — риск для vulnerability tracking
    local no_purl
    no_purl=$(jq '[.components[] | select(.purl == null)] | length' "$sbom" 2>/dev/null || echo 0)
    if [ "${no_purl}" -gt 0 ]; then
        warn "Компонентов без PURL: ${no_purl} (не будут покрыты vulnerability scanning)"
    fi

    # Компоненты без версии
    local no_version
    no_version=$(jq '[.components[] | select(.version == null or .version == "")] | length' "$sbom" 2>/dev/null || echo 0)
    if [ "${no_version}" -gt 0 ]; then
        warn "Компонентов без версии: ${no_version}"
    fi

    # Компоненты без лицензий
    local no_license
    no_license=$(jq '[.components[] | select(.licenses == null or (.licenses | length) == 0)] | length' "$sbom" 2>/dev/null || echo 0)
    if [ "${no_license}" -gt 0 ]; then
        info "Компонентов без лицензий: ${no_license} (рекомендуется добавить)"
    fi

    if [ "${errors}" -eq 0 ]; then
        log "Структура CycloneDX: корректна"
    else
        warn "Найдено структурных ошибок: ${errors}"
    fi
}

# ─── MAIN ────────────────────────────────────────────────────────────────────
main() {
    [ -f "${SBOM_FILE}" ] || { err "Файл не найден: ${SBOM_FILE}"; exit 1; }

    log "======================================================"
    log "SBOM Validation & Enrichment"
    log "Файл: ${SBOM_FILE}"
    log "======================================================"

    # 1. Обогащение
    local enriched
    enriched=$(enrich_sbom "${SBOM_FILE}")

    # 2. Валидация
    validate_sbom "${enriched}" || true

    # 3. Проверка source URLs (опционально, может быть медленно)
    if [ "${SBOM_CHECK_SOURCES:-false}" = "true" ]; then
        validate_sources "${enriched}"
    fi

    # 4. Структурная проверка
    validate_structure "${enriched}"

    log ""
    log "======================================================"
    log "Итоговый файл: ${enriched}"
    log "======================================================"
    echo "${enriched}"
}

main "$@"
