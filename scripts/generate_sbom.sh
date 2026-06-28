#!/usr/bin/env bash
# SBOM Generator для C-проектов с CycloneDX
# Автоматически определяет тип проекта и выбирает оптимальный инструмент
set -euo pipefail

# ─── Константы ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${1:-$(pwd)}"
CONFIG_FILE="${SBOM_CONFIG:-${SCRIPT_DIR}/../config/sbom.config.yaml}"
OUTPUT_DIR="${SBOM_OUTPUT_DIR:-${ROOT_DIR}/sbom-output}"
SPEC_VERSION="${SBOM_SPEC_VERSION:-1.6}"
PROJECT_NAME="${SBOM_PROJECT_NAME:-$(basename "${ROOT_DIR}")}"
PROJECT_VERSION="${SBOM_VERSION:-$(git -C "${ROOT_DIR}" describe --tags --abbrev=0 2>/dev/null || echo "0.0.0")}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
LOG_FILE="${OUTPUT_DIR}/sbom-generate.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# ─── Вспомогательные функции ────────────────────────────────────────────────
log()  { echo -e "${GREEN}[SBOM]${NC} $*" | tee -a "${LOG_FILE}"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "${LOG_FILE}"; }
err()  { echo -e "${RED}[ERR]${NC}  $*" | tee -a "${LOG_FILE}"; }
info() { echo -e "${BLUE}[INFO]${NC} $*" | tee -a "${LOG_FILE}"; }

check_tool() { command -v "$1" &>/dev/null; }

# ─── Инициализация ──────────────────────────────────────────────────────────
init() {
    mkdir -p "${OUTPUT_DIR}"
    : > "${LOG_FILE}"
    log "======================================================"
    log "SBOM Generation — ${PROJECT_NAME} v${PROJECT_VERSION}"
    log "Scan target: ${ROOT_DIR}"
    log "Timestamp:   ${TIMESTAMP}"
    log "======================================================"
}

# ─── Установка инструментов ─────────────────────────────────────────────────
install_tools() {
    local missing=()

    if ! check_tool cdxgen; then
        warn "cdxgen не найден. Устанавливаю..."
        npm install -g @cyclonedx/cdxgen --prefer-offline 2>>"${LOG_FILE}" \
            && log "cdxgen установлен" \
            || { err "Не удалось установить cdxgen"; missing+=("cdxgen"); }
    fi

    if ! check_tool syft; then
        warn "syft не найден. Устанавливаю..."
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
            | sh -s -- -b /usr/local/bin 2>>"${LOG_FILE}" \
            && log "syft установлен" \
            || { err "Не удалось установить syft"; missing+=("syft"); }
    fi

    if ! check_tool cyclonedx; then
        warn "CycloneDX CLI не найден. Устанавливаю..."
        # Для Linux x86_64
        local cdx_ver="v0.27.1"
        local cdx_url="https://github.com/CycloneDX/cyclonedx-cli/releases/download/${cdx_ver}/cyclonedx-linux-x64"
        curl -sSfL "${cdx_url}" -o /usr/local/bin/cyclonedx 2>>"${LOG_FILE}" \
            && chmod +x /usr/local/bin/cyclonedx \
            && log "CycloneDX CLI установлен" \
            || { err "Не удалось установить CycloneDX CLI"; missing+=("cyclonedx-cli"); }
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        warn "Пропущены инструменты: ${missing[*]}. Продолжаю с доступными."
    fi
}

# ─── Определение типа C-проекта ─────────────────────────────────────────────
detect_project_type() {
    local types=()

    # Conan — лучший вариант для C: даёт детерминированный lock-файл
    [ -f "${ROOT_DIR}/conanfile.py" ] || [ -f "${ROOT_DIR}/conanfile.txt" ] && types+=("conan")
    [ -f "${ROOT_DIR}/conan.lock" ] && types+=("conan_lock")

    # vcpkg
    [ -f "${ROOT_DIR}/vcpkg.json" ] && types+=("vcpkg")

    # CMake без пакетного менеджера
    [ -f "${ROOT_DIR}/CMakeLists.txt" ] && types+=("cmake")

    # Makefile без CMake
    [ -f "${ROOT_DIR}/Makefile" ] && ! echo "${types[@]:-}" | grep -q "cmake" && types+=("makefile")

    # Meson
    [ -f "${ROOT_DIR}/meson.build" ] && types+=("meson")

    # Bare C (только .c/.h файлы)
    if find "${ROOT_DIR}" -maxdepth 3 -name "*.c" | grep -q .; then
        types+=("c_source")
    fi

    echo "${types[@]:-unknown}"
}

# ─── Фильтр шума (системные пакеты) ─────────────────────────────────────────
# Применяется к JSON-файлу CycloneDX через jq
filter_noise() {
    local input_file="$1"
    local output_file="$2"

    if ! check_tool jq; then
        apt-get install -y jq -qq 2>>"${LOG_FILE}" || { warn "jq не найден, фильтрация пропущена"; cp "$input_file" "$output_file"; return; }
    fi

    info "Применяю фильтр шума к: $(basename "${input_file}")"

    # Паттерны шума: системные deb/rpm пакеты, libc, linux-libs
    # Фильтруем компоненты у которых purl содержит pkg:deb или pkg:rpm
    # и имена которые совпадают с системными паттернами
    jq '
    # Системные PURL-типы — основной источник шума в C-проектах
    def is_system_pkg:
        .purl? // "" | test("^pkg:(deb|rpm|apk)/") or
        (.name? // "" | test("^(linux-|libc6|libgcc|libstdc\\+\\+|gcc-[0-9]|binutils|coreutils|base-files|base-passwd|bash|debianutils|diffutils|dpkg|e2fsprogs|findutils|grep|gzip|hostname|init-system-helpers|login|mount|ncurses|passwd|perl-base|procps|sed|sensible-utils|sysvinit-utils|tar|tzdata|util-linux|zlib1g|libssl|openssl|ca-certificates)"));

    def count_filtered:
        [.components[]? | select(is_system_pkg)] | length;

    # Отчёт + фильтрация
    . as $orig |
    ($orig | count_filtered) as $removed |
    .components = [.components[]? | select(is_system_pkg | not)] |
    .metadata.properties = (
        (.metadata.properties // []) +
        [{"name": "sbom:filtered_system_packages", "value": ($removed | tostring)},
         {"name": "sbom:generator", "value": "sbomsauto"},
         {"name": "sbom:generated_at", "value": now | todate}]
    )
    ' "${input_file}" > "${output_file}"

    local before after removed
    before=$(jq '.components | length' "${input_file}" 2>/dev/null || echo "?")
    after=$(jq '.components | length' "${output_file}" 2>/dev/null || echo "?")
    removed=$(( before - after )) 2>/dev/null || removed="?"
    log "Фильтрация: ${before} → ${after} компонентов (удалено ${removed} системных)"
}

# ─── Сканер 1: Conan (ЛУЧШИЙ для C проектов) ────────────────────────────────
scan_conan() {
    local out="${OUTPUT_DIR}/sbom-conan.json"
    log "[1/4] Сканирование через Conan CycloneDX plugin..."

    if ! check_tool conan; then
        warn "conan не найден, пропускаю"
        return 1
    fi

    # Убедимся что conan sbom плагин установлен
    if ! conan config list 2>/dev/null | grep -q "sbom"; then
        pip3 install cyclonedx-conan 2>>"${LOG_FILE}" || true
    fi

    cd "${ROOT_DIR}"

    # Генерация lock-файла если его нет
    if [ ! -f conan.lock ]; then
        info "Генерирую conan.lock..."
        conan lock create . 2>>"${LOG_FILE}" || conan install . --lockfile-out conan.lock 2>>"${LOG_FILE}" || true
    fi

    if [ -f conan.lock ]; then
        # cyclonedx-conan: официальный CycloneDX плагин для Conan
        if check_tool cyclonedx-conan; then
            cyclonedx-conan conan.lock > "${out}" 2>>"${LOG_FILE}" \
                && log "Conan SBOM: ${out}" \
                || warn "cyclonedx-conan завершился с ошибкой"
        # Встроенный плагин Conan 2.x
        elif conan help sbom 2>/dev/null; then
            conan sbom:cyclonedx \
                --format "cyclonedx-json-v${SPEC_VERSION}" \
                conanfile.py 2>/dev/null \
                || conanfile.txt 2>/dev/null \
                > "${out}" 2>>"${LOG_FILE}" \
                && log "Conan native SBOM: ${out}"
        fi
    fi

    [ -f "${out}" ] && filter_noise "${out}" "${OUTPUT_DIR}/sbom-conan-filtered.json"
}

# ─── Сканер 2: vcpkg ─────────────────────────────────────────────────────────
scan_vcpkg() {
    log "[2/4] Сканирование через vcpkg..."

    if [ ! -f "${ROOT_DIR}/vcpkg.json" ]; then
        info "vcpkg.json не найден, пропускаю"
        return 0
    fi

    local out="${OUTPUT_DIR}/sbom-vcpkg.json"

    # vcpkg генерирует SPDX natively, конвертируем через cdxgen или CLI
    if check_tool vcpkg; then
        vcpkg install --vcpkg-root "${ROOT_DIR}" 2>>"${LOG_FILE}" || true
        # vcpkg генерирует _manifest/versions/_baseline.json
        find "${ROOT_DIR}/vcpkg_installed" -name "*.spdx.json" 2>/dev/null | head -1 | \
            xargs -I{} cyclonedx convert --input-file {} --output-file "${out}" \
                --output-format json --output-version v${SPEC_VERSION} 2>>"${LOG_FILE}" || true
    fi

    # Fallback: cdxgen умеет читать vcpkg.json
    if [ ! -f "${out}" ] && check_tool cdxgen; then
        cdxgen \
            --type "cpp" \
            --spec-version "${SPEC_VERSION}" \
            --output "${out}" \
            "${ROOT_DIR}" 2>>"${LOG_FILE}" \
            && log "vcpkg SBOM через cdxgen: ${out}"
    fi

    [ -f "${out}" ] && filter_noise "${out}" "${OUTPUT_DIR}/sbom-vcpkg-filtered.json"
}

# ─── Сканер 3: cdxgen (универсальный, OWASP официальный) ────────────────────
scan_cdxgen() {
    log "[3/4] Сканирование через cdxgen (OWASP)..."

    if ! check_tool cdxgen; then
        warn "cdxgen не найден, пропускаю"
        return 1
    fi

    local out="${OUTPUT_DIR}/sbom-cdxgen.json"

    # cdxgen для C/C++: использует Conan, vcpkg, cmake manifests
    # --required-only: только прямые зависимости (меньше шума)
    # --filter: исключаем pkg:deb и pkg:rpm через PURL фильтр
    CDXGEN_DEBUG_MODE="${CDXGEN_DEBUG_MODE:-false}" \
    cdxgen \
        --type "c" \
        --spec-version "${SPEC_VERSION}" \
        --output "${out}" \
        --filter "pkg:deb" \
        --filter "pkg:rpm" \
        --project-name "${PROJECT_NAME}" \
        --project-version "${PROJECT_VERSION}" \
        "${ROOT_DIR}" 2>>"${LOG_FILE}" \
        && log "cdxgen SBOM: ${out}" \
        || warn "cdxgen завершился с ошибкой"

    [ -f "${out}" ] && filter_noise "${out}" "${OUTPUT_DIR}/sbom-cdxgen-filtered.json"
}

# ─── Сканер 4: Syft (бинарный анализ) ────────────────────────────────────────
scan_syft() {
    log "[4/4] Бинарный анализ через Syft..."

    if ! check_tool syft; then
        warn "syft не найден, пропускаю"
        return 1
    fi

    local out="${OUTPUT_DIR}/sbom-syft.json"

    # КЛЮЧЕВЫЕ ФЛАГИ для C-проектов без шума:
    # --override-default-catalogers: только бинарный анализ, БЕЗ dpkg/rpm (главный источник шума)
    # binary-cataloger: fingerprint .so, .a, бинарей по версионным строкам
    # conan-cataloger: читает conaninfo.txt и conan.lock
    syft \
        dir:"${ROOT_DIR}" \
        --output "cyclonedx-json@${SPEC_VERSION}=${out}" \
        --override-default-catalogers "binary-cataloger,conan-cataloger" \
        --exclude "/usr/share/**" \
        --exclude "/var/**" \
        --exclude "/etc/**" \
        --exclude "/boot/**" \
        --exclude "/proc/**" \
        --exclude "/sys/**" \
        --exclude "**/.git/**" \
        --exclude "**/node_modules/**" \
        2>>"${LOG_FILE}" \
        && log "Syft SBOM: ${out}" \
        || warn "Syft завершился с ошибкой"

    [ -f "${out}" ] && filter_noise "${out}" "${OUTPUT_DIR}/sbom-syft-filtered.json"
}

# ─── Слияние результатов всех сканеров ──────────────────────────────────────
merge_sboms() {
    log "Объединяю результаты сканеров..."

    local filtered_files=()
    for f in "${OUTPUT_DIR}"/sbom-*-filtered.json; do
        [ -f "$f" ] && filtered_files+=("$f")
    done

    if [ ${#filtered_files[@]} -eq 0 ]; then
        warn "Нет отфильтрованных файлов для слияния"
        return 1
    fi

    local final="${OUTPUT_DIR}/sbom-${PROJECT_NAME}-${PROJECT_VERSION}.json"

    if [ ${#filtered_files[@]} -eq 1 ]; then
        cp "${filtered_files[0]}" "${final}"
        log "Единственный SBOM: ${final}"
        return 0
    fi

    # Слияние через CycloneDX CLI (дедупликация по purl)
    if check_tool cyclonedx; then
        local merge_args=()
        for f in "${filtered_files[@]}"; do
            merge_args+=("--input-file" "$f")
        done
        cyclonedx merge \
            "${merge_args[@]}" \
            --output-file "${final}" \
            --output-format json \
            --output-version "v${SPEC_VERSION}" \
            2>>"${LOG_FILE}" \
            && log "Merged SBOM: ${final}" \
            || warn "Слияние через CycloneDX CLI не удалось, использую jq-merge"
    fi

    # Fallback: слияние через jq (дедупликация по purl)
    if [ ! -f "${final}" ] && check_tool jq; then
        jq -s '
        .[0] as $base |
        reduce .[1:][] as $other (
            $base;
            .components += ($other.components // [])
        ) |
        # Дедупликация по purl (или по name+version если нет purl)
        .components = (
            [.components[] | {key: (.purl // (.name + "@" + (.version // ""))), value: .}] |
            group_by(.key) |
            map(.[0].value)
        )
        ' "${filtered_files[@]}" > "${final}" \
            && log "jq-merged SBOM: ${final}"
    fi

    echo "${final}"
}

# ─── Валидация итогового SBOM ────────────────────────────────────────────────
validate_sbom() {
    local sbom_file="$1"
    [ -f "${sbom_file}" ] || { err "Файл SBOM не найден: ${sbom_file}"; return 1; }

    log "Валидация SBOM..."

    local component_count
    component_count=$(jq '.components | length' "${sbom_file}" 2>/dev/null || echo 0)
    info "Итоговых компонентов в SBOM: ${component_count}"

    if check_tool cyclonedx; then
        cyclonedx validate \
            --input-file "${sbom_file}" \
            --input-format json \
            --input-version "v${SPEC_VERSION}" \
            2>>"${LOG_FILE}" \
            && log "Валидация CycloneDX: PASSED" \
            || warn "Валидация CycloneDX: WARNING (SBOM может быть неполным)"
    fi

    # Краткая статистика
    if check_tool jq; then
        echo ""
        info "=== Статистика SBOM ==="
        jq -r '
        "  Компонентов: " + (.components | length | tostring),
        "  С лицензией: " + ([.components[] | select(.licenses != null and (.licenses | length) > 0)] | length | tostring),
        "  С PURL:      " + ([.components[] | select(.purl != null)] | length | tostring),
        "  С хэшами:    " + ([.components[] | select(.hashes != null and (.hashes | length) > 0)] | length | tostring),
        "  Типы пакетов: " + ([.components[].purl? // "" | split("/")[0] | split(":")[1]? // "unknown"] | group_by(.) | map("\(.[0])(\(. | length))") | join(", "))
        ' "${sbom_file}" 2>/dev/null | tee -a "${LOG_FILE}"
        echo ""
    fi
}

# ─── Генерация отчёта ────────────────────────────────────────────────────────
generate_report() {
    local sbom_file="$1"
    local report="${OUTPUT_DIR}/sbom-report-${TIMESTAMP}.md"

    cat > "${report}" << REPORT
# SBOM Report — ${PROJECT_NAME} v${PROJECT_VERSION}

**Generated:** ${TIMESTAMP}
**Format:** CycloneDX JSON v${SPEC_VERSION}
**Target:** \`${ROOT_DIR}\`

## Результаты сканирования

| Сканер | Файл | Компонентов |
|--------|------|-------------|
REPORT

    for f in "${OUTPUT_DIR}"/sbom-*-filtered.json; do
        [ -f "$f" ] || continue
        local scanner count
        scanner=$(basename "$f" | sed 's/sbom-//;s/-filtered.json//')
        count=$(jq '.components | length' "$f" 2>/dev/null || echo "?")
        echo "| ${scanner} | \`$(basename "$f")\` | ${count} |" >> "${report}"
    done

    cat >> "${report}" << REPORT

## Итоговый SBOM

\`\`\`
$(basename "${sbom_file}")
\`\`\`

Компонентов после дедупликации и фильтрации: **$(jq '.components | length' "${sbom_file}" 2>/dev/null || echo "?")**

## Использование

\`\`\`bash
# Список всех зависимостей
jq '.components[] | "\(.name) \(.version // "?")"' ${sbom_file}

# Зависимости с известными уязвимостями (через grype)
grype sbom:${sbom_file}

# Загрузка в Dependency Track
curl -X PUT https://dtrack.example.com/api/v1/bom \\
  -H "X-Api-Key: \${DTRACK_API_KEY}" \\
  -F "bom=@${sbom_file}"
\`\`\`
REPORT

    log "Отчёт: ${report}"
}

# ─── MAIN ────────────────────────────────────────────────────────────────────
main() {
    init

    log "Установка/проверка инструментов..."
    install_tools

    log "Определение типа проекта..."
    local project_types
    project_types=$(detect_project_type)
    info "Обнаруженные типы: ${project_types}"

    local ran=0

    # Запускаем сканеры в порядке точности
    if echo "${project_types}" | grep -q "conan"; then
        scan_conan && ran=$((ran+1)) || true
    fi

    if echo "${project_types}" | grep -q "vcpkg"; then
        scan_vcpkg && ran=$((ran+1)) || true
    fi

    # cdxgen — всегда запускаем как universal fallback
    scan_cdxgen && ran=$((ran+1)) || true

    # Syft — бинарный анализ как дополнение
    scan_syft && ran=$((ran+1)) || true

    if [ "${ran}" -eq 0 ]; then
        err "Ни один сканер не дал результатов. Проверьте ${LOG_FILE}"
        exit 1
    fi

    local final_sbom
    final_sbom=$(merge_sboms)

    if [ -n "${final_sbom}" ] && [ -f "${final_sbom}" ]; then
        validate_sbom "${final_sbom}"
        generate_report "${final_sbom}"
        log ""
        log "======================================================"
        log "SBOM готов: ${final_sbom}"
        log "Лог:        ${LOG_FILE}"
        log "======================================================"
    else
        err "Не удалось создать итоговый SBOM"
        exit 1
    fi
}

main "$@"
