#!/usr/bin/env bash
# Установка всех инструментов для SBOM-автоматизации
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()  { echo -e "${RED}[ERR]${NC}   $*"; }

TOOLS_DIR="${TOOLS_DIR:-${HOME}/.sbomtools}"
mkdir -p "${TOOLS_DIR}"

log "=== SBOM Tools Setup ==="

# ─── 1. Системные зависимости ────────────────────────────────────────────────
log "Системные пакеты..."
apt-get update -qq 2>/dev/null && \
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    curl wget git jq \
    cmake pkg-config \
    2>/dev/null || warn "Некоторые системные пакеты не установлены"

# ─── 2. Node.js / cdxgen (OWASP официальный, лучший CycloneDX) ───────────────
log "cdxgen (OWASP CycloneDX официальный)..."
if ! command -v cdxgen &>/dev/null; then
    npm install -g @cyclonedx/cdxgen 2>/dev/null \
        && log "cdxgen установлен: $(cdxgen --version 2>/dev/null || echo '?')" \
        || warn "cdxgen не удалось установить — нужен npm"
else
    log "cdxgen уже установлен: $(cdxgen --version 2>/dev/null || echo '?')"
fi

# ─── 3. Syft (Anchore, бинарный анализ) ─────────────────────────────────────
log "Syft (бинарный анализ)..."
if ! command -v syft &>/dev/null; then
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
        | sh -s -- -b /usr/local/bin 2>/dev/null \
        && log "Syft установлен: $(syft --version 2>/dev/null || echo '?')" \
        || warn "Syft не удалось установить"
else
    log "Syft уже установлен: $(syft --version 2>/dev/null || echo '?')"
fi

# ─── 4. CycloneDX CLI (слияние, валидация, конвертация) ─────────────────────
log "CycloneDX CLI..."
if ! command -v cyclonedx &>/dev/null; then
    CDX_VER="v0.27.1"
    CDX_URL="https://github.com/CycloneDX/cyclonedx-cli/releases/download/${CDX_VER}/cyclonedx-linux-x64"
    curl -sSfL "${CDX_URL}" -o /usr/local/bin/cyclonedx \
        && chmod +x /usr/local/bin/cyclonedx \
        && log "CycloneDX CLI установлен" \
        || warn "CycloneDX CLI не удалось установить"
else
    log "CycloneDX CLI уже установлен"
fi

# ─── 5. cyclonedx-conan (CycloneDX плагин для Conan) ────────────────────────
log "cyclonedx-conan (Python плагин)..."
pip3 install --quiet cyclonedx-conan 2>/dev/null \
    && log "cyclonedx-conan установлен" \
    || warn "cyclonedx-conan не удалось установить"

# ─── 6. sbom-checker (ИСПРАН, валидация ГОСТ-совместимости) ─────────────────
log "sbom-checker (ИСПРАН SDL-Tools)..."
SBOM_CHECKER_DIR="${TOOLS_DIR}/sbom-checker"

if [ ! -d "${SBOM_CHECKER_DIR}" ]; then
    git clone --quiet \
        "https://gitlab.community.ispras.ru/sdl-tools/sbom-checker.git" \
        "${SBOM_CHECKER_DIR}" 2>/dev/null \
        && log "sbom-checker клонирован в ${SBOM_CHECKER_DIR}" \
        || warn "Не удалось клонировать sbom-checker (возможно, нет доступа к gitlab.community.ispras.ru)"
else
    git -C "${SBOM_CHECKER_DIR}" pull --quiet 2>/dev/null \
        && log "sbom-checker обновлён" \
        || warn "Не удалось обновить sbom-checker"
fi

if [ -d "${SBOM_CHECKER_DIR}" ]; then
    python3 -m venv "${SBOM_CHECKER_DIR}/venv" 2>/dev/null
    "${SBOM_CHECKER_DIR}/venv/bin/pip" install --quiet \
        -r "${SBOM_CHECKER_DIR}/requirements.txt" 2>/dev/null \
        && log "sbom-checker зависимости установлены" \
        || warn "Не удалось установить зависимости sbom-checker"

    # Создаём wrapper-скрипты
    cat > /usr/local/bin/sbom-checker << EOF
#!/usr/bin/env bash
exec "${SBOM_CHECKER_DIR}/venv/bin/python3" "${SBOM_CHECKER_DIR}/sbom-checker.py" "\$@"
EOF
    chmod +x /usr/local/bin/sbom-checker

    cat > /usr/local/bin/sbom-updater << EOF
#!/usr/bin/env bash
exec "${SBOM_CHECKER_DIR}/venv/bin/python3" "${SBOM_CHECKER_DIR}/sbom-updater.py" "\$@"
EOF
    chmod +x /usr/local/bin/sbom-updater
    log "Wrapper-скрипты созданы: sbom-checker, sbom-updater"
fi

# ─── Итог ────────────────────────────────────────────────────────────────────
echo ""
log "=== Статус инструментов ==="
printf "  %-25s %s\n" "cdxgen"          "$(command -v cdxgen         &>/dev/null && echo '✓ установлен' || echo '✗ не найден')"
printf "  %-25s %s\n" "syft"            "$(command -v syft           &>/dev/null && echo '✓ установлен' || echo '✗ не найден')"
printf "  %-25s %s\n" "cyclonedx-cli"   "$(command -v cyclonedx      &>/dev/null && echo '✓ установлен' || echo '✗ не найден')"
printf "  %-25s %s\n" "cyclonedx-conan" "$(command -v cyclonedx-conan &>/dev/null && echo '✓ установлен' || echo '✗ не найден')"
printf "  %-25s %s\n" "jq"              "$(command -v jq             &>/dev/null && echo '✓ установлен' || echo '✗ не найден')"
printf "  %-25s %s\n" "sbom-checker"    "$(command -v sbom-checker   &>/dev/null && echo '✓ установлен' || echo '✗ не найден')"
printf "  %-25s %s\n" "sbom-updater"    "$(command -v sbom-updater   &>/dev/null && echo '✓ установлен' || echo '✗ не найден')"
echo ""
log "Готово! Запустите: scripts/generate_sbom.sh <путь-к-проекту>"
