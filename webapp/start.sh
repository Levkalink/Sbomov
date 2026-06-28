#!/usr/bin/env bash
# Запуск веб-интерфейса SBOM Automation
set -euo pipefail

cd "$(dirname "$0")"
PORT="${PORT:-8000}"
HOST="${HOST:-0.0.0.0}"

echo "=== SBOM Automation Web UI ==="
echo "Адрес: http://${HOST}:${PORT}"
echo "Остановка: Ctrl+C"
echo ""

exec uvicorn main:app --host "${HOST}" --port "${PORT}" --reload
