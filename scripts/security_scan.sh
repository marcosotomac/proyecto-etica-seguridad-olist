#!/usr/bin/env bash
# Análisis de seguridad reproducible. Guarda los reportes en informe/evidencias/.
#   SAST:        Bandit sobre todo el código Python (incluye pki.py y scripts/).
#   SCA Python:  pip-audit contra la base de vulnerabilidades de PyPI/OSV.
#   SCA JS:      npm audit de las dependencias de producción del frontend.
#   Pruebas:     pytest (35 pruebas de requerimientos S01-S06, P01 y F1-F3).
set -uo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python}
OUT=informe/evidencias
mkdir -p "$OUT"
status=0

echo "== Bandit (SAST)"
$PY -m bandit -q -r app.py backup.py db_crypto.py import_data.py migrate_db.py pki.py scripts \
  -f json -o "$OUT/bandit.json"; b=$?
$PY -m bandit -q -r app.py backup.py db_crypto.py import_data.py migrate_db.py pki.py scripts || status=1

echo "== pip-audit (dependencias Python)"
$PY -m pip_audit -r requirements.txt --format json -o "$OUT/pip-audit.json" || status=1
$PY -m pip_audit -r requirements.txt || true

echo "== npm audit (dependencias de producción del frontend)"
(cd frontend && npm audit --omit=dev --json > "../$OUT/npm-audit.json"); n=$?
(cd frontend && npm audit --omit=dev) || status=1

echo "== pytest"
$PY -m pytest -q --junitxml="$OUT/pytest.xml" || status=1

exit $status
