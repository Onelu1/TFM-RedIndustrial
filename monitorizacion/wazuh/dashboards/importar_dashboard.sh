#!/usr/bin/env bash
# importar_dashboard.sh - Importa el dashboard TFM OT en Wazuh via la API de
# saved_objects. Idempotente (overwrite=true).
#
# Ejecuta el curl DENTRO del contenedor wazuh.manager en vez de en el host.
# Razon: en Windows Git Bash, curl usa el backend TLS schannel que pierde
# las cookies de autenticacion durante la renegotiation que hace el server
# en multipart POST grandes (401 Unauthorized tras el upload). El curl
# dentro del contenedor (Linux + OpenSSL) no tiene ese bug.
#
# Prerrequisitos: wazuh.manager y wazuh.dashboard arriba.
# Credenciales: admin / SecretPassword (hard-coded; stack de laboratorio).
set -euo pipefail
export MSYS_NO_PATHCONV=1

AQUI="$(cd "$(dirname "$0")" && pwd)"
NDJSON_HOST="$AQUI/tfm_ot_dashboard.ndjson"
NDJSON_CT="/tmp/tfm_ot_dashboard.ndjson"
USUARIO="${WAZUH_USER:-admin}"
PASSWORD="${WAZUH_PASS:-SecretPassword}"

if [ ! -f "$NDJSON_HOST" ]; then
    echo "[dashboard] ERROR: $NDJSON_HOST no existe." >&2
    echo "            Regeneralo con: python $AQUI/generar_ndjson.py" >&2
    exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q '^wazuh.manager$'; then
    echo "[dashboard] ERROR: wazuh.manager no esta arriba." >&2
    exit 1
fi

echo "[dashboard] 1/3 Copiando NDJSON a wazuh.manager..."
# docker cp en Windows no entiende /c/... Usamos stdin pipe para evitar paths.
docker exec -i wazuh.manager tee "$NDJSON_CT" > /dev/null < "$NDJSON_HOST"

echo "[dashboard] 2/3 Login + refresh index pattern + import desde el contenedor..."
IMPORT_RESP=$(docker exec wazuh.manager bash -c "
    curl -sk -c /tmp/w.cookies \
        -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
        -d '{\"username\":\"$USUARIO\",\"password\":\"$PASSWORD\"}' \
        'https://wazuh.dashboard:5601/auth/login?security_payload=true' > /dev/null 2>&1

    # Refrescar los campos del index pattern wazuh-alerts-* (si Wazuh lo creo
    # antes de que llegaran los eventos Suricata, los nuevos campos
    # data.src_ip/dest_ip/dest_port/location no estaban en el pattern y los
    # widgets fallan con 'Could not locate index-pattern-field'). IMPORTANTE:
    # Wazuh espera 'attributes.fields' como *string JSON* (doble escapado),
    # no como array nativo; si se guarda como array la UI muere con
    # 'Unexpected token o, [object Object]... is not valid JSON'.
    REFRESH_BODY=\$(curl -sk -b /tmp/w.cookies \
        'https://wazuh.dashboard:5601/api/index_patterns/_fields_for_wildcard?pattern=wazuh-alerts-*&meta_fields=%5B%22_source%22%2C%22_id%22%2C%22_type%22%2C%22_index%22%2C%22_score%22%5D' \
        | python3 -c '
import json, sys
inner = json.dumps(json.load(sys.stdin)[\"fields\"])
body = {\"attributes\": {\"title\": \"wazuh-alerts-*\", \"timeFieldName\": \"timestamp\", \"fields\": inner}}
print(json.dumps(body))
')
    curl -sk -b /tmp/w.cookies -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
        -X PUT 'https://wazuh.dashboard:5601/api/saved_objects/index-pattern/wazuh-alerts-*' \
        -d \"\$REFRESH_BODY\" > /dev/null 2>&1

    curl -sk -b /tmp/w.cookies -H 'osd-xsrf: true' \
        -F 'file=@$NDJSON_CT' \
        'https://wazuh.dashboard:5601/api/saved_objects/_import?overwrite=true'
    rm -f /tmp/w.cookies $NDJSON_CT
")

if echo "$IMPORT_RESP" | grep -q '"success":true'; then
    N=$(echo "$IMPORT_RESP" | grep -oE '"successCount":[0-9]+' | head -1 | cut -d: -f2)
    echo "[dashboard] 3/3 OK: $N saved objects importados."
    echo "[dashboard]     Dashboard disponible en:"
    echo "[dashboard]       https://localhost:5601/app/dashboards#/view/tfm-ot-dashboard"
else
    echo "[dashboard] FALLO del import." >&2
    echo "[dashboard] Respuesta: $IMPORT_RESP" >&2
    echo "[dashboard] Importa a mano desde la UI:"
    echo "[dashboard]   Stack Management -> Saved Objects -> Import -> $NDJSON_HOST"
    exit 1
fi
