#!/usr/bin/env bash
# Copia las listas CDB generadas por kb/construir_kb.py al directorio que
# monta Wazuh, y espeja suricata_vars.yaml -> suricata/vars_kb.yaml (que es
# el fichero que Suricata hace `include:` en suricata.yaml). Idempotente.
set -euo pipefail
AQUI="$(cd "$(dirname "$0")" && pwd)"
KB="$(cd "$AQUI/../kb" && pwd)"
SURI="$(cd "$AQUI/../suricata" && pwd)"
DST="$AQUI/listas"
mkdir -p "$DST"
for f in comunicaciones_ok.cdb plcs.cdb plcs_ips.cdb funciones_modbus_ok.cdb mac_ok.cdb; do
    if [ -f "$KB/$f" ]; then
        # Wazuh espera listas sin extension; el .cdb binario lo genera el manager.
        cp -v "$KB/$f" "$DST/${f%.cdb}"
    else
        echo "[sync_listas] AVISO: $KB/$f no existe. Ejecuta construir_kb.py primero." >&2
    fi
done
if [ -f "$KB/suricata_vars.yaml" ]; then
    cp -v "$KB/suricata_vars.yaml" "$SURI/vars_kb.yaml"
else
    echo "[sync_listas] AVISO: $KB/suricata_vars.yaml no existe (sin inventario entrenado)." >&2
fi
echo "[sync_listas] Listas sincronizadas en $DST/ (+ vars_kb.yaml en $SURI/)"
