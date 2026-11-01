#!/usr/bin/env bash
# entrenar.sh - Fase de aprendizaje dinamico de roles / KB (opcion [E]).
#
# 5 pasos:
#   1) Captura N segundos de trafico limpio desde los 4 puntos.
#   2) PCAP -> NDJSON de flujos (softflowd + nfdump).
#   3) Inferir roles -> inventario.json + inventario_vs_hosts.md.
#   4) Construir KB (CDBs + umbrales + suricata_vars) a partir del inventario.
#   5) Sincronizar listas a Wazuh y espejo de suricata_vars -> suricata/vars_kb.yaml.
#
# Uso: entrenar.sh [DURACION_SEG]   (por defecto 1800 = 30 min)
#
# Precondiciones (verificadas por el orquestador antes de invocar este
# script): el lab + Wazuh estan arriba y kali_nodo esta pausado/silenciado.
set -euo pipefail

SEG="${1:-1800}"
AQUI="$(cd "$(dirname "$0")" && pwd)"
MON="$(cd "$AQUI/.." && pwd)"
RAIZ="$(cd "$MON/.." && pwd)"

echo "========================================================================"
echo "  [E] MODO ENTRENAMIENTO — captura limpia (${SEG}s) + inferir roles"
echo "========================================================================"

echo
echo "[entrenamiento] 1/5 Captura baseline (${SEG}s) desde 4 puntos..."
bash "$MON/captura/capturar.sh" baseline "$SEG"

echo
echo "[entrenamiento] 2/5 PCAP -> NDJSON de flujos..."
bash "$MON/flujos/pcap2flujos.sh"

echo
echo "[entrenamiento] 3/5 Inferir roles -> inventario.json..."
python "$MON/kb/inferir_roles.py" \
    --flujos  "$MON/flujos/salida/baseline/*.json" \
    --salida  "$MON/kb" \
    --duracion-segundos "$SEG"

echo
echo "[entrenamiento] 4/5 Construir KB desde inventario..."
python "$MON/kb/construir_kb.py" \
    --baseline   "$MON/flujos/salida/baseline/*.json" \
    --inventario "$MON/kb/inventario.json" \
    --c2-mailbox "$MON/kb/c2_mailbox.yaml" \
    --salida     "$MON/kb"

echo
echo "[entrenamiento] 4b/5 Extraer pares (ip,mac) del baseline -> mac_ok.cdb..."
# Requiere scapy -> corre dentro del contenedor tfm_monitor.
docker run --rm \
    -v "$RAIZ/capturas pcap:/datos/pcaps:ro" \
    -v "$MON/kb:/datos/salida" \
    tfm_monitor python3 /datos/salida/aprender_macs.py \
        --baseline '/datos/pcaps/baseline/*.pcap' \
        --salida   /datos/salida/mac_ok.cdb

echo
echo "[entrenamiento] 4c/5 Aprender rangos de valores Modbus -> valores_ok.json..."
docker run --rm \
    -v "$RAIZ/capturas pcap:/datos/pcaps:ro" \
    -v "$MON/kb:/datos/salida" \
    tfm_monitor python3 /datos/salida/aprender_valores.py \
        --baseline '/datos/pcaps/baseline/*.pcap' \
        --salida   /datos/salida/valores_ok.json

echo
echo "[entrenamiento] 4d/5 Aprender rangos DNP3 desde eve.json de baseline..."
# Requiere que evaluar.sh haya corrido antes sobre los baseline. Si no hay
# eve.json aun, lanzamos solo los baseline dnp3 por nosotros.
EVES="$MON/suricata/salida/baseline"
if ! find "$EVES" -name "eve.json" -path "*dnp3*" | grep -q .; then
    echo "[entrenamiento]   (no hay eve.json dnp3; evaluando baselines dnp3 ahora)"
    SURI_IMG="jasonish/suricata:latest"
    for p in "$RAIZ/capturas pcap/baseline/"*dnp3*.pcap; do
        n="$(basename "$p" .pcap)"
        mkdir -p "$EVES/${n}"
        cp "$p" "$MON/suricata/pcaps_in/${n}.pcap"
        docker run --rm \
            -v "$MON/suricata/pcaps_in:/pcaps:ro" \
            -v "$MON/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro" \
            -v "$MON/suricata/vars_kb.yaml:/etc/suricata/vars_kb.yaml:ro" \
            -v "$MON/suricata/rules:/etc/suricata/rules:ro" \
            -v "$EVES/${n}:/var/log/suricata" \
            "$SURI_IMG" suricata -c /etc/suricata/suricata.yaml \
                -S /etc/suricata/rules/local.rules \
                -r "/pcaps/${n}.pcap" -l /var/log/suricata >/dev/null 2>&1 || true
        rm -f "$MON/suricata/pcaps_in/${n}.pcap"
    done
fi
python "$MON/kb/aprender_valores_dnp3.py" \
    --eves  "$MON/suricata/salida/baseline/*dnp3*/eve.json" \
    --salida "$MON/kb/valores_ok_dnp3.json"

echo
echo "[entrenamiento] 4e/5 Generar reglas Suricata por valor fuera de banda..."
# Produce valores_generado.rules (SIDs 2001000+) que suricata_ids carga via
# `include` desde local.rules. El reload en caliente lo hace el orquestador
# con `docker restart suricata_ids` al final de [E] (scenario/orquestador.py).
python "$MON/kb/generar_reglas_valores.py" \
    --bandas "$MON/kb/valores_ok.json" \
    --salida "$MON/suricata/rules/valores_generado.rules"

echo
echo "[entrenamiento] 5/5 Sincronizar listas a Wazuh + espejo vars_kb.yaml..."
bash "$MON/wazuh/sync_listas.sh"
cp "$MON/kb/suricata_vars.yaml" "$MON/suricata/vars_kb.yaml"

echo
echo "========================================================================"
echo "  [OK] Entrenamiento completado"
echo "========================================================================"
echo "  Inventario : $MON/kb/inventario.json"
echo "  Reporte    : $MON/kb/inventario_vs_hosts.md"
echo "  Vars Suri  : $MON/suricata/vars_kb.yaml"
echo
echo "  Siguiente paso: [9] Pipeline completo (reutiliza este inventario)."
echo "========================================================================"
