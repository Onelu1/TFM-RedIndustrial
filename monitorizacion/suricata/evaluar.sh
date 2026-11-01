#!/usr/bin/env bash
# evaluar.sh - Corre Suricata offline (-r pcap) sobre todos los pcaps del
# arbol "capturas pcap/" (baseline/ + ataques/<escenario>/) y produce
# eve.json espejando la estructura en monitorizacion/suricata/salida/.
set -euo pipefail
export MSYS_NO_PATHCONV=1

AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../.." && pwd)"
MON="$(cd "$AQUI/.." && pwd)"
PCAPS_SRC="$RAIZ/capturas pcap"
PCAPS_WORK="$AQUI/pcaps_in"
SAL="$AQUI/salida"
IMG="jasonish/suricata:latest"
# Para extraer escrituras DNP3 fuera de rango a partir del eve.json
BANDAS_DNP3="$MON/kb/valores_ok_dnp3.json"
VAL_DNP3="$MON/valores/salida"

mkdir -p "$PCAPS_WORK" "$SAL" "$VAL_DNP3"

contar() {
    local f="$1"
    if [ -f "$f" ]; then
        grep -c '"event_type":"alert"' "$f" 2>/dev/null || true
    fi
}

evaluar() {
    local pcap="$1"
    local relpath="${pcap#$PCAPS_SRC/}"
    local nombre="$(basename "$pcap" .pcap)"
    local relsubdir="$(dirname "$relpath")"
    local tam
    tam=$(stat -c %s "$pcap" 2>/dev/null || echo 0)
    [ "$tam" -lt 100 ] && return   # pcap vacio
    # Copia a pcaps_in con nombre plano (los subdirs chocarian con el mount)
    cp "$pcap" "$PCAPS_WORK/${nombre}.pcap"
    local outdir="$SAL/$relsubdir/${nombre}"
    mkdir -p "$outdir"
    docker run --rm \
        -v "$PCAPS_WORK":/pcaps:ro \
        -v "$AQUI/suricata.yaml":/etc/suricata/suricata.yaml:ro \
        -v "$AQUI/vars_kb.yaml":/etc/suricata/vars_kb.yaml:ro \
        -v "$AQUI/rules":/etc/suricata/rules:ro \
        -v "$outdir":/var/log/suricata \
        "$IMG" \
        suricata -c /etc/suricata/suricata.yaml \
                 -S /etc/suricata/rules/local.rules \
                 -r "/pcaps/${nombre}.pcap" \
                 -l /var/log/suricata >/dev/null 2>&1 || true
    rm -f "$PCAPS_WORK/${nombre}.pcap"
    local n
    n=$(contar "$outdir/eve.json")
    [ -z "$n" ] && n=0
    printf "   %-60s %4d alertas\n" "$relpath" "$n"

    # DNP3: por cada escritura analogica (Operate sobre G41) marca fuera_rango
    # contra valores_ok_dnp3.json. El NDJSON producido lo recoge agregar_eve.sh
    # para que Wazuh 100410 reaccione igual que con Modbus.
    if [ -f "$BANDAS_DNP3" ] && [ -f "$outdir/eve.json" ]; then
        mkdir -p "$VAL_DNP3/$relsubdir"
        python3 "$MON/flujos/eve2valores_dnp3.py" \
            --eve    "$outdir/eve.json" \
            --salida "$VAL_DNP3/$relsubdir/${nombre}.dnp3.ndjson" \
            --bandas "$BANDAS_DNP3" \
            --src    "${relpath}" >/dev/null 2>&1 || true
    fi
}

echo "[eval] Evaluando pcaps..."
while IFS= read -r -d '' pcap; do
    evaluar "$pcap"
done < <(find "$PCAPS_SRC" -type f -name '*.pcap' -print0 | sort -z)

echo
echo "===================== RESUMEN =============================="
printf "%-55s %6s  %s\n" "Pcap" "Alerts" "SIDs disparados"
echo "------------------------------------------------------------"
while IFS= read -r -d '' eve; do
    nombre="$(basename "$(dirname "$eve")")"
    n=$(contar "$eve")
    [ -z "$n" ] && n=0
    sids=$(grep -oP '"signature_id":[0-9]+' "$eve" 2>/dev/null | sort -u | sed 's/"signature_id"://' | tr '\n' ' ' | sed 's/ *$//')
    printf "%-55s %6d  %s\n" "$nombre" "$n" "$sids"
done < <(find "$SAL" -name eve.json -print0 | sort -z)
