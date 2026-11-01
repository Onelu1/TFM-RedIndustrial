#!/usr/bin/env bash
# pcap2flujos.sh - convierte todos los pcaps en ../capturas pcap/ a flujos
# IPFIX y los re-exporta en JSON (una línea por flujo) para alimentar la KB
# y Wazuh. Usa softflowd (exportador IPFIX) + nfdump (colector + a JSON).
#
# Cómo funciona:
#   1) softflowd -r <pcap>  genera flujos NetFlow v10 (= IPFIX) y los exporta
#      por UDP al puerto 9995 del localhost del contenedor.
#   2) nfcapd escucha en 9995 y los escribe a disco en formato nfcapd binario.
#   3) nfdump lee el nfcapd y vuelca a JSON (una línea por flujo).
#
# Todo en un único `docker run`, aislado por pcap.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash en Windows: no reescribas /datos/... a C:/Program Files/Git/datos/...

AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../.." && pwd)"
PCAPS="$RAIZ/capturas pcap"
SAL="$AQUI/salida"
SAL_MACS="$AQUI/../macs/salida"
SAL_VALS="$AQUI/../valores/salida"
KB="$AQUI/../kb"
IMG="tfm_monitor"

mkdir -p "$SAL" "$SAL_MACS" "$SAL_VALS"

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    echo "[flujos] Construyendo imagen $IMG..."
    docker build -t "$IMG" "$AQUI"
fi

procesar_pcap() {
    local pcap="$1"
    local nombre="$(basename "$pcap" .pcap)"
    # Preservar la jerarquía: pcap bajo "capturas pcap/baseline/x.pcap" -> salida/baseline/x.csv
    # idem con "ataques/<escenario>/". El 'relpath' = ruta dentro de PCAPS.
    local relpath="${pcap#$PCAPS/}"
    local relsubdir="$(dirname "$relpath")"
    local out_subdir="$SAL/$relsubdir"
    mkdir -p "$out_subdir"
    echo "[flujos] $relpath"

    docker run --rm \
        -v "$PCAPS":/datos/pcaps:ro \
        -v "$SAL":/datos/salida \
        -v "$SAL_MACS":/datos/macs \
        -v "$SAL_VALS":/datos/valores \
        -v "$KB":/datos/kb:ro \
        -v "$AQUI":/datos/scripts:ro \
        "$IMG" bash -c "
            set -e
            rm -rf /tmp/nf && mkdir -p /tmp/nf
            # 0a) Extraer pares (ip, mac) del pcap ORIGINAL (antes del
            # reencap SLL2->Ether) para alimentar la deteccion MAC (regla
            # Wazuh 100310 contra mac_ok.cdb aprendida en entrenamiento).
            mkdir -p '/datos/macs/${relsubdir}'
            python3 /datos/scripts/pcap2macs.py \
                --pcap   '/datos/pcaps/${relpath}' \
                --salida '/datos/macs/${relsubdir}/${nombre}.ndjson' \
                --src    '${relpath}' 2>&1 | sed 's/^/   /'
            # 0a2) Extraer operaciones Modbus con valor y marcar fuera_rango
            # contra valores_ok.json (regla Wazuh 100410). Solo writes para
            # reducir ruido; reads se usan en el baseline para APRENDER la
            # banda pero no para alertar.
            mkdir -p '/datos/valores/${relsubdir}'
            python3 /datos/scripts/pcap2valores.py \
                --pcap   '/datos/pcaps/${relpath}' \
                --salida '/datos/valores/${relsubdir}/${nombre}.ndjson' \
                --bandas /datos/kb/valores_ok.json \
                --src    '${relpath}' \
                --solo-writes 2>&1 | sed 's/^/   /'
            # 0b) softflowd no soporta LINUX_SLL/SLL2. Reencapsular con scapy.
            INPCAP='/datos/pcaps/${relpath}'
            LT=\$(tcpdump -r \"\$INPCAP\" 2>&1 | head -1 | grep -oE 'link-type [A-Z0-9_]+' | awk '{print \$2}')
            if [ \"\$LT\" = 'LINUX_SLL' ] || [ \"\$LT\" = 'LINUX_SLL2' ]; then
                sll2ether \"\$INPCAP\" /tmp/norm.pcap 2>&1 | sed 's/^/   /'
                INPCAP=/tmp/norm.pcap
            fi
            # 1) nfcapd (colector IPFIX) en background escuchando 9995
            nfcapd -D -b 127.0.0.1 -p 9995 -w /tmp/nf -I captura -t 5 >/dev/null 2>&1
            sleep 2
            # 2) softflowd lee pcap y exporta IPFIX al colector.
            softflowd -r \"\$INPCAP\" \
                -n 127.0.0.1:9995 -v 10 -t maxlife=120 -t expint=1 \
                -a >/dev/null 2>&1 || true
            # 3) dejar que nfcapd flush y pararlo
            sleep 8
            pkill -SIGTERM -f nfcapd 2>/dev/null || true
            sleep 2
            # 4) exportar los nfcapd a CSV y a JSON (para Wazuh)
            mkdir -p '/datos/salida/${relsubdir}'
            nfdump -r /tmp/nf -o csv 2>/dev/null | \
                awk 'NR==1{print; next} /^Summary/{exit} {print}' \
                > '/datos/salida/${relsubdir}/${nombre}.csv' || true
            # JSON (una linea por flujo). nfdump JSON output es array con
            # bracket inicial y final; filtramos para quedarnos con los
            # objetos de flujo linea a linea.
            nfdump -r /tmp/nf -o json 2>/dev/null | \
                python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for r in data:
    if r.get(\"type\") == \"FLOW\":
        print(json.dumps(r))
' > '/datos/salida/${relsubdir}/${nombre}.json' 2>/dev/null || true
        " 2>&1 | sed 's/^/   /'
    # Conteo en el host (CSV es cabecera + flujos)
    local csv_out="$SAL/$relsubdir/${nombre}.csv"
    if [ -f "$csv_out" ]; then
        local n=$(( $(wc -l < "$csv_out") - 1 ))
        [ "$n" -lt 0 ] && n=0
        echo "   flujos: $n"
    fi
}

# Encuentra recursivamente todos los pcaps (baseline/*.pcap y ataques/<X>/*.pcap)
while IFS= read -r -d '' pcap; do
    procesar_pcap "$pcap"
done < <(find "$PCAPS" -type f -name '*.pcap' -print0 | sort -z)

echo "[flujos] Hecho. Salida en $SAL/"
echo
echo "=== Resumen ==="
while IFS= read -r -d '' f; do
    relpath="${f#$SAL/}"
    n_flujos=$(($(wc -l < "$f" 2>/dev/null) - 1))
    [ "$n_flujos" -lt 0 ] && n_flujos=0
    printf "   %-70s %5d flujos\n" "$relpath" "$n_flujos"
done < <(find "$SAL" -type f -name '*.csv' -print0 | sort -z)
