#!/usr/bin/env bash
# agregar_eve.sh - Concatena todos los eve.json y flujos JSON TFM en un único
# fichero cada uno para que Wazuh logcollector los lea (no soporta globs
# anidados estilo **/eve.json).
#
# Añade a cada evento el campo "tfm_src" con la ruta original para trazabilidad.
# Idempotente: trunca los all_*.json y los rellena desde cero.
set -euo pipefail
AQUI="$(cd "$(dirname "$0")" && pwd)"
SURICATA="$AQUI/../suricata/salida"
FLUJOS="$AQUI/../flujos/salida"
MACS="$AQUI/../macs/salida"
VALORES="$AQUI/../valores/salida"
OUT_EVE="$AQUI/all_eve.json"
OUT_FLUJOS="$AQUI/all_flujos.json"
OUT_MACS="$AQUI/all_macs.json"
OUT_VALORES="$AQUI/all_valores.json"

: > "$OUT_EVE"
: > "$OUT_FLUJOS"
: > "$OUT_MACS"
: > "$OUT_VALORES"

n_eve=0
# Encuentra todos los eve.json bajo suricata/salida
while IFS= read -r -d '' f; do
    rel="${f#$SURICATA/}"
    rel="${rel%/eve.json}"
    # Añade "tfm_src":"<rel>" al final de cada JSON (antes del }), con sed
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        # Reemplaza el último } por ,"tfm_src":"<rel>"}
        echo "${line%\}},\"tfm_src\":\"${rel}\"}" >> "$OUT_EVE"
        n_eve=$((n_eve+1))
    done < "$f"
done < <(find "$SURICATA" -name 'eve.json' -print0 | sort -z)
echo "[agregar_eve] eve.json consolidado: $n_eve eventos -> $OUT_EVE"

n_fj=0
while IFS= read -r -d '' f; do
    rel="${f#$FLUJOS/}"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in \{*\}) ;; *) continue ;; esac
        echo "${line%\}},\"tfm_src\":\"${rel}\"}" >> "$OUT_FLUJOS"
        n_fj=$((n_fj+1))
    done < "$f"
done < <(find "$FLUJOS" -name '*.json' -print0 | sort -z)
echo "[agregar_eve] flujos consolidados: $n_fj flujos -> $OUT_FLUJOS"

n_mac=0
if [ -d "$MACS" ]; then
    while IFS= read -r -d '' f; do
        rel="${f#$MACS/}"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            case "$line" in \{*\}) ;; *) continue ;; esac
            # pcap2macs.py ya incluye "tfm_src", no lo reinyectamos.
            echo "$line" >> "$OUT_MACS"
            n_mac=$((n_mac+1))
        done < "$f"
    done < <(find "$MACS" -name '*.ndjson' -print0 | sort -z)
fi
echo "[agregar_eve] macs consolidados: $n_mac pares -> $OUT_MACS"

n_val=0
if [ -d "$VALORES" ]; then
    while IFS= read -r -d '' f; do
        rel="${f#$VALORES/}"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            case "$line" in \{*\}) ;; *) continue ;; esac
            echo "$line" >> "$OUT_VALORES"
            n_val=$((n_val+1))
        done < "$f"
    done < <(find "$VALORES" -name '*.ndjson' -print0 | sort -z)
fi
echo "[agregar_eve] valores Modbus consolidados: $n_val ops -> $OUT_VALORES"
