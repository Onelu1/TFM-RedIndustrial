#!/usr/bin/env bash
# ejecutar_escenario.sh - Captura + lanza un modulo del toolkit, todo en uno.
#
# Uso:
#   bash ejecutar_escenario.sh <nombre_escenario> [--seg <seg>] -- <cmd a ejecutar>
#
# El <cmd a ejecutar> se corre dentro de kali_nodo con "docker exec kali_nodo bash -lc".
# Se le dan 10s de margen antes para que arranque tcpdump, y 10s de margen
# despues para que termine la cola de paquetes.
#
# Ejemplos:
#   bash ejecutar_escenario.sh recon_modbus -- \
#     python3 -m modules.recon modbus_discover --target 192.168.10.10
#
#   bash ejecutar_escenario.sh modbus_write_register -- \
#     python3 -m modules.modbus_msf write_register \
#       --target 192.168.10.10 --data-address 20 --data 1500 --unit-id 1
set -euo pipefail

AQUI="$(cd "$(dirname "$0")" && pwd)"
NOMBRE="${1:-}"
shift || true
SEG=60
# Si viene "--seg N", lo capturamos
if [ "${1:-}" = "--seg" ]; then SEG="$2"; shift 2; fi
# El resto debe empezar por "--"
if [ "${1:-}" != "--" ]; then
    echo "Uso: $0 <nombre> [--seg N] -- <cmd>" >&2
    exit 1
fi
shift
CMD="$*"

[ -z "$NOMBRE" ] && { echo "Falta <nombre_escenario>" >&2; exit 1; }
[ -z "$CMD"    ] && { echo "Falta <cmd>" >&2; exit 1; }

echo "[escenario] $NOMBRE  (captura ${SEG}s)"
echo "[escenario] comando: $CMD"
echo

# 1) Lanza captura en background
bash "$AQUI/capturar.sh" escenario "$NOMBRE" "$SEG" > /tmp/cap_${NOMBRE}.log 2>&1 &
CAP_PID=$!
# 2) 10s de pre-roll (tcpdump arranca)
until grep -q "mqtt (broker):" /tmp/cap_${NOMBRE}.log 2>/dev/null; do sleep 1; done
sleep 10
# 3) Ejecuta el comando dentro de kali_nodo (en /ataques, con PYTHONPATH)
echo "[escenario] lanzando ataque..."
docker exec kali_nodo bash -lc "cd /ataques && export PYTHONPATH=/ataques && $CMD" 2>&1 | sed 's/^/   atk| /' || true
# 4) Espera a que termine la captura
echo "[escenario] atacante terminado; esperando a que termine la captura (max $(( SEG + 10 ))s)..."
wait $CAP_PID 2>/dev/null || true
# Margen para que los tcpdump cierren y liberen sus pcap destino antes
# de que el siguiente escenario arranque sus propios tcpdump.
sleep 3
echo
echo "[escenario] OK. Logs:"
# cat ... | tail evita la carrera clasica tail-f-con-rm (cat lee el fichero
# completo, cierra el fd y lo pasa por tubería; luego el rm es inocuo).
cat /tmp/cap_${NOMBRE}.log 2>/dev/null | tail -5
rm -f /tmp/cap_${NOMBRE}.log
