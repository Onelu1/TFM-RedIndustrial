#!/usr/bin/env bash
# preparar_router.sh - Prepara router_gw tras un 'docker compose up':
#   1) instala tcpdump + iptables en router_gw (Alpine) y en broker_mqtt
#   2) instala reglas iptables MASQUERADE para que el tráfico que entra
#      desde red_control/red_empresa hacia zonas OT (internal) salga con la
#      IP del router en la zona de destino. Sin esto, el bridge Docker de
#      la red internal descarta paquetes forwardeados cuyo SRC no esté en
#      la propia red.
#   3) inyecta default gw en los contenedores que lo necesiten
#      (opcional / de refuerzo; MASQUERADE ya resuelve el camino de vuelta).
#
# Es idempotente. Hay que correrlo cada vez que se levanta el lab de cero.
set -euo pipefail

echo "[router] Instalando tcpdump + iptables en router_gw..."
docker exec -u 0 router_gw sh -c "
    command -v tcpdump >/dev/null || apk add --no-cache tcpdump >/dev/null
    command -v iptables >/dev/null || apk add --no-cache iptables >/dev/null
" 2>&1 | sed 's/^/   /'

echo "[router] Instalando tcpdump en broker_mqtt..."
docker exec -u 0 broker_mqtt sh -c "
    command -v tcpdump >/dev/null || apk add --no-cache tcpdump >/dev/null
" 2>&1 | sed 's/^/   /'

echo "[router] Mapeando interfaces por red..."
# Las interfaces de router_gw cambian de orden entre arranques. Deduzco el
# nombre a partir de la IP para que las reglas iptables sean estables.
iface_de() {
    local red="$1"
    docker exec router_gw ip -o -4 addr show | awk -v r="$red" '$4 ~ r {print $2}'
}
IF_CTRL=$(iface_de "192.168.20.254")
IF_EMPR=$(iface_de "192.168.60.254")
IF_MOD=$(iface_de "192.168.10.254")
IF_S7=$(iface_de "192.168.30.254")
IF_DNP=$(iface_de "192.168.40.254")
echo "   red_control    = $IF_CTRL"
echo "   red_empresa    = $IF_EMPR"
echo "   red_ot_zona_a  = $IF_MOD   (Modbus)"
echo "   red_ot_zona_b  = $IF_S7    (S7)"
echo "   red_ot_zona_c  = $IF_DNP   (DNP3)"

echo "[router] Instalando reglas MASQUERADE..."
docker exec -u 0 router_gw sh -c "
    iptables -t nat -F POSTROUTING 2>/dev/null || true
    iptables -t nat -A POSTROUTING -d 192.168.10.0/24 -o $IF_MOD -j MASQUERADE
    iptables -t nat -A POSTROUTING -d 192.168.30.0/24 -o $IF_S7  -j MASQUERADE
    iptables -t nat -A POSTROUTING -d 192.168.40.0/24 -o $IF_DNP -j MASQUERADE
    echo '[iptables] reglas finales:'
    iptables -t nat -L POSTROUTING -n -v --line-numbers
" 2>&1 | sed 's/^/   /'

# Exportamos los nombres de interfaz para capturar.sh.
mkdir -p "$(dirname "$0")"
cat > "$(dirname "$0")/.ifaces.env" <<ENV
# Generado por preparar_router.sh (NO EDITAR A MANO)
IF_CTRL=$IF_CTRL
IF_EMPR=$IF_EMPR
IF_MOD=$IF_MOD
IF_S7=$IF_S7
IF_DNP=$IF_DNP
ENV
echo "[router] OK. Mapeo guardado en captura/.ifaces.env"
