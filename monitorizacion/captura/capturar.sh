#!/usr/bin/env bash
# capturar.sh - Captura PCAPs del laboratorio (Fase 1 del plan).
#
# Punto de captura: router_gw, en las interfaces EXTERNAS al NAT:
#   eth2 = red_control (IPs reales de SCADA, broker, gateways DNP3, srv_empresa)
#   eth3 = red_empresa (atacante kali, srv_empresa pivote)
# Más broker_mqtt (tráfico MQTT intra red_control, que no cruza el router).
#
# ¿Por qué no capturar en las patas OT (eth0/1/5)? Porque llevan paquetes
# tras MASQUERADE (SRC = router). Las interfaces externas conservan las
# IPs originales de cliente, que es lo que necesitan la KB y Suricata.
#
# Modos:
#   baseline [SEG]           Captura tráfico limpio durante SEG segundos (def 1800).
#   escenario NOMBRE [SEG]   Captura NOMBREd durante SEG segundos (def 180).
#
# Salida: ../capturas pcap/<tipo>_<punto>-YYYYmmdd-HHMMSS.pcap
set -euo pipefail

MODO="${1:-}"
AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../.." && pwd)"
SALIDA="$RAIZ/capturas pcap"
mkdir -p "$SALIDA"

# Cargar el mapeo de interfaces generado por preparar_router.sh
if [ -f "$AQUI/.ifaces.env" ]; then
    . "$AQUI/.ifaces.env"
else
    echo "[captura] ERROR: $AQUI/.ifaces.env no existe. Ejecuta preparar_router.sh primero." >&2
    exit 1
fi

usar() {
    sed -n '2,20p' "$0"
    exit 1
}

# Lanza tcpdump en una interfaz del router y vuelca pcap vía stdout al host.
capturar_router() {
    local iface="$1" segundos="$2" fichero="$3"
    timeout "${segundos}s" docker exec -i router_gw \
        tcpdump -i "$iface" -U -s 0 -w - 2>/dev/null > "$fichero" || true
}

# Lanza tcpdump en un contenedor cualquiera (any), para tráfico intra-zona.
# Instala tcpdump si no está (idempotente para Alpine / Debian).
capturar_contenedor() {
    local contenedor="$1" segundos="$2" fichero="$3"
    docker exec -u 0 "$contenedor" sh -c '
        command -v tcpdump >/dev/null 2>&1 || {
            if command -v apk >/dev/null;      then apk add --no-cache tcpdump >/dev/null 2>&1
            elif command -v apt-get >/dev/null; then apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq tcpdump >/dev/null 2>&1
            fi
        }
    ' 2>/dev/null || true
    timeout "${segundos}s" docker exec -i "$contenedor" \
        tcpdump -i any -U -s 0 -w - 2>/dev/null > "$fichero" || true
}

# Lanza los puntos de captura en paralelo con el mismo prefijo y timestamp.
#   control: eth2 del router (IPs reales SCADA, srv_empresa, gateways DNP3)
#   empresa: eth3 del router (atacante kali, srv_empresa pivote)
#   mqtt:    broker_mqtt (MQTT intra red_control)
#   dnp3_N:  cada gateway_dnp3_N vivo (DNP3 intra red_ot_zona_c, no cruza router)
#
# Numero de puntos DNP3 = numero de gateway_dnp3_* detectados por `docker ps`.
# Por eso una ejecucion con 3 gateways produce 6 pcaps (3 fijos + 3 DNP3).
#
# dir_dest: subcarpeta destino bajo "capturas pcap/" (p.ej. "baseline" o
# "ataques/recon_modbus"). Se crea con mkdir -p.
lanzar_cuatro_capturas() {
    local prefijo="$1" seg="$2" dir_dest="$3"
    local ts="$(date +%Y%m%d-%H%M%S)"
    local dir="$SALIDA/$dir_dest"
    mkdir -p "$dir"
    local base="$dir/${prefijo}"
    local f_ctrl="${base}_control-${ts}.pcap"
    local f_empr="${base}_empresa-${ts}.pcap"
    local f_mqtt="${base}_mqtt-${ts}.pcap"

    # Detecta todos los gateways DNP3 vivos y les asigna un pcap propio.
    local gateways
    gateways=$(docker ps --format '{{.Names}}' 2>/dev/null \
                 | grep -E '^gateway_dnp3_[0-9]+$' | sort || true)
    local pcaps_gw=()

    echo "[captura] ${prefijo} durante ${seg}s en $dir_dest/"
    echo "   control (${IF_CTRL}): $f_ctrl"
    echo "   empresa (${IF_EMPR}): $f_empr"
    echo "   mqtt (broker):         $f_mqtt"
    capturar_router "$IF_CTRL" "$seg" "$f_ctrl" &
    capturar_router "$IF_EMPR" "$seg" "$f_empr" &
    capturar_contenedor broker_mqtt "$seg" "$f_mqtt" &

    if [ -z "$gateways" ]; then
        echo "   (sin gateways DNP3 vivos: solo 3 puntos de captura)"
    fi
    for gw in $gateways; do
        local n="${gw##*_}"   # extrae el indice numerico tras el ultimo _
        local f_gw="${base}_dnp3_${n}-${ts}.pcap"
        pcaps_gw+=("$f_gw")
        echo "   dnp3_${n} (${gw}): $f_gw"
        capturar_contenedor "$gw" "$seg" "$f_gw" &
    done
    wait
    echo "[captura] OK:"
    ls -la "$f_ctrl" "$f_empr" "$f_mqtt" "${pcaps_gw[@]}" 2>/dev/null
}

case "$MODO" in
    baseline)
        lanzar_cuatro_capturas "baseline" "${2:-1800}" "baseline"
        ;;
    escenario)
        NOMBRE="${2:-}"
        SEG="${3:-180}"
        [ -z "$NOMBRE" ] && usar
        lanzar_cuatro_capturas "atk_${NOMBRE}" "$SEG" "ataques/$NOMBRE"
        ;;

    *)
        usar
        ;;
esac
