#!/usr/bin/env python3
"""Despliegue end-to-end, limpieza y cambio de modo de `kali_nodo`."""

import os
import subprocess
import time

from .compose import generate_docker_compose, read_scenario_sizes
from .docker_images import build_openplc_image_if_needed, build_s7_image_if_needed
from .nodered_flow import save_flows_file  # noqa: F401 — reservado para extensiones
from .samba import setup_vulnerable_samba
from .shell import run_cmd


def preparar_router():
    """Instala tcpdump+iptables en router_gw y añade reglas MASQUERADE hacia
    las zonas OT. Puerto en Python del antiguo `preparar_router.sh` para que
    funcione desde `python main.py` sin depender de bash en el host (en
    Windows la invocacion a `bash` tiraba de WSL y fallaba silenciosa).

    Es idempotente. Tambien escribe `monitorizacion/captura/.ifaces.env`
    para que `capturar.sh` lo use mas adelante.
    """
    print("[router] Instalando tcpdump + iptables en router_gw...")
    run_cmd(
        'docker exec -u 0 router_gw sh -c '
        '"command -v tcpdump >/dev/null || apk add --no-cache tcpdump >/dev/null; '
        'command -v iptables >/dev/null || apk add --no-cache iptables >/dev/null"',
        check=False,
    )

    print("[router] Instalando tcpdump en broker_mqtt...")
    run_cmd(
        'docker exec -u 0 broker_mqtt sh -c '
        '"command -v tcpdump >/dev/null || apk add --no-cache tcpdump >/dev/null"',
        check=False,
    )

    print("[router] Mapeando interfaces por red...")
    # Las interfaces de router_gw cambian de orden entre arranques. Deduzco
    # el nombre a partir de la IP para que las reglas iptables sean estables.
    def iface_de(ip):
        # Nota: usamos subprocess directo para evitar la captura/limpieza
        # ambigua de run_cmd y procesar la salida linea a linea.
        out = subprocess.run(
            ["docker", "exec", "router_gw", "ip", "-o", "-4", "addr", "show"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        ).stdout
        for linea in out.splitlines():
            # formato: "N: ethX    inet 192.168.X.Y/24 brd ... scope global ethX"
            partes = linea.split()
            if len(partes) >= 4 and partes[3].startswith(ip + "/"):
                return partes[1]
        return ""

    mapeo = {
        "IF_CTRL": iface_de("192.168.20.254"),
        "IF_EMPR": iface_de("192.168.60.254"),
        "IF_MOD":  iface_de("192.168.10.254"),
        "IF_S7":   iface_de("192.168.30.254"),
        "IF_DNP":  iface_de("192.168.40.254"),
    }
    for k, v in mapeo.items():
        print(f"   {k} = {v}")

    if not (mapeo["IF_MOD"] and mapeo["IF_S7"] and mapeo["IF_DNP"]):
        print("[router] ERROR: no he podido mapear alguna interfaz OT; abortando MASQUERADE.")
        return

    print("[router] Instalando reglas MASQUERADE...")
    run_cmd(
        'docker exec -u 0 router_gw sh -c "'
        'iptables -t nat -F POSTROUTING 2>/dev/null || true; '
        f'iptables -t nat -A POSTROUTING -d 192.168.10.0/24 -o {mapeo["IF_MOD"]} -j MASQUERADE; '
        f'iptables -t nat -A POSTROUTING -d 192.168.30.0/24 -o {mapeo["IF_S7"]} -j MASQUERADE; '
        f'iptables -t nat -A POSTROUTING -d 192.168.40.0/24 -o {mapeo["IF_DNP"]} -j MASQUERADE'
        '"',
        check=False,
    )

    # Exportamos el mapeo para capturar.sh (misma ruta que generaba el .sh).
    env_path = os.path.join("monitorizacion", "captura", ".ifaces.env")
    try:
        os.makedirs(os.path.dirname(env_path), exist_ok=True)
        with open(env_path, "w", encoding="utf-8") as f:
            f.write("# Generado por scenario.deploy.preparar_router() (NO EDITAR A MANO)\n")
            for k, v in mapeo.items():
                f.write(f"{k}={v}\n")
        print(f"[router] OK. Mapeo guardado en {env_path}")
    except OSError as e:
        print(f"[router] Aviso: no pude escribir {env_path}: {e}")


def switch_kali_mode():
    """Cambia el modo de kali_nodo (empresa <-> control) sin tocar los PLCs.

    - Pregunta el nuevo modo.
    - Lee cuántos PLCs tiene el escenario (del compose actual) o los pide.
    - Regenera `docker-compose.generated.yml` con el nuevo kali_mode.
    - Recrea solo `kali_nodo` con `--force-recreate --no-deps`.
    - Si pasa a 'control', añade las 5 rutas inter-zona.
    - Reinicia el dashboard dentro del contenedor.
    """
    # Importación local para romper el ciclo scenario.deploy <-> scenario.menu
    from .menu import ask_kali_mode

    new_mode = ask_kali_mode()
    n_mb, n_s7, n_dnp3 = read_scenario_sizes()
    if n_mb is None:
        print("[!] No encuentro docker-compose.generated.yml. Introduce los números:")
        n_mb = int(input("Número de PLCs Modbus TCP (Zona A): "))
        n_s7 = int(input("Número de PLCs Siemens S7 (Zona B): "))
        n_dnp3 = int(input("Número de PLCs DNP3 (Zona C): "))
    else:
        print(f"[*] Escenario detectado: {n_mb} Modbus, {n_s7} S7, {n_dnp3} DNP3.")

    print(f"[*] Regenerando compose con kali_mode='{new_mode}'...")
    generate_docker_compose(n_mb, n_s7, n_dnp3, kali_mode=new_mode)

    print("[*] Recreando únicamente kali_nodo (los PLCs siguen arriba)...")
    run_cmd("docker compose -f docker-compose.generated.yml up -d --force-recreate --no-deps kali_nodo",
            capture=False)
    time.sleep(3)

    if new_mode == "control":
        print("[*] Añadiendo rutas inter-zona a kali_nodo...")
        for net in ("192.168.10.0/24", "192.168.30.0/24", "192.168.40.0/24",
                    "192.168.50.0/24", "192.168.60.0/24"):
            run_cmd(f"docker exec kali_nodo ip route add {net} via 192.168.20.254",
                    check=False)

    # Reiniciar dashboard para que recoja el nuevo .mode. Si todavía no hay
    # Flask (apt+pip en curso), el fuser falla silenciosamente y el usuario
    # tendrá que usar [6] cuando termine la instalación.
    print("[*] Reiniciando dashboard dentro de kali_nodo...")
    run_cmd("docker exec kali_nodo bash -c 'fuser -k 8888/tcp 2>/dev/null; sleep 1'",
            check=False)
    run_cmd("docker exec -d kali_nodo bash -c 'cd /ataques && python3 web/app.py > /tmp/dashboard.log 2>&1'",
            check=False)

    print(f"\n[OK] kali_nodo ahora corre en modo '{new_mode}'.")
    if new_mode == "control":
        print("     Rutas inter-zona añadidas; sin pivote. Dashboard sin tarjeta Samba.")
    else:
        print("     Sin rutas directas; prepara el túnel desde la tarjeta Samba del dashboard.")
    print("     Dashboard: http://localhost:8888")
    print("     Si no responde todavía, es que apt+pip aún no terminó;")
    print("     espera unos minutos y usa [6] para relanzarlo.")


def deploy_scenario(num_modbus_a, num_s7_b, num_dnp3_c=0, kali_mode="empresa"):
    if num_s7_b > 0 and not build_s7_image_if_needed():
        return
    if (num_modbus_a > 0 or num_dnp3_c > 0) and not build_openplc_image_if_needed():
        return

    print(f"\n[*] Generando archivos de configuración IaC (kali_mode={kali_mode})...")
    setup_vulnerable_samba()
    generate_docker_compose(num_modbus_a, num_s7_b, num_dnp3_c, kali_mode=kali_mode)

    print("\n[*] [1/4] Levantando contenedores con Docker Compose...")
    run_cmd("docker compose -f docker-compose.generated.yml up -d --build")

    print("[*] [2/4] Instalando paquetes de S7, Modbus y Dashboard en Node-RED...")
    run_cmd("docker exec nodered_scada_1 npm install --prefix /data node-red-contrib-modbus node-red-contrib-s7 @flowfuse/node-red-dashboard -qq")

    print("[*] [3/4] Reiniciando Node-RED para cargar los nuevos módulos...")
    run_cmd("docker restart nodered_scada_1")
    time.sleep(8)

    print("[*] [4/4] Instalando utilidades e inyectando rutas estáticas inter-zona...")

    # MASQUERADE + iptables en router_gw. Imprescindible porque las zonas OT
    # son internal:true y, sin SNAT, las respuestas de los PLCs no vuelven a
    # red_control/red_empresa. Antes solo lo hacía la opción 8 (arrancar_todo)
    # vía bash; ahora lo hace esta misma funcion en Python para que funcione
    # tambien desde `python main.py` en Windows sin bash en PATH.
    print("[*] Preparando router_gw (MASQUERADE hacia zonas OT)...")
    preparar_router()

    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.10.0/24 via 192.168.20.254", check=False)
    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.30.0/24 via 192.168.20.254", check=False)
    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.40.0/24 via 192.168.20.254", check=False)
    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.50.0/24 via 192.168.20.254", check=False)
    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.60.0/24 via 192.168.20.254", check=False)

    # kali_nodo: solo necesita rutas inter-zona cuando está dentro de red_control
    # (modo "control"). En modo "empresa" NO se añaden: el acceso a OT debe pasar
    # obligatoriamente por el túnel SSH SOCKS vía srv_empresa.
    if kali_mode == "control":
        print("[*] Añadiendo rutas inter-zona a kali_nodo (modo control)...")
        for net in ("192.168.10.0/24", "192.168.30.0/24", "192.168.40.0/24",
                    "192.168.50.0/24", "192.168.60.0/24"):
            run_cmd(f"docker exec kali_nodo ip route add {net} via 192.168.20.254", check=False)

    run_cmd("docker exec srv_monitorizacion ip route add 192.168.0.0/16 via 192.168.50.254", check=False)
    run_cmd("docker exec srv_empresa ip route add 192.168.0.0/16 via 192.168.20.254", check=False)

    for i in range(1, num_modbus_a + 1):
        run_cmd(f"docker exec plc_agua_{i} apt-get update -qq && docker exec plc_agua_{i} apt-get install -y iproute2 iputils-ping -qq", check=False)
        run_cmd(f"docker exec plc_agua_{i} ip route add 192.168.20.0/24 via 192.168.10.254", check=False)

    for i in range(1, num_s7_b + 1):
        run_cmd(f"docker exec plc_s7_{i} ip route add 192.168.20.0/24 via 192.168.30.254", check=False)

    for i in range(1, num_dnp3_c + 1):
        run_cmd(f"docker exec plc_dnp3_{i} apt-get update -qq && docker exec plc_dnp3_{i} apt-get install -y iproute2 iputils-ping -qq", check=False)
        run_cmd(f"docker exec plc_dnp3_{i} ip route add 192.168.20.0/24 via 192.168.40.254", check=False)

    print("\n[✔] Escenario Purdue desplegado y enrutado con éxito.")


def clean_environment():
    print("\n[*] Eliminando infraestructura activa...")
    if os.path.exists("docker-compose.generated.yml"):
        run_cmd("docker compose -f docker-compose.generated.yml down --remove-orphans", check=False)
    print("[✔] Entorno totalmente limpio.")
