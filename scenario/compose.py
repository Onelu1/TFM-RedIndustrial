#!/usr/bin/env python3
"""Genera `docker-compose.generated.yml`, `mosquitto.conf`, las ACLs Modbus
y el marcador `ataques/.mode`. Rutas relativas al cwd."""

import os
import re


def read_scenario_sizes(compose_path="docker-compose.generated.yml"):
    """Devuelve (num_modbus, num_s7, num_dnp3) leyendo `container_name:` del
    compose; (None, None, None) si no existe."""
    try:
        with open(compose_path, "r", encoding="utf-8") as f:
            texto = f.read()
    except FileNotFoundError:
        return (None, None, None)
    n_mb = len(re.findall(r"container_name:\s*plc_agua_\d+", texto))
    n_s7 = len(re.findall(r"container_name:\s*plc_s7_\d+", texto))
    n_dnp3 = len(re.findall(r"container_name:\s*plc_dnp3_\d+", texto))
    return (n_mb, n_s7, n_dnp3)


def write_kali_mode_marker(kali_mode):
    """Escribe `ataques/.mode` con el modo elegido (empresa|control)."""
    ataques_dir = os.path.join(os.getcwd(), "ataques")
    os.makedirs(ataques_dir, exist_ok=True)
    with open(os.path.join(ataques_dir, ".mode"), "w", encoding="utf-8") as f:
        f.write(kali_mode.strip())
    print(f"[+] Modo kali_nodo marcado como '{kali_mode}' en ataques/.mode")


def generate_docker_compose(num_modbus_a, num_s7_b, num_dnp3_c=0, incluir_kali=True,
                             kali_mode="empresa"):
    with open("mosquitto.conf", "w") as f:
        f.write("listener 1883\nallow_anonymous true\n")

    compose_content = f"""name: tfm-purdue-scenarios

networks:
  red_control:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.20.0/24
  red_ot_zona_a:
    driver: bridge
    internal: true                # fuerza inter-zona via router_gw (Purdue real)
    ipam:
      config:
        - subnet: 192.168.10.0/24
  red_ot_zona_b:
    driver: bridge
    internal: true                # fuerza inter-zona via router_gw (Purdue real)
    ipam:
      config:
        - subnet: 192.168.30.0/24
  red_ot_zona_c:
    driver: bridge
    internal: true                # fuerza inter-zona via router_gw (Purdue real)
    ipam:
      config:
        - subnet: 192.168.40.0/24
  red_monitorizacion:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.50.0/24
  red_empresa:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.60.0/24

services:
  router_gw:
    image: alpine:latest
    container_name: router_gw
    sysctls:
      - net.ipv4.ip_forward=1
    command: tail -f /dev/null
    cap_add:
      - NET_ADMIN
    networks:
      red_control:
        ipv4_address: 192.168.20.254
      red_ot_zona_a:
        ipv4_address: 192.168.10.254
      red_ot_zona_b:
        ipv4_address: 192.168.30.254
      red_ot_zona_c:
        ipv4_address: 192.168.40.254
      red_monitorizacion:
        ipv4_address: 192.168.50.254
      red_empresa:
        ipv4_address: 192.168.60.254

  nodered_scada_1:
    image: nodered/node-red:latest
    container_name: nodered_scada_1
    cap_add:
      - NET_ADMIN
    networks:
      red_control:
        ipv4_address: 192.168.20.10
    ports:
      - "1880:1880"
    volumes:
      - ./nodered_data_scada_1:/data
    restart: always

  mosquitto:
    image: eclipse-mosquitto:2
    container_name: broker_mqtt
    ports:
      - "1883:1883"
    volumes:
      - ./mosquitto.conf:/mosquitto/config/mosquitto.conf:ro
    networks:
      red_control:
        ipv4_address: 192.168.20.15
 
  # --- ZONA C: RED DE EMPRESA (Pivote Vulnerable Samba) ---
  srv_empresa:
    image: dperson/samba
    container_name: srv_empresa
    cap_add:
      - NET_ADMIN
    networks:
      red_empresa:
        ipv4_address: 192.168.60.50
      red_control:
        ipv4_address: 192.168.20.50
    ports:
      - "2222:22"
    volumes:
      - ./recurso_compartido:/mount
    command: >
      sh -c "apk update && apk add openssh && ssh-keygen -A && 
      mkdir -p /root/.ssh && chmod 700 /root/.ssh && 
      cp /mount/ssh_keys/id_rsa.pub /root/.ssh/authorized_keys && 
      chmod 600 /root/.ssh/authorized_keys && 
      chmod 700 /root && 
      echo 'root:root' | chpasswd && 
      passwd -u root && 
      sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && 
      sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config && 
      sed -i 's/.*AllowTcpForwarding.*/AllowTcpForwarding yes/g' /etc/ssh/sshd_config && 
      sed -i 's/.*DisableForwarding.*/DisableForwarding no/g' /etc/ssh/sshd_config && 
      echo 'AllowTcpForwarding yes' >> /etc/ssh/sshd_config && 
      echo 'PubkeyAcceptedKeyTypes +ssh-rsa' >> /etc/ssh/sshd_config && 
      echo 'HostKeyAlgorithms +ssh-rsa' >> /etc/ssh/sshd_config && 
      /usr/sbin/sshd && 
      samba.sh -s 'Backups_SCADA;/mount;yes;no;yes;all;none' -p"
    restart: always

  # --- ZONA D: RED DE MONITORIZACION ---
  # El SIEM Wazuh (manager + indexer + dashboard) se despliega en
  # red_monitorizacion desde un compose propio:
  #     monitorizacion/wazuh/docker-compose.yml
  # que usa el stack wazuh-docker v4.9.2 oficial con volumenes Docker
  # nombrados para los certs (evita el bug bind-mount + Java SecurityManager
  # en Docker Desktop Windows). La red red_monitorizacion la crea este
  # compose; el de Wazuh la referencia como external.

  # --- Sidecars de enrutamiento (patron init-container) ---
  # Comparten el network namespace del contenedor objetivo y le anaden las
  # rutas estaticas hacia las zonas OT via router_gw (192.168.20.254). Como
  # las zonas OT son internal:true, este es el unico camino.
  net_setup_nodered:
    image: alpine:latest
    container_name: net_setup_nodered
    network_mode: "service:nodered_scada_1"
    cap_add:
      - NET_ADMIN
    depends_on:
      - nodered_scada_1
    command: >
      sh -c "apk add --no-cache iproute2 >/dev/null 2>&1 &&
      ip route replace 192.168.10.0/24 via 192.168.20.254 &&
      ip route replace 192.168.30.0/24 via 192.168.20.254 &&
      ip route replace 192.168.40.0/24 via 192.168.20.254 &&
      echo '[net_setup] rutas instaladas en nodered_scada_1' &&
      tail -f /dev/null"
    restart: "no"

  net_setup_srv_empresa:
    image: alpine:latest
    container_name: net_setup_srv_empresa
    network_mode: "service:srv_empresa"
    cap_add:
      - NET_ADMIN
    depends_on:
      - srv_empresa
    command: >
      sh -c "apk add --no-cache iproute2 >/dev/null 2>&1 &&
      ip route replace 192.168.10.0/24 via 192.168.20.254 &&
      ip route replace 192.168.30.0/24 via 192.168.20.254 &&
      ip route replace 192.168.40.0/24 via 192.168.20.254 &&
      echo '[net_setup] rutas instaladas en srv_empresa' &&
      tail -f /dev/null"
    restart: "no"

  # --- Suricata IDS en vivo ---
  # Comparte el network namespace de router_gw (que esta en las 6 redes del
  # lab) para ver TODO el trafico OT desde una sola interfaz virtual `any`.
  # Lee suricata.yaml con `include: /etc/suricata/vars_kb.yaml` → las
  # variables ($SCADA_SERVERS, $MQTT_BROKER, $DNP3_GATEWAYS, ...) salen del
  # inventario aprendido por el modo entrenamiento [E]. Si se re-aprende,
  # [E] hace `docker restart suricata_ids` para que relea las variables.
  # eve.json cae en monitorizacion/suricata/salida/live/ que ya esta
  # bind-montado como /var/log/tfm/suricata en wazuh.manager (lectura RO).
  suricata_ids:
    image: jasonish/suricata:latest
    container_name: suricata_ids
    network_mode: "service:router_gw"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    depends_on:
      - router_gw
    volumes:
      - ./monitorizacion/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
      - ./monitorizacion/suricata/vars_kb.yaml:/etc/suricata/vars_kb.yaml:ro
      - ./monitorizacion/suricata/rules:/etc/suricata/rules:ro
      - ./monitorizacion/suricata/salida/live:/var/log/suricata
    command: >
      suricata -c /etc/suricata/suricata.yaml
               -s /etc/suricata/rules/valores_generado.rules
               --pcap=any
               -l /var/log/suricata
    restart: unless-stopped

  # Sidecar LIVE: escucha ARP en TODAS las interfaces del router_gw (6 bridges)
  # y escribe pares (ip, mac) nuevos en NDJSON append-only. Wazuh lo ingiere
  # con un <localfile> propio y la regla 100310 dispara contra mac_ok.cdb.
  arp_sniffer:
    image: python:3.12-alpine
    container_name: arp_sniffer
    network_mode: "service:router_gw"
    cap_add:
      - NET_ADMIN
      - NET_RAW
    depends_on:
      - router_gw
    volumes:
      - ./monitorizacion/flujos/arp_sniffer.py:/app/arp_sniffer.py:ro
      - ./monitorizacion/wazuh:/out
    command: sh -c "pip install --quiet --root-user-action=ignore scapy && python -u /app/arp_sniffer.py --salida /out/all_arp_live.ndjson --src arp_live"
    restart: unless-stopped
"""

    if incluir_kali:
        # Red donde se ubica kali_nodo según el modo elegido:
        #   - "empresa": en red_empresa (atacante externo, requiere pivote SSH)
        #   - "control": en red_control (atacante dentro de SCADA, acceso directo)
        if kali_mode == "control":
            kali_net_block = """    networks:
      red_control:
        ipv4_address: 192.168.20.66"""
        else:
            kali_net_block = """    networks:
      red_empresa:
        ipv4_address: 192.168.60.66"""

        compose_content += f"""
  kali_nodo:
    image: kalilinux/kali-rolling
    container_name: kali_nodo
    cap_add:
      - NET_ADMIN
    command: /bin/sh -c "apt-get update && apt-get install -y nmap iputils-ping iproute2 openssh-client smbclient proxychains4 python3 python3-pip python3-dev build-essential cmake metasploit-framework && sed -i 's/socks4/socks5/' /etc/proxychains4.conf && pip3 install --break-system-packages flask python-snap7 requests pymodbus scapy || true && tail -f /dev/null"
{kali_net_block}
    ports:
      - "8888:8888"
    volumes:
      - ./ataques:/ataques
      - /var/run/docker.sock:/var/run/docker.sock
"""
        # En modo 'control', kali_nodo esta en red_control (20.66) y necesita
        # rutas estaticas hacia OT via router_gw. En modo 'empresa' no, porque
        # kali solo ve red_empresa y accede a OT por pivote SSH SOCKS.
        if kali_mode == "control":
            compose_content += """
  net_setup_kali:
    image: alpine:latest
    container_name: net_setup_kali
    network_mode: "service:kali_nodo"
    cap_add:
      - NET_ADMIN
    depends_on:
      - kali_nodo
    command: >
      sh -c "apk add --no-cache iproute2 >/dev/null 2>&1 &&
      ip route replace 192.168.10.0/24 via 192.168.20.254 &&
      ip route replace 192.168.30.0/24 via 192.168.20.254 &&
      ip route replace 192.168.40.0/24 via 192.168.20.254 &&
      echo '[net_setup] rutas instaladas en kali_nodo (modo control)' &&
      tail -f /dev/null"
    restart: "no"
"""

    for i in range(1, num_modbus_a + 1):
        # ACL Modbus: UID esperado por este PLC = i, coincidiendo con el
        # unit_id que usa Node-RED (ver generate_nodered_flow). El fichero se
        # monta como volumen de solo lectura en /etc/openplc/acl.conf y lo
        # consulta el parche uid_acl.patch aplicado en el Dockerfile.
        acl_path = os.path.join("openplc", f"acl_plc_agua_{i}.conf")
        with open(acl_path, "w", encoding="utf-8") as acl_f:
            acl_f.write(
                "# ACL Modbus TCP generada por main.py (NO EDITAR A MANO)\n"
                f"# UID aceptado para peticiones Modbus en plc_agua_{i}\n"
                f"expected_uid = {i}\n"
            )
        compose_content += f"""
  plc_agua_{i}:
    image: mi_openplc
    container_name: plc_agua_{i}
    environment:
      - PLC_MODE=MODBUS
    cap_add:
      - NET_ADMIN
    networks:
      red_ot_zona_a:
        ipv4_address: 192.168.10.{9 + i}
    ports:
      - "{8080 + i}:8080"
      - "{5020 + i}:502"
    volumes:
      - ./openplc/acl_plc_agua_{i}.conf:/etc/openplc/acl.conf:ro
    restart: always
"""

    for i in range(1, num_s7_b + 1):
        compose_content += f"""
  plc_s7_{i}:
    image: mi_plc_siemens
    container_name: plc_s7_{i}
    cap_add:
      - NET_ADMIN
    networks:
      red_ot_zona_b:
        ipv4_address: 192.168.30.{9 + i}
    ports:
      - "{1020 + i}:102"
    restart: always
"""

    for i in range(1, num_dnp3_c + 1):
        compose_content += f"""
  gateway_dnp3_{i}:
    build:
      context: ./dnp3
      dockerfile: Dockerfile.gateway
    container_name: gateway_dnp3_{i}
    environment:
      - MQTT_BROKER_IP=192.168.20.15
      - PLC_DNP3_IP=192.168.40.{9 + i}
      - PLC_ID={i}
    networks:
      red_control:
        ipv4_address: 192.168.20.{15 + i}
      red_ot_zona_c:
        ipv4_address: 192.168.40.{15 + i}
    depends_on:
      - mosquitto
    restart: always
"""
        compose_content += f"""
  plc_dnp3_{i}:
    image: mi_openplc
    container_name: plc_dnp3_{i}
    environment:
      - PLC_MODE=DNP3
    cap_add:
      - NET_ADMIN
    networks:
      red_ot_zona_c:
        ipv4_address: 192.168.40.{9 + i}
    ports:
      - "{8180 + i}:8080"
      - "{20000 + i}:20000"
    restart: always
"""

    # Volumenes nombrados de Wazuh (persisten configuracion, logs, datos del
    # indexer y de filebeat entre reinicios).
    # Nota: los volumenes nombrados de Wazuh viven en el compose propio
    # monitorizacion/wazuh/docker-compose.yml (no aqui), para que el stack
    # del lab OT quede desacoplado del SIEM.

    with open("docker-compose.generated.yml", "w", encoding="utf-8") as f:
        f.write(compose_content)
    print("[+] Archivo 'docker-compose.generated.yml' generado.")
    if incluir_kali:
        write_kali_mode_marker(kali_mode)
