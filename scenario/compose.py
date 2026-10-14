#!/usr/bin/env python3
"""Generación del `docker-compose.generated.yml`, ACLs Modbus y marcador de modo.

Función pública principal: :func:`generate_docker_compose`. Escribe también
`mosquitto.conf`, cada `openplc/acl_plc_agua_<i>.conf` y, si se incluye
`kali_nodo`, el marcador `ataques/.mode` (vía :func:`write_kali_mode_marker`).

Complementos:

- :func:`read_scenario_sizes` — devuelve `(num_mb, num_s7, num_dnp3)` leyendo
  los `container_name:` del compose existente. Lo usa `switch_kali_mode` para
  regenerar sin preguntar al usuario.

Todas las rutas son relativas al cwd (mismo contrato que el `main.py` original).
"""

import os
import re


def read_scenario_sizes(compose_path="docker-compose.generated.yml"):
    """Lee el compose existente y devuelve (num_modbus, num_s7, num_dnp3).

    Si el fichero no existe o no se puede parsear, devuelve (None, None, None)
    y el que llame tendrá que preguntar al usuario.
    """
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
    """Deja un marcador en ataques/.mode que el dashboard lee al arrancar."""
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
    ipam:
      config:
        - subnet: 192.168.10.0/24
  red_ot_zona_b:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.30.0/24
  red_ot_zona_c:
    driver: bridge
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

  # --- ZONA D: RED DE MONITORIZACIÓN ---
  srv_monitorizacion:
    image: dperson/samba
    container_name: srv_monitorizacion
    cap_add:
      - NET_ADMIN
    networks:
      red_monitorizacion:
        ipv4_address: 192.168.50.10
    command: '-s "logs;/share;yes;no;yes;all;none" -p'
    restart: always
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
    command: /bin/sh -c "apt-get update && apt-get install -y nmap iputils-ping iproute2 openssh-client smbclient proxychains4 python3 python3-pip python3-dev build-essential cmake metasploit-framework && sed -i 's/socks4/socks5/' /etc/proxychains4.conf && pip3 install --break-system-packages flask python-snap7 requests pymodbus || true && tail -f /dev/null"
{kali_net_block}
    ports:
      - "8888:8888"
    volumes:
      - ./ataques:/ataques
      - /var/run/docker.sock:/var/run/docker.sock
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

    with open("docker-compose.generated.yml", "w", encoding="utf-8") as f:
        f.write(compose_content)
    print("[+] Archivo 'docker-compose.generated.yml' generado.")
    if incluir_kali:
        write_kali_mode_marker(kali_mode)
