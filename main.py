#!/usr/bin/env python3
"""
Orquestador CLI de Testbed OT/ICS (TFM)
Modelado de red segmentada según el Modelo Purdue (ISA-95).
Soporta Siemens S7, Modbus TCP y auto-configuración de SCADA Node-RED.
"""

import os
import sys
import json
import time
import subprocess

def run_cmd(cmd, check=True, capture=True):
    """Ejecuta comandos del sistema con captura de errores."""
    try:
        res = subprocess.run(
            cmd, shell=True, check=check, text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None
        )
        return res.stdout.strip() if capture else ""
    except subprocess.CalledProcessError as e:
        if capture and e.stderr:
            print(f"[!] Error ejecutando el comando: {cmd}\n[!] {e.stderr.strip()}")
        return None

def build_s7_image_if_needed():
    """Compila la imagen Docker de Siemens S7 si no existe."""
    image = run_cmd("docker images -q mi_plc_siemens")
    if not image:
        print("[*] Compilando imagen 'mi_plc_siemens' desde 'siemens_s7/Dockerfile'...")
        path_s7 = os.path.join(os.getcwd(), "siemens_s7")
        if not os.path.exists(path_s7):
            print(f"[!] ERROR: No existe el directorio {path_s7}")
            return False
        run_cmd(f"docker build -t mi_plc_siemens {path_s7}", capture=False)
        print("[✔] Imagen 'mi_plc_siemens' compilada correctamente.")
    return True

def build_openplc_image_if_needed():
    """Compila la imagen Docker de OpenPLC v3 si no existe."""
    image = run_cmd("docker images -q mi_openplc")
    if not image:
        print("[*] Compilando imagen 'mi_openplc' desde 'openplc/Dockerfile' (puede llevar un tiempo)...")
        path_oplc = os.path.join(os.getcwd(), "openplc")
        if not os.path.exists(path_oplc):
            print(f"[!] ERROR: No existe el directorio {path_oplc}")
            return False
        run_cmd(f"docker build -t mi_openplc {path_oplc}", capture=False)
        print("[✔] Imagen 'mi_openplc' compilada correctamente.")
    return True

import json

def generate_nodered_flow(num_plcs_modbus=1, base_ip="192.168.10.10"):
    flow = []
    
    # 1. Tab Principal
    tab_id = "tab_supervision_purdue"
    flow.append({
        "id": tab_id,
        "type": "tab",
        "label": "Supervisión OT Multi-Protocolo (Purdue)",
        "disabled": False
    })

    # 2. Nodo Debug General (Recibe los datos de todos los PLCs)
    debug_id = "debug_telemetria_general"
    flow.append({
        "id": debug_id,
        "type": "debug",
        "z": tab_id,
        "name": "Telemetría SCADA",
        "active": True,
        "tosidebar": True,
        "complete": "payload",
        "x": 850,
        "y": 80,
        "wires": []
    })

    # 3. Generación dinámica para cada PLC Modbus
    for i in range(1, num_plcs_modbus + 1):
        client_id = f"client_modbus_{i}"
        ip_addr = f"192.168.10.{9 + i}"  # Cada cliente Modbus asignado a la IP fija del PLC correspondiente
        
        # Coordenada vertical para cada bloque para que queden correctamente espaciados
        y_base = (i - 1) * 500

        # Cliente Modbus TCP con todas sus propiedades
        flow.append({
            "id": client_id,
            "type": "modbus-client",
            "name": f"PLC_Modbus_Agua_{i}",
            "clienttype": "tcp",
            "bufferCommands": True,
            "stateLogEnabled": False,
            "queueLogEnabled": False,
            "failureLogEnabled": True,
            "tcpHost": ip_addr,
            "tcpPort": "502",
            "tcpType": "DEFAULT",
            "serialPort": "/dev/ttyUSB",
            "serialType": "RTU-BUFFERD",
            "serialBaudrate": "9600",
            "serialDatabits": "8",
            "serialStopbits": "1",
            "serialParity": "none",
            "serialConnectionDelay": "100",
            "serialAsciiResponseStartDelimiter": "0x3A",
            "unit_id": "1",
            "commandDelay": "1",
            "clientTimeout": "2000",
            "reconnectOnTimeout": True,
            "reconnectTimeout": "2000",
            "parallelUnitIdsAllowed": True,
            "showErrors": False,
            "showWarnings": True,
            "showLogs": True
        })

        # Lectura Holding Registers (0-19) cada 2 s.
        read_id = f"read_modbus_{i}"
        flow.append({
            "id": read_id,
            "type": "modbus-read",
            "z": tab_id,
            "name": f"Leer Modbus Agua {i}",
            "topic": "",
            "showStatusActivities": False,
            "logIOActivities": False,
            "showErrors": False,
            "showWarnings": True,
            "unitid": "1",
            "dataType": "HoldingRegister",
            "adr": "0",
            "quantity": "20",
            "rate": "2",
            "rateUnit": "s",
            "delayOnStart": False,
            "startDelayTime": "",
            "server": client_id,
            "useIOFile": False,
            "ioFile": "",
            "useIOForPayload": False,
            "emptyMsgOnFail": False,
            "x": 250,
            "y": y_base + 80,
            "wires": [[debug_id], []]
        })

        # Controles de Escritura (FC05 y FC06) por PLC
        
        # Parada de Emergencia (Coil 0). Por cada PLC, dos nodos inject (Activar/Desactivar) y un nodo modbus_write
        write_emerg_id = f"write_emerg_{i}"
        flow.extend([
            {
                "id": f"inj_emerg_on_{i}",
                "type": "inject",
                "z": tab_id,
                "name": f"Activar Parada PLC {i}",
                "props": [{"p": "payload"}],
                "repeat": "", "crontab": "", "once": False, "onceDelay": 0.1,
                "topic": "", "payload": "true", "payloadType": "bool",
                "x": 230, "y": y_base + 160,
                "wires": [[write_emerg_id]]
            },
            {
                "id": f"inj_emerg_off_{i}",
                "type": "inject",
                "z": tab_id,
                "name": f"Desactivar Parada PLC {i}",
                "props": [{"p": "payload"}],
                "repeat": "", "crontab": "", "once": False, "onceDelay": 0.1,
                "topic": "", "payload": "false", "payloadType": "bool",
                "x": 250, "y": y_base + 210,
                "wires": [[write_emerg_id]]
            },
            {
                "id": write_emerg_id,
                "type": "modbus-write",
                "z": tab_id,
                "name": f"Modbus-write-parada PLC {i}",
                "showStatusActivities": False, "showErrors": False, "showWarnings": True,
                "unitid": "1", "dataType": "Coil", "adr": "0", "quantity": "1",
                "server": client_id, "emptyMsgOnFail": False, "keepMsgProperties": False,
                "delayOnStart": False, "startDelayTime": "",
                "x": 600, "y": y_base + 185,
                "wires": [[], []]
            }
        ])

        # Control Marcha Bomba 1 (Coil 1)
        write_pump_id = f"write_pump_{i}"
        flow.extend([
            {
                "id": f"inj_pump_on_{i}",
                "type": "inject",
                "z": tab_id,
                "name": f"Encender Bomba 1 PLC {i}",
                "props": [{"p": "payload"}],
                "repeat": "", "crontab": "", "once": False, "onceDelay": 0.1,
                "topic": "", "payload": "true", "payloadType": "bool",
                "x": 170, "y": y_base + 280,
                "wires": [[write_pump_id]]
            },
            {
                "id": f"inj_pump_off_{i}",
                "type": "inject",
                "z": tab_id,
                "name": f"Apagar Bomba 1 PLC {i}",
                "props": [{"p": "payload"}],
                "repeat": "", "crontab": "", "once": False, "onceDelay": 0.1,
                "topic": "", "payload": "false", "payloadType": "bool",
                "x": 160, "y": y_base + 330,
                "wires": [[write_pump_id]]
            },
            {
                "id": write_pump_id,
                "type": "modbus-write",
                "z": tab_id,
                "name": f"Modbus-write-bomba1 PLC {i}",
                "showStatusActivities": False, "showErrors": False, "showWarnings": True,
                "unitid": "1", "dataType": "Coil", "adr": "1", "quantity": "1",
                "server": client_id, "emptyMsgOnFail": False, "keepMsgProperties": False,
                "delayOnStart": False, "startDelayTime": "",
                "x": 600, "y": y_base + 305,
                "wires": [[], []]
            }
        ])

        # Limitacion Max RPM (Holding Register 20)
        write_rpm_id = f"write_rpm_{i}"
        flow.extend([
            {
                "id": f"inj_rpm_limit_{i}",
                "type": "inject",
                "z": tab_id,
                "name": f"Limitación RPM 800 PLC {i}",
                "props": [{"p": "payload"}],
                "repeat": "", "crontab": "", "once": False, "onceDelay": 0.1,
                "topic": "", "payload": "800", "payloadType": "num",
                "x": 140, "y": y_base + 400,
                "wires": [[write_rpm_id]]
            },
            {
                "id": f"inj_rpm_reset_{i}",
                "type": "inject",
                "z": tab_id,
                "name": f"Restablecer RPM 1500 PLC {i}",
                "props": [{"p": "payload"}],
                "repeat": "", "crontab": "", "once": False, "onceDelay": 0.1,
                "topic": "", "payload": "1500", "payloadType": "num",
                "x": 150, "y": y_base + 450,
                "wires": [[write_rpm_id]]
            },
            {
                "id": write_rpm_id,
                "type": "modbus-write",
                "z": tab_id,
                "name": f"Modbus-write-rpm PLC {i}",
                "showStatusActivities": False, "showErrors": False, "showWarnings": True,
                "unitid": "1", "dataType": "HoldingRegister", "adr": "20", "quantity": "1",
                "server": client_id, "emptyMsgOnFail": False, "keepMsgProperties": False,
                "delayOnStart": False, "startDelayTime": "",
                "x": 600, "y": y_base + 425,
                "wires": [[], []]
            }
        ])

    # Configuración Global Modbus
    flow.append({
        "id": "global_modbus_config",
        "type": "global-config",
        "env": [],
        "modules": {
            "node-red-contrib-modbus": "5.60.2"
        }
    })

    return flow


def save_flows_file(filepath="nodered_data_scada_1/flows.json", num_plcs=3):
    """Crea el directorio ./nodered_data_scada_1/ y genera el JSON que lee Node-RED en el arranque"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    flows = generate_nodered_flow(num_plcs_modbus=num_plcs)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(flows, f, indent=4)
    print(f"[+] Flujos creados correctamente para {num_plcs} PLC(s) en '{filepath}'.")

def generate_docker_compose(num_modbus_a, num_s7_b, incluir_kali=True):
    """Genera la arquitectura de red segmentada en docker-compose.generated.yml."""
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
"""

    if incluir_kali:
        compose_content += """
  kali_nodo:
    image: kalilinux/kali-rolling
    container_name: kali_nodo
    cap_add:
      - NET_ADMIN
    command: /bin/sh -c "apt-get update && apt-get install -y nmap iputils-ping iproute2 && tail -f /dev/null"
    networks:
      red_control:
        ipv4_address: 192.168.20.66
"""

# PLCs Modbus (Zona OT A)
    for i in range(1, num_modbus_a + 1):
        compose_content += f"""
  plc_agua_{i}:
    image: mi_openplc
    container_name: plc_agua_{i}
    cap_add:
      - NET_ADMIN
    networks:
      red_ot_zona_a:
        ipv4_address: 192.168.10.{9 + i}
    ports:
      - "{8080 + i}:8080"
      - "{5020 + i}:502"
    restart: always
"""

    # PLCs Siemens S7 (Zona OT B)
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

    with open("docker-compose.generated.yml", "w", encoding="utf-8") as f:
        f.write(compose_content)
    print("[+] Archivo 'docker-compose.generated.yml' generado.")

def deploy_scenario(num_modbus_a, num_s7_b):
    """Despliega la infraestructura completa e instala paquetes/rutas."""

    #Comprueba si falta alguna imagen
    if num_s7_b > 0 and not build_s7_image_if_needed():
        return
    if num_modbus_a > 0 and not build_openplc_image_if_needed():
        return

    #Genera docker-compose
    print("\n[*] Generando archivos de configuración IaC...")
    generate_nodered_flow(num_modbus_a, num_s7_b)
    generate_docker_compose(num_modbus_a, num_s7_b)

    #Levanta los contenedores Docker
    print("\n[*] [1/4] Levantando contenedores con Docker Compose...")
    run_cmd("docker compose -f docker-compose.generated.yml up -d")

    #Instala las librerías de Modbus y S7 en Node-RED y reinicia el contenedor para que Node-RED cargue correctamente
    print("[*] [2/4] Instalando paquetes de S7 y Modbus en Node-RED...")
    run_cmd("docker exec nodered_scada_1 npm install --prefix /data node-red-contrib-modbus node-red-contrib-s7 -qq")
    
    print("[*] [3/4] Reiniciando Node-RED para cargar los nuevos módulos...")
    run_cmd("docker restart nodered_scada_1")
    time.sleep(8)

    print("[*] [4/4] Instalando utilidades e inyectando rutas estáticas inter-zona...")
    
    # Añade rutas desde SCADA y Kali (Red Control) hacia redes OT via Gateway (.254)
    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.10.0/24 via 192.168.20.254", check=False)
    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.30.0/24 via 192.168.20.254", check=False)
    run_cmd("docker exec kali_nodo ip route add 192.168.10.0/24 via 192.168.20.254", check=False)
    run_cmd("docker exec kali_nodo ip route add 192.168.30.0/24 via 192.168.20.254", check=False)

    # Rutas desde redes OT hacia Red de Control
    for i in range(1, num_modbus_a + 1):
        run_cmd(f"docker exec plc_agua_{i} apt-get update -qq && docker exec plc_agua_{i} apt-get install -y iproute2 iputils-ping -qq", check=False)
        run_cmd(f"docker exec plc_agua_{i} ip route add 192.168.20.0/24 via 192.168.10.254", check=False)

    for i in range(1, num_s7_b + 1):
        run_cmd(f"docker exec plc_s7_{i} ip route add 192.168.20.0/24 via 192.168.30.254", check=False)

    print("\n[✔] Escenario Purdue desplegado y enrutado con éxito.")

def clean_environment():
    """Limpia todo el escenario previo."""
    print("\n[*] Eliminando infraestructura activa...")
    #Detiene todos los contenedores
    if os.path.exists("docker-compose.generated.yml"):
        run_cmd("docker compose -f docker-compose.generated.yml down --remove-orphans", check=False)
    print("[✔] Entorno totalmente limpio.")

def main_menu():
    while True:
        print("""
======================================================================
  ORQUESTADOR OT/ICS CON SEGMENTACIÓN PURDUE (TFM CIBERSEGURIDAD)
======================================================================
  [1] Desplegar Escenario Siemens S7 (Zona OT B)
  [2] Desplegar Escenario Modbus TCP (Zona OT A)
  [3] Desplegar Escenario Híbrido S7 + Modbus (Modelo Purdue Completo)
  [4] Limpiar Entorno (Detener contenedores)
  [0] Salir
======================================================================
        """)
        opt = input("Selecciona una opción [0-4]: ").strip()
        
        if opt == "1":
            n_s7 = int(input("Número de PLCs Siemens S7: "))
            deploy_scenario(0, n_s7)
            input("\nPresiona ENTER para continuar...")
        elif opt == "2":
            n_mb = int(input("Número de PLCs Modbus TCP: "))
            save_flows_file("nodered_data_scada_1/flows.json", num_plcs=n_mb)
            deploy_scenario(n_mb, 0)
            input("\nPresiona ENTER para continuar...")
        elif opt == "3":
            n_mb = int(input("Número de PLCs Modbus TCP (Zona A): "))
            n_s7 = int(input("Número de PLCs Siemens S7 (Zona B): "))
            save_flows_file("nodered_data_scada_1/flows.json", num_plcs=n_mb)
            deploy_scenario(n_mb, n_s7)
            input("\nPresiona ENTER para continuar...")
        elif opt == "4":
            clean_environment()
            input("\nPresiona ENTER para continuar...")
        elif opt == "0":
            sys.exit(0)

if __name__ == "__main__":
    main_menu()