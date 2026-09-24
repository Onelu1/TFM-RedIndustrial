import os

# ==============================================================================
# CONFIGURACIÓN DE LOS PARÁMETROS DEL ESCENARIO
# ==============================================================================
NUM_SCADAS = 1          # Cantidad de servidores SCADA (Red Control .20.x)
NUM_PLCS_ZONA_A = 1     # Cantidad de PLCs en Zona A (Red OT .10.x)
NUM_PLCS_ZONA_B = 1     # Cantidad de PLCs en Zona B (Red OT .30.x)
INCLUIR_KALI = True     # Incluir el nodo de auditoria/ataque Kali Linux
# ==============================================================================

print("===================================================")
print("  GENERADOR AUTOMÁTICO DE TESTBED OT (IaC - TFM)")
print("===================================================")
print(f"[*] Configuración seleccionada:")
print(f"    - SCADA / HMIs: {NUM_SCADAS}")
print(f"    - PLCs Zona A (Tratamiento): {NUM_PLCS_ZONA_A}")
print(f"    - PLCs Zona B (Bombeo): {NUM_PLCS_ZONA_B}")
print(f"    - Total Nodos de Red: {NUM_SCADAS + NUM_PLCS_ZONA_A + NUM_PLCS_ZONA_B + 1 + (1 if INCLUIR_KALI else 0)}")
print("---------------------------------------------------")

# 1. GENERACIÓN DE DOCKER-COMPOSE.YML
compose_content = f"""name: tfm-escenario-autogenerado

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
  # --- PASARELA INTER-VLAN (ROUTER) ---
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
"""

# Añadir SCADA(s)
for i in range(1, NUM_SCADAS + 1):
    scada_ip = f"192.168.20.{9 + i}"
    scada_port = 1879 + i
    compose_content += f"""
  nodered_scada_{i}:
    image: nodered/node-red:latest
    container_name: nodered_scada_{i}
    cap_add:
      - NET_ADMIN
    networks:
      red_control:
        ipv4_address: {scada_ip}
    ports:
      - "{scada_port}:1880"
    volumes:
      - ./nodered_data_scada_{i}:/data
    restart: always
"""

# Añadir Kali si está activado
if INCLUIR_KALI:
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

# Añadir PLCs Zona A
for i in range(1, NUM_PLCS_ZONA_A + 1):
    plc_ip = f"192.168.10.{9 + i}"
    web_port = 8079 + i
    modbus_port = 501 + i
    compose_content += f"""
  plc_agua_{i}:
    build: https://github.com/thiagoralves/OpenPLC_v3.git
    container_name: plc_agua_{i}
    cap_add:
      - NET_ADMIN
    networks:
      red_ot_zona_a:
        ipv4_address: {plc_ip}
    ports:
      - "{web_port}:8080"
      - "{modbus_port}:502"
    restart: always
"""

# Añadir PLCs Zona B
for i in range(1, NUM_PLCS_ZONA_B + 1):
    plc_ip = f"192.168.30.{9 + i}"
    web_port = 8079 + NUM_PLCS_ZONA_A + i
    modbus_port = 501 + NUM_PLCS_ZONA_A + i
    compose_content += f"""
  plc_bombeo_{i}:
    build: https://github.com/thiagoralves/OpenPLC_v3.git
    container_name: plc_bombeo_{i}
    cap_add:
      - NET_ADMIN
    networks:
      red_ot_zona_b:
        ipv4_address: {plc_ip}
    ports:
      - "{web_port}:8080"
      - "{modbus_port}:502"
    restart: always
"""

# Guardar docker-compose.generated.yml
with open("docker-compose.generated.yml", "w", encoding="utf-8") as f:
    f.write(compose_content)
print("[+] Archivo 'docker-compose.generated.yml' generado correctamente.")


# 2. GENERACIÓN DEL SCRIPT DESPLEGAR_AUTOGENERADO.BAT
bat_content = f"""@echo off
echo ===================================================
echo   DESPLIEGUE AUTOMÁTICO DE ESCENARIO PARAMETRIZADO
echo ===================================================

echo.
echo [1/5] Levantando contenedores con Docker Compose...
docker compose -f docker-compose.generated.yml up -d

echo.
echo [2/5] Instalando paquetes Modbus en nodos SCADA...
"""

for i in range(1, NUM_SCADAS + 1):
    bat_content += f"docker exec nodered_scada_{i} npm install --prefix /data node-red-contrib-modbus -qq\n"
    bat_content += f"docker restart nodered_scada_{i} > NUL\n"

bat_content += """
echo.
echo [3/5] Esperando 15 segundos al inicio de los servicios...
timeout /t 15 /nobreak > NUL

echo.
echo [4/5] Instalando iproute2 en contenedores PLC...
"""

for i in range(1, NUM_PLCS_ZONA_A + 1):
    bat_content += f"docker exec plc_agua_{i} apt-get update -qq && docker exec plc_agua_{i} apt-get install -y iproute2 iputils-ping -qq\n"

for i in range(1, NUM_PLCS_ZONA_B + 1):
    bat_content += f"docker exec plc_bombeo_{i} apt-get update -qq && docker exec plc_bombeo_{i} apt-get install -y iproute2 iputils-ping -qq\n"

bat_content += """
echo.
echo [5/5] Inyectando rutas estaticas para evitar el bypass de Docker...

:: Rutas desde SCADAs hacia Zonas OT
"""

for i in range(1, NUM_SCADAS + 1):
    bat_content += f"docker exec -u root nodered_scada_{i} ip route add 192.168.10.0/24 via 192.168.20.254\n"
    bat_content += f"docker exec -u root nodered_scada_{i} ip route add 192.168.30.0/24 via 192.168.20.254\n"

if INCLUIR_KALI:
    bat_content += "docker exec kali_nodo ip route add 192.168.10.0/24 via 192.168.20.254\n"
    bat_content += "docker exec kali_nodo ip route add 192.168.30.0/24 via 192.168.20.254\n"

bat_content += "\n:: Rutas desde Zonas OT hacia Red de Control\n"
for i in range(1, NUM_PLCS_ZONA_A + 1):
    bat_content += f"docker exec plc_agua_{i} ip route add 192.168.20.0/24 via 192.168.10.254\n"

for i in range(1, NUM_PLCS_ZONA_B + 1):
    bat_content += f"docker exec plc_bombeo_{i} ip route add 192.168.20.0/24 via 192.168.30.254\n"

bat_content += """
echo.
echo ===================================================
echo   ENTORNO DESPLEGADO Y ENRUTADO CORRECTAMENTE.
echo ===================================================
pause
"""

# Guardar desplegar_autogenerado.bat
with open("desplegar_autogenerado.bat", "w", encoding="utf-8") as f:
    f.write(bat_content)
print("[+] Archivo 'desplegar_autogenerado.bat' generado correctamente.")
print("\n[OK] ¡Proceso completado! Puedes ejecutar 'desplegar_autogenerado.bat' para iniciar la red.")