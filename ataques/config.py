#!/usr/bin/env python3
"""Configuración del toolkit de ataques: IPs y puertos por defecto del
laboratorio, lectura del modo kali_nodo (empresa/control) y mapa MITRE
ATT&CK for ICS por acción."""

import os

# Subredes del laboratorio (deben coincidir con docker-compose.generated.yml)
LAB_SUBNETS = [
    "192.168.10.0/24",  # Zona OT A - Modbus TCP
    "192.168.20.0/24",  # Red de control / Node-RED / MQTT
    "192.168.30.0/24",  # Zona OT B - Siemens S7
    "192.168.40.0/24",  # Zona OT C - DNP3
    "192.168.50.0/24",  # Red de monitorización
    "192.168.60.0/24",  # Red de empresa (pivote Samba)
    "127.0.0.0/8",       # loopback (túneles SSH locales)
]

# --- Objetivos por defecto (primer PLC de cada zona en el escenario híbrido) ---
MODBUS_DEFAULT_TARGET = "192.168.10.10"
MODBUS_DEFAULT_PORT = 502

S7_DEFAULT_TARGET = "192.168.30.10"
S7_DEFAULT_RACK = 0
S7_DEFAULT_SLOT = 1

DNP3_DEFAULT_TARGET = "192.168.40.10"
DNP3_DEFAULT_PORT = 20000

SAMBA_HOST = "192.168.60.50"
# Interfaz de srv_empresa dentro de red_control (dual-homed). Se usa en modo
# "control" si alguna vez se quisiera reactivar las acciones de pivote (hoy la
# tarjeta Samba queda OCULTA en modo control, así que no se consume).
SAMBA_HOST_CONTROL = "192.168.20.50"
SAMBA_SHARE = "Backups_SCADA"
SAMBA_SSH_KEY_PATH_REMOTE = "ssh_keys/id_rsa"

OPENPLC_DEFAULT_TARGET = "192.168.10.10"
OPENPLC_DEFAULT_PORT = 8080
OPENPLC_DEFAULT_USER = "openplc"
OPENPLC_DEFAULT_PASS = "openplc"

# --- C2 Modbus (FrostyGoop) ---
# PLC-buzón para el canal encubierto. Se usa plc_agua_2 para no
# interferir con el PLC principal (plc_agua_1). Los holding registers
# 1000+ no están mapeados a I/O del programa .st.
C2_MAILBOX_PLC = "192.168.10.11"
C2_MAILBOX_PORT = 502
C2_MAILBOX_UID = 2        # Unit ID que acepta plc_agua_2 (ver acl_plc_agua_2.conf)
C2_CMD_BASE_REG = 1000   # Zona de comandos (operador → implante)
C2_RSP_BASE_REG = 1200   # Zona de respuestas (implante → operador)
C2_POLL_INTERVAL = 3      # Segundos entre polls del implante
C2_XOR_KEY = ""           # Clave XOR precompartida (vacío = sin cifrar)

# --- Rutas del toolkit ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(BASE_DIR, "evidencias")
RESOURCE_SCRIPTS_DIR = os.path.join(BASE_DIR, "resource_scripts")
WORK_DIR = os.path.join(BASE_DIR, "work")  # claves ssh descargadas, .st subidos, etc.
MODE_FILE = os.path.join(BASE_DIR, ".mode")  # "empresa" o "control" (escrito por main.py)

for _d in (EVIDENCE_DIR, RESOURCE_SCRIPTS_DIR, WORK_DIR):
    os.makedirs(_d, exist_ok=True)


def get_mode():
    """Devuelve el modo de despliegue de kali_nodo: 'empresa' o 'control'.

    - 'empresa': kali está en red_empresa (192.168.60.66) y los ataques hacia
      IPs OT (10/30/40.x) deben pasar por el túnel SSH SOCKS vía srv_empresa.
    - 'control': kali está en red_control (192.168.20.66), con rutas estáticas
      hacia todas las zonas OT; los ataques salen directos sin proxychains.
    """
    try:
        with open(MODE_FILE, "r", encoding="utf-8") as f:
            v = f.read().strip().lower()
            return v if v in ("empresa", "control") else "empresa"
    except FileNotFoundError:
        return "empresa"


# Subredes consideradas "OT" (requieren proxychains en modo empresa).
OT_SUBNETS = ["192.168.10.0/24", "192.168.30.0/24", "192.168.40.0/24"]

# Mapeo de acciones -> técnicas MITRE ATT&CK for ICS, para mostrarlas en el dashboard.
MITRE_MAP = {
    "modbus.discover_nmap": ["T0846", "T0888"],
    "modbus.findunitid": ["T0888"],
    "modbus.uid_contrast": ["T0888", "T0861"],
    "modbus.detect": ["T0846", "T0888"],
    "modbus.read_coils": ["T0861"],
    "modbus.read_registers": ["T0861"],
    "modbus.write_coil": ["T0855"],
    "modbus.write_register": ["T0836"],
    "s7.discover_nmap": ["T0846", "T0888"],
    "s7.read_db1": ["T0861"],
    "s7.write_setpoint": ["T0836"],
    "s7.write_marcha": ["T0855"],
    "dnp3.discover_nmap": ["T0846", "T0888"],
    "dnp3.read": ["T0861"],
    "dnp3.write_manual": ["T0855"],
    "dnp3.write_bomba": ["T0855"],
    "samba.download_key": ["T1039", "T1552.004"],
    "samba.open_tunnel": ["T1078.003", "T1090"],
    "samba.scan_via_tunnel": ["T1046"],
    "openplc.default_login": ["T0812"],
    "openplc.cve_2026_71268": ["T0843", "T0873"],
    "openplc.get_current_program": ["T0888", "T0845"],
    "openplc.upload_run": ["T0843", "T0821", "T0831"],

    # C2 Modbus (FrostyGoop)
    "c2_modbus.deploy_implant": ["T0869", "T1570"],
    "c2_modbus.shell": ["T0869", "T0807"],
    "c2_modbus.trigger_ot": ["T0869", "T0855", "T0836"],
    "c2_modbus.exfil_response": ["T0869", "T0882"],

    # Ataques L2 para disparar Wazuh 100310 (allowlist MAC)
    "mac_spoof.mac_change": ["T0849", "T1036"],
    "mac_spoof.arp_spoof":  ["T0859", "T1557"],

    # Valor Modbus fuera de rango (Wazuh 100410)
    "modbus.write_outlier": ["T0836", "T0831"],
    # Valor DNP3 analogico fuera de rango (Wazuh 100410)
    "dnp3.write_analog_outlier": ["T0836", "T0831"],
}
