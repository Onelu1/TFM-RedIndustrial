#!/usr/bin/env python3
"""ground_truth_hosts.py - Tabla de hosts conocidos del laboratorio.

Este modulo es *pasivo*: solo lo importa `inferir_roles.py` para generar
el reporte comparativo `inventario_vs_hosts.md`, y `construir_kb.py`
cuando se arranca con `--legacy-hardcoded` como escape de emergencia.

NO se usa en el camino de produccion: la inferencia dinamica
(fase de entrenamiento) genera `inventario.json` que es la unica fuente
de verdad en condiciones normales. Mantener sincronizado con
`scenario/compose.py` solo para que el reporte de precision sea util.
"""
from __future__ import annotations

import ipaddress


SUBREDES = {
    "red_control":        ipaddress.ip_network("192.168.20.0/24"),
    "red_ot_zona_a":      ipaddress.ip_network("192.168.10.0/24"),
    "red_ot_zona_b":      ipaddress.ip_network("192.168.30.0/24"),
    "red_ot_zona_c":      ipaddress.ip_network("192.168.40.0/24"),
    "red_monitorizacion": ipaddress.ip_network("192.168.50.0/24"),
    "red_empresa":        ipaddress.ip_network("192.168.60.0/24"),
}


HOSTS = {
    # SCADA / infra de control
    "192.168.20.10":  ("nodered_scada",  "scada"),
    "192.168.20.15":  ("mosquitto",      "broker_mqtt"),
    "192.168.20.16":  ("gateway_dnp3_1", "gateway_dnp3"),
    "192.168.20.17":  ("gateway_dnp3_2", "gateway_dnp3"),
    "192.168.20.18":  ("gateway_dnp3_3", "gateway_dnp3"),
    # PLCs Modbus
    "192.168.10.10":  ("plc_agua_1",     "plc_modbus"),
    "192.168.10.11":  ("plc_agua_2",     "plc_modbus_c2_mailbox"),
    "192.168.10.12":  ("plc_agua_3",     "plc_modbus"),
    # PLCs S7
    "192.168.30.10":  ("plc_s7_1",       "plc_s7"),
    "192.168.30.11":  ("plc_s7_2",       "plc_s7"),
    "192.168.30.12":  ("plc_s7_3",       "plc_s7"),
    # PLCs DNP3
    "192.168.40.10":  ("plc_dnp3_1",     "plc_dnp3"),
    "192.168.40.11":  ("plc_dnp3_2",     "plc_dnp3"),
    "192.168.40.12":  ("plc_dnp3_3",     "plc_dnp3"),
    # Enterprise (pivote)
    "192.168.60.50":  ("srv_empresa",    "it_fileserver"),
    "192.168.20.50":  ("srv_empresa",    "it_fileserver_dual_homed"),
    "192.168.60.66":  ("kali_nodo",      "atacante"),
}


def subred_de(ip: str) -> str:
    """Devuelve el nombre logico de la subred Docker a la que pertenece la IP,
    o 'externo' si cae fuera del lab, o 'invalido' si la IP no es parseable.
    """
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "invalido"
    for nombre, red in SUBREDES.items():
        if a in red:
            return nombre
    return "externo"


def rol_esperado(ip: str) -> str:
    """Rol esperado segun la tabla ground truth. 'desconocido' si no esta."""
    if ip in HOSTS:
        return HOSTS[ip][1]
    return "desconocido"


# Rol C2 "normalizado" para comparar con el inferidor: el inferidor no sabe
# distinguir plc_modbus_c2_mailbox de plc_modbus (es la misma firma de red),
# asi que para el reporte de precision tratamos ambos como plc_modbus.
NORMALIZACION_ROL = {
    "plc_modbus_c2_mailbox": "plc_modbus",
    "it_fileserver_dual_homed": "it_fileserver",
}


def rol_normalizado(rol: str) -> str:
    """Para el reporte de precision inferido-vs-ground-truth."""
    return NORMALIZACION_ROL.get(rol, rol)
