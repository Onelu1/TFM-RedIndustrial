#!/usr/bin/env python3
"""Reconocimiento (nmap) para las tres zonas OT (Modbus / S7 / DNP3)."""

import config
from core import runner, evidence


def modbus_discover(target=None, sink=None):
    """nmap -sV --script modbus-discover -p 502 <red/ip> (zona Modbus)."""
    target = target or f"192.168.10.0/24"
    # Permitimos red o IP; validamos solo si es una IP suelta
    if "/" not in target:
        runner.assert_lab_target(target)
    path = evidence.new_evidence_file("recon", "modbus_discover")
    evidence.header(path, "Descubrimiento Modbus (modbus-discover)",
                    target, config.MITRE_MAP["modbus.discover_nmap"])
    # -sT + -Pn obligatorios cuando nmap va por proxychains (SOCKS solo
    # canaliza TCP; sin -Pn el ping falla y nmap marca el host como "down").
    # -sV se omite a propósito: por el túnel sus 20+ probes por puerto eran
    # el principal cuello de botella. El script modbus-discover ya identifica
    # el servicio.
    # wrap_live fuerza line-buffering para ver el progreso en vivo.
    runner.run_command(
        runner.wrap_proxy(runner.wrap_live(
            ["nmap", "-sT", "-Pn", "--script",
             "modbus-discover", "-p", "502", target])),
        path, sink=sink, timeout=600)
    return path


def s7_discover(target=None, sink=None):
    """nmap --script s7-info.nse -p 102 <red/ip> (zona Siemens S7)."""
    target = target or "192.168.30.0/24"
    if "/" not in target:
        runner.assert_lab_target(target)
    path = evidence.new_evidence_file("recon", "s7_info")
    evidence.header(path, "Descubrimiento Siemens S7 (s7-info.nse)",
                    target, config.MITRE_MAP["s7.discover_nmap"])
    runner.run_command(
        runner.wrap_proxy(runner.wrap_live(
            ["nmap", "-sT", "-Pn", "--script",
             "s7-info.nse", "-p", "102", target])),
        path, sink=sink, timeout=600)
    return path


def dnp3_discover(target=None, sink=None):
    """nmap -sT -Pn -p 20000 <red/ip> + intento de dnp3-info.nse (zona DNP3)."""
    target = target or "192.168.40.0/24"
    if "/" not in target:
        runner.assert_lab_target(target)
    path = evidence.new_evidence_file("recon", "dnp3_discover")
    evidence.header(path, "Descubrimiento DNP3 (puerto 20000 + dnp3-info)",
                    target, config.MITRE_MAP["dnp3.discover_nmap"])
    runner.run_command(
        runner.wrap_proxy(runner.wrap_live(
            ["nmap", "-sT", "-Pn", "-p", "20000", target])),
        path, sink=sink, timeout=600)
    runner.log("\n[*] Intento adicional con dnp3-info.nse "
               "(en las pruebas del TFM no aportó datos extra):", path, sink)
    runner.run_command(
        runner.wrap_proxy(runner.wrap_live(
            ["nmap", "-sT", "-Pn", "--script",
             "dnp3-info.nse", "-p", "20000", target])),
        path, sink=sink, timeout=600)
    return path
