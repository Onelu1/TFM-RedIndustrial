#!/usr/bin/env python3
"""
Ejecución de comandos/funciones con captura de salida en vivo + escritura a
fichero de evidencia. Incluye una guarda de seguridad (`assert_lab_target`) que
impide lanzar ataques contra IPs que no pertenezcan al laboratorio local.
"""

import ipaddress
import socket
import subprocess
import threading

import config


class LabScopeError(Exception):
    """Se lanza cuando un objetivo no pertenece a las subredes del laboratorio."""


def wrap_proxy(cmd):
    """Antepone 'proxychains' al comando si el modo es 'empresa'.

    En modo 'control' devuelve `cmd` tal cual (kali tiene rutas directas a OT).
    Acepta tanto una lista como un string (para shell=True).
    """
    if config.get_mode() != "empresa":
        return cmd
    if isinstance(cmd, str):
        return "proxychains " + cmd
    return ["proxychains"] + list(cmd)


def wrap_live(cmd):
    """Antepone 'stdbuf -oL -eL' para forzar line-buffering del subproceso.

    Útil para herramientas (msfconsole, nmap) que detectan "no TTY" y
    bufferizan stdout entero: sin stdbuf no vemos nada hasta que el proceso
    termina. Combinable con wrap_proxy:
        runner.wrap_proxy(runner.wrap_live(cmd))
    """
    if isinstance(cmd, str):
        return "stdbuf -oL -eL " + cmd
    return ["stdbuf", "-oL", "-eL"] + list(cmd)


def tunnel_up(host="127.0.0.1", port=9050, timeout=0.5):
    """True si hay algo escuchando en el puerto del túnel SOCKS."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def assert_lab_target(ip):
    """Verifica que `ip` pertenece a alguna subred del laboratorio.

    Evita, por error de tecleo, lanzar un módulo contra una IP real externa.
    Devuelve la IP si es válida; lanza LabScopeError en caso contrario.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise LabScopeError(f"'{ip}' no es una dirección IP válida.")

    for subnet in config.LAB_SUBNETS:
        if addr in ipaddress.ip_network(subnet):
            return ip
    raise LabScopeError(
        f"'{ip}' no pertenece al laboratorio local {config.LAB_SUBNETS}. "
        "El toolkit solo puede apuntar a las subredes del entorno de pruebas."
    )


def _emit(line, evidence_path, sink):
    """Escribe una línea al fichero de evidencia y, si hay sink, lo notifica."""
    with open(evidence_path, "a", encoding="utf-8") as f:
        f.write(line if line.endswith("\n") else line + "\n")
    if sink is not None:
        sink(line.rstrip("\n"))


def run_command(cmd, evidence_path, sink=None, shell=False, timeout=None, cwd=None):
    """Ejecuta un comando de sistema capturando stdout+stderr línea a línea.

    - cmd: lista de argumentos (o string si shell=True).
    - evidence_path: fichero donde se vuelca toda la salida.
    - sink: callable(str) opcional para streaming en vivo (dashboard).
    Devuelve el código de retorno.
    """
    printable = cmd if isinstance(cmd, str) else " ".join(cmd)
    _emit(f"$ {printable}", evidence_path, sink)
    try:
        proc = subprocess.Popen(
            cmd, shell=shell, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
    except FileNotFoundError as e:
        _emit(f"[!] Comando no encontrado: {e}", evidence_path, sink)
        return 127

    def _reader():
        for raw in iter(proc.stdout.readline, ""):
            _emit(raw.rstrip("\n"), evidence_path, sink)
        proc.stdout.close()

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        _emit(f"[!] Timeout ({timeout}s): proceso terminado.", evidence_path, sink)
    t.join(timeout=2)
    _emit(f"[=] Código de salida: {proc.returncode}", evidence_path, sink)
    return proc.returncode


def log(msg, evidence_path, sink=None):
    """Escribe un mensaje informativo (desde Python, no desde un subproceso)."""
    _emit(msg, evidence_path, sink)
