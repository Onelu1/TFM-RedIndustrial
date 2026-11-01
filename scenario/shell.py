#!/usr/bin/env python3
"""Helper `run_cmd` sobre subprocess (shell=True, captura opcional)."""

import subprocess


def run_cmd(cmd, check=True, capture=True):
    """Ejecuta un comando del sistema; imprime stderr si falla."""
    try:
        res = subprocess.run(
            cmd, shell=True, check=check, text=True,
            encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None
        )
        return res.stdout.strip() if capture else ""
    except subprocess.CalledProcessError as e:
        if capture and e.stderr:
            print(f"[!] Error ejecutando el comando: {cmd}\n[!] {e.stderr.strip()}")
        return None
