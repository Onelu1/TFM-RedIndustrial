#!/usr/bin/env python3
"""Utilidad común de ejecución de comandos del sistema con captura.

Usada por el resto de módulos del paquete `scenario` para invocar `docker`,
`ssh-keygen`, etc. Mantiene exactamente la semántica del `run_cmd` original de
`main.py`: shell=True, captura opcional y mensaje de error homogéneo.
"""

import subprocess


def run_cmd(cmd, check=True, capture=True):
    """Ejecuta comandos del sistema con captura de errores."""
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
