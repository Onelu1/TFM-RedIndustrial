#!/usr/bin/env python3
"""Genera la clave SSH que `srv_empresa` publica (vulnerable a propósito) en el
share Samba anónimo del laboratorio."""

import os

from .shell import run_cmd


def setup_vulnerable_samba():
    """Genera el directorio compartido y las claves SSH para el escenario vulnerable."""
    path_keys = os.path.join(os.getcwd(), "recurso_compartido", "ssh_keys")
    os.makedirs(path_keys, exist_ok=True)

    if not os.path.exists(os.path.join(path_keys, "id_rsa")):
        print("[*] Generando claves SSH vulnerables para Samba...")
        run_cmd(f'ssh-keygen -t rsa -b 2048 -f {path_keys}/id_rsa -q -N ""', capture=False)
