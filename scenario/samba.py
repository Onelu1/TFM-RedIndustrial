#!/usr/bin/env python3
"""Preparación del pivote vulnerable Samba y claves SSH del laboratorio.

Genera (si no existe) el directorio `recurso_compartido/ssh_keys/` con una clave
RSA 2048 sin passphrase que luego el contenedor `srv_empresa` monta como
`authorized_keys`. Este par de claves es, intencionadamente, inseguro: el
toolkit de ataques lo descarga desde el share Samba anónimo.
"""

import os

from .shell import run_cmd


def setup_vulnerable_samba():
    """Genera el directorio compartido y las claves SSH para el escenario vulnerable."""
    path_keys = os.path.join(os.getcwd(), "recurso_compartido", "ssh_keys")
    os.makedirs(path_keys, exist_ok=True)

    if not os.path.exists(os.path.join(path_keys, "id_rsa")):
        print("[*] Generando claves SSH vulnerables para Samba...")
        run_cmd(f'ssh-keygen -t rsa -b 2048 -f {path_keys}/id_rsa -q -N ""', capture=False)
