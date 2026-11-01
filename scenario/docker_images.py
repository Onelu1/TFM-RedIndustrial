#!/usr/bin/env python3
"""Compilación bajo demanda de las dos imágenes Docker locales del laboratorio
(`mi_plc_siemens` y `mi_openplc`); se omite si `docker images -q` las encuentra."""

import os

from .shell import run_cmd


def build_s7_image_if_needed():
    image = run_cmd("docker images -q mi_plc_siemens")
    if not image:
        print("[*] Compilando imagen 'mi_plc_siemens' desde 'siemens_s7/Dockerfile'...")
        path_s7 = os.path.join(os.getcwd(), "siemens_s7")
        if not os.path.exists(path_s7):
            print(f"[!] ERROR: No existe el directorio {path_s7}")
            return False
        run_cmd(f"docker build -t mi_plc_siemens {path_s7}", capture=False)
        print("[✔] Imagen 'mi_plc_siemens' compilada correctamente.")
    return True


def build_openplc_image_if_needed():
    image = run_cmd("docker images -q mi_openplc")
    if not image:
        print("[*] Compilando imagen 'mi_openplc' desde 'openplc/Dockerfile' (puede llevar un tiempo)...")
        path_oplc = os.path.join(os.getcwd(), "openplc")
        if not os.path.exists(path_oplc):
            print(f"[!] ERROR: No existe el directorio {path_oplc}")
            return False
        run_cmd(f"docker build -t mi_openplc {path_oplc}", capture=False)
        print("[✔] Imagen 'mi_openplc' compilada correctamente.")
    return True
