#!/usr/bin/env python3
"""
Gestión de evidencias: cada ejecución de un ataque se guarda en un fichero de log
con timestamp, listo para adjuntarse como captura en la memoria del TFM.
"""

import os
import datetime

import config


def new_evidence_file(modulo, accion):
    """Crea la ruta de un nuevo fichero de evidencia con timestamp.

    Formato: evidencias/YYYYmmdd_HHMMSS_<modulo>_<accion>.log
    """
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = f"{modulo}_{accion}".replace("/", "-").replace(" ", "_")
    path = os.path.join(config.EVIDENCE_DIR, f"{ts}_{safe}.log")
    return path


def header(path, titulo, objetivo="", mitre=None):
    """Escribe una cabecera descriptiva al principio del fichero de evidencia."""
    mitre = mitre or []
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 70,
        f"  TFM - TOOLKIT DE ATAQUES OT/ICS (laboratorio local aislado)",
        f"  {titulo}",
        "=" * 70,
        f"  Fecha      : {ts}",
    ]
    if objetivo:
        lines.append(f"  Objetivo   : {objetivo}")
    if mitre:
        lines.append(f"  MITRE ICS  : {', '.join(mitre)}")
    lines.append("=" * 70 + "\n")
    text = "\n".join(lines)
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)
    return text
