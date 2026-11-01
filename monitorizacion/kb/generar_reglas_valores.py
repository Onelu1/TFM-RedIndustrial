#!/usr/bin/env python3
"""generar_reglas_valores.py - Convierte el baseline `valores_ok.json`
aprendido por aprender_valores.py en reglas Suricata que detectan EN VIVO
escrituras Modbus con valor fuera de la banda.

Por cada banda (plc_ip, clave=`r<N>`/`c<N>`, min, max) emite hasta dos
reglas:
    modbus: access write holding, address <N+1>, value <min
    modbus: access write holding, address <N+1>, value >max

Dos matices clave aprendidos empíricamente con Suricata 8.0.7:
    - `address` en el keyword modbus es 1-based (el PDU es 0-based).
    - La sintaxis es `value <X` SIN espacio tras el operador.

Las reglas resultantes se cargan en Suricata via `include:` desde
`suricata/rules/local.rules`. El contenedor `suricata_ids` fuerza
`-S .../local.rules`, por eso NO basta con añadirlas a `rule-files:`
en suricata.yaml.

Uso:
  python3 generar_reglas_valores.py \
      --bandas monitorizacion/kb/valores_ok.json \
      --salida monitorizacion/suricata/rules/valores_generado.rules
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone


# Rango reservado por el proyecto (ver SIDS.md): 2001000-2001999.
SID_BASE = 2001000

# Suricata keyword `value` admite comparaciones en el espacio u16.
U16_MAX = 65535

# Bandas inservibles: amplitud casi todo el u16 -> ninguna regla.
AMPLITUD_MAX_UTIL = 60000

# Muestras minimas para confiar en la banda.
N_MIN = 100


def _mitre_tag() -> str:
    # T0836 Modify Parameter + T0831 Manipulation of Control.
    return "mitre_technique_id T0836, mitre_technique_id T0831"


def _emitir(plc_ip: str, clave: str, banda: dict, sid_ini: int) -> tuple[list[str], int]:
    """Devuelve (lineas_rules, siguiente_sid). Hasta 2 lineas por banda."""
    try:
        min_v = int(banda["min"])
        max_v = int(banda["max"])
        n = int(banda.get("n", 0))
    except (TypeError, ValueError):
        return [], sid_ini

    if n < N_MIN:
        return [], sid_ini
    if (max_v - min_v) > AMPLITUD_MAX_UTIL:
        return [], sid_ini

    tipo = clave[0]
    if tipo == "r":
        access = "access write holding"
    elif tipo == "c":
        access = "access write coils"
    else:
        return [], sid_ini
    try:
        addr0 = int(clave[1:])
    except ValueError:
        return [], sid_ini
    addr1 = addr0 + 1  # Suricata usa address 1-based.

    sid = sid_ini
    lineas: list[str] = []

    # value <min (solo si min>0 — por debajo de 0 no existe en u16).
    if min_v > 0:
        msg = f"TFM/Valores: write a {plc_ip} reg {clave} valor <{min_v}"
        lineas.append(
            f'alert modbus any any -> {plc_ip} 502 '
            f'(msg:"{msg}"; '
            f'modbus: {access}, address {addr1}, value <{min_v}; '
            f'classtype:policy-violation; '
            f'metadata:{_mitre_tag()}; '
            f'sid:{sid}; rev:1;)'
        )
        sid += 1

    # value >max (solo si max<65535).
    if max_v < U16_MAX:
        msg = f"TFM/Valores: write a {plc_ip} reg {clave} valor >{max_v}"
        lineas.append(
            f'alert modbus any any -> {plc_ip} 502 '
            f'(msg:"{msg}"; '
            f'modbus: {access}, address {addr1}, value >{max_v}; '
            f'classtype:policy-violation; '
            f'metadata:{_mitre_tag()}; '
            f'sid:{sid}; rev:1;)'
        )
        sid += 1

    return lineas, sid


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Genera reglas Suricata 'valor fuera de banda' desde valores_ok.json."
    )
    ap.add_argument("--bandas", required=True)
    ap.add_argument("--salida", required=True)
    args = ap.parse_args()

    try:
        with open(args.bandas, encoding="utf-8") as f:
            bandas = json.load(f)
    except FileNotFoundError:
        print(f"[valores_rules] ERROR: {args.bandas} no existe", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"[valores_rules] ERROR: {args.bandas} JSON invalido: {e}", file=sys.stderr)
        return 1

    sid = SID_BASE
    todas: list[str] = []
    saltadas = 0
    for plc_ip in sorted(bandas.keys()):
        regs = bandas[plc_ip] or {}
        bloque: list[str] = []
        for clave in sorted(regs.keys()):
            lineas, sid = _emitir(plc_ip, clave, regs[clave], sid)
            if lineas:
                bloque.extend(lineas)
            else:
                saltadas += 1
        if bloque:
            todas.append(f"# ---- {plc_ip} ----")
            todas.extend(bloque)
            todas.append("")

    gen_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cab = [
        f"# Generado por generar_reglas_valores.py desde {args.bandas}.",
        f"# NO EDITAR A MANO — se regenera cada [E] (modo entrenamiento).",
        f"# Generado: {gen_at}",
        f"# SIDs usados: {SID_BASE}..{sid - 1}  (rango reservado 2001000-2001999).",
        f"# Bandas descartadas (amplitud >{AMPLITUD_MAX_UTIL} o n<{N_MIN}): {saltadas}",
        "",
    ]
    with open(args.salida, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(cab + todas))
        if todas:
            f.write("\n")

    print(f"[valores_rules] {sid - SID_BASE} reglas -> {args.salida} "
          f"({saltadas} bandas descartadas)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
