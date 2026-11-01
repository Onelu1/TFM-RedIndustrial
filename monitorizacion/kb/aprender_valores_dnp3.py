#!/usr/bin/env python3
"""aprender_valores_dnp3.py - Aprende rangos habituales de valores analogicos
DNP3 a partir de los eve.json que ha producido Suricata offline sobre los
PCAPs de baseline (evaluar.sh).

Suricata ya decodifica el protocolo DNP3 (app-layer: dnp3) y emite eventos
con `data.dnp3.application.objects[].points[]`; nosotros no parseamos
el protocolo, solo cosechamos sus eventos.

Grupos considerados:
  G30 (Analog Input)         - valor leido del sensor fisico
  G40 (Analog Output Status) - lectura actual del setpoint
  G42 (Analog Output Event)  - evento asincrono con el valor del setpoint
Todos tienen `value` entero/float; aprendemos min/max por (plc_ip, idx).

Produce `valores_ok_dnp3.json`:
    {"<plc_ip>": {"a<idx>": {"min": N, "max": N, "n": N}}}
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import defaultdict


GRUPOS_ANALOGICOS = {30, 40, 42}
PUERTO_PLC = 20000


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eves", required=True,
                    help="Glob de eve.json (p.ej. '.../salida/baseline/*/eve.json')")
    ap.add_argument("--salida", required=True)
    args = ap.parse_args()

    rutas = sorted(glob.glob(args.eves))
    if not rutas:
        print(f"[dnp3] ERROR: ningun eve.json matchea '{args.eves}'", file=sys.stderr)
        return 1

    bandas: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(
        lambda: [0, None, None]
    ))

    for ruta in rutas:
        n_eve = 0
        n_pts = 0
        with open(ruta, encoding="utf-8") as f:
            for line in f:
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                if d.get("event_type") != "dnp3":
                    continue
                n_eve += 1
                # PLC = el extremo con puerto 20000. En nuestro lab eso es
                # siempre dest_ip porque Suricata reporta el flujo desde el
                # cliente (gateway).
                if d.get("dest_port") == PUERTO_PLC:
                    plc_ip = d["dest_ip"]
                elif d.get("src_port") == PUERTO_PLC:
                    plc_ip = d["src_ip"]
                else:
                    continue
                for obj in d.get("dnp3", {}).get("application", {}).get("objects", []):
                    if obj.get("group") not in GRUPOS_ANALOGICOS:
                        continue
                    for p in obj.get("points", []) or []:
                        if "value" not in p:
                            continue
                        idx = p.get("index")
                        val = p["value"]
                        if idx is None or not isinstance(val, (int, float)):
                            continue
                        clave = f"a{idx}"
                        b = bandas[plc_ip][clave]
                        b[0] += 1
                        if b[1] is None or val < b[1]:
                            b[1] = val
                        if b[2] is None or val > b[2]:
                            b[2] = val
                        n_pts += 1
        print(f"[dnp3] {ruta}: {n_eve} eventos, {n_pts} puntos analogicos")

    out: dict[str, dict[str, dict[str, float]]] = {}
    for plc_ip, mapa in bandas.items():
        out[plc_ip] = {}
        for clave, (n, lo, hi) in mapa.items():
            out[plc_ip][clave] = {"min": lo, "max": hi, "n": n}

    with open(args.salida, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2, sort_keys=True)

    total = sum(len(v) for v in out.values())
    print(f"[dnp3] PLCs: {len(out)}, (plc x idx) con banda: {total}")
    print(f"[dnp3] Salida: {args.salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
