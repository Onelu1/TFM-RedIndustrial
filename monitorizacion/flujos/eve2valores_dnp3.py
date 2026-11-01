#!/usr/bin/env python3
"""eve2valores_dnp3.py - Runtime: por cada escritura DNP3 (Operate /
DirectOperate sobre Group 41 Analog Output), extrae el valor y lo contrasta
con la banda aprendida en `valores_ok_dnp3.json`. Emite NDJSON con el
flag `fuera_rango`.

Fuente: eve.json de Suricata procesado offline (evaluar.sh) o live.
No parseamos DNP3; Suricata ya lo hace y nos entrega
`data.dnp3.application.objects[].points[].value`.

Formato de la linea NDJSON (mismo que pcap2valores.py para Modbus, con
`protocol: dnp3`):
    {"timestamp", "tfm_src", "src_ip", "dst_ip", "plc_ip", "protocol": "dnp3",
     "fc", "addr": "a<idx>", "value", "banda", "es_write": true,
     "fuera_rango"}
"""
from __future__ import annotations

import argparse
import json
import sys


GRUPOS_WRITE = {41}      # Analog Output (writes)
FUNC_OPERATE = {3, 4, 5, 6}   # Select, Operate, DirectOperate, DirectOp-NoAck
PUERTO_PLC = 20000


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eve", required=True,
                    help="Fichero eve.json a procesar")
    ap.add_argument("--salida", required=True)
    ap.add_argument("--bandas", required=True,
                    help="valores_ok_dnp3.json aprendido en entrenamiento")
    ap.add_argument("--src", default="",
                    help="Etiqueta tfm_src")
    args = ap.parse_args()

    try:
        with open(args.bandas, encoding="utf-8") as f:
            bandas = json.load(f)
    except FileNotFoundError:
        print(f"[dnp3] AVISO: {args.bandas} no existe; bandas vacias", file=sys.stderr)
        bandas = {}

    emitidos = 0
    fuera = 0
    with open(args.eve, encoding="utf-8") as fin, \
         open(args.salida, "w", encoding="utf-8", newline="\n") as fout:
        for linea in fin:
            try:
                d = json.loads(linea)
            except Exception:
                continue
            if d.get("event_type") != "dnp3":
                continue
            dnp3 = d.get("dnp3", {})
            app = dnp3.get("application", {}) or {}
            fc = app.get("function_code")
            if fc not in FUNC_OPERATE:
                continue
            # Identificar PLC
            if d.get("dest_port") == PUERTO_PLC:
                plc_ip = d["dest_ip"]
            elif d.get("src_port") == PUERTO_PLC:
                plc_ip = d["src_ip"]
            else:
                continue
            for obj in app.get("objects", []) or []:
                if obj.get("group") not in GRUPOS_WRITE:
                    continue
                for p in obj.get("points", []) or []:
                    if "value" not in p:
                        continue
                    idx = p.get("index")
                    val = p["value"]
                    if idx is None or not isinstance(val, (int, float)):
                        continue
                    clave = f"a{idx}"
                    banda = bandas.get(plc_ip, {}).get(clave)
                    if banda:
                        fuera_rango = (val < banda["min"] or val > banda["max"])
                        banda_str = f"{banda['min']}-{banda['max']}"
                    else:
                        fuera_rango = True
                        banda_str = "sin_banda"
                    if fuera_rango:
                        fuera += 1
                    fout.write(json.dumps({
                        "timestamp":   d.get("timestamp"),
                        "tfm_src":     args.src,
                        "src_ip":      d.get("src_ip"),
                        "dst_ip":      d.get("dest_ip"),
                        "plc_ip":      plc_ip,
                        "protocol":    "dnp3",
                        "fc":          fc,
                        "addr":        clave,
                        "value":       val,
                        "banda":       banda_str,
                        "es_write":    True,
                        "fuera_rango": fuera_rango,
                    }, ensure_ascii=False) + "\n")
                    emitidos += 1

    print(f"[dnp3] {args.eve}: {emitidos} writes ({fuera} fuera) -> {args.salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
