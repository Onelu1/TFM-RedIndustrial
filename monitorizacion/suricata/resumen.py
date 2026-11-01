#!/usr/bin/env python3
"""resumen.py - Agrega las alertas Suricata por escenario y las mapea a MITRE
ATT&CK for ICS, produciendo la tabla final del TFM.

Lee todos los eve.json bajo monitorizacion/suricata/salida/<pcap>/eve.json,
agrupa los pcaps por escenario (quitando _control/_empresa/_mqtt/_dnp3 y
timestamp) y vuelca la tabla.
"""
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

AQUI = Path(__file__).parent
SAL = AQUI / "salida"


def nombre_a_escenario(path):
    """De una ruta como:
       salida/ataques/recon_modbus/atk_recon_modbus_control-20261016-001227/
       salida/baseline/baseline_control-20261015-194821/
    extrae 'recon_modbus' o 'baseline' (el nombre de la carpeta padre).
    """
    # path es un pathlib.Path al directorio del eve.json
    parent = path.parent.name       # p.ej. 'recon_modbus' o 'baseline'
    if parent in ("ataques", "baseline"):
        # path es ya la carpeta de escenario (p.ej. salida/baseline/<pcap>/)
        return parent
    return parent


# Mapeo SID -> (nombre_corto, MITRE_IDs). Alineado con local.rules.
SID_INFO = {
    2000001: ("Modbus conn no auth",               ["T0846", "T0888"]),
    2000002: ("S7 conn no auth",                   ["T0846", "T0888"]),
    2000003: ("DNP3 conn no auth",                 ["T0846", "T0888"]),
    2000010: ("Modbus Write Single Coil (FC=5)",   ["T0855"]),
    2000011: ("Modbus Write Single Register (6)",  ["T0836"]),
    2000012: ("Modbus Write Mult Coils (15)",      ["T0855"]),
    2000013: ("Modbus Write Mult Regs (16)",       ["T0836"]),
    2000020: ("Pivote IT->OT",                     ["T0866", "T1046"]),
    2000021: ("Exfil OT->Enterprise",              ["T0882"]),
    2000100: ("Recon nmap modbus-discover (FC=43)",["T0846", "T0888"]),
    2000101: ("Recon S7 enum (COTP+S7)",           ["T0846", "T0888"]),
    2000110: ("Modbus Read Holding Registers",     ["T0861", "T0888"]),
    2000120: ("S7 trafico no SCADA",               ["T0836", "T0855"]),
    2000130: ("DNP3 Operate no auth",              ["T0855", "T0836"]),
    2000131: ("DNP3 DirectOperateNR no auth",      ["T0855"]),
    2000140: ("Samba Backups_SCADA acceso",        ["T1039", "T1552.004"]),
    2000141: ("SSH entrante srv_empresa",          ["T1078.003", "T1090"]),
    2000150: ("OpenPLC web login",                 ["T0812"]),
    2000151: ("OpenPLC subida .st",                ["T0843", "T0821", "T0831"]),
    2000160: ("C2 FrostyGoop Write regs 1000+",    ["T0869", "T1570"]),
    2000161: ("C2 FrostyGoop Read regs 1200+",     ["T0869"]),
    2000162: ("C2 FrostyGoop beaconing",           ["T0869"]),
}


def leer_eve(p):
    alertas = []
    try:
        with open(p, encoding="utf-8") as f:
            for linea in f:
                try:
                    ev = json.loads(linea)
                    if ev.get("event_type") == "alert":
                        alertas.append(ev)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return alertas


def main():
    por_escenario = defaultdict(list)
    # Busca recursivamente todos los eve.json. Estructura esperada:
    #   SAL/baseline/<pcap>/eve.json
    #   SAL/ataques/<escenario>/<pcap>/eve.json
    for eve in sorted(SAL.rglob("eve.json")):
        rel = eve.relative_to(SAL)
        # rel.parts: ('baseline', '<pcap>', 'eve.json')  -> esc = 'baseline'
        #            ('ataques', '<escenario>', '<pcap>', 'eve.json') -> esc = '<escenario>'
        if rel.parts[0] == "baseline":
            esc = "baseline"
        elif rel.parts[0] == "ataques" and len(rel.parts) >= 3:
            esc = rel.parts[1]
        else:
            esc = rel.parts[0]
        for a in leer_eve(eve):
            por_escenario[esc].append(a)

    print(f"{'ESCENARIO':<30} {'ALERTAS':>8}  {'SIDs únicos':<32}  MITRE únicos")
    print("-" * 110)
    for esc in sorted(por_escenario.keys()):
        alertas = por_escenario[esc]
        sids = sorted({a["alert"]["signature_id"] for a in alertas})
        mitre = sorted({mid for s in sids for mid in SID_INFO.get(s, ("", []))[1]})
        sid_str = " ".join(str(s) for s in sids)
        mitre_str = ", ".join(mitre) if mitre else "-"
        print(f"{esc:<30} {len(alertas):>8}  {sid_str:<32}  {mitre_str}")

    print()
    print("=" * 110)
    print("DETALLE POR ESCENARIO (SID -> firma -> MITRE):")
    print("=" * 110)
    for esc in sorted(por_escenario.keys()):
        alertas = por_escenario[esc]
        if not alertas:
            continue
        print(f"\n[{esc}]  {len(alertas)} alertas")
        por_sid = defaultdict(int)
        for a in alertas:
            por_sid[a["alert"]["signature_id"]] += 1
        for sid in sorted(por_sid):
            n = por_sid[sid]
            nombre, mitre = SID_INFO.get(sid, ("<regla externa>", []))
            print(f"   SID {sid}  x{n:<3}  {nombre:<40}  MITRE: {','.join(mitre) or '-'}")


if __name__ == "__main__":
    main()
