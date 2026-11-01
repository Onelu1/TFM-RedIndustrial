#!/usr/bin/env python3
"""construir_kb.py - Construye la Base de Conocimiento (allowlist OT) a partir
de los flujos del baseline y del INVENTARIO aprendido por `inferir_roles.py`.

Hace dos cosas que antes estaban mezcladas:

  1) Agrega los flujos del baseline (CSV nfdump o NDJSON) en:
     - comunicaciones_ok.cdb      5-tuplas permitidas (origen -> destino:puerto/proto)
     - plcs.cdb                   servicios OT catalogados (ip:puerto -> rol)
     - plcs_ips.cdb               IPs de PLCs conocidos (ip -> ok) para 100270
     - funciones_modbus_ok.cdb    (sip, dip) -> FC lecturas permitidas (1,2,3,4)
     - umbrales.json              bytes/pkts percentiles 50/90/99 por conversacion
     - baseline_flows.csv         vuelco legible del baseline (trazabilidad TFM)

  2) Genera `suricata_vars.yaml` DINAMICAMENTE a partir del inventario:
     - SCADA_SERVERS   = inventario.role_index["scada"]
     - MQTT_BROKER     = inventario.role_index["broker_mqtt"]
     - DNP3_GATEWAYS   = inventario.role_index["gateway_dnp3"]
     - MODBUS_PLCS     = inventario.role_index["plc_modbus"]
     - S7_PLCS         = inventario.role_index["plc_s7"]
     - DNP3_PLCS       = inventario.role_index["plc_dnp3"]
     - ENTERPRISE      = subred(es) donde cae it_fileserver (si todas en 60.0/24
                         -> "[192.168.60.0/24]"; si no, lista explicita)
     - C2_MAILBOX      = del fichero manual c2_mailbox.yaml (vacio = never-match)
     - HOME_NET / OT_PLCS / MGMT = subredes del compose (constantes de red,
                         no de rol — definidas al principio del script)

El rol de cada IP se consulta en el inventario; `rol_de(ip)` ya no mira
una tabla hardcoded. Si no hay inventario, pasa `--legacy-hardcoded` para
caer a `ground_truth_hosts.HOSTS` como ESCAPE DE EMERGENCIA (deprecado).

Formato de entrada: autodetectado por extension.
  - .csv  → nfdump -o csv  (sa, da, sp, dp, pr, ipkt, ibyt, ts, te, flg)
  - .json → nfdump -o json (src4_addr, dst4_addr, src_port, dst_port, proto, ...)

Uso:
  python construir_kb.py \\
      --baseline   "flujos/salida/baseline/*.json" \\
      --inventario monitorizacion/kb/inventario.json \\
      --c2-mailbox monitorizacion/kb/c2_mailbox.yaml \\
      --salida     monitorizacion/kb/
"""
from __future__ import annotations

import argparse
import csv
import glob
import ipaddress
import json
import os
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def _normalizar_path(p: str) -> str:
    """Convierte paths MSYS (/c/Users/..) a Windows (C:/Users/..) si procede.

    Git Bash pasa `/c/Users/...` a python.exe nativo, que no los entiende.
    """
    if (os.name == "nt" and p and p.startswith("/") and len(p) > 2
            and p[2] == "/" and p[1].isalpha()):
        return f"{p[1].upper()}:{p[2:]}"
    return p


# ---------------------------------------------------------------------------
# Constantes de RED del lab (no de rol).
# Si se modifica el compose para cambiar subredes, actualizar aqui.
# ---------------------------------------------------------------------------
HOME_NET_SUBREDES = [
    "192.168.10.0/24",
    "192.168.20.0/24",
    "192.168.30.0/24",
    "192.168.40.0/24",
    "192.168.50.0/24",
    "192.168.60.0/24",
]
OT_PLCS_SUBREDES = [
    "192.168.10.0/24",
    "192.168.30.0/24",
    "192.168.40.0/24",
]
MGMT_SUBREDES = ["192.168.50.0/24"]
ENTERPRISE_SUBRED_DEFAULT = ["192.168.60.0/24"]

PUERTOS_OT = {502, 102, 20000, 1883}
PROTO_NUM = {"TCP": 6, "UDP": 17, "ICMP": 1, "SCTP": 132}

NEVER_MATCH = "0.0.0.0/32"


# ---------------------------------------------------------------------------
# Lectura de flujos (autodetecta CSV vs NDJSON)
# ---------------------------------------------------------------------------


def leer_flujos(ruta_glob):
    """Lee uno o varios ficheros de flujos. Autodetecta por extension.

    Normaliza al mismo dict en ambos formatos para que `extraer()` no sepa
    de donde salio el flujo. Campos del dict: sa, da, sp, dp, pr, ipkt, ibyt,
    ts, te, flg.
    """
    rutas = sorted(glob.glob(_normalizar_path(ruta_glob)))
    for ruta in rutas:
        ext = Path(ruta).suffix.lower()
        if ext == ".csv":
            yield from _leer_csv(ruta)
        elif ext == ".json":
            yield from _leer_ndjson(ruta)
        else:
            print(f"[kb] AVISO: ignorando {ruta} (extension desconocida)", file=sys.stderr)


def _leer_csv(ruta):
    with open(ruta, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for fila in reader:
            yield fila


def _leer_ndjson(ruta):
    """NDJSON de nfdump -o json (una linea por flujo). Renombra campos largos
    a los nombres cortos del CSV para que extraer() no cambie.
    """
    with open(ruta, encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                r = json.loads(linea)
            except json.JSONDecodeError:
                continue
            src = r.get("src4_addr") or r.get("src_addr")
            dst = r.get("dst4_addr") or r.get("dst_addr")
            if not src or not dst:
                continue
            yield {
                "sa":   src,
                "da":   dst,
                "sp":   r.get("src_port") or 0,
                "dp":   r.get("dst_port") or 0,
                "pr":   r.get("proto") or 0,
                "ipkt": r.get("in_packets") or 0,
                "ibyt": r.get("in_bytes") or 0,
                "ts":   r.get("t_first") or r.get("first") or "",
                "te":   r.get("t_last") or r.get("last") or "",
                "flg":  r.get("tcp_flags", ""),
            }


def extraer(f):
    sip = f.get("sa")
    dip = f.get("da")
    spt = f.get("sp") or 0
    dpt = f.get("dp") or 0
    pro = f.get("pr") or "0"
    try:
        pro_num = int(pro)
    except (ValueError, TypeError):
        pro_num = PROTO_NUM.get(str(pro).upper(), 0)
    pks = int(f.get("ipkt") or 0)
    bts = int(f.get("ibyt") or 0)
    ts  = f.get("ts")
    te  = f.get("te")
    app = f.get("flg")
    return sip, dip, int(spt), int(dpt), pro_num, pks, bts, ts, te, app


# ---------------------------------------------------------------------------
# Fuente de rol: inventario o legacy
# ---------------------------------------------------------------------------


def cargar_inventario(ruta: str | None) -> dict:
    """Lee inventario.json. Devuelve dict con 'hosts' y 'role_index' al menos.
    Si la ruta es None/no existe, devuelve dict vacio para que rol_de() caiga
    a 'desconocido' limpiamente.
    """
    if not ruta:
        return {"hosts": {}, "role_index": {}}
    p = Path(ruta)
    if not p.exists():
        print(f"[kb] AVISO: inventario {ruta} no existe; roles seran 'desconocido'.",
              file=sys.stderr)
        return {"hosts": {}, "role_index": {}}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def cargar_c2_mailbox(ruta: str | None) -> list[str]:
    """Lee el YAML manual de IPs C2. Parser casero (una clave `c2_mailbox:`
    seguida de items `- <ip>`), para no depender de PyYAML en el entorno TFM.
    Lineas que empiezan con `#` o estan vacias se ignoran.
    """
    if not ruta:
        return []
    p = Path(ruta)
    if not p.exists():
        return []
    ips: list[str] = []
    dentro = False
    with open(p, encoding="utf-8") as f:
        for linea in f:
            s = linea.rstrip("\n")
            desnuda = s.strip()
            if not desnuda or desnuda.startswith("#"):
                continue
            if desnuda.startswith("c2_mailbox:"):
                dentro = True
                resto = desnuda.split(":", 1)[1].strip()
                if resto.startswith("[") and resto.endswith("]"):
                    inner = resto[1:-1]
                    ips.extend(ip.strip().strip('"\'') for ip in inner.split(",") if ip.strip())
                    dentro = False
                continue
            if dentro:
                m = re.match(r"^-\s*(.+?)\s*(?:#.*)?$", desnuda)
                if m:
                    val = m.group(1).strip().strip('"\'')
                    if val:
                        ips.append(val)
                else:
                    dentro = False
    # Validar IPs y filtrar duplicados preservando orden
    vistos = set()
    salida = []
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"[kb] AVISO: IP C2 invalida ignorada: {ip!r}", file=sys.stderr)
            continue
        if ip not in vistos:
            vistos.add(ip)
            salida.append(ip)
    return salida


def hacer_rol_de(inventario: dict, c2_mailbox: set[str], legacy: bool):
    """Devuelve una funcion rol_de(ip) que consulta el inventario (o la tabla
    legacy si --legacy-hardcoded). Promueve a 'plc_modbus_c2_mailbox' las IPs
    en c2_mailbox.
    """
    if legacy:
        from ground_truth_hosts import HOSTS
        legacy_tbl = HOSTS

        def rol_de(ip):
            if ip in c2_mailbox:
                return "plc_modbus_c2_mailbox"
            if ip in legacy_tbl:
                return legacy_tbl[ip][1]
            return "desconocido"
        return rol_de

    hosts = inventario.get("hosts", {}) or {}

    def rol_de(ip):
        if ip in c2_mailbox:
            return "plc_modbus_c2_mailbox"
        info = hosts.get(ip)
        if info:
            return info.get("rol", "desconocido")
        return "desconocido"
    return rol_de


# ---------------------------------------------------------------------------
# Generacion de suricata_vars.yaml dinamico
# ---------------------------------------------------------------------------


def _grupo_direcciones(ips: list[str] | set[str]) -> str:
    """Devuelve el literal YAML para un address-group a partir de una lista
    de IPs. Si la lista esta vacia, usa el placeholder never-match.
    """
    if not ips:
        return f'"[{NEVER_MATCH}]"'
    return '"[' + ",".join(sorted(set(ips))) + ']"'


def _enterprise_group(role_index: dict) -> str:
    """Si todas las IPs it_fileserver caen en 192.168.60.0/24 se emite la
    subred; en caso contrario, lista explicita. Si no hay fileserver, cae al
    default (60.0/24) + warning.
    """
    ips = role_index.get("it_fileserver", []) or []
    if not ips:
        print("[kb] AVISO: inventario sin it_fileserver; "
              "ENTERPRISE queda como 192.168.60.0/24 (default).", file=sys.stderr)
        return '"[' + ",".join(ENTERPRISE_SUBRED_DEFAULT) + ']"'
    red_60 = ipaddress.ip_network("192.168.60.0/24")
    todas_en_60 = all(
        ipaddress.ip_address(ip) in red_60 for ip in ips
    )
    if todas_en_60:
        return '"[192.168.60.0/24]"'
    return '"[' + ",".join(sorted(set(ips))) + ']"'


def escribir_suricata_vars(path: Path, inventario: dict, c2_mailbox: list[str]) -> None:
    role_index = inventario.get("role_index", {}) or {}
    scada = role_index.get("scada", [])
    brokers = role_index.get("broker_mqtt", [])
    gateways = role_index.get("gateway_dnp3", [])
    modbus_plcs = role_index.get("plc_modbus", [])
    s7_plcs = role_index.get("plc_s7", [])
    dnp3_plcs = role_index.get("plc_dnp3", [])

    if not scada:
        print("[kb] AVISO: inventario sin SCADA; $SCADA_SERVERS = never-match.",
              file=sys.stderr)
    if not brokers:
        print("[kb] AVISO: inventario sin broker MQTT; $MQTT_BROKER = never-match.",
              file=sys.stderr)
    if not gateways:
        print("[kb] AVISO: inventario sin gateways DNP3; $DNP3_GATEWAYS = never-match.",
              file=sys.stderr)
    if not modbus_plcs:
        print("[kb] AVISO: inventario sin PLCs Modbus; $MODBUS_PLCS = never-match.",
              file=sys.stderr)
    if not s7_plcs:
        print("[kb] AVISO: inventario sin PLCs S7; $S7_PLCS = never-match.",
              file=sys.stderr)
    if not dnp3_plcs:
        print("[kb] AVISO: inventario sin outstations DNP3; $DNP3_PLCS = never-match.",
              file=sys.stderr)
    if not c2_mailbox:
        print("[kb] INFO: c2_mailbox.yaml vacio; $C2_MAILBOX = never-match "
              "(las reglas FrostyGoop no disparan hasta que se defina).",
              file=sys.stderr)

    home_net   = '"[' + ",".join(HOME_NET_SUBREDES) + ']"'
    ot_plcs    = '"[' + ",".join(OT_PLCS_SUBREDES)  + ']"'
    mgmt       = '"[' + ",".join(MGMT_SUBREDES)     + ']"'

    scada_g      = _grupo_direcciones(scada)
    mqtt_g       = _grupo_direcciones(brokers)
    gateways_g   = _grupo_direcciones(gateways)
    modbus_plcs_g = _grupo_direcciones(modbus_plcs)
    s7_plcs_g    = _grupo_direcciones(s7_plcs)
    dnp3_plcs_g  = _grupo_direcciones(dnp3_plcs)
    enterprise   = _enterprise_group(role_index)
    c2_g         = _grupo_direcciones(c2_mailbox)

    gen_at = inventario.get("metadata", {}).get("generated_at", "")

    with open(path, "w", encoding="utf-8") as f:
        # Cabecera YAML explicita obligatoria para Suricata 7.x cuando el
        # fichero se trae con `include:` desde suricata.yaml.
        f.write("%YAML 1.1\n")
        f.write("---\n")
        f.write("# Generado por construir_kb.py a partir de inventario.json.\n")
        f.write("# NO EDITAR A MANO — se regenera cada [E] (modo entrenamiento).\n")
        if gen_at:
            f.write(f"# Inventario generado: {gen_at}\n")
        f.write("vars:\n")
        f.write("  address-groups:\n")
        f.write(f'    HOME_NET: {home_net}\n')
        f.write('    EXTERNAL_NET: "!$HOME_NET"\n')
        f.write(f'    OT_PLCS: {ot_plcs}\n')
        f.write(f'    MODBUS_PLCS: {modbus_plcs_g}\n')
        f.write(f'    S7_PLCS: {s7_plcs_g}\n')
        f.write(f'    DNP3_PLCS: {dnp3_plcs_g}\n')
        f.write(f'    SCADA_SERVERS: {scada_g}\n')
        f.write(f'    MQTT_BROKER: {mqtt_g}\n')
        f.write(f'    DNP3_GATEWAYS: {gateways_g}\n')
        f.write(f'    ENTERPRISE: {enterprise}\n')
        f.write(f'    MGMT: {mgmt}\n')
        f.write(f'    C2_MAILBOX: {c2_g}\n')
        f.write("  port-groups:\n")
        f.write('    MODBUS_PORTS: "502"\n')
        f.write('    S7_PORTS: "102"\n')
        f.write('    DNP3_PORTS: "20000"\n')
        f.write('    MQTT_PORTS: "1883"\n')
        f.write('    HTTP_PORTS: "[80,8080,8181,8182,8183]"\n')
        f.write('    SSH_PORTS: "[22,2222]"\n')


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", required=True,
                   help="Glob a flujos del baseline (.csv o .json; se autodetecta).")
    p.add_argument("--salida", required=True,
                   help="Directorio donde escribir las listas y variables.")
    p.add_argument("--inventario", default=None,
                   help="Ruta a inventario.json (producido por inferir_roles.py).")
    p.add_argument("--c2-mailbox", default=None,
                   help="Ruta a c2_mailbox.yaml (manual) con IPs C2 FrostyGoop.")
    p.add_argument("--legacy-hardcoded", action="store_true",
                   help="Escape de emergencia: usar ground_truth_hosts.HOSTS "
                        "en lugar del inventario (deprecado).")
    args = p.parse_args()

    sal = Path(_normalizar_path(args.salida))
    sal.mkdir(parents=True, exist_ok=True)

    inv_ruta = _normalizar_path(args.inventario) if args.inventario else None
    c2_ruta = _normalizar_path(args.c2_mailbox) if args.c2_mailbox else None
    inventario = cargar_inventario(inv_ruta)
    c2_list = cargar_c2_mailbox(c2_ruta)
    c2_set = set(c2_list)
    rol_de = hacer_rol_de(inventario, c2_set, args.legacy_hardcoded)

    comunicaciones = set()
    servicios = {}
    bytes_por_tupla = defaultdict(list)
    pkts_por_tupla  = defaultdict(list)
    cnt = 0

    with open(sal / "baseline_flows.csv", "w", newline="", encoding="utf-8") as fcsv:
        w = csv.writer(fcsv)
        w.writerow(["sip", "dip", "proto", "sport", "dport",
                    "pkts", "bytes", "stime", "etime", "applabel",
                    "rol_src", "rol_dst"])

        for f in leer_flujos(args.baseline):
            sip, dip, spt, dpt, pro, pks, bts, ts, te, app = extraer(f)
            if not (sip and dip and pro):
                continue
            cnt += 1
            rsrc, rdst = rol_de(sip), rol_de(dip)
            w.writerow([sip, dip, pro, spt, dpt, pks, bts, ts, te, app, rsrc, rdst])

            if dpt > 1023 and spt <= 1023 and spt > 0:
                pass
            else:
                comunicaciones.add((sip, dip, pro, dpt))

            if dpt and (dpt in PUERTOS_OT or dpt < 1024):
                servicios[f"{dip}:{dpt}"] = f"{rol_de(dip)}:proto={pro}"

            tup = (sip, dip, dpt)
            bytes_por_tupla[tup].append(bts)
            pkts_por_tupla[tup].append(pks)

    if cnt == 0:
        print("[kb] AVISO: el baseline no contenia flujos legibles. "
              "Ejecuta pcap2flujos.sh antes.", file=sys.stderr)
        sys.exit(1)

    # -------- comunicaciones_ok.cdb --------
    with open(sal / "comunicaciones_ok.cdb", "w", encoding="utf-8") as f:
        for sip, dip, pro, dpt in sorted(comunicaciones):
            f.write(f"{sip}->{dip}:{dpt}/{pro}:ok\n")

    # -------- plcs.cdb --------
    with open(sal / "plcs.cdb", "w", encoding="utf-8") as f:
        for k, v in sorted(servicios.items()):
            f.write(f"{k}:{v}\n")

    # -------- plcs_ips.cdb --------
    # Lista de IPs (sin puerto) de PLCs conocidos, extraida de los roles
    # OT en el inventario. La consume la regla Wazuh 100270: alerta cuando
    # Suricata ve app-layer modbus/dnp3/enip hablando con una IP que no
    # esta aqui (= servidor OT desconocido / PLC pirata).
    role_index = inventario.get("role_index", {}) or {}
    plcs_ips = sorted({
        ip
        for rol in ("plc_modbus", "plc_s7", "plc_dnp3")
        for ip in (role_index.get(rol, []) or [])
    })
    with open(sal / "plcs_ips.cdb", "w", encoding="utf-8") as f:
        for ip in plcs_ips:
            f.write(f"{ip}:ok\n")

    # -------- funciones_modbus_ok.cdb --------
    with open(sal / "funciones_modbus_ok.cdb", "w", encoding="utf-8") as f:
        for sip, dip, pro, dpt in sorted(comunicaciones):
            if dpt == 502:
                f.write(f"{sip}->{dip}:3:ok\n")   # Read Holding Registers
                f.write(f"{sip}->{dip}:4:ok\n")   # Read Input Registers
                f.write(f"{sip}->{dip}:1:ok\n")   # Read Coils
                f.write(f"{sip}->{dip}:2:ok\n")   # Read Discrete Inputs

    # -------- umbrales.json --------
    def pct(xs, p):
        if not xs:
            return 0
        if len(xs) < 2:
            return int(xs[0])
        return int(statistics.quantiles(xs, n=100, method="inclusive")[p-1])

    umbrales = {}
    for tup, bts in bytes_por_tupla.items():
        pks = pkts_por_tupla[tup]
        k = f"{tup[0]}->{tup[1]}:{tup[2]}"
        umbrales[k] = {
            "bytes_p50":   pct(bts, 50),
            "bytes_p90":   pct(bts, 90),
            "bytes_p99":   pct(bts, 99),
            "packets_p50": pct(pks, 50),
            "packets_p90": pct(pks, 90),
            "packets_p99": pct(pks, 99),
            "n_flujos":    len(bts),
        }
    with open(sal / "umbrales.json", "w", encoding="utf-8") as f:
        json.dump(umbrales, f, indent=2, sort_keys=True)

    # -------- suricata_vars.yaml --------
    escribir_suricata_vars(sal / "suricata_vars.yaml", inventario, c2_list)

    print(f"[kb] Flujos leidos: {cnt}")
    print(f"[kb] Comunicaciones unicas: {len(comunicaciones)}")
    print(f"[kb] Servicios catalogados: {len(servicios)}")
    print(f"[kb] C2_MAILBOX manual: {c2_list or '(vacio)'}")
    print(f"[kb] Salida en: {sal}/")


if __name__ == "__main__":
    main()
