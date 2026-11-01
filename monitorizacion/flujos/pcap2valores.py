#!/usr/bin/env python3
"""pcap2valores.py - Por cada operacion Modbus del PCAP, emite una linea
JSON con el valor observado y una marca `fuera_rango` segun la banda
aprendida en `valores_ok.json`.

Wazuh ingiere este NDJSON (ver decoder `tfm-modbus-value`) y la regla
100410 dispara cuando `fuera_rango=true`.

Uso dentro del contenedor `tfm_monitor`:

  python3 pcap2valores.py \
      --pcap    /datos/pcaps/ataques/modbus_outlier/control.pcap \
      --salida  /datos/valores/ataques/modbus_outlier/control.ndjson \
      --bandas  /datos/salida/valores_ok.json \
      --src     ataques/modbus_outlier/control
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

try:
    from scapy.all import PcapReader, IP, TCP, Raw
except ImportError as e:
    print(f"[valores] ERROR: scapy no disponible: {e}", file=sys.stderr)
    sys.exit(2)


MODBUS_PORT = 502


def _mbap(buf: bytes):
    if len(buf) < 8:
        return None
    length = int.from_bytes(buf[4:6], "big")
    return {"length": length, "uid": buf[6], "pdu": buf[7:7 + length - 1]}


def _parse_pdu(fc: int, data: bytes, es_respuesta: bool):
    pairs = []
    try:
        if fc in (1, 2) and es_respuesta:
            nb = data[0]
            for i in range(nb):
                byte = data[1 + i]
                for bit in range(8):
                    pairs.append((i * 8 + bit, (byte >> bit) & 1))
        elif fc in (3, 4) and es_respuesta:
            nb = data[0]
            for i in range(nb // 2):
                off = 1 + i * 2
                pairs.append((i, int.from_bytes(data[off:off + 2], "big")))
        elif fc == 5:
            addr = int.from_bytes(data[0:2], "big")
            raw = int.from_bytes(data[2:4], "big")
            pairs.append((addr, 1 if raw == 0xFF00 else 0))
        elif fc == 6:
            addr = int.from_bytes(data[0:2], "big")
            val = int.from_bytes(data[2:4], "big")
            pairs.append((addr, val))
        elif fc == 15:
            addr = int.from_bytes(data[0:2], "big")
            qty = int.from_bytes(data[2:4], "big")
            for i in range(qty):
                b = data[5 + (i // 8)]
                pairs.append((addr + i, (b >> (i % 8)) & 1))
        elif fc == 16:
            addr = int.from_bytes(data[0:2], "big")
            qty = int.from_bytes(data[2:4], "big")
            for i in range(qty):
                off = 5 + i * 2
                pairs.append((addr + i, int.from_bytes(data[off:off + 2], "big")))
    except Exception:
        pass
    return pairs


def _ts_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


# Clasificacion de FCs
FC_WRITE = {5, 6, 15, 16}


def main() -> int:
    ap = argparse.ArgumentParser(description="Emite NDJSON de valores Modbus con fuera_rango.")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--salida", required=True)
    ap.add_argument("--bandas", required=True,
                    help="valores_ok.json (banda aprendida)")
    ap.add_argument("--src", default="",
                    help="Etiqueta tfm_src.")
    ap.add_argument("--solo-writes", action="store_true",
                    help="Si se pasa, emite solo escrituras (ignora reads).")
    args = ap.parse_args()

    try:
        with open(args.bandas, encoding="utf-8") as f:
            bandas = json.load(f)
    except FileNotFoundError:
        print(f"[valores] AVISO: {args.bandas} no existe; bandas vacias", file=sys.stderr)
        bandas = {}

    emitidos = 0
    fuera = 0
    with open(args.salida, "w", encoding="utf-8", newline="\n") as fout:
        try:
            with PcapReader(args.pcap) as rdr:
                for pkt in rdr:
                    if IP not in pkt or TCP not in pkt or Raw not in pkt:
                        continue
                    if pkt[TCP].sport != MODBUS_PORT and pkt[TCP].dport != MODBUS_PORT:
                        continue
                    es_respuesta = (pkt[TCP].sport == MODBUS_PORT)
                    plc_ip = pkt[IP].src if es_respuesta else pkt[IP].dst
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    ts = float(pkt.time)

                    raw = bytes(pkt[Raw].load)
                    offset = 0
                    while offset + 8 <= len(raw):
                        header = _mbap(raw[offset:])
                        if not header:
                            break
                        pdu = header["pdu"]
                        if len(pdu) < 1:
                            offset += 6 + header["length"]
                            continue
                        fc = pdu[0]
                        if args.solo_writes and fc not in FC_WRITE:
                            offset += 6 + header["length"]
                            continue
                        es_write = fc in FC_WRITE
                        for addr, val in _parse_pdu(fc, pdu[1:], es_respuesta):
                            clave = f"c{addr}" if fc in (1, 2, 5, 15) else f"r{addr}"
                            banda = bandas.get(plc_ip, {}).get(clave)
                            if banda:
                                fuera_rango = (val < banda["min"] or val > banda["max"])
                                banda_str = f"{banda['min']}-{banda['max']}"
                            else:
                                # Registro no visto en baseline: lo marcamos
                                # fuera_rango=True pero con flag "sin_banda" para
                                # poder filtrar FP de registros nuevos legitimos.
                                fuera_rango = True
                                banda_str = "sin_banda"
                            if fuera_rango:
                                fuera += 1
                            fout.write(json.dumps({
                                "timestamp":   _ts_to_iso(ts),
                                "tfm_src":     args.src,
                                "src_ip":      src_ip,
                                "dst_ip":      dst_ip,
                                "plc_ip":      plc_ip,
                                "protocol":    "modbus",
                                "fc":          fc,
                                "addr":        f"{clave}",
                                "value":       val,
                                "banda":       banda_str,
                                "es_write":    es_write,
                                "fuera_rango": fuera_rango,
                            }, ensure_ascii=False) + "\n")
                            emitidos += 1
                        offset += 6 + header["length"]
        except Exception as e:
            print(f"[valores] AVISO: {args.pcap}: {e}", file=sys.stderr)

    print(f"[valores] {args.pcap}: {emitidos} ops ({fuera} fuera de banda) -> {args.salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
