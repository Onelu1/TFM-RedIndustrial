#!/usr/bin/env python3
"""aprender_valores.py - Aprende el rango habitual de valores escritos y
leidos en registros Modbus a partir de los PCAPs de baseline. Produce
`valores_ok.json` con el mapa:

    {
      "<dst_ip>": {
        "<addr>": {"min": <int>, "max": <int>, "n": <int>}
      }
    }

Se usa en runtime desde pcap2valores.py: cada operacion Modbus se compara
con esta banda; si el valor cae fuera -> `fuera_rango=true` -> Wazuh 100410.

Codigos de funcion Modbus soportados:
  FC 1,2  Read Coils / Read Discrete Inputs: parsea respuesta como bits.
  FC 3,4  Read Holding / Read Input Registers: respuesta = valores de 16b.
  FC 5    Write Single Coil: 0xFF00 (ON) / 0x0000 (OFF).
  FC 6    Write Single Register: valor de 16b en la request.
  FC 15   Write Multiple Coils: bits empaquetados en bytes.
  FC 16   Write Multiple Registers: lista de valores de 16b.

Diseno: tanto los valores observados en reads como en writes alimentan
la banda. Para coils el rango queda {0, 1}; para registros es el rango
dinamico real que la SCADA ha visto durante el entrenamiento.
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import defaultdict

try:
    from scapy.all import PcapReader, IP, TCP, Raw
except ImportError as e:
    print(f"[valores] ERROR: scapy no disponible: {e}", file=sys.stderr)
    sys.exit(2)


# Para distinguir request de response, Modbus guarda la direccion
# del par (ip, port). El dispositivo esclavo (PLC) escucha en el puerto
# 502; cualquier respuesta sale de ese puerto. Las requests las origina
# el maestro (SCADA) hacia 502.
MODBUS_PORT = 502


def _mbap(buf: bytes):
    """Extrae el header MBAP de los primeros 7 bytes:
      txn_id (2), proto_id (2), length (2), unit_id (1)."""
    if len(buf) < 8:
        return None
    length = int.from_bytes(buf[4:6], "big")
    return {"txn": int.from_bytes(buf[0:2], "big"),
            "length": length,
            "uid": buf[6],
            "pdu": buf[7:7 + length - 1]}


def _parse_pdu(fc: int, data: bytes, es_respuesta: bool):
    """Devuelve lista de (addr_relativo, valor) extraidos del PDU.
    Si no se puede parsear, devuelve lista vacia (sin fallar)."""
    pairs = []
    try:
        if fc in (1, 2):
            # Read Coils/Discrete Inputs
            if es_respuesta:
                # byte_count (1) + bits
                nb = data[0]
                for i in range(nb):
                    byte = data[1 + i]
                    for bit in range(8):
                        pairs.append((i * 8 + bit, (byte >> bit) & 1))
            # request: addr (2) + qty (2) -- no values
        elif fc in (3, 4):
            # Read Holding/Input Registers
            if es_respuesta:
                nb = data[0]
                for i in range(nb // 2):
                    off = 1 + i * 2
                    val = int.from_bytes(data[off:off + 2], "big")
                    pairs.append((i, val))  # addr relativo
            else:
                # request: addr (2) + qty (2); no valores
                pass
        elif fc == 5:
            # Write Single Coil: addr (2) + value (2) con 0xFF00/0x0000.
            addr = int.from_bytes(data[0:2], "big")
            raw = int.from_bytes(data[2:4], "big")
            pairs.append((addr, 1 if raw == 0xFF00 else 0))
        elif fc == 6:
            # Write Single Register: addr (2) + value (2).
            addr = int.from_bytes(data[0:2], "big")
            val = int.from_bytes(data[2:4], "big")
            pairs.append((addr, val))
        elif fc == 15:
            # Write Multiple Coils: addr (2) + qty (2) + byte_count (1) + bits
            addr = int.from_bytes(data[0:2], "big")
            qty = int.from_bytes(data[2:4], "big")
            for i in range(qty):
                b = data[5 + (i // 8)]
                pairs.append((addr + i, (b >> (i % 8)) & 1))
        elif fc == 16:
            # Write Multiple Registers: addr (2) + qty (2) + byte_count (1) + values
            addr = int.from_bytes(data[0:2], "big")
            qty = int.from_bytes(data[2:4], "big")
            for i in range(qty):
                off = 5 + i * 2
                val = int.from_bytes(data[off:off + 2], "big")
                pairs.append((addr + i, val))
    except Exception:
        pass
    return pairs


def iter_modbus_ops(pcap_path: str):
    """Itera sobre operaciones Modbus del pcap. Yields:
       (dst_ip_lado_plc, fc, addr_absoluta, valor)
    donde `dst_ip_lado_plc` es la IP del PLC (siempre el lado del puerto 502),
    tanto para request como para response, para que la banda se agrupe por
    el registro FISICO (en el PLC), no por el extremo que habla."""
    try:
        with PcapReader(pcap_path) as rdr:
            for pkt in rdr:
                if IP not in pkt or TCP not in pkt or Raw not in pkt:
                    continue
                if pkt[TCP].sport != MODBUS_PORT and pkt[TCP].dport != MODBUS_PORT:
                    continue
                es_respuesta = (pkt[TCP].sport == MODBUS_PORT)
                plc_ip = pkt[IP].src if es_respuesta else pkt[IP].dst

                raw = bytes(pkt[Raw].load)
                # Un segmento TCP puede llevar varios PDUs Modbus concatenados.
                offset = 0
                while offset + 8 <= len(raw):
                    header = _mbap(raw[offset:])
                    if not header:
                        break
                    tam_pdu = header["length"] - 1  # length incluye uid
                    siguiente = offset + 6 + header["length"]
                    pdu = header["pdu"]
                    if len(pdu) < 1:
                        offset = siguiente
                        continue
                    fc = pdu[0]
                    data = pdu[1:]
                    for addr_rel, val in _parse_pdu(fc, data, es_respuesta):
                        yield (plc_ip, fc, addr_rel, val)
                    offset = siguiente
    except Exception as e:
        print(f"[valores] AVISO: {pcap_path}: {e}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description="Aprende rangos de valores Modbus.")
    ap.add_argument("--baseline", required=True,
                    help="Glob de PCAPs de baseline")
    ap.add_argument("--salida", required=True,
                    help="Fichero valores_ok.json")
    args = ap.parse_args()

    rutas = sorted(glob.glob(args.baseline))
    if not rutas:
        print(f"[valores] ERROR: ningun PCAP matchea '{args.baseline}'", file=sys.stderr)
        return 1

    # bandas[plc_ip][addr] = [n, min, max]
    bandas: dict[str, dict[int, list[int]]] = defaultdict(lambda: defaultdict(
        lambda: [0, None, None]
    ))
    for ruta in rutas:
        cnt = 0
        for plc_ip, fc, addr, val in iter_modbus_ops(ruta):
            # Normalizamos: para coils (fc 1,2,5,15) la direccion fisica se
            # mantiene; para registros (3,4,6,16) tambien. No mezclamos entre
            # coils y registros para evitar falsos matches, prefijamos
            # el espacio: "c0001" para coils, "r0001" para registros.
            if fc in (1, 2, 5, 15):
                clave = f"c{addr}"
            else:
                clave = f"r{addr}"
            b = bandas[plc_ip][clave]
            b[0] += 1
            if b[1] is None or val < b[1]:
                b[1] = val
            if b[2] is None or val > b[2]:
                b[2] = val
            cnt += 1
        print(f"[valores] {ruta}: {cnt} ops Modbus")

    out: dict[str, dict[str, dict[str, int]]] = {}
    for plc_ip, mapa in bandas.items():
        out[plc_ip] = {}
        for clave, (n, lo, hi) in mapa.items():
            out[plc_ip][clave] = {"min": int(lo), "max": int(hi), "n": n}

    with open(args.salida, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2, sort_keys=True)

    total = sum(len(v) for v in out.values())
    print(f"[valores] PLCs con registros aprendidos: {len(out)}")
    print(f"[valores] Direcciones (ip x addr) con banda: {total}")
    print(f"[valores] Salida: {args.salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
