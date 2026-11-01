#!/usr/bin/env python3
"""pcap2macs.py - Emisor runtime: por cada PCAP de escenario emite un NDJSON
con una linea por par (ip, mac) unico. Lo consume Wazuh via decoder
`tfm-mac-binding` + regla 100310 (dispara si el par no esta en mac_ok.cdb).

Uso (dentro de contenedor tfm_monitor):

  python3 pcap2macs.py --pcap /datos/pcaps/ataques/mac_spoof/control.pcap \
                        --salida /datos/macs/ataques/mac_spoof/control.ndjson \
                        --src ataques/mac_spoof/control

El campo `tfm_src` identifica el pcap origen para trazabilidad. Formato de
cada linea NDJSON:

    {"timestamp": "<iso UTC>", "tfm_src": "<rel>", "ip": "<x>", "mac": "<yy>"}

El timestamp es el instante primera-vista del par dentro de ese pcap.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

try:
    from scapy.all import PcapReader, Ether, IP, ARP
    try:
        from scapy.layers.l2 import CookedLinuxV2, CookedLinux
    except Exception:
        CookedLinuxV2 = None
        CookedLinux = None
except ImportError as e:
    print(f"[macs] ERROR: scapy no disponible: {e}", file=sys.stderr)
    sys.exit(2)


_IGNORED_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


def _norm_mac(m):
    if m is None:
        return None
    if isinstance(m, (bytes, bytearray)):
        if len(m) < 6:
            return None
        m = ":".join(f"{b:02x}" for b in m[:6])
    m = m.lower().strip().replace("-", ":")
    if m in _IGNORED_MACS:
        return None
    partes = m.split(":")
    if len(partes) != 6 or any(len(p) != 2 for p in partes):
        return None
    return m


def _ts_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def main() -> int:
    ap = argparse.ArgumentParser(description="Emite NDJSON de pares (ip,mac) de un PCAP.")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--salida", required=True)
    ap.add_argument("--src", default="",
                    help="Etiqueta tfm_src (ruta relativa del pcap para Wazuh).")
    args = ap.parse_args()

    # Para cada par (ip,mac), guardamos SOLO el timestamp primera-vista.
    primera: dict[tuple[str, str], float] = {}
    try:
        with PcapReader(args.pcap) as rdr:
            for pkt in rdr:
                ts = float(pkt.time)
                mac_src = mac_dst = None
                if Ether in pkt:
                    mac_src = _norm_mac(pkt[Ether].src)
                    mac_dst = _norm_mac(pkt[Ether].dst)
                elif CookedLinuxV2 is not None and CookedLinuxV2 in pkt:
                    mac_src = _norm_mac(pkt[CookedLinuxV2].src)
                elif CookedLinux is not None and CookedLinux in pkt:
                    mac_src = _norm_mac(pkt[CookedLinux].src)

                pares = []
                if IP in pkt:
                    if mac_src:
                        pares.append((pkt[IP].src, mac_src))
                    if mac_dst:
                        pares.append((pkt[IP].dst, mac_dst))
                elif ARP in pkt:
                    arp = pkt[ARP]
                    hs = _norm_mac(arp.hwsrc)
                    hd = _norm_mac(arp.hwdst)
                    if hs:
                        pares.append((arp.psrc, hs))
                    if hd:
                        pares.append((arp.pdst, hd))

                for par in pares:
                    if par not in primera:
                        primera[par] = ts
    except Exception as e:
        print(f"[macs] AVISO: {args.pcap}: {e}", file=sys.stderr)

    with open(args.salida, "w", encoding="utf-8", newline="\n") as f:
        for (ip, mac), ts in sorted(primera.items()):
            # ip_mac pre-compuesto. Las MACs van con '-' en lugar de ':' para
            # que el primer ':' de la CDB (clave/valor) no caiga dentro de la
            # MAC y rompa el matching (ver aprender_macs.py).
            mac_safe = mac.replace(":", "-")
            f.write(json.dumps({
                "timestamp": _ts_to_iso(ts),
                "tfm_src":   args.src,
                "ip":        ip,
                "mac":       mac,
                "ip_mac":    f"{ip}|{mac_safe}",
            }, ensure_ascii=False) + "\n")

    print(f"[macs] {args.pcap}: {len(primera)} pares -> {args.salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
