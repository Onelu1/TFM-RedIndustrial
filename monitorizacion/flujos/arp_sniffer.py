#!/usr/bin/env python3
"""arp_sniffer.py - Sidecar LIVE: escucha ARP en todas las interfaces del
contenedor router_gw (que es donde cuelga como namespace) y emite una linea
NDJSON por cada par (ip, mac) nuevo. Lo consume Wazuh via la regla 100310
(dispara si el par no está en mac_ok.cdb).

Hermano runtime de pcap2macs.py (que es offline sobre pcaps). El formato de
salida es IDÉNTICO para que el mismo decoder/regla sirvan sin cambios.

Uso (dentro del sidecar `arp_sniffer`):

  python3 -u arp_sniffer.py \
      --salida /out/all_arp_live.ndjson \
      --src arp_live
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

try:
    from scapy.all import sniff, ARP
except ImportError as e:
    print(f"[arp_sniffer] ERROR: scapy no disponible: {e}", file=sys.stderr)
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


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def main() -> int:
    ap = argparse.ArgumentParser(description="Emite NDJSON LIVE de pares (ip,mac) vistos en ARP.")
    ap.add_argument("--salida", required=True,
                    help="Fichero NDJSON append-only.")
    ap.add_argument("--src", default="arp_live",
                    help="Etiqueta tfm_src para trazabilidad.")
    args = ap.parse_args()

    print(f"[arp_sniffer] iniciando. salida={args.salida} src={args.src}", flush=True)

    # Dedupe simple en memoria. Si el proceso cae y vuelve, se reemiten pares,
    # pero Wazuh dedupe por timestamp+contenido en indexer (y a efectos de la
    # regla 100310 reemitir no causa daño: es informacion, no estado).
    vistos: set[tuple[str, str]] = set()
    fout = open(args.salida, "a", encoding="utf-8", newline="\n")

    def _callback(pkt):
        # Filtro manual (evita dependencia de libpcap/BPF en Alpine).
        if ARP not in pkt:
            return
        arp = pkt[ARP]
        pares = []
        hs = _norm_mac(arp.hwsrc)
        hd = _norm_mac(arp.hwdst)
        if hs:
            pares.append((arp.psrc, hs))
        if hd:
            pares.append((arp.pdst, hd))

        for ip, mac in pares:
            if (ip, mac) in vistos:
                continue
            vistos.add((ip, mac))
            mac_safe = mac.replace(":", "-")
            linea = json.dumps({
                "timestamp": _now_iso(),
                "tfm_src":   args.src,
                "ip":        ip,
                "mac":       mac,
                "ip_mac":    f"{ip}|{mac_safe}",
            }, ensure_ascii=False)
            fout.write(linea + "\n")
            fout.flush()
            print(f"[arp_sniffer] nuevo par {ip} -> {mac}", flush=True)

    try:
        # iface=None → sniffea en TODAS las interfaces (router_gw ve 6 bridges).
        sniff(iface=None, store=0, prn=_callback)
    except KeyboardInterrupt:
        pass
    finally:
        fout.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
