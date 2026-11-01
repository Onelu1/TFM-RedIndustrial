#!/usr/bin/env python3
"""aprender_macs.py - Extrae pares (ip, mac) de los PCAPs de baseline y
produce `mac_ok.cdb` para que Wazuh (regla 100310) alerte cuando aparece un
par nuevo en runtime (spoofing MAC, host no inventariado).

Uso:
  python3 aprender_macs.py --baseline '/datos/pcaps/baseline/*.pcap' \
                           --salida   /datos/salida/mac_ok.cdb

El script se disena para correr DENTRO del contenedor `tfm_monitor` (que trae
python3-scapy). Desde el host se invoca con:

  docker run --rm \
      -v "$PCAPS":/datos/pcaps:ro \
      -v "$KB":/datos/salida \
      tfm_monitor python3 /datos/salida/aprender_macs.py \
          --baseline '/datos/pcaps/baseline/*.pcap' \
          --salida   /datos/salida/mac_ok.cdb

Formato de la lista CDB (una linea por par unico):

    <ip>|<mac-con-guiones>:ok

donde `<mac-con-guiones>` siempre en minuscula con separador '-' (p.ej.
aa-bb-cc-dd-ee-ff) para evitar que el ':' de la MAC rompa la particion
clave/valor que Wazuh hace al primer ':'. Pares con MAC broadcast
(ff:ff:...) o nula (00:00:...) se descartan: no son una asignacion
real IP->MAC, son destino de ARP/multicast.
"""
from __future__ import annotations

import argparse
import glob
import sys

try:
    from scapy.all import PcapReader, Ether, IP, ARP, Dot1Q
    try:
        from scapy.layers.l2 import CookedLinuxV2, CookedLinux
    except Exception:  # scapy antiguo
        CookedLinuxV2 = None
        CookedLinux = None
except ImportError as e:
    print(f"[macs] ERROR: scapy no disponible: {e}", file=sys.stderr)
    sys.exit(2)


_IGNORED_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


def _norm_mac(m: str | bytes | None) -> str | None:
    """Normaliza una MAC a 'aa:bb:cc:dd:ee:ff' minuscula. None si invalida."""
    if m is None:
        return None
    if isinstance(m, (bytes, bytearray)):
        if len(m) < 6:
            return None
        m = ":".join(f"{b:02x}" for b in m[:6])
    m = m.lower().strip()
    if m in _IGNORED_MACS:
        return None
    # scapy a veces entrega MACs con guiones o espacios
    m = m.replace("-", ":")
    partes = m.split(":")
    if len(partes) != 6 or any(len(p) != 2 for p in partes):
        return None
    return m


def extraer_pares(pcap_path: str) -> set[tuple[str, str]]:
    """Devuelve el conjunto de pares (ip, mac) unicos vistos en el pcap."""
    pares: set[tuple[str, str]] = set()
    try:
        with PcapReader(pcap_path) as rdr:
            for pkt in rdr:
                # Prioridad: Ether (pcap nativo de router_gw)
                mac_src = mac_dst = None
                if Ether in pkt:
                    mac_src = _norm_mac(pkt[Ether].src)
                    mac_dst = _norm_mac(pkt[Ether].dst)
                elif CookedLinuxV2 is not None and CookedLinuxV2 in pkt:
                    mac_src = _norm_mac(pkt[CookedLinuxV2].src)
                elif CookedLinux is not None and CookedLinux in pkt:
                    mac_src = _norm_mac(pkt[CookedLinux].src)

                # Caso IP: toma src/dst IP del payload IP
                if IP in pkt:
                    if mac_src:
                        pares.add((pkt[IP].src, mac_src))
                    if mac_dst:
                        pares.add((pkt[IP].dst, mac_dst))
                # Caso ARP: trae IP+MAC explicitas en el payload
                elif ARP in pkt:
                    arp = pkt[ARP]
                    hs = _norm_mac(arp.hwsrc)
                    hd = _norm_mac(arp.hwdst)
                    if hs:
                        pares.add((arp.psrc, hs))
                    if hd:
                        pares.add((arp.pdst, hd))
    except Exception as e:
        print(f"[macs] AVISO: {pcap_path}: {e}", file=sys.stderr)
    return pares


def main() -> int:
    ap = argparse.ArgumentParser(description="Extrae pares (ip, mac) de PCAPs.")
    ap.add_argument("--baseline", required=True,
                    help="Glob de PCAPs de baseline (p.ej. '/datos/pcaps/baseline/*.pcap')")
    ap.add_argument("--salida", required=True,
                    help="Fichero de salida (lista CDB para Wazuh)")
    args = ap.parse_args()

    rutas = sorted(glob.glob(args.baseline))
    if not rutas:
        print(f"[macs] ERROR: ningun PCAP matchea '{args.baseline}'", file=sys.stderr)
        return 1

    pares_global: set[tuple[str, str]] = set()
    for r in rutas:
        pares = extraer_pares(r)
        print(f"[macs] {r}: {len(pares)} pares (ip,mac)")
        pares_global.update(pares)

    with open(args.salida, "w", encoding="utf-8", newline="\n") as f:
        for ip, mac in sorted(pares_global):
            # ':' en la MAC rompe el split clave/valor de Wazuh (primer ':').
            # Normalizamos a '-' en el fichero y en el campo ip_mac que
            # emite pcap2macs.py; asi la clave CDB queda unambigua.
            mac_safe = mac.replace(":", "-")
            f.write(f"{ip}|{mac_safe}:ok\n")

    print(f"[macs] Total unico baseline: {len(pares_global)} pares")
    print(f"[macs] Salida: {args.salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
