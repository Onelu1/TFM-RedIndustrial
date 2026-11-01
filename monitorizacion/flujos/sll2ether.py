#!/usr/bin/env python3
"""sll2ether - Reencapsula un pcap LINUX_SLL/SLL2 a Ethernet.

Soltar el header SLL/SLL2 y envolver cada paquete en un Ether() sintetico
para que softflowd lo pueda procesar. Preserva timestamps.
"""
import sys
from scapy.all import rdpcap, wrpcap, Ether, IP, IPv6, PcapReader, PcapWriter

if len(sys.argv) != 3:
    print("uso: sll2ether <in.pcap> <out.pcap>", file=sys.stderr)
    sys.exit(1)

inp, out = sys.argv[1], sys.argv[2]
n_total = 0
n_ok = 0
with PcapReader(inp) as rd, PcapWriter(out, linktype=1, sync=True) as wr:
    for pkt in rd:
        n_total += 1
        # Buscar la primera capa IP/IPv6 y re-envolverla en Ether.
        if IP in pkt:
            inner = pkt[IP]
            new = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / inner
        elif IPv6 in pkt:
            inner = pkt[IPv6]
            new = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02", type=0x86dd) / inner
        else:
            continue
        new.time = pkt.time
        wr.write(new)
        n_ok += 1

print(f"[sll2ether] {n_ok}/{n_total} paquetes reencapsulados -> {out}")
