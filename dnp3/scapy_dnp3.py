from scapy.all import sniff, TCP

def dnp3_packet_callback(pkt):
    if pkt.haslayer(TCP) and (pkt[TCP].dport == 20000 or pkt[TCP].sport == 20000):
        raw_payload = bytes(pkt[TCP].payload)
        if len(raw_payload) > 0 and raw_payload[0:2] == b'\x05\x64': # Cabecera de inicio DNP3 (0x0564)
            print(f"[DNP3 Frame Detected] Longitud Payload: {len(raw_payload)} bytes | Hex: {raw_payload.hex()}")

print("[*] Escuchando tramas DNP3 en el puerto TCP 20000...")
sniff(filter="tcp port 20000", prn=dnp3_packet_callback, store=0)