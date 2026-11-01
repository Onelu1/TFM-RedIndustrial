# Imagen 'monitor' para generación de flujos IPFIX desde PCAP.
#
# Stack: softflowd (exportador IPFIX, RFC 7011 / NetFlow v10) + nfdump
# (colector + exportador a JSON/CSV). Ambos en los repos oficiales de Debian,
# 100% libres y bien documentados. Alternativa al stack YAF/super_mediator/SiLK
# cuando éste no está empaquetado en la distro de despliegue (equivalente
# funcional para flujos IPFIX; menos semántica OT, pero esa la aporta Suricata
# en nuestra cadena).
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        softflowd nfdump \
        tcpdump jq python3 python3-scapy \
        tshark tcpreplay \
    && rm -rf /var/lib/apt/lists/*

# Helper: re-encapsula pcaps capturados con tcpdump -i any (LINUX_SLL / SLL2)
# a Ethernet, ya que softflowd no entiende SLL2.
COPY sll2ether.py /usr/local/bin/sll2ether
RUN chmod +x /usr/local/bin/sll2ether

WORKDIR /datos
VOLUME ["/datos/pcaps", "/datos/salida"]
CMD ["/bin/bash"]
