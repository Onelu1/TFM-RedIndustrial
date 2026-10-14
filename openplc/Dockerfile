FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Fijamos la versión de OpenPLC_v3 por SHA (el repo upstream fue archivado el
# 2026-04-04 y no publica tags, así que un SHA concreto es la única forma de
# tener una imagen reproducible). Este commit es el último de master.
ARG OPENPLC_SHA=b5d41356dab4aeadca0dd7ca64ba542f870b595d

RUN apt-get update && apt-get install -y \
    git \
    sudo \
    curl \
    sqlite3 \
    build-essential \
    patch \
    python3 \
    python3-pip \
    python3-setuptools \
    pkg-config \
    iproute2 \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
RUN git clone https://github.com/thiagoralves/OpenPLC_v3.git

WORKDIR /work/OpenPLC_v3
RUN git -c advice.detachedHead=false checkout "${OPENPLC_SHA}"

# Parche TFM: valida el Unit Identifier (byte 6 del MBAP) contra
# /etc/openplc/acl.conf y responde con excepción Modbus 0x0B si no coincide.
# Se aplica antes de install.sh porque éste es quien compila el core en C++.
COPY uid_acl.patch /tmp/uid_acl.patch
RUN patch -p1 < /tmp/uid_acl.patch && rm /tmp/uid_acl.patch

RUN ./install.sh linux

# Copiamos ambos programas a la carpeta de OpenPLC
COPY programa_sensores.st /work/OpenPLC_v3/webserver/st_files/programa_sensores.st
COPY planta.st /work/OpenPLC_v3/webserver/st_files/planta.st

# Copiamos el script de arranque personalizado y le damos permisos
COPY start_custom.sh /work/OpenPLC_v3/start_custom.sh
RUN chmod +x /work/OpenPLC_v3/start_custom.sh

EXPOSE 8080 502 20000

# Usamos el script personalizado como punto de entrada
CMD ["./start_custom.sh"]