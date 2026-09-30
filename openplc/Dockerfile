FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    sudo \
    curl \
    sqlite3 \
    build-essential \
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