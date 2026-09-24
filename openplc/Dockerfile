FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Instalar sqlite3 y dependencias requeridas por OpenPLC v3
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

# Copia el programa de sensores a la carpeta de programas de OpenPLC
COPY programa_sensores.st /work/OpenPLC_v3/webserver/st_files/programa_sensores.st

# Compila, actualiza BD, activa Auto-Start y define active_program
WORKDIR /work/OpenPLC_v3/webserver/scripts
RUN ./compile_program.sh programa_sensores.st && \
    sqlite3 /work/OpenPLC_v3/webserver/openplc.db "INSERT INTO Programs (Name, Description, File, Date_upload) VALUES ('SimuladorPlanta', 'Simulador OT', 'programa_sensores.st', strftime('%s', 'now'));" && \
    sqlite3 /work/OpenPLC_v3/webserver/openplc.db "UPDATE Settings SET Value = (SELECT Prog_ID FROM Programs WHERE File='programa_sensores.st') WHERE Key = 'Loaded_Program';" && \
    sqlite3 /work/OpenPLC_v3/webserver/openplc.db "UPDATE Settings SET Value = 'true' WHERE Key = 'Start_run_mode';" && \
    echo "programa_sensores.st" > /work/OpenPLC_v3/webserver/active_program

WORKDIR /work/OpenPLC_v3

EXPOSE 8080 502

CMD ["./start_openplc.sh"]