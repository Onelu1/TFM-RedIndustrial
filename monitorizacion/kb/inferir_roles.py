#!/usr/bin/env python3
"""inferir_roles.py - Fase de aprendizaje dinamico de roles del lab OT.

Lee los NDJSON de flujos del baseline (producidos por pcap2flujos.sh en los
4 puntos de captura) y, aplicando heuristicas de comportamiento sobre el
trafico (puertos escuchados, puertos conectados, cardinalidad, periodicidad
del polling, tamano medio de los flujos), infiere el ROL de cada IP vista.

Produce:
  - inventario.json         (fuente unica de verdad del lab aprendido)
  - inventario_vs_hosts.md  (reporte comparativo contra ground_truth_hosts)

Diseno:
  - Las reglas de rol NO dependen de la subred Docker. La subred es solo
    una evidencia secundaria que sube/baja la confianza. Pensado para que
    si manana se anade un PLC extra o se mueve de VLAN, el aprendizaje
    siga funcionando como lo haria una herramienta real (Nozomi/Claroty).
  - La IP de kali_nodo se obtiene del compose/docker y se EXCLUYE antes
    de evaluar nada. Durante [E] kali ademas queda pausada.
  - Nunca aborta: si una IP esperada no aparece en los flujos (silente),
    se registra en silent_hosts con warning, pero el pipeline continua.

Uso:
  python inferir_roles.py \\
      --flujos  "monitorizacion/flujos/salida/baseline/*.json" \\
      --compose docker-compose.generated.yml \\
      --salida  monitorizacion/kb/ \\
      --duracion-segundos 1800
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import ipaddress
import json
import math
import os
import re
import statistics
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from ground_truth_hosts import HOSTS, SUBREDES, rol_normalizado, subred_de


def _normalizar_path(p: str) -> str:
    """Convierte paths estilo MSYS/Git-Bash (/c/Users/..) a Windows (C:/Users/..).

    Git Bash en Windows pasa paths tipo `/c/Users/...` a procesos Python nativos
    que no los entienden (glob no encuentra matches). Esta funcion normaliza
    la convencion a algo que python en Windows si consume.
    """
    if os.name == "nt" and p.startswith("/") and len(p) > 2 and p[2] == "/" and p[1].isalpha():
        return f"{p[1].upper()}:{p[2:]}"
    return p


# ---------------------------------------------------------------------------
# Constantes de dominio
# ---------------------------------------------------------------------------

PUERTO_MODBUS = 502
PUERTO_S7     = 102
PUERTO_DNP3   = 20000
PUERTO_MQTT   = 1883
PUERTO_SMB1   = 139
PUERTO_SMB2   = 445
PUERTO_SSH    = 22

PUERTOS_OT = {PUERTO_MODBUS, PUERTO_S7, PUERTO_DNP3, PUERTO_MQTT}

# Puertos "de servidor" para desambiguar cliente/servidor en flujos ambiguos.
PUERTOS_SERVIDOR_CONOCIDOS = {
    PUERTO_MODBUS, PUERTO_S7, PUERTO_DNP3, PUERTO_MQTT,
    PUERTO_SMB1, PUERTO_SMB2, PUERTO_SSH,
    80, 443, 1880, 8080, 8081, 8082, 8083, 8181, 8182, 8183, 2222,
}


# ---------------------------------------------------------------------------
# Features por IP
# ---------------------------------------------------------------------------


class Features:
    """Agregado de evidencias de red para una IP."""

    __slots__ = (
        "ip",
        "listens_peers",     # dict[puerto -> set[ip_cliente]]
        "connects_peers",    # dict[puerto -> set[ip_servidor]]
        "n_flujos_in",       # dict[puerto -> int]
        "n_flujos_out",      # dict[puerto -> int]
        "bytes_in_sum",      # dict[puerto -> int]  (para media)
        "flujos_in_count",   # dict[puerto -> int]  (denominador de la media)
        "intervalos",        # dict[(peer, dport) -> list[float] segundos entre t_first]
        "_ultimo_t",         # dict[(peer, dport) -> float] para calcular intervalos
    )

    def __init__(self, ip: str):
        self.ip = ip
        self.listens_peers  = defaultdict(set)
        self.connects_peers = defaultdict(set)
        self.n_flujos_in    = defaultdict(int)
        self.n_flujos_out   = defaultdict(int)
        self.bytes_in_sum   = defaultdict(int)
        self.flujos_in_count = defaultdict(int)
        self.intervalos     = defaultdict(list)
        self._ultimo_t      = {}

    def registrar_entrante(self, peer_src: str, puerto: int, bts: int, t: float):
        self.listens_peers[puerto].add(peer_src)
        self.n_flujos_in[puerto] += 1
        self.bytes_in_sum[puerto] += bts
        self.flujos_in_count[puerto] += 1
        clave = (peer_src, puerto)
        prev = self._ultimo_t.get(clave)
        if prev is not None:
            self.intervalos[clave].append(t - prev)
        self._ultimo_t[clave] = t

    def registrar_saliente(self, peer_dst: str, puerto: int, t: float):
        self.connects_peers[puerto].add(peer_dst)
        self.n_flujos_out[puerto] += 1
        clave = (peer_dst, puerto)
        prev = self._ultimo_t.get(clave)
        if prev is not None:
            self.intervalos[clave].append(t - prev)
        self._ultimo_t[clave] = t

    @property
    def total_flujos_in(self) -> int:
        return sum(self.n_flujos_in.values())

    @property
    def total_flujos_out(self) -> int:
        return sum(self.n_flujos_out.values())

    @property
    def peers_in(self) -> set:
        s = set()
        for peers in self.listens_peers.values():
            s |= peers
        return s

    @property
    def peers_out(self) -> set:
        s = set()
        for peers in self.connects_peers.values():
            s |= peers
        return s

    def bytes_in_mean(self, puerto: int) -> float:
        n = self.flujos_in_count.get(puerto, 0)
        return (self.bytes_in_sum[puerto] / n) if n else 0.0

    def stdev_periodicidad(self, puerto: int) -> float | None:
        """Desviacion tipica (segundos) de los intervalos entre peticiones a `puerto`
        agregadas sobre todos los peers. Devuelve None si no hay bastantes muestras.
        """
        vals = []
        for (peer, dport), ivs in self.intervalos.items():
            if dport == puerto and len(ivs) >= 2:
                vals.extend(ivs)
        if len(vals) < 2:
            return None
        try:
            return statistics.stdev(vals)
        except statistics.StatisticsError:
            return None

    def mediana_periodicidad(self, puerto: int) -> float | None:
        vals = []
        for (peer, dport), ivs in self.intervalos.items():
            if dport == puerto and ivs:
                vals.extend(ivs)
        if not vals:
            return None
        return statistics.median(vals)


# ---------------------------------------------------------------------------
# Carga de flujos
# ---------------------------------------------------------------------------


_RE_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def _parse_iso_epoch(s: str) -> float:
    """Parsea un timestamp ISO devuelto por nfdump a epoch (segundos float).
    nfdump JSON emite 't_first'/'t_last' tipo '2026-10-21T11:33:00.123'.
    """
    if not s or not _RE_ISO.match(s):
        return 0.0
    try:
        return dt.datetime.fromisoformat(s).timestamp()
    except ValueError:
        try:
            return dt.datetime.fromisoformat(s.split(".")[0]).timestamp()
        except ValueError:
            return 0.0


def cargar_flujos(glob_pat: str, solo_punto: str | None = None):
    """Generador que yielda dicts de flujo normalizados.

    Lee los NDJSON de los 4 puntos de captura. Si `solo_punto` esta puesto,
    filtra por sufijo del nombre de fichero (control|empresa|mqtt|dnp3).
    Normaliza nombres: src/dst/sport/dport/proto/first/last/pkts/bytes.
    """
    rutas = sorted(glob.glob(_normalizar_path(glob_pat)))
    for ruta in rutas:
        nombre = Path(ruta).stem
        # Filtro por punto de captura. Para `dnp3` acepta tambien `dnp3_1`,
        # `dnp3_2`, etc. (varios gateways capturados por `capturar.sh`).
        if solo_punto and f"_{solo_punto}" not in nombre:
            continue
        with open(ruta, encoding="utf-8") as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    r = json.loads(linea)
                except json.JSONDecodeError:
                    continue
                src = r.get("src4_addr") or r.get("src_addr")
                dst = r.get("dst4_addr") or r.get("dst_addr")
                if not src or not dst:
                    yield {"__ipv6": True}
                    continue
                yield {
                    "src": src,
                    "dst": dst,
                    "sport": int(r.get("src_port") or 0),
                    "dport": int(r.get("dst_port") or 0),
                    "proto": int(r.get("proto") or 0),
                    "first": _parse_iso_epoch(r.get("t_first") or r.get("first") or ""),
                    "last":  _parse_iso_epoch(r.get("t_last") or r.get("last") or ""),
                    "pkts":  int(r.get("in_packets") or 0),
                    "bytes": int(r.get("in_bytes") or 0),
                    "tcp_flags": r.get("tcp_flags", ""),
                    "__src_file": nombre,
                }


# ---------------------------------------------------------------------------
# Compose / Docker helpers
# ---------------------------------------------------------------------------


def ip_de_contenedor(nombre: str) -> list[str]:
    """Obtiene las IPs IPv4 de un contenedor Docker (todas sus redes).

    Devuelve [] si docker no esta disponible o el contenedor no existe.
    Pensado para localizar la IP de kali_nodo (cualquiera que sea su modo).
    """
    cmd = [
        "docker", "inspect", "--format",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
        nombre,
    ]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode != 0:
        return []
    return [ip for ip in out.stdout.split() if ip]


def ips_esperadas_del_lab() -> dict[str, str]:
    """IPs vistas via `docker ps` + inspect. Si docker no esta disponible,
    cae a `ground_truth_hosts.HOSTS` como fallback (solo para que silent_hosts
    tenga algo sensato que reportar).

    Devuelve dict ip -> nombre_contenedor.
    """
    resultado: dict[str, str] = {}
    try:
        ps = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        ps = None
    nombres: list[str] = []
    if ps and ps.returncode == 0:
        nombres = [n for n in ps.stdout.splitlines() if n]
    if not nombres:
        for ip, (nombre, _rol) in HOSTS.items():
            resultado[ip] = nombre
        return resultado
    for nombre in nombres:
        for ip in ip_de_contenedor(nombre):
            resultado.setdefault(ip, nombre)
    return resultado


# ---------------------------------------------------------------------------
# Inferencia de rol (reglas R1..R8)
# ---------------------------------------------------------------------------


def _es_puerto_servidor(dport: int, sport: int) -> bool:
    """Decide si en un flujo (src:sport -> dst:dport), dst es el servidor."""
    if dport in PUERTOS_SERVIDOR_CONOCIDOS:
        return True
    if sport in PUERTOS_SERVIDOR_CONOCIDOS:
        return False
    if dport > 0 and dport <= 1023 and sport > 1023:
        return True
    if sport > 0 and sport <= 1023 and dport > 1023:
        return False
    return False  # ambos efimeros/ambos privilegiados: ambiguo


def aplicar_reglas(ip: str, feat: Features, umbrales: dict) -> tuple[str, str, list[str]]:
    """Aplica R1..R8 (first-wins) sobre las features. Devuelve (rol, confianza, evidencias).

    Confianza:
      - alta: cumple la condicion necesaria + >=2 evidencias secundarias
      - media: cumple + 1 evidencia secundaria
      - baja: cumple solo la condicion necesaria
    """
    subnet = subred_de(ip)
    evid: list[str] = []
    sec: list[str] = []  # evidencias secundarias (suben la confianza)

    # ---- R1: broker_mqtt ----
    peers_1883_in = feat.listens_peers.get(PUERTO_MQTT, set())
    if (len(peers_1883_in) >= umbrales["broker_min_peers"]
            and feat.n_flujos_in.get(PUERTO_MQTT, 0) >= umbrales["broker_min_flujos"]):
        evid.append(f"escucha :1883/TCP, {len(peers_1883_in)} clientes distintos "
                    f"({feat.n_flujos_in[PUERTO_MQTT]} flujos entrantes)")
        if subnet == "red_control":
            sec.append("subnet=red_control (esperada para broker MQTT)")
        if len(peers_1883_in) >= 3:
            sec.append(f"{len(peers_1883_in)} publicadores >=3")
        return "broker_mqtt", _confianza(sec), evid + sec

    # ---- R2: scada ----
    puertos_ot_cliente = PUERTOS_OT & set(feat.connects_peers.keys())
    if (len(puertos_ot_cliente) >= umbrales["scada_min_puertos_ot"]
            and len(feat.peers_out) >= umbrales["scada_min_peers_out"]):
        evid.append(f"cliente de {sorted(puertos_ot_cliente)}, "
                    f"fan-out={len(feat.peers_out)} peers")
        std502 = feat.stdev_periodicidad(PUERTO_MODBUS)
        med502 = feat.mediana_periodicidad(PUERTO_MODBUS)
        if std502 is not None and std502 < umbrales["scada_stdev_polling"]:
            sec.append(f"polling :502 regular (mediana {med502:.1f}s, "
                       f"stdev {std502:.2f}s < {umbrales['scada_stdev_polling']}s)")
        if subnet == "red_control":
            sec.append("subnet=red_control (esperada para SCADA)")
        return "scada", _confianza(sec), evid + sec

    # ---- R3: gateway_dnp3 ----
    # Cliente DNP3 maestro (:20000). En el TFM los gateways son dual-homed:
    # la pata OT-C (.40.16-18) hace DNP3 maestro, la pata control (.20.16-18)
    # publica MQTT. R2 (SCADA) va antes para capturar la SCADA primero (en
    # este lab la SCADA NO habla DNP3, pero por si cambia).
    # La pata MQTT-only se marca mas abajo via dual_homed_as en un 2o pase.
    if PUERTO_DNP3 in feat.connects_peers:
        n_plcs = len(feat.connects_peers[PUERTO_DNP3])
        evid.append(f"cliente DNP3 (:20000) a {n_plcs} PLC(s)")
        if PUERTO_MQTT in feat.connects_peers:
            n_brokers = len(feat.connects_peers[PUERTO_MQTT])
            sec.append(f"ademas publicador MQTT (:1883) a {n_brokers} broker(s)")
        if subnet in {"red_control", "red_ot_zona_c"}:
            sec.append(f"subnet={subnet} (esperada para gateway DNP3)")
        if n_plcs == 1:
            sec.append("1 PLC DNP3 asignado (patron maestro dedicado)")
        return "gateway_dnp3", _confianza(sec), evid + sec

    # ---- R4: plc_modbus ----
    if (PUERTO_MODBUS in feat.listens_peers
            and feat.n_flujos_in.get(PUERTO_MODBUS, 0) >= umbrales["plc_min_flujos_in"]):
        media_bytes = feat.bytes_in_mean(PUERTO_MODBUS)
        evid.append(f"escucha :502/TCP, {feat.n_flujos_in[PUERTO_MODBUS]} flujos entrantes "
                    f"de {len(feat.listens_peers[PUERTO_MODBUS])} peer(s)")
        if media_bytes < umbrales["modbus_max_bytes_mean"]:
            sec.append(f"payload medio {media_bytes:.0f}B < {umbrales['modbus_max_bytes_mean']}B "
                       "(coherente con Modbus TCP)")
        if subnet == "red_ot_zona_a":
            sec.append("subnet=red_ot_zona_a (esperada para PLC Modbus)")
        return "plc_modbus", _confianza(sec), evid + sec

    # ---- R5: plc_s7 ----
    if (PUERTO_S7 in feat.listens_peers
            and feat.n_flujos_in.get(PUERTO_S7, 0) >= umbrales["plc_min_flujos_in"]):
        evid.append(f"escucha :102/TCP, {feat.n_flujos_in[PUERTO_S7]} flujos entrantes "
                    f"de {len(feat.listens_peers[PUERTO_S7])} peer(s)")
        if subnet == "red_ot_zona_b":
            sec.append("subnet=red_ot_zona_b (esperada para PLC S7)")
        return "plc_s7", _confianza(sec), evid + sec

    # ---- R6: plc_dnp3 ----
    if (PUERTO_DNP3 in feat.listens_peers
            and feat.n_flujos_in.get(PUERTO_DNP3, 0) >= umbrales["plc_min_flujos_in"]):
        evid.append(f"escucha :20000/TCP, {feat.n_flujos_in[PUERTO_DNP3]} flujos entrantes "
                    f"de {len(feat.listens_peers[PUERTO_DNP3])} peer(s)")
        if subnet == "red_ot_zona_c":
            sec.append("subnet=red_ot_zona_c (esperada para PLC DNP3)")
        return "plc_dnp3", _confianza(sec), evid + sec

    # ---- R7: it_fileserver ----
    puertos_smb = {PUERTO_SMB1, PUERTO_SMB2} & set(feat.listens_peers.keys())
    if puertos_smb:
        evid.append(f"escucha SMB ({sorted(puertos_smb)})")
        if subnet == "red_empresa":
            sec.append("subnet=red_empresa (esperada para fileserver)")
        if PUERTO_SSH in feat.listens_peers:
            sec.append(f"tambien escucha :22/TCP de {len(feat.listens_peers[PUERTO_SSH])} peer(s)")
        return "it_fileserver", _confianza(sec), evid + sec

    # ---- R8: fallback ----
    rol = f"desconocido_{subnet}" if subnet in SUBREDES else "desconocido"
    razon = "visto en flujos pero ninguna regla aplico"
    return rol, "baja", [razon]


def _confianza(sec: list[str]) -> str:
    if len(sec) >= 2:
        return "alta"
    if len(sec) == 1:
        return "media"
    return "baja"


# ---------------------------------------------------------------------------
# Pipeline principal
# ---------------------------------------------------------------------------


def construir_inventario(
    glob_flujos: str,
    excluir_ips: set[str],
    ips_esperadas: dict[str, str],
    duracion_s: int,
    umbrales: dict,
    solo_punto: str | None = None,
):
    """Lee flujos, agrega features, aplica reglas, devuelve dict completo
    para serializar como `inventario.json`.
    """
    vistos = set()
    dedup: set[tuple] = set()
    n_leidos = 0
    n_ipv6 = 0
    n_254 = 0
    n_excluidos = 0
    source_files: set[str] = set()
    features: dict[str, Features] = {}
    t_min = math.inf
    t_max = -math.inf

    def _get(ip: str) -> Features:
        f = features.get(ip)
        if f is None:
            f = Features(ip)
            features[ip] = f
        return f

    for flujo in cargar_flujos(glob_flujos, solo_punto=solo_punto):
        if flujo.get("__ipv6"):
            n_ipv6 += 1
            continue
        n_leidos += 1
        src, dst = flujo["src"], flujo["dst"]
        sport, dport = flujo["sport"], flujo["dport"]
        proto = flujo["proto"]
        t = flujo["first"] or 0.0
        if flujo.get("__src_file"):
            source_files.add(flujo["__src_file"])
        if t:
            t_min = min(t_min, t)
            t_max = max(t_max, t)

        if src.endswith(".254") or dst.endswith(".254"):
            n_254 += 1
            continue
        if src == "127.0.0.1" or dst == "127.0.0.1":
            # Artefacto de nfdump (ip4_router por defecto del colector), no host real.
            n_254 += 1
            continue
        if src in excluir_ips or dst in excluir_ips:
            n_excluidos += 1
            continue

        # Dedup entre los 4 capture points (mismo tcp 3way visto 2 veces)
        clave = (src, dst, sport, dport, proto, int(t) if t else 0)
        if clave in dedup:
            continue
        dedup.add(clave)
        vistos.add(src)
        vistos.add(dst)

        # Decidir cliente/servidor
        if _es_puerto_servidor(dport, sport):
            _get(dst).registrar_entrante(src, dport, flujo["bytes"], t)
            _get(src).registrar_saliente(dst, dport, t)
        elif _es_puerto_servidor(sport, dport):
            _get(src).registrar_entrante(dst, sport, flujo["bytes"], t)
            _get(dst).registrar_saliente(src, sport, t)
        # Flujos ambiguos no cuentan en listens/connects, pero las IPs quedan vistas.

    # Aplicar reglas por IP
    hosts_out: dict[str, dict] = {}
    role_index: dict[str, list[str]] = defaultdict(list)
    n_candidatas_scada = 0
    for ip in sorted(vistos, key=lambda s: tuple(int(x) for x in s.split(".") if x.isdigit()) or (0,)):
        feat = features.get(ip) or Features(ip)
        rol, conf, evid = aplicar_reglas(ip, feat, umbrales)
        if rol == "scada":
            n_candidatas_scada += 1
        hosts_out[ip] = {
            "rol": rol,
            "confianza": conf,
            "subnet": subred_de(ip),
            "docker_name_hint": ips_esperadas.get(ip),
            "dual_homed_as": None,  # se rellena abajo
            "evidencias": evid,
            "listens_on":  {str(p): len(peers) for p, peers in feat.listens_peers.items()},
            "connects_to": {str(p): len(peers) for p, peers in feat.connects_peers.items()},
            "n_flujos_in":  feat.total_flujos_in,
            "n_flujos_out": feat.total_flujos_out,
        }
        role_index[rol].append(ip)

    # Detectar dual-homed: dos IPs del inventario con el mismo docker_name_hint.
    por_nombre: dict[str, list[str]] = defaultdict(list)
    for ip, info in hosts_out.items():
        if info["docker_name_hint"]:
            por_nombre[info["docker_name_hint"]].append(ip)
    for nombre, ips in por_nombre.items():
        if len(ips) == 2:
            hosts_out[ips[0]]["dual_homed_as"] = ips[1]
            hosts_out[ips[1]]["dual_homed_as"] = ips[0]

    # 2o pase: propagar roles no triviales entre las dos patas de un dual-homed.
    # Caso real: gateway_dnp3 tiene pata OT-C que habla DNP3 (R3 la clasifica
    # como gateway_dnp3) y pata control que solo habla MQTT (R8 la deja como
    # desconocido_red_control). Heredar el rol del hermano cuando el nuestro
    # es `desconocido_*`.
    ROLES_PROPAGABLES = {"gateway_dnp3", "it_fileserver", "scada", "broker_mqtt"}
    for ip, info in hosts_out.items():
        gemela = info.get("dual_homed_as")
        if not gemela:
            continue
        otro = hosts_out.get(gemela, {}).get("rol", "desconocido")
        if info["rol"].startswith("desconocido") and otro in ROLES_PROPAGABLES:
            info["rol"] = otro
            info["confianza"] = "media"
            info["evidencias"].append(
                f"rol heredado de la pata dual-homed {gemela} ({otro})")

    # 3er pase: publicadores MQTT puros (no SCADA, no broker) en red_control.
    # Patron del TFM: los gateways DNP3 cuya pata OT-C no fue capturada solo
    # se ven en red_control publicando a :1883. Como por diseno los unicos
    # clientes del broker son SCADA (ya clasificada por R2) y gateways, cualquier
    # cliente MQTT que no sea SCADA es, con alta probabilidad, un gateway.
    brokers = {ip for ip, info in hosts_out.items() if info["rol"] == "broker_mqtt"}
    for ip, info in hosts_out.items():
        if not info["rol"].startswith("desconocido"):
            continue
        feat = features.get(ip)
        if feat is None:
            continue
        peers_mqtt = feat.connects_peers.get(PUERTO_MQTT, set())
        # Debe conectar a algun broker ya identificado
        if peers_mqtt and (peers_mqtt & brokers):
            info["rol"] = "gateway_dnp3"
            info["confianza"] = "media"
            info["evidencias"].append(
                f"cliente MQTT (:1883) a broker {sorted(peers_mqtt & brokers)[:1]} "
                "sin otro rol OT visible: patron tipico de gateway de telemetria")

    # Rehacer role_index tras los pases 2 y 3
    role_index = defaultdict(list)
    for ip, info in hosts_out.items():
        role_index[info["rol"]].append(ip)

    # Silent hosts: IPs esperadas por el compose que no aparecieron en flujos.
    silent_hosts = []
    for ip, nombre in sorted(ips_esperadas.items()):
        if ip in excluir_ips:
            continue
        if ip.endswith(".254"):
            continue
        if ip not in vistos:
            silent_hosts.append({
                "ip": ip,
                "esperado_nombre": nombre,
                "motivo": "sin flujos en la ventana de entrenamiento",
            })

    def _t_iso(ts: float) -> str | None:
        if not ts or ts == math.inf or ts == -math.inf:
            return None
        return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()

    inventario = {
        "version": 1,
        "metadata": {
            "generated_at": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
            "training_window": {
                "start": _t_iso(t_min),
                "end":   _t_iso(t_max),
                "duration_seconds": duracion_s,
            },
            "source_files": sorted(source_files),
            "n_capture_points": len(source_files),
            "n_flujos_leidos": n_leidos,
            "n_flujos_tras_dedup": len(dedup),
            "n_flujos_descartados_254": n_254,
            "n_flujos_ipv6_descartados": n_ipv6,
            "n_flujos_excluidos_kali": n_excluidos,
            "n_ips_vistas": len(vistos),
            "n_ips_silentes": len(silent_hosts),
            "n_candidatas_scada": n_candidatas_scada,
            "excluded_hosts": sorted(excluir_ips),
            "umbrales_usados": umbrales,
        },
        "hosts": hosts_out,
        "silent_hosts": silent_hosts,
        "role_index": {k: sorted(v) for k, v in role_index.items()},
    }
    return inventario


def reporte_markdown(inventario: dict) -> str:
    """Genera el markdown `inventario_vs_hosts.md` comparando con HOSTS."""
    lines = []
    lines.append("# Validacion inferencia vs ground truth\n")
    md = inventario["metadata"]
    tw = md["training_window"]
    lines.append(f"- Ventana: `{tw['start']}` -> `{tw['end']}` ({tw['duration_seconds']}s)")
    lines.append(f"- Flujos leidos: {md['n_flujos_leidos']}  "
                 f"| tras dedup: {md['n_flujos_tras_dedup']}  "
                 f"| descartados .254: {md['n_flujos_descartados_254']}  "
                 f"| excluidos kali: {md['n_flujos_excluidos_kali']}")
    lines.append(f"- IPs vistas: {md['n_ips_vistas']}  "
                 f"| silentes: {md['n_ips_silentes']}  "
                 f"| excluidas: {len(md['excluded_hosts'])}")
    lines.append("")

    # Comparar por rol normalizado
    inferido_por_ip = {ip: info["rol"] for ip, info in inventario["hosts"].items()}

    por_rol_esperado: dict[str, list[str]] = defaultdict(list)
    por_rol_acertado: dict[str, int] = defaultdict(int)
    por_rol_total: dict[str, int] = defaultdict(int)
    detalles = []

    for ip, (nombre, rol_truth) in sorted(HOSTS.items()):
        rol_truth_norm = rol_normalizado(rol_truth)
        if ip.endswith(".254"):
            continue
        if nombre == "kali_nodo":
            # Kali esta excluida del reconocimiento por diseno; no cuenta.
            detalles.append((ip, nombre, rol_truth_norm,
                             inferido_por_ip.get(ip, "excluida/silente"),
                             "N/A (excluida del training)"))
            continue
        por_rol_total[rol_truth_norm] += 1
        por_rol_esperado[rol_truth_norm].append(ip)
        inferido = inferido_por_ip.get(ip, "SILENTE")
        inferido_norm = rol_normalizado(inferido)
        acierto = (inferido_norm == rol_truth_norm)
        if acierto:
            por_rol_acertado[rol_truth_norm] += 1
        detalles.append((ip, nombre, rol_truth_norm, inferido,
                         "OK" if acierto else ("SILENTE" if inferido == "SILENTE" else "MISMATCH")))

    lines.append("## Precision por rol\n")
    lines.append("| Rol esperado | Aciertos | Total | % |")
    lines.append("|---|---|---|---|")
    total_ac = 0
    total_tot = 0
    for rol in sorted(por_rol_total):
        ac = por_rol_acertado[rol]
        tot = por_rol_total[rol]
        total_ac += ac
        total_tot += tot
        pct = (100.0 * ac / tot) if tot else 0.0
        lines.append(f"| `{rol}` | {ac} | {tot} | {pct:.1f}% |")
    pct_global = (100.0 * total_ac / total_tot) if total_tot else 0.0
    lines.append(f"| **TOTAL** | **{total_ac}** | **{total_tot}** | **{pct_global:.1f}%** |")

    lines.append("\n## Detalle por IP\n")
    lines.append("| IP | Hostname (truth) | Rol esperado | Rol inferido | Estado |")
    lines.append("|---|---|---|---|---|")
    for ip, nombre, truth, infer, estado in detalles:
        lines.append(f"| `{ip}` | {nombre} | `{truth}` | `{infer}` | {estado} |")

    if inventario["silent_hosts"]:
        lines.append("\n## Hosts silentes (esperados pero sin flujos)\n")
        for s in inventario["silent_hosts"]:
            lines.append(f"- `{s['ip']}` ({s['esperado_nombre']}): {s['motivo']}")

    if md["n_candidatas_scada"] > 1:
        lines.append("\n## AVISO\n")
        lines.append(f"- Se detectaron {md['n_candidatas_scada']} IPs candidatas a `scada` "
                     "(deberia ser 1). Posible trafico espurio durante training.")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--flujos", required=True,
                   help="Glob a NDJSON del baseline (ej 'flujos/salida/baseline/*.json').")
    p.add_argument("--salida", required=True,
                   help="Directorio donde escribir inventario.json e inventario_vs_hosts.md.")
    p.add_argument("--compose", default=None,
                   help="Ruta al docker-compose.generated.yml (informativo; se usa docker ps).")
    p.add_argument("--duracion-segundos", type=int, default=1800,
                   help="Duracion de la ventana de training (solo metadata).")
    p.add_argument("--solo-punto", default=None,
                   choices=["control", "empresa", "mqtt", "dnp3"],
                   help="Debug: usar solo los NDJSON de un capture point.")
    p.add_argument("--umbral-broker-peers", type=int, default=2)
    p.add_argument("--umbral-broker-flujos", type=int, default=10)
    p.add_argument("--umbral-scada-puertos", type=int, default=3)
    p.add_argument("--umbral-scada-peers-out", type=int, default=3)
    p.add_argument("--umbral-scada-stdev-polling", type=float, default=1.0)
    p.add_argument("--umbral-plc-flujos-in", type=int, default=1,
                   help="Minimo de flujos entrantes para considerar PLC. En baselines "
                        "cortos un solo flujo valido ya basta (en subred OT no hay "
                        "otros servicios en 502/102/20000).")
    p.add_argument("--umbral-modbus-bytes-mean", type=int, default=300)
    p.add_argument("--atacante", default="kali_nodo",
                   help="Nombre del contenedor atacante a excluir del training.")
    args = p.parse_args()

    sal = Path(_normalizar_path(args.salida))
    sal.mkdir(parents=True, exist_ok=True)

    umbrales = {
        "broker_min_peers":    args.umbral_broker_peers,
        "broker_min_flujos":   args.umbral_broker_flujos,
        "scada_min_puertos_ot": args.umbral_scada_puertos,
        "scada_min_peers_out": args.umbral_scada_peers_out,
        "scada_stdev_polling": args.umbral_scada_stdev_polling,
        "plc_min_flujos_in":   args.umbral_plc_flujos_in,
        "modbus_max_bytes_mean": args.umbral_modbus_bytes_mean,
    }

    # Excluir atacante antes de analizar nada
    excluir = set(ip_de_contenedor(args.atacante))
    if excluir:
        print(f"[inferir] Excluyendo {args.atacante}: {sorted(excluir)}")
    else:
        print(f"[inferir] AVISO: no se pudo resolver IP de {args.atacante} "
              "(docker inspect fallo o contenedor no existe).")

    ips_esperadas = ips_esperadas_del_lab()
    print(f"[inferir] IPs esperadas (docker inspect): {len(ips_esperadas)}")

    inventario = construir_inventario(
        args.flujos,
        excluir_ips=excluir,
        ips_esperadas=ips_esperadas,
        duracion_s=args.duracion_segundos,
        umbrales=umbrales,
        solo_punto=args.solo_punto,
    )

    md = inventario["metadata"]
    print(f"[inferir] Flujos leidos: {md['n_flujos_leidos']}, "
          f"tras dedup: {md['n_flujos_tras_dedup']}, "
          f"descartados .254: {md['n_flujos_descartados_254']}, "
          f"excluidos kali: {md['n_flujos_excluidos_kali']}")
    print(f"[inferir] IPs vistas: {md['n_ips_vistas']}, "
          f"silentes: {md['n_ips_silentes']}")
    for rol, ips in sorted(inventario["role_index"].items()):
        print(f"[inferir]   {rol}: {len(ips)} ({', '.join(ips)})")

    if md["n_candidatas_scada"] > 1:
        print(f"[inferir] AVISO: {md['n_candidatas_scada']} candidatas a scada "
              "(deberia ser 1).", file=sys.stderr)

    with open(sal / "inventario.json", "w", encoding="utf-8") as f:
        json.dump(inventario, f, indent=2, ensure_ascii=False)
    print(f"[inferir] Escrito {sal / 'inventario.json'}")

    md_text = reporte_markdown(inventario)
    with open(sal / "inventario_vs_hosts.md", "w", encoding="utf-8") as f:
        f.write(md_text)
    print(f"[inferir] Escrito {sal / 'inventario_vs_hosts.md'}")


if __name__ == "__main__":
    main()
