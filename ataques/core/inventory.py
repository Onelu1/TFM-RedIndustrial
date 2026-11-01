#!/usr/bin/env python3
"""Inventario del escenario para el mapa de red del dashboard.

Fuente primaria: Docker Engine API via el socket Unix montado en kali_nodo
(`/var/run/docker.sock`). Devuelve topologia + estado 'running' en un solo
viaje. Si el socket no esta disponible, cae a un parser regex del compose
(topologia unica, estado 'unknown').

API publica:
    load_topology() -> {"nodes": [...], "edges": [...], "subnets": [...],
                         "source": "docker" | "compose", "mode": "..."}
    probe_status()  -> {container_name: "up" | "down" | "unknown", ...}
"""

import http.client
import json
import os
import re
import socket
import threading
import time
from typing import Any

DOCKER_SOCKET = os.environ.get("DOCKER_HOST_SOCKET", "/var/run/docker.sock")

# Ruta por defecto: parent dir del paquete ataques/ (es decir, tfm_simulacion/).
# Cuando el dashboard corre dentro de kali_nodo, /ataques esta montado pero el
# compose no suele estarlo: en ese caso Docker API es el camino.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ATAQUES = os.path.dirname(_HERE)
COMPOSE_PATH = os.environ.get(
    "TFM_COMPOSE_PATH",
    os.path.join(os.path.dirname(_ATAQUES), "docker-compose.generated.yml"),
)

# Nombre del proyecto compose (clave `name:` en la primera linea del yml). Se
# usa para quitar el prefijo que Docker aniade a los nombres de red.
_COMPOSE_PROJECT = "tfm-purdue-scenarios"

# Rol inferido por prefijo del container_name. El tercer campo (puerto) se
# conserva aunque la fuente sea Docker API, por si en un futuro queremos
# complementar con sondeos.
# (prefix, role_id, role_label, probe_port)  -- role_id None => excluir del mapa
ROLE_BY_PREFIX = [
    ("router_gw",       "router",       "Router inter-zona", None),
    ("nodered_scada",   "scada",        "SCADA/HMI (Node-RED)", 1880),
    ("broker_mqtt",     "mqtt",         "Broker MQTT",      1883),
    ("srv_empresa",     "samba",        "Samba/SSH Pivote", 445),
    ("kali_nodo",       "attacker",     "Kali (atacante)",  8888),
    ("plc_agua_",       "plc_modbus",   "PLC Modbus",       502),
    ("plc_s7_",         "plc_s7",       "PLC Siemens S7",   102),
    ("plc_dnp3_",       "plc_dnp3",     "PLC DNP3",         20000),
    ("gateway_dnp3_",   "gateway_dnp3", "Gateway DNP3",     None),
    ("net_setup_",      None,           None,               None),
]

ROLE_COLORS = {
    "router":       "#4da3ff",
    "scada":        "#3fcf8e",
    "mqtt":         "#8ea0bf",
    "samba":        "#ff6b6b",
    "attacker":     "#ffcc55",
    "plc_modbus":   "#4da3ff",
    "plc_s7":       "#c88cff",
    "plc_dnp3":     "#3fcf8e",
    "gateway_dnp3": "#ffcc55",
}

SUBNET_LABELS = {
    "red_control":        ("Zona Control (192.168.20.0/24)", "#4da3ff"),
    "red_ot_zona_a":      ("OT Zona A - Modbus (192.168.10.0/24)", "#3fcf8e"),
    "red_ot_zona_b":      ("OT Zona B - S7 (192.168.30.0/24)", "#c88cff"),
    "red_ot_zona_c":      ("OT Zona C - DNP3 (192.168.40.0/24)", "#ffa366"),
    "red_empresa":        ("Red Empresa (192.168.60.0/24)", "#ff6b6b"),
    "red_monitorizacion": ("Monitorizacion (192.168.50.0/24)", "#8ea0bf"),
}

# Cache del snapshot para no martillear la API/compose.
_CACHE: dict[str, Any] = {"ts": 0.0, "topology": None, "status": None}
_CACHE_LOCK = threading.Lock()
_CACHE_TTL = 3.0


# ---------------------------------------------------------------------------
# Docker API via unix socket (sin dependencias extra: solo stdlib)
# ---------------------------------------------------------------------------

class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost")
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(self._path)
        self.sock = s


def _docker_get(path: str, timeout: float = 2.0):
    conn = _UnixHTTPConnection(DOCKER_SOCKET)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError(f"docker API {resp.status}: {body[:200]!r}")
        return json.loads(body)
    finally:
        conn.close()


def _strip_project(net_name: str) -> str:
    """Quita el prefijo `tfm-purdue-scenarios_` de los nombres de red."""
    prefix = _COMPOSE_PROJECT + "_"
    if net_name.startswith(prefix):
        return net_name[len(prefix):]
    return net_name


def _role_for(container_name: str):
    for prefix, role_id, label, port in ROLE_BY_PREFIX:
        if container_name.startswith(prefix):
            return role_id, label, port
    return "other", "Otro", None


def _snapshot_from_docker() -> tuple[dict, dict]:
    """Devuelve (topology, status) consultando la API de Docker."""
    try:
        containers = _docker_get("/containers/json?all=1")
    except (FileNotFoundError, PermissionError, OSError, RuntimeError, socket.error):
        raise

    nodes_by_name: dict[str, dict] = {}
    edges: list[dict] = []
    subnets_seen: set[str] = set()
    status: dict[str, str] = {}

    for c in containers:
        names = c.get("Names", [])
        if not names:
            continue
        name = names[0].lstrip("/")
        role_id, label, port = _role_for(name)
        if role_id is None:
            continue  # sidecar

        state = c.get("State", "unknown")
        status[name] = "up" if state == "running" else "down"

        networks = (c.get("NetworkSettings") or {}).get("Networks") or {}
        ips: list[tuple[str, str]] = []  # (short_subnet, ip)
        for raw_net, net_info in networks.items():
            short = _strip_project(raw_net)
            if short not in SUBNET_LABELS:
                continue  # red externa no reconocida
            ip = (net_info or {}).get("IPAddress") or ""
            if ip:
                ips.append((short, ip))

        if not ips:
            continue

        # Un unico nodo por contenedor. IP principal: red_control si existe,
        # si no la primera. El resto de redes se reflejan como aristas.
        primary = next(((s, i) for s, i in ips if s == "red_control"), ips[0])
        nodes_by_name[name] = {
            "id": name,
            "label": f"{name}\n{primary[1]}",
            "role": role_id,
            "role_label": label,
            "ip": primary[1],
            "color": ROLE_COLORS.get(role_id, "#8ea0bf"),
            "title": _tooltip(name, label, ips, port),  # vis-network usa 'title'
            "probe_port": port,
        }
        for subnet, ip in ips:
            subnets_seen.add(subnet)
            edges.append({"from": name, "to": subnet, "ip": ip})

    subnets = []
    for s in subnets_seen:
        slabel, scolor = SUBNET_LABELS[s]
        subnets.append({"id": s, "label": slabel, "color": scolor})

    topology = {
        "nodes": list(nodes_by_name.values()),
        "edges": edges,
        "subnets": subnets,
        "source": "docker",
    }
    return topology, status


# ---------------------------------------------------------------------------
# Fallback: parser regex del compose (sin PyYAML)
# ---------------------------------------------------------------------------

_SERVICE_RE = re.compile(
    r"^\s{2}([a-zA-Z_][\w-]*):\s*$"
    r"((?:\n(?!\s{0,2}[^\s].*$).*)*)",
    re.MULTILINE,
)
_CONTAINER_NAME_RE = re.compile(r"container_name:\s*([\w-]+)")
_NET_BLOCK_RE = re.compile(
    r"(red_[\w]+):\s*\n\s+ipv4_address:\s*(\d+\.\d+\.\d+\.\d+)"
)


def _snapshot_from_compose() -> tuple[dict, dict]:
    """Devuelve (topology, status) parseando el compose. Estado = 'unknown'."""
    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        text = f.read()

    # Partimos por bloques de servicio: cada servicio es una entrada bajo
    # `services:` indentada con 2 espacios. Hacemos un parse muy ligero.
    services_split = re.split(r"\n  (?=[a-zA-Z_])", text)
    nodes_by_name: dict[str, dict] = {}
    edges: list[dict] = []
    subnets_seen: set[str] = set()
    status: dict[str, str] = {}

    for block in services_split:
        m_name = _CONTAINER_NAME_RE.search(block)
        if not m_name:
            continue
        name = m_name.group(1)
        role_id, label, port = _role_for(name)
        if role_id is None:
            continue

        ips = [(sn, ip) for sn, ip in _NET_BLOCK_RE.findall(block)
               if sn in SUBNET_LABELS]
        if not ips:
            continue

        primary = next(((s, i) for s, i in ips if s == "red_control"), ips[0])
        nodes_by_name[name] = {
            "id": name,
            "label": f"{name}\n{primary[1]}",
            "role": role_id,
            "role_label": label,
            "ip": primary[1],
            "color": ROLE_COLORS.get(role_id, "#8ea0bf"),
            "title": _tooltip(name, label, ips, port),
            "probe_port": port,
        }
        for subnet, ip in ips:
            subnets_seen.add(subnet)
            edges.append({"from": name, "to": subnet, "ip": ip})
        status[name] = "unknown"

    subnets = []
    for s in subnets_seen:
        slabel, scolor = SUBNET_LABELS[s]
        subnets.append({"id": s, "label": slabel, "color": scolor})

    return {
        "nodes": list(nodes_by_name.values()),
        "edges": edges,
        "subnets": subnets,
        "source": "compose",
    }, status


def _tooltip(name: str, role_label: str, ips: list[tuple[str, str]], port):
    lines = [f"<b>{name}</b>", role_label]
    for subnet, ip in ips:
        lines.append(f"{subnet}: {ip}")
    if port:
        lines.append(f"Puerto servicio: {port}")
    return "<br>".join(lines)


# ---------------------------------------------------------------------------
# API publica + cache
# ---------------------------------------------------------------------------

def _refresh_cache(force: bool = False) -> None:
    """Rellena _CACHE si lleva mas de _CACHE_TTL segundos o si force=True."""
    with _CACHE_LOCK:
        if not force and (time.time() - _CACHE["ts"] < _CACHE_TTL) \
                and _CACHE["topology"] is not None:
            return
        try:
            topo, status = _snapshot_from_docker()
        except Exception:
            try:
                topo, status = _snapshot_from_compose()
            except Exception as e2:
                topo = {"nodes": [], "edges": [], "subnets": [],
                        "source": "none", "error": str(e2)}
                status = {}
        _CACHE["topology"] = topo
        _CACHE["status"] = status
        _CACHE["ts"] = time.time()


def load_topology() -> dict:
    """Devuelve la topologia (nodos, aristas, subredes)."""
    _refresh_cache()
    return _CACHE["topology"] or {"nodes": [], "edges": [], "subnets": []}


def probe_status() -> dict:
    """Devuelve {container_name: 'up'|'down'|'unknown'}."""
    _refresh_cache()
    return _CACHE["status"] or {}
