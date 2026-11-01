#!/usr/bin/env python3
"""Genera la Tabla 6.2 (inventario completo de contenedores) a partir del
`docker-compose.generated.yml` del lab y, opcionalmente, del compose del
stack Wazuh. Sale en Markdown por stdout; redirige a fichero para pegar
en la memoria.

Uso:
    python scenario/tabla_inventario.py                  # solo lab OT
    python scenario/tabla_inventario.py --con-wazuh      # añade Wazuh
    python scenario/tabla_inventario.py --formato latex  # formato LaTeX
"""

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("[!] Falta PyYAML. Instala con: pip install pyyaml")


# Roles por contenedor. Clave: nombre literal o patron `plc_agua_*`.
ROLES = {
    "router_gw":          "Router/gateway inter-zona (ip_forward + MASQUERADE)",
    "nodered_scada_1":    "SCADA/HMI (Node-RED + dashboard)",
    "broker_mqtt":        "Broker MQTT (telemetria DNP3)",
    "srv_empresa":        "Servidor empresarial Samba+SSH (pivote IDMZ)",
    "kali_nodo":          "Puesto atacante (toolkit del cap. 7)",
    "net_setup_nodered":  "Sidecar: rutas estaticas en nodered_scada_1",
    "net_setup_srv_empresa": "Sidecar: rutas estaticas en srv_empresa",
    "net_setup_kali":     "Sidecar: rutas estaticas en kali_nodo (modo control)",
    "plc_agua_*":         "PLC OpenPLC con backend Modbus TCP (planta de aguas)",
    "plc_s7_*":           "PLC simulado Siemens S7-1200 (python-snap7)",
    "plc_dnp3_*":         "PLC OpenPLC con backend DNP3 outstation",
    "gateway_dnp3_*":     "Pasarela DNP3 outstation -> MQTT",
    "wazuh.manager":      "Wazuh manager (analysisd + logcollector)",
    "wazuh.indexer":      "Wazuh indexer (OpenSearch)",
    "wazuh.dashboard":    "Wazuh dashboard (Kibana fork, HTTPS :5601)",
    "wazuh-certs-generator": "Generador de certificados TLS (one-shot)",
}


def rol_de(nombre):
    if nombre in ROLES:
        return ROLES[nombre]
    for patron, texto in ROLES.items():
        if patron.endswith("*") and nombre.startswith(patron[:-1]):
            return texto
    return ""


# Zona legible por nombre de red Docker.
ZONA_LEGIBLE = {
    "red_empresa":         "enterprise (L4)",
    "red_control":         "control (L3)",
    "red_ot_zona_a":       "OT A - Modbus (L2)",
    "red_ot_zona_b":       "OT B - S7 (L2)",
    "red_ot_zona_c":       "OT C - DNP3 (L2)",
    "red_monitorizacion":  "monitorizacion",
}


def extraer_servicio(nombre, spec, prefijo_red=""):
    """Devuelve dict con los campos de la tabla para un service del compose.

    `prefijo_red` permite diferenciar redes homonimas entre composes (ej.
    Wazuh usa `red_monitorizacion` como external pero algunos stacks la
    renombran internamente).
    """
    container = spec.get("container_name", nombre)
    image = spec.get("image") or (
        f"build:{spec['build']['context']}" if "build" in spec else "-"
    )

    redes = spec.get("networks") or {}
    network_mode = spec.get("network_mode", "")

    zonas = []
    ips = []
    if network_mode.startswith("service:"):
        # Sidecar: comparte el ns del contenedor objetivo.
        objetivo = network_mode.split(":", 1)[1]
        zonas.append(f"ns de {objetivo}")
        ips.append("(comparte IP)")
    elif isinstance(redes, dict):
        for red, cfg in redes.items():
            zonas.append(ZONA_LEGIBLE.get(red, red))
            if isinstance(cfg, dict) and "ipv4_address" in cfg:
                ips.append(cfg["ipv4_address"])
            else:
                ips.append("DHCP")
    elif isinstance(redes, list):
        for red in redes:
            zonas.append(ZONA_LEGIBLE.get(red, red))
            ips.append("DHCP")

    puertos = []
    for p in spec.get("ports", []) or []:
        s = str(p).strip('"')
        # formatos: "host:cont", "host:cont/udp", "host:cont-rango"
        m = re.match(r'^"?(\d+(?:-\d+)?):(\d+(?:-\d+)?)(?:/(tcp|udp))?"?$', s)
        if m:
            puertos.append(f"{m.group(1)}->{m.group(2)}" + (f"/{m.group(3)}" if m.group(3) else ""))
        else:
            puertos.append(s)
    puertos_str = ", ".join(puertos) if puertos else "-"

    return {
        "container": container,
        "image": image,
        "zonas": " + ".join(zonas) if zonas else "-",
        "ips": ", ".join(ips) if ips else "-",
        "puertos": puertos_str,
        "rol": rol_de(container),
    }


def cargar_servicios(compose_path):
    with open(compose_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return [
        extraer_servicio(n, spec)
        for n, spec in (data.get("services") or {}).items()
    ]


# --- Orden preferente para la memoria: router -> red_empresa -> red_control
# -> OT A/B/C -> monitorizacion -> sidecars. Dentro de cada zona, por nombre.

ORDEN_ZONAS = {
    "Router/gateway inter-zona (ip_forward + MASQUERADE)": 0,
    "enterprise (L4)": 1,
    "control (L3)": 2,
    "OT A - Modbus (L2)": 3,
    "OT B - S7 (L2)": 4,
    "OT C - DNP3 (L2)": 5,
    "monitorizacion": 6,
    "ns de": 9,
}


def orden_zona(fila):
    if fila["container"] == "router_gw":
        return (0, fila["container"])
    for clave, val in ORDEN_ZONAS.items():
        if clave in fila["zonas"]:
            return (val, fila["container"])
    return (99, fila["container"])


# --- Salida ---

def _escape_md(s):
    return s.replace("|", "\\|")


def imprimir_markdown(filas):
    cabecera = ["Contenedor", "Imagen", "Zona(s)", "IP(s)", "Puertos host->cont", "Rol"]
    print("| " + " | ".join(cabecera) + " |")
    print("|" + "|".join(["---"] * len(cabecera)) + "|")
    for f in filas:
        print("| " + " | ".join(_escape_md(f[c]) for c in (
            "container", "image", "zonas", "ips", "puertos", "rol"
        )) + " |")


def imprimir_latex(filas):
    print(r"\begin{table}[h]")
    print(r"\centering\footnotesize")
    print(r"\caption{Inventario completo de contenedores del escenario hibrido.}")
    print(r"\label{tab:inventario}")
    print(r"\begin{tabular}{l l l l l l}")
    print(r"\toprule")
    print(r"Contenedor & Imagen & Zona(s) & IP(s) & Puertos & Rol \\")
    print(r"\midrule")
    for f in filas:
        print(" & ".join(
            str(f[c]).replace("_", r"\_").replace("&", r"\&")
            for c in ("container", "image", "zonas", "ips", "puertos", "rol")
        ) + r" \\")
    print(r"\bottomrule")
    print(r"\end{tabular}")
    print(r"\end{table}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--compose", default="docker-compose.generated.yml",
                    help="Compose principal del lab (por defecto: docker-compose.generated.yml)")
    ap.add_argument("--con-wazuh", action="store_true",
                    help="Incluye el stack Wazuh (monitorizacion/wazuh/docker-compose.yml)")
    ap.add_argument("--formato", choices=("md", "latex"), default="md")
    args = ap.parse_args()

    base = Path.cwd()
    filas = cargar_servicios(base / args.compose)
    if args.con_wazuh:
        wazuh_compose = base / "monitorizacion" / "wazuh" / "docker-compose.yml"
        if wazuh_compose.exists():
            filas += cargar_servicios(wazuh_compose)
        else:
            print(f"[!] Aviso: no encuentro {wazuh_compose}; omito Wazuh.",
                  file=sys.stderr)

    filas.sort(key=orden_zona)

    if args.formato == "md":
        imprimir_markdown(filas)
    else:
        imprimir_latex(filas)


if __name__ == "__main__":
    main()
