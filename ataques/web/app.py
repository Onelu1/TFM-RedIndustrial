#!/usr/bin/env python3
"""
Dashboard Flask para el toolkit de ataques OT/ICS del TFM.

Se ejecuta DENTRO del contenedor `kali_nodo` (ver docker-compose generado por
tfm_simulacion/main.py). Expone en el puerto 8888 un panel con tarjetas por
módulo, selector de IP y streaming de salida (Server-Sent Events) con el
contenido del fichero de evidencia en vivo.

Arranque manual:
    docker exec -d kali_nodo python3 /ataques/web/app.py

El puerto 8888 se publica en el host desde el docker-compose, así que el panel
queda accesible en http://localhost:8888 desde el navegador del equipo.
"""

import os
import sys
import time
import uuid
import threading
import traceback

# Permitir importar el paquete raíz 'ataques/' aunque el proceso arranque desde
# dentro de 'web/'.
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from flask import Flask, Response, jsonify, render_template, request  # noqa: E402

import config  # noqa: E402
from core import runner  # noqa: E402
from modules import (  # noqa: E402
    recon, modbus_msf, s7_snap7, dnp3_pydnp3, samba_pivot, openplc_rce,
    c2_modbus,
)

app = Flask(__name__, static_folder="static", template_folder="templates")

# Modo de despliegue de kali_nodo: lo escribe main.py en /ataques/.mode y se lee
# una sola vez al arrancar el dashboard.
MODE = config.get_mode()

# Estado de los jobs en memoria. Cada job: {status, path, started_at, module, action}
JOBS = {}
JOBS_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Catálogo de acciones expuestas por el dashboard. Cada entrada describe una
# llamada a los módulos del toolkit, con los parámetros que admite el panel.
# ---------------------------------------------------------------------------
CATALOG = {
    "recon.modbus": {
        "titulo": "Modbus — Descubrir red (nmap)",
        "mitre": config.MITRE_MAP["modbus.discover_nmap"],
        "params": {"target": "192.168.10.0/24"},
        "fn": lambda p, sink: recon.modbus_discover(p.get("target"), sink=sink),
    },
    "recon.s7": {
        "titulo": "Siemens S7 — Descubrir red (s7-info)",
        "mitre": config.MITRE_MAP["s7.discover_nmap"],
        "params": {"target": "192.168.30.0/24"},
        "fn": lambda p, sink: recon.s7_discover(p.get("target"), sink=sink),
    },
    "recon.dnp3": {
        "titulo": "DNP3 — Descubrir red (puerto 20000)",
        "mitre": config.MITRE_MAP["dnp3.discover_nmap"],
        "params": {"target": "192.168.40.0/24"},
        "fn": lambda p, sink: recon.dnp3_discover(p.get("target"), sink=sink),
    },

    "modbus.findunitid": {
        "titulo": "Modbus — Enumerar Unit/Station ID (MSF)",
        "mitre": config.MITRE_MAP["modbus.findunitid"],
        "params": {"target": config.MODBUS_DEFAULT_TARGET, "port": config.MODBUS_DEFAULT_PORT,
                    "unit_first": 1, "unit_last": 5},
        "fn": lambda p, sink: modbus_msf.findunitid(
            p.get("target"), int(p.get("port") or 502),
            int(p.get("unit_first") or 1), int(p.get("unit_last") or 5), sink=sink),
    },
    "modbus.detect": {
        "titulo": "Modbus — Detectar servicio (MSF)",
        "mitre": config.MITRE_MAP["modbus.detect"],
        "params": {"target": config.MODBUS_DEFAULT_TARGET, "port": config.MODBUS_DEFAULT_PORT},
        "fn": lambda p, sink: modbus_msf.detect(p.get("target"), int(p.get("port") or 502), sink=sink),
    },
    "modbus.uid_contrast": {
        "titulo": "Modbus — Comparativa UID: findunitid vs modbusclient",
        "mitre": config.MITRE_MAP["modbus.uid_contrast"],
        "params": {"target": config.MODBUS_DEFAULT_TARGET, "port": config.MODBUS_DEFAULT_PORT,
                    "unit_first": 1, "unit_last": 5,
                    "data_address": 0, "number": 5},
        "fn": lambda p, sink: modbus_msf.uid_contrast(
            p.get("target"), int(p.get("port") or 502),
            int(p.get("unit_first") or 1), int(p.get("unit_last") or 5),
            int(p.get("data_address") or 0), int(p.get("number") or 5),
            sink=sink),
    },
    "modbus.read_coils": {
        "titulo": "Modbus — Leer coils (READ_COILS)",
        "mitre": config.MITRE_MAP["modbus.read_coils"],
        "params": {"target": config.MODBUS_DEFAULT_TARGET, "port": config.MODBUS_DEFAULT_PORT,
                    "data_address": 0, "number": 2, "unit_id": 1},
        "fn": lambda p, sink: modbus_msf.read_coils(
            p.get("target"), int(p.get("port") or 502),
            int(p.get("data_address") or 0), int(p.get("number") or 2),
            int(p.get("unit_id") or 1), sink=sink),
    },
    "modbus.read_registers": {
        "titulo": "Modbus — Leer holding registers",
        "mitre": config.MITRE_MAP["modbus.read_registers"],
        "params": {"target": config.MODBUS_DEFAULT_TARGET, "port": config.MODBUS_DEFAULT_PORT,
                    "data_address": 0, "number": 20, "unit_id": 1},
        "fn": lambda p, sink: modbus_msf.read_registers(
            p.get("target"), int(p.get("port") or 502),
            int(p.get("data_address") or 0), int(p.get("number") or 20),
            int(p.get("unit_id") or 1), sink=sink),
    },
    "modbus.write_coil": {
        "titulo": "Modbus — Escribir coil (WRITE_COIL)",
        "mitre": config.MITRE_MAP["modbus.write_coil"],
        "params": {"target": config.MODBUS_DEFAULT_TARGET, "port": config.MODBUS_DEFAULT_PORT,
                    "data_address": 0, "data": 1, "unit_id": 1},
        "fn": lambda p, sink: modbus_msf.write_coil(
            p.get("target"), int(p.get("port") or 502),
            int(p.get("data_address") or 0), int(p.get("data") or 0),
            int(p.get("unit_id") or 1), sink=sink),
    },
    "modbus.write_register": {
        "titulo": "Modbus — Escribir registro (WRITE_REGISTER)",
        "mitre": config.MITRE_MAP["modbus.write_register"],
        "params": {"target": config.MODBUS_DEFAULT_TARGET, "port": config.MODBUS_DEFAULT_PORT,
                    "data_address": 0, "data": 0, "unit_id": 1},
        "fn": lambda p, sink: modbus_msf.write_register(
            p.get("target"), int(p.get("port") or 502),
            int(p.get("data_address") or 0), int(p.get("data") or 0),
            int(p.get("unit_id") or 1), sink=sink),
    },

    "s7.read_db1": {
        "titulo": "Siemens S7 — Leer variables DB1",
        "mitre": config.MITRE_MAP["s7.read_db1"],
        "params": {"target": config.S7_DEFAULT_TARGET,
                    "rack": config.S7_DEFAULT_RACK, "slot": config.S7_DEFAULT_SLOT},
        "fn": lambda p, sink: s7_snap7.read_db1(
            p.get("target"), int(p.get("rack") or 0), int(p.get("slot") or 1), sink=sink),
    },
    "s7.write_setpoint": {
        "titulo": "Siemens S7 — Escribir Setpoint (DB1.DBD6 REAL)",
        "mitre": config.MITRE_MAP["s7.write_setpoint"],
        "params": {"target": config.S7_DEFAULT_TARGET,
                    "rack": config.S7_DEFAULT_RACK, "slot": config.S7_DEFAULT_SLOT,
                    "valor": 75.5},
        "fn": lambda p, sink: s7_snap7.write_setpoint(
            p.get("target"), int(p.get("rack") or 0), int(p.get("slot") or 1),
            float(p.get("valor") or 0.0), sink=sink),
    },
    "s7.write_marcha": {
        "titulo": "Siemens S7 — Escribir bit Marcha (DB1.DBX4.0)",
        "mitre": config.MITRE_MAP["s7.write_marcha"],
        "params": {"target": config.S7_DEFAULT_TARGET,
                    "rack": config.S7_DEFAULT_RACK, "slot": config.S7_DEFAULT_SLOT,
                    "valor": "true"},
        "fn": lambda p, sink: s7_snap7.write_marcha(
            p.get("target"), int(p.get("rack") or 0), int(p.get("slot") or 1),
            p.get("valor", "true"), sink=sink),
    },

    "dnp3.discover": {
        "titulo": "DNP3 — Descubrimiento (nmap)",
        "mitre": config.MITRE_MAP["dnp3.discover_nmap"],
        "params": {"target": "192.168.40.0/24"},
        "fn": lambda p, sink: dnp3_pydnp3.discover(p.get("target"), sink=sink),
    },
    "dnp3.read": {
        "titulo": "DNP3 — Lectura de puntos (integrity poll)",
        "mitre": config.MITRE_MAP["dnp3.read"],
        "params": {"target": config.DNP3_DEFAULT_TARGET, "port": config.DNP3_DEFAULT_PORT},
        "fn": lambda p, sink: dnp3_pydnp3.read(
            p.get("target"), int(p.get("port") or 20000), sink=sink),
    },
    "dnp3.write_manual": {
        "titulo": "DNP3 — Activar/Desactivar Modo Manual",
        "mitre": config.MITRE_MAP["dnp3.write_manual"],
        "params": {"target": config.DNP3_DEFAULT_TARGET, "port": config.DNP3_DEFAULT_PORT,
                    "value": "true"},
        "fn": lambda p, sink: dnp3_pydnp3.write_modo_manual(
            p.get("target"), int(p.get("port") or 20000),
            p.get("value", "true"), sink=sink),
    },
    "dnp3.write_bomba": {
        "titulo": "DNP3 — Activar/Desactivar Bomba Principal",
        "mitre": config.MITRE_MAP["dnp3.write_bomba"],
        "params": {"target": config.DNP3_DEFAULT_TARGET, "port": config.DNP3_DEFAULT_PORT,
                    "value": "true"},
        "fn": lambda p, sink: dnp3_pydnp3.write_bomba(
            p.get("target"), int(p.get("port") or 20000),
            p.get("value", "true"), sink=sink),
    },

    "samba.download_key": {
        "titulo": "Samba — Descargar clave SSH (anónimo)",
        "mitre": config.MITRE_MAP["samba.download_key"],
        "params": {},
        "fn": lambda p, sink: samba_pivot.download_key(sink=sink),
    },
    "samba.open_tunnel": {
        "titulo": "Samba — Levantar túnel SOCKS (ssh -D 9050)",
        "mitre": config.MITRE_MAP["samba.open_tunnel"],
        "params": {},
        "fn": lambda p, sink: samba_pivot.open_tunnel(sink=sink),
    },
    "samba.scan_via_tunnel": {
        "titulo": "Samba — Escanear red OT por el túnel",
        "mitre": config.MITRE_MAP["samba.scan_via_tunnel"],
        "params": {"target": config.DNP3_DEFAULT_TARGET, "port": config.DNP3_DEFAULT_PORT},
        "fn": lambda p, sink: samba_pivot.scan_via_tunnel(
            p.get("target"), int(p.get("port") or 20000), sink=sink),
    },
    "samba.full_chain": {
        "titulo": "Samba — Cadena completa (clave + túnel + nmap)",
        "mitre": sum([config.MITRE_MAP["samba.download_key"],
                       config.MITRE_MAP["samba.open_tunnel"],
                       config.MITRE_MAP["samba.scan_via_tunnel"]], []),
        "params": {"target": config.DNP3_DEFAULT_TARGET, "port": config.DNP3_DEFAULT_PORT},
        "fn": lambda p, sink: samba_pivot.full_chain(
            p.get("target"), int(p.get("port") or 20000), sink=sink),
    },

    "openplc.default_login": {
        "titulo": "OpenPLC — Login con credenciales por defecto",
        "mitre": config.MITRE_MAP["openplc.default_login"],
        "params": {"target": config.OPENPLC_DEFAULT_TARGET, "port": config.OPENPLC_DEFAULT_PORT,
                    "user": config.OPENPLC_DEFAULT_USER, "password": config.OPENPLC_DEFAULT_PASS},
        "fn": lambda p, sink: openplc_rce.default_login(
            p.get("target"), int(p.get("port") or 8080),
            p.get("user"), p.get("password"), sink=sink),
    },
    "openplc.cve_2026_71268": {
        "titulo": "OpenPLC — PoC path traversal (CVE-2026-71268)",
        "mitre": config.MITRE_MAP["openplc.cve_2026_71268"],
        "params": {"target": config.OPENPLC_DEFAULT_TARGET, "port": config.OPENPLC_DEFAULT_PORT,
                    "user": config.OPENPLC_DEFAULT_USER, "password": config.OPENPLC_DEFAULT_PASS,
                    "st_file": "/ataques/work/cve_2026_71268_poc.st",
                    "prog_name": "CVE-2026-71268-PoC",
                    "prog_descr": "PoC TFM"},
        "fn": lambda p, sink: openplc_rce.cve_2026_71268(
            p.get("target"), int(p.get("port") or 8080),
            p.get("user"), p.get("password"), p.get("st_file"),
            p.get("prog_name") or "CVE-2026-71268-PoC",
            p.get("prog_descr") or "PoC TFM", sink=sink),
    },
    "openplc.get_current_program": {
        "titulo": "OpenPLC — Leer programa activo (y descargar .st)",
        "mitre": config.MITRE_MAP["openplc.get_current_program"],
        "params": {"target": config.OPENPLC_DEFAULT_TARGET, "port": config.OPENPLC_DEFAULT_PORT,
                    "user": config.OPENPLC_DEFAULT_USER, "password": config.OPENPLC_DEFAULT_PASS},
        "fn": lambda p, sink: openplc_rce.get_current_program(
            p.get("target"), int(p.get("port") or 8080),
            p.get("user"), p.get("password"), sink=sink),
    },
    "openplc.upload_run": {
        "titulo": "OpenPLC — Subir + compilar + arrancar (con backup previo)",
        "mitre": config.MITRE_MAP["openplc.upload_run"],
        "params": {"target": config.OPENPLC_DEFAULT_TARGET, "port": config.OPENPLC_DEFAULT_PORT,
                    "user": config.OPENPLC_DEFAULT_USER, "password": config.OPENPLC_DEFAULT_PASS,
                    "st_file": "/ataques/work/malicioso.st",
                    "prog_name": "UPLOAD-RUN-PoC",
                    "prog_descr": "PoC TFM upload_run"},
        "fn": lambda p, sink: openplc_rce.upload_run(
            p.get("target"), int(p.get("port") or 8080),
            p.get("user"), p.get("password"), p.get("st_file"),
            p.get("prog_name") or "UPLOAD-RUN-PoC",
            p.get("prog_descr") or "PoC TFM upload_run", sink=sink),
    },

    # --- C2 MODBUS (FrostyGoop) ---
    "c2_modbus.deploy": {
        "titulo": "C2 — Desplegar implante en host comprometido",
        "mitre": config.MITRE_MAP["c2_modbus.deploy_implant"],
        "params": {"implant_host": config.SAMBA_HOST},
        "fn": lambda p, sink: c2_modbus.deploy_implant(
            p.get("implant_host"), sink=sink),
    },
    "c2_modbus.shell": {
        "titulo": "C2 — Comando shell encubierto",
        "mitre": config.MITRE_MAP["c2_modbus.shell"],
        "params": {"command": "whoami", "mailbox": config.C2_MAILBOX_PLC,
                    "port": config.C2_MAILBOX_PORT},
        "fn": lambda p, sink: c2_modbus.c2_shell(
            p.get("command") or "whoami",
            p.get("mailbox"), int(p.get("port") or 502), sink=sink),
    },
    "c2_modbus.write_coil": {
        "titulo": "C2 — Ataque OT: WRITE_COIL vía C2",
        "mitre": config.MITRE_MAP["c2_modbus.trigger_ot"],
        "params": {"target_ip": config.MODBUS_DEFAULT_TARGET,
                    "data_address": 0, "value": 1,
                    "mailbox": config.C2_MAILBOX_PLC, "port": config.C2_MAILBOX_PORT},
        "fn": lambda p, sink: c2_modbus.c2_write_coil(
            p.get("target_ip") or config.MODBUS_DEFAULT_TARGET,
            int(p.get("data_address") or 0), int(p.get("value") or 1),
            p.get("mailbox"), int(p.get("port") or 502), sink=sink),
    },
    "c2_modbus.write_register": {
        "titulo": "C2 — Ataque OT: WRITE_REGISTER vía C2",
        "mitre": config.MITRE_MAP["c2_modbus.trigger_ot"],
        "params": {"target_ip": config.MODBUS_DEFAULT_TARGET,
                    "data_address": 0, "value": 0,
                    "mailbox": config.C2_MAILBOX_PLC, "port": config.C2_MAILBOX_PORT},
        "fn": lambda p, sink: c2_modbus.c2_write_register(
            p.get("target_ip") or config.MODBUS_DEFAULT_TARGET,
            int(p.get("data_address") or 0), int(p.get("value") or 0),
            p.get("mailbox"), int(p.get("port") or 502), sink=sink),
    },
    "c2_modbus.exit": {
        "titulo": "C2 — Finalizar implante (EXIT)",
        "mitre": config.MITRE_MAP["c2_modbus.shell"],
        "params": {"mailbox": config.C2_MAILBOX_PLC, "port": config.C2_MAILBOX_PORT},
        "fn": lambda p, sink: c2_modbus.c2_exit(
            p.get("mailbox"), int(p.get("port") or 502), sink=sink),
    },
}

# Agrupación por tarjetas (orden de aparición en el panel).
GROUPS = [
    ("Reconocimiento", ["recon.modbus", "recon.s7", "recon.dnp3"]),
    ("Modbus TCP (Metasploit)", [
        "modbus.findunitid", "modbus.uid_contrast", "modbus.detect",
        "modbus.read_coils", "modbus.read_registers",
        "modbus.write_coil", "modbus.write_register"]),
    ("Siemens S7 (snap7)", ["s7.read_db1", "s7.write_setpoint", "s7.write_marcha"]),
    ("DNP3", ["dnp3.discover", "dnp3.read", "dnp3.write_manual", "dnp3.write_bomba"]),
    ("Pivoting Samba", [
        "samba.download_key", "samba.open_tunnel",
        "samba.scan_via_tunnel", "samba.full_chain"]),
    ("OpenPLC (panel web)", ["openplc.default_login", "openplc.get_current_program",
                               "openplc.cve_2026_71268", "openplc.upload_run"]),
    ("C2 Modbus — FrostyGoop", [
        "c2_modbus.deploy", "c2_modbus.shell",
        "c2_modbus.write_coil", "c2_modbus.write_register",
        "c2_modbus.exit"]),
]


def _launch(action_id, params):
    job_id = uuid.uuid4().hex[:12]
    entry = CATALOG[action_id]
    with JOBS_LOCK:
        JOBS[job_id] = {"status": "running", "path": None, "action": action_id,
                        "titulo": entry["titulo"], "started_at": time.time()}

    def _worker():
        try:
            path = entry["fn"](params, sink=None)
            with JOBS_LOCK:
                JOBS[job_id]["path"] = path
                JOBS[job_id]["status"] = "done"
        except runner.LabScopeError as e:
            # Guardamos el error en un fichero propio para que el panel pueda mostrarlo
            from core import evidence as ev
            p = ev.new_evidence_file(action_id.split(".")[0], action_id.split(".")[1])
            ev.header(p, f"ERROR DE ALCANCE: {entry['titulo']}", str(params))
            with open(p, "a", encoding="utf-8") as f:
                f.write(f"[!] {e}\n")
            with JOBS_LOCK:
                JOBS[job_id]["path"] = p
                JOBS[job_id]["status"] = "error"
        except Exception as e:  # noqa: BLE001
            from core import evidence as ev
            p = ev.new_evidence_file(action_id.split(".")[0], action_id.split(".")[1])
            ev.header(p, f"EXCEPCIÓN: {entry['titulo']}", str(params))
            with open(p, "a", encoding="utf-8") as f:
                f.write(f"[!] {e}\n\n")
                f.write(traceback.format_exc())
            with JOBS_LOCK:
                JOBS[job_id]["path"] = p
                JOBS[job_id]["status"] = "error"

    threading.Thread(target=_worker, daemon=True).start()
    return job_id


def _visible_groups():
    """Devuelve GROUPS filtrado segun el modo.

    En modo control oculta la tarjeta 'Pivoting Samba' (no aplica).
    """
    if MODE == "control":
        return [(n, a) for (n, a) in GROUPS if n != "Pivoting Samba"]
    return GROUPS


@app.route("/")
def index():
    return render_template(
        "index.html",
        groups=_visible_groups(), catalog=CATALOG,
        mode=MODE,
        tunnel_up=runner.tunnel_up(),
        ot_subnets=config.OT_SUBNETS,
    )


@app.route("/mode")
def mode_info():
    """Endpoint JSON para refresco del banner (estado del túnel en vivo)."""
    return jsonify({
        "mode": MODE,
        "tunnel_up": runner.tunnel_up(),
        "ot_subnets": config.OT_SUBNETS,
    })


@app.route("/run/<action_id>", methods=["POST"])
def run_action(action_id):
    if action_id not in CATALOG:
        return jsonify({"error": "acción desconocida"}), 404
    params = request.get_json(silent=True) or {}
    job_id = _launch(action_id, params)
    return jsonify({"job_id": job_id})


@app.route("/jobs/<job_id>")
def job_status(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "job no encontrado"}), 404
    return jsonify({"status": job["status"], "titulo": job["titulo"],
                     "path": job["path"], "action": job["action"]})


@app.route("/stream/<job_id>")
def stream(job_id):
    """SSE: emite las líneas del fichero de evidencia a medida que crece."""
    def gen():
        pos = 0
        waited = 0.0
        while True:
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            if not job:
                yield "event: error\ndata: job no encontrado\n\n"
                return
            path = job["path"]
            if path and os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                if chunk:
                    for line in chunk.splitlines():
                        yield f"data: {line}\n\n"
                    waited = 0.0
            if job["status"] in ("done", "error"):
                yield f"event: end\ndata: {job['status']}\n\n"
                return
            time.sleep(0.3)
            waited += 0.3
            if waited > 1.5:
                # heartbeat para que algunos proxies no cierren el stream
                yield ": keepalive\n\n"
                waited = 0.0

    return Response(gen(), mimetype="text/event-stream")


if __name__ == "__main__":
    # 0.0.0.0 para que el puerto publicado por docker-compose llegue al host.
    app.run(host="0.0.0.0", port=8888, debug=False, threaded=True)
