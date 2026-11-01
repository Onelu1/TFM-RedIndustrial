#!/usr/bin/env python3
"""Orquestación end-to-end del laboratorio TFM.

Tres funciones para las opciones [8]/[9]/[A] del menú:

- `arrancar_todo()`  — lab OT + MASQUERADE + Wazuh.
- `pipeline_completo()` — baseline opcional + 10 ataques + Suricata + Wazuh ingest.
- `verificar()` — 15 chequeos de salud; devuelve 0 si todo OK, 1 si hay fallos.

Reutiliza `deploy_scenario()` y los scripts bash de `monitorizacion/`.
"""

import json
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

from .compose import read_scenario_sizes, write_kali_mode_marker
from .deploy import deploy_scenario
from .nodered_flow import save_flows_file
from .shell import run_cmd


RAIZ = pathlib.Path(__file__).resolve().parents[1]
MONITOR = RAIZ / "monitorizacion"
WAZUH = MONITOR / "wazuh"


# ---------- helpers ---------------------------------------------------------


_CACHE_BASH = None


def _find_bash():
    """Localiza bash.exe preferentemente Git Bash sobre el wrapper WSL
    (C:\\Windows\\System32\\bash.exe). Cachea el resultado tras la 1ª llamada.
    """
    global _CACHE_BASH
    if _CACHE_BASH:
        return _CACHE_BASH
    candidatos = [
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Program Files\Git\bin\bash.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Git\usr\bin\bash.exe"),
        r"C:\Program Files (x86)\Git\usr\bin\bash.exe",
    ]
    for ruta in candidatos:
        if os.path.isfile(ruta):
            _CACHE_BASH = ruta
            return ruta
    hallado = shutil.which("bash")
    if hallado and "System32" not in hallado:
        _CACHE_BASH = hallado
        return hallado
    _CACHE_BASH = "bash"
    return "bash"


def _bash_env():
    """Devuelve un env con las utilidades Unix de Git Bash (dirname, cat, grep,
    find, awk, sed, ...) en el PATH. Sin esto, invocar bash.exe desde Python
    no carga /etc/profile y los scripts fallan con `dirname: command not found`.
    """
    env = os.environ.copy()
    bash_exe = _find_bash()
    extras = []
    if bash_exe and os.path.isfile(bash_exe):
        usr_bin = os.path.dirname(bash_exe)                 # ...\Git\usr\bin
        git_root = os.path.dirname(os.path.dirname(usr_bin))  # ...\Git
        extras = [usr_bin, os.path.join(git_root, "bin"),
                  os.path.join(git_root, "mingw64", "bin")]
    extras = [p for p in extras if os.path.isdir(p)]
    if extras:
        env["PATH"] = os.pathsep.join(extras) + os.pathsep + env.get("PATH", "")
    return env


def _bash(script_rel, *args):
    """Ejecuta un script bash de `monitorizacion/` reenviando stdout/stderr.

    `script_rel` es relativo a `MONITOR` (ej. 'captura/preparar_router.sh').
    Devuelve el returncode.
    """
    bash_exe = _find_bash()
    cmd = [bash_exe, str(MONITOR / script_rel), *args]
    print(f"[*] $ {bash_exe} {MONITOR / script_rel} {' '.join(args)}".rstrip())
    try:
        rc = subprocess.run(cmd, cwd=RAIZ, env=_bash_env(),
                            check=False).returncode
        if rc != 0:
            print(f"[!] El script devolvió código {rc}.")
        return rc
    except FileNotFoundError:
        print(f"[!] 'bash' no encontrado. Instala Git for Windows (incluye Git Bash).")
        return 127


def _docker_ok():
    return run_cmd("docker info", check=False, capture=True) is not None


def _container_up(nombre):
    out = run_cmd(f'docker ps --filter name=^{nombre}$ --format "{{{{.Names}}}}"',
                  check=False)
    return bool(out) and nombre in out


def _volume_exists(nombre):
    return run_cmd(f"docker volume inspect {nombre}", check=False) is not None


def _image_exists(nombre):
    return run_cmd(f"docker image inspect {nombre}", check=False) is not None


def _http_code(url, insecure=False, timeout=3):
    """Devuelve el código HTTP de `url` o None si no responde."""
    ctx = ssl._create_unverified_context() if insecure else None
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.getcode()
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def _plcs_esperados():
    """Numero de PLCs vivos por tipo: (modbus, s7, dnp3).

    Cuenta los contenedores `plc_agua_N` / `plc_s7_N` / `plc_dnp3_N` que estan
    arriba. Usado para saber a cuantos PLCs OT deberia tener conexion Node-RED.
    """
    out = run_cmd('docker ps --format "{{.Names}}"', check=False) or ""
    nombres = out.splitlines()
    n_mb = sum(1 for n in nombres if n.startswith("plc_agua_"))
    n_s7 = sum(1 for n in nombres if n.startswith("plc_s7_"))
    n_dnp3 = sum(1 for n in nombres if n.startswith("plc_dnp3_"))
    return n_mb, n_s7, n_dnp3


def _conexiones_tcp_nodered():
    """Lee /proc/net/tcp dentro de nodered_scada_1 y devuelve el conjunto de
    IPs destino con estado ESTABLISHED hacia los puertos OT (502, 102).
    Devuelve ({ip_502}, {ip_102}) o (set(), set()) si no se puede leer.
    """
    out = run_cmd('docker exec nodered_scada_1 cat /proc/net/tcp',
                  check=False) or ""
    if not out:
        return set(), set()
    ips_502, ips_102 = set(), set()
    for i, linea in enumerate(out.splitlines()):
        if i == 0:
            continue  # cabecera
        campos = linea.split()
        if len(campos) < 4:
            continue
        # Columna 2 = remote address (hex IP:port), columna 3 = state hex
        hex_rem = campos[2]
        state = campos[3]
        if state != "01" or ":" not in hex_rem:  # 01 = TCP_ESTABLISHED
            continue
        try:
            hex_ip, hex_port = hex_rem.split(":")
            ip = ".".join(str(int(hex_ip[i:i+2], 16)) for i in (6, 4, 2, 0))
            port = int(hex_port, 16)
        except ValueError:
            continue
        if port == 502:
            ips_502.add(ip)
        elif port == 102:
            ips_102.add(ip)
    return ips_502, ips_102


def _esperar_nodered_estable(timeout_s=90):
    """Bloquea hasta que Node-RED tenga TCP ESTABLISHED a los N PLCs Modbus y S7
    desplegados. Imprime puntos de progreso. Devuelve True si llego al estado
    estable, False si expiro el timeout.

    Pensado para [E]: evita capturar un baseline antes de que Node-RED haya
    completado los retries iniciales de conexion.
    """
    n_mb, n_s7, _ = _plcs_esperados()
    if n_mb == 0 and n_s7 == 0:
        return True  # no hay nada que esperar
    print(f"[*] Esperando polling Node-RED estable: {n_mb} Modbus + {n_s7} S7...",
          end="", flush=True)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        ips_502, ips_102 = _conexiones_tcp_nodered()
        if len(ips_502) >= n_mb and len(ips_102) >= n_s7:
            print(f" OK (:502={len(ips_502)}, :102={len(ips_102)})")
            return True
        print(".", end="", flush=True)
        time.sleep(3)
    ips_502, ips_102 = _conexiones_tcp_nodered()
    print(f" TIMEOUT (:502={len(ips_502)}/{n_mb}, :102={len(ips_102)}/{n_s7})")
    return False


def _esperar_dashboard(seg=90):
    """Espera a que el dashboard de Wazuh responda. Imprime puntos cada 2s."""
    print(f"[*] Esperando dashboard Wazuh (hasta {seg}s)...", end="", flush=True)
    deadline = time.time() + seg
    while time.time() < deadline:
        code = _http_code("https://localhost:5601", insecure=True, timeout=2)
        if code in (200, 302):
            print(f" responde {code}")
            return True
        print(".", end="", flush=True)
        time.sleep(2)
    print(" TIMEOUT")
    print("[!] El dashboard no respondió. Investiga: docker logs wazuh.dashboard")
    return False


# ---------- opción [8] ------------------------------------------------------


def arrancar_todo():
    """Lab OT (3+3+3 por defecto, kali_mode=control) + MASQUERADE + Wazuh."""
    print("""
======================================================================
  [8] Arrancar TODO — Lab OT (Purdue) + Wazuh SIEM
======================================================================
""")
    if not _docker_ok():
        print("[!] Docker no responde. Arranca Docker Desktop y vuelve a intentarlo.")
        return

    # 1. Despliegue del lab -------------------------------------------------
    ya_arriba = _container_up("router_gw") and _container_up("nodered_scada_1")
    if ya_arriba:
        n_mb, n_s7, n_dnp3 = read_scenario_sizes()
        print(f"[i] Lab detectado arriba ({n_mb}MB + {n_s7}S7 + {n_dnp3}DNP3).")
        rsp = input("    ¿Saltar despliegue del lab? [S/n]: ").strip().lower()
        if rsp in ("", "s", "y"):
            pass
        else:
            ya_arriba = False

    if not ya_arriba:
        print("\n[*] Tamaños (Enter = valor por defecto):")
        n_mb = int(input("   PLCs Modbus [3]: ").strip() or "3")
        n_s7 = int(input("   PLCs S7     [3]: ").strip() or "3")
        n_dnp3 = int(input("   PLCs DNP3   [3]: ").strip() or "3")
        save_flows_file("nodered_data_scada_1/flows.json",
                        num_modbus_a=n_mb, num_s7_b=n_s7, num_dnp3_c=n_dnp3)
        # Asegurar que el directorio de eve.json live existe antes de
        # arrancar suricata_ids (si no, el bind mount lo crea como fichero
        # fantasma propiedad root y Suricata no puede escribir).
        (MONITOR / "suricata" / "salida" / "live").mkdir(parents=True, exist_ok=True)
        deploy_scenario(n_mb, n_s7, n_dnp3, kali_mode="control")

    # 2. MASQUERADE + mapeo iface -------------------------------------------
    print("\n[*] [B] MASQUERADE + mapeo de interfaces en router_gw...")
    _bash("captura/preparar_router.sh")

    # 3. Modo kali = control ------------------------------------------------
    write_kali_mode_marker("control")

    # 4. Wazuh --------------------------------------------------------------
    print("\n[*] [C] Levantando stack Wazuh (manager + indexer + dashboard)...")
    if _container_up("wazuh.manager") and _container_up("wazuh.dashboard"):
        print("[i] Wazuh ya está arriba. Saltando up.")
    else:
        _arrancar_wazuh()
        _esperar_dashboard(90)

    # 5. Suricata IDS en vivo ---------------------------------------------
    if _container_up("suricata_ids"):
        print("\n[*] [D] Suricata IDS en vivo: OK (ya arriba).")
    else:
        print("\n[!] [D] suricata_ids no esta arriba. Revisa `docker ps -a`"
              " y los logs: `docker logs suricata_ids`.")

    # 6. Import del dashboard TFM OT en Wazuh (idempotente) ---------------
    print("\n[*] [E] Importando dashboard TFM OT en Wazuh...")
    rc = _bash("wazuh/dashboards/importar_dashboard.sh")
    if rc != 0:
        print("[i] Import del dashboard fallo; puedes importarlo manualmente"
              " desde Stack Management -> Saved Objects.")

    _resumen_arranque()


def _arrancar_wazuh():
    if not (WAZUH / ".env").exists():
        ejemplo = WAZUH / ".env.example"
        if ejemplo.exists():
            print("[!] monitorizacion/wazuh/.env no existe; copiando .env.example.")
            (WAZUH / ".env").write_text(ejemplo.read_text(encoding="utf-8"),
                                        encoding="utf-8")
        else:
            print("[!] Falta monitorizacion/wazuh/.env y no hay .env.example. Abortando.")
            return

    if not _volume_exists("wazuh_certs"):
        print("[*] Volumen wazuh_certs no existe; generando certificados...")
        run_cmd(
            f'docker compose -f "{WAZUH / "generate-certs.yml"}" run --rm generator',
            check=False, capture=False)

    run_cmd(
        f'docker compose --env-file "{WAZUH / ".env"}" '
        f'-f "{WAZUH / "docker-compose.yml"}" up -d',
        check=False, capture=False)


def _resumen_arranque():
    print("""
======================================================================
  [OK] Lab + Wazuh arriba
======================================================================
  Dashboard Wazuh:   https://localhost:5601  (admin / SecretPassword)
  Dashboard ataques: http://localhost:8888   (opción [6] si no está)
  Node-RED SCADA:    http://localhost:1880/ui

  Siguiente paso:
    [A] para verificar la salud del laboratorio (15 chequeos).
    [9] para lanzar el pipeline completo de ataques + ingesta Wazuh.
======================================================================
""")


# ---------- opción [9] ------------------------------------------------------


def pipeline_completo():
    """Baseline (opt-in) + 10 ataques + flujos + KB + Suricata + agregador."""
    print("""
======================================================================
  [9] Pipeline completo — captura, Suricata offline, ingesta Wazuh
======================================================================
""")
    if not (_container_up("router_gw") and _container_up("wazuh.manager")):
        print("[!] Falta infraestructura (router_gw o wazuh.manager). Corre [8] primero.")
        return

    # 0. ¿Relanzar ataques o reutilizar pcaps ya en disco? -----------------
    print("\n¿Qué quieres hacer con los pcaps?")
    print("  [a] Relanzar los 10 ataques (genera pcaps nuevos, ~15-20 min).")
    print("  [b] Reutilizar los pcaps existentes en 'capturas pcap/'.")
    while True:
        rsp = input("Elige [a/b] (por defecto b): ").strip().lower()
        if rsp in ("", "a", "b"):
            relanzar_ataques = (rsp == "a")
            break
        print("Opción no válida.")

    if relanzar_ataques:
        rsp_base = input("\n¿Lanzar baseline de 1 hora antes de los ataques? [s/N]: ").strip().lower()
        if rsp_base in ("s", "y"):
            print("\n[*] [1/8] Baseline 3600 s...")
            _bash("captura/capturar.sh", "baseline", "3600")
        print("\n[*] [2/8] Ejecutando los 10 escenarios de ataque (~15-20 min)...")
        _bash("captura/ejecutar_todos.sh")
    else:
        base_pcaps = RAIZ / "capturas pcap"
        n_pcaps = sum(1 for _ in base_pcaps.rglob("*.pcap")) if base_pcaps.exists() else 0
        if n_pcaps == 0:
            print("[!] No hay pcaps en 'capturas pcap/'. Vuelve a entrar en [9] y elige [a].")
            return
        print(f"\n[i] Reutilizando {n_pcaps} pcaps existentes en 'capturas pcap/'.")

    # 2. PCAP -> IPFIX ------------------------------------------------------
    print("\n[*] [3/8] PCAP -> flujos IPFIX (softflowd + nfdump)...")
    _bash("flujos/pcap2flujos.sh")

    # 3. KB desde baseline --------------------------------------------------
    baseline_dir = MONITOR / "flujos" / "salida" / "baseline"
    baseline_glob = baseline_dir / "*.json"
    hay_baseline = any(baseline_dir.glob("*.json"))
    inv_path = MONITOR / "kb" / "inventario.json"
    c2_path = MONITOR / "kb" / "c2_mailbox.yaml"
    if hay_baseline:
        if inv_path.exists():
            print("\n[*] [4/8] Construyendo KB desde baseline + inventario inferido...")
            run_cmd(
                f'python "{MONITOR / "kb" / "construir_kb.py"}" '
                f'--baseline "{baseline_glob}" '
                f'--inventario "{inv_path}" '
                f'--c2-mailbox "{c2_path}" '
                f'--salida "{MONITOR / "kb"}"',
                check=False, capture=False)
        else:
            print("\n[!] [4/8] No hay inventario (corre [E] antes para aprender roles).")
            print("    Usando fallback --legacy-hardcoded (deprecado).")
            run_cmd(
                f'python "{MONITOR / "kb" / "construir_kb.py"}" '
                f'--baseline "{baseline_glob}" '
                f'--c2-mailbox "{c2_path}" '
                f'--legacy-hardcoded '
                f'--salida "{MONITOR / "kb"}"',
                check=False, capture=False)
    else:
        print("\n[i] [4/8] Sin baseline (no NDJSON en flujos/salida/baseline/); salto KB.")

    # 4. Listas CDB a Wazuh -------------------------------------------------
    print("\n[*] [5/8] Sincronizando listas CDB a Wazuh...")
    _bash("wazuh/sync_listas.sh")

    # 5. Suricata offline + resumen ----------------------------------------
    print("\n[*] [6/8] Suricata offline sobre todos los pcaps...")
    _bash("suricata/evaluar.sh")
    print("\n[*] [7/8] Resumen Suricata por escenario:")
    run_cmd(f'python "{MONITOR / "suricata" / "resumen.py"}"',
            check=False, capture=False)

    # 6. Agregador para Wazuh logcollector ---------------------------------
    print("\n[*] [8/8] Concatenando eve.json y flujos para Wazuh...")
    _bash("wazuh/agregar_eve.sh")

    print("""
======================================================================
  [OK] Pipeline completo terminado
======================================================================
  Dashboard Wazuh:   https://localhost:5601
  Las alertas aparecen en Security Events (rule.id:86601).
  Usa [A] para contar las alertas indexadas.
======================================================================
""")


# ---------- opción [E] — modo entrenamiento --------------------------------


def modo_entrenamiento(duracion_s: int = 1800):
    """Fase de aprendizaje dinamico: captura N segundos sin ataques,
    infiere roles de todos los dispositivos vistos en el trafico, y regenera
    la KB + variables Suricata a partir de ese inventario.

    Siempre pausa kali_nodo durante la ventana para que no contamine el
    baseline (segunda linea de defensa: inferir_roles.py tambien excluye su
    IP por si el pause falla).
    """
    print("""
======================================================================
  [E] Modo entrenamiento — aprendizaje dinamico de roles
======================================================================
""")
    if not (_container_up("router_gw") and _container_up("broker_mqtt")):
        print("[!] El lab debe estar arriba. Corre [8] primero.")
        return
    if duracion_s < 60:
        print(f"[!] Duracion demasiado corta ({duracion_s}s). Minimo recomendado: 300s.")
        rsp = input("    ¿Continuar igualmente? [s/N]: ").strip().lower()
        if rsp not in ("s", "y"):
            return

    print(f"[*] Ventana de entrenamiento: {duracion_s}s "
          f"(~{duracion_s//60} min). Sin ataques, kali pausado.")

    # 0. Esperar a que Node-RED (SCADA) tenga el polling estable con TODOS los
    # PLCs OT. Sin esto, un [E] lanzado justo tras [8] captura solo el polling
    # a los PLCs que conectaron rapido y deja los retrasados con pocos flujos
    # (caeran a `desconocido` o requeriran bajar el umbral manualmente).
    if not _esperar_nodered_estable(timeout_s=90):
        rsp = input("[!] Node-RED aun no tiene polling estable a todos los PLCs. "
                    "¿Continuar? [s/N]: ").strip().lower()
        if rsp not in ("s", "y"):
            print("[*] Abortando. Reintenta [E] en ~1 min.")
            return

    # 1. Silenciar kali: parar dashboard de ataques y pausar el contenedor.
    kali_arriba = _container_up("kali_nodo")
    if kali_arriba:
        print("[*] Pausando kali_nodo (atacante) para asegurar baseline limpio...")
        run_cmd("docker exec -d kali_nodo pkill -f 'app.py'", check=False)
        run_cmd("docker pause kali_nodo", check=False)
    else:
        print("[i] kali_nodo no estaba arriba; sin accion.")

    # 2. Pausar Suricata-IDS para que no genere alertas durante el training
    # y para que relea `vars_kb.yaml` tras el restart (el `include:` solo
    # se procesa en el arranque, SIGHUP no basta).
    suricata_arriba = _container_up("suricata_ids")
    if suricata_arriba:
        print("[*] Pausando suricata_ids durante el training...")
        run_cmd("docker pause suricata_ids", check=False)
    else:
        print("[i] suricata_ids no estaba arriba; sin accion.")

    try:
        rc = _bash("entrenamiento/entrenar.sh", str(duracion_s))
        if rc != 0:
            print(f"[!] entrenar.sh devolvio codigo {rc}. Revisa los mensajes arriba.")
    finally:
        if kali_arriba:
            print("\n[*] Reanudando kali_nodo...")
            run_cmd("docker unpause kali_nodo", check=False)
        if suricata_arriba:
            # Restart (no unpause) para que relea vars_kb.yaml nuevo.
            print("[*] Reiniciando suricata_ids para aplicar vars_kb.yaml nuevo...")
            run_cmd("docker unpause suricata_ids", check=False)
            run_cmd("docker restart suricata_ids", check=False)

    # Resumen final — leer inventario y mostrar roles descubiertos
    inv_path = MONITOR / "kb" / "inventario.json"
    if inv_path.exists():
        try:
            inv = json.loads(inv_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            print(f"[!] No se pudo leer el inventario: {e}")
            return
        role_index = inv.get("role_index", {}) or {}
        md = inv.get("metadata", {}) or {}
        print("""
======================================================================
  [OK] Modo entrenamiento terminado
======================================================================""")
        print(f"  Flujos leidos: {md.get('n_flujos_leidos', '?')}  "
              f"| IPs vistas: {md.get('n_ips_vistas', '?')}  "
              f"| Silentes: {md.get('n_ips_silentes', '?')}")
        print("  Roles descubiertos:")
        for rol, ips in sorted(role_index.items()):
            print(f"    {rol}: {len(ips)}  [{', '.join(ips)}]")
        print(f"\n  Inventario : {inv_path}")
        print(f"  Reporte    : {MONITOR / 'kb' / 'inventario_vs_hosts.md'}")
        print(f"  Vars Suri  : {MONITOR / 'suricata' / 'vars_kb.yaml'}")
        print("""
  Siguiente paso: [9] para lanzar ataques (reutilizara este inventario).
======================================================================
""")


# ---------- opción [D] — demo detección en vivo ---------------------------


# Catalogo de demos para [D]. Cada entrada: (nombre, modulo, funcion, kwargs,
# descripcion, sids_esperados).
_DEMOS = {
    "1": {
        "nombre": "recon_modbus",
        "modulo": "recon",
        "funcion": "modbus_discover",
        "kwargs": {"target": "192.168.10.10"},
        "descripcion": "Escaneo FC=43 (Read Device ID) contra plc_agua_1",
        "sids": [2000100, 2000001],
    },
    "2": {
        "nombre": "modbus_write",
        "modulo": "modbus_msf",
        "funcion": "write_register",
        "kwargs": {"target": "192.168.10.10", "data_address": "20",
                   "data": "9999", "unit_id": "1"},
        "descripcion": "Escritura Modbus FC=6 (Write Single Register) a plc_agua_1",
        "sids": [2000011, 2000001],
    },
    "3": {
        "nombre": "s7_write_setpoint",
        "modulo": "s7_snap7",
        "funcion": "write_setpoint",
        "kwargs": {"target": "192.168.30.10"},
        "descripcion": "Escritura S7 setpoint a plc_s7_1 desde no-SCADA",
        "sids": [2000120, 2000002],
    },
    "4": {
        "nombre": "c2_frostygoop",
        "modulo": "c2_modbus",
        "funcion": "beacon",
        "kwargs": {"target": "192.168.10.11"},
        "descripcion": "Beacon C2 FrostyGoop a plc_agua_2 (buzon)",
        "sids": [2000160, 2000161, 2000162],
    },
}


def demo_deteccion_en_vivo():
    """[D] Elige un ataque, lo lanza desde kali_nodo, imprime la URL del
    dashboard Wazuh filtrada por timestamp. Pensado para la defensa oral.
    """
    import datetime as _dt

    print("""
======================================================================
  [D] Demo detección en vivo — ataque + alertas en Wazuh
======================================================================
""")
    if not _container_up("suricata_ids"):
        print("[!] suricata_ids no esta arriba. Corre [8] primero.")
        return
    if not _container_up("wazuh.manager"):
        print("[!] wazuh.manager no esta arriba. Corre [8] primero.")
        return
    if not _container_up("kali_nodo"):
        print("[!] kali_nodo no esta arriba. Corre [8] primero.")
        return

    print("Escenarios disponibles:")
    for k, d in _DEMOS.items():
        print(f"  [{k}] {d['nombre']:20s}  {d['descripcion']}")
    print("  [0] Volver")
    opt = input("\nElige escenario [1-4]: ").strip()
    if opt == "0" or opt not in _DEMOS:
        return

    demo = _DEMOS[opt]
    # Timestamp con 30 s de margen hacia atras para absorber skew de reloj
    # host/contenedor y asegurar que la alerta cae dentro de la ventana.
    t0 = _dt.datetime.utcnow() - _dt.timedelta(seconds=30)
    t0_iso = t0.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Construir el comando _tfm_run.py con los kwargs
    kw_cli = " ".join(f"{k}={v}" for k, v in demo["kwargs"].items()
                      if k != "target")
    tgt = demo["kwargs"].get("target", "")
    cmd = (f"python3 /ataques/_tfm_run.py {demo['modulo']} {demo['funcion']} "
           f"--target {tgt} {kw_cli}").strip()

    print(f"\n[*] T0 = {t0_iso}  (hora de referencia del filtro Wazuh)")
    print(f"[*] Ejecutando en kali_nodo:")
    print(f"    {cmd}")
    run_cmd(f'docker exec -d kali_nodo {cmd}', check=False)

    print("\n[*] Esperando 10 s para que la alerta se indexe en Wazuh...")
    time.sleep(10)

    # Dashboard custom TFM OT (importado via importar_dashboard.sh). Como
    # fallback, mantener la kuery para pegar manualmente en Threat Hunting
    # si el import no se ha ejecutado.
    url_tfm = "https://localhost:5601/app/dashboards#/view/tfm-ot-dashboard"
    url_threat = "https://localhost:5601/app/threat-hunting"

    sids_str = ", ".join(f"SID {s}" for s in demo["sids"])
    print(f"""
======================================================================
  [OK] Ataque {demo['nombre']} lanzado — comprobar en Wazuh
======================================================================
  Hora del ataque (UTC) : {t0_iso}
  SIDs esperados        : {sids_str}

  Dashboard TFM OT (KPIs + top PLCs + protocolo + tabla alertas):
    {url_tfm}
  Credenciales: admin / SecretPassword
  Ajusta el rango temporal (arriba derecha) a los ultimos 15 min.

  Alternativa (Threat Hunting nativo de Wazuh):
    {url_threat}
    Pega esta kuery: data.alert.signature_id:>=2000000
======================================================================
""")


# ---------- opción [A] — verificar ------------------------------------------


def _check(fn):
    """Decorator: convierte (titulo, status, detalle) en tupla uniforme."""
    def wrap():
        try:
            titulo, status, detalle = fn()
        except Exception as e:
            return (fn.__doc__ or fn.__name__, "FAIL", f"excepción: {e}")
        return (titulo, status, detalle)
    return wrap


@_check
def _c01_lab():
    out = run_cmd(
        'docker ps --format "{{.Names}}"', check=False) or ""
    nombres = out.splitlines()
    objetivo = ["router_gw", "nodered_scada_1", "broker_mqtt",
                "kali_nodo", "srv_empresa"]
    presentes = [n for n in objetivo if n in nombres]
    plcs = sum(1 for n in nombres if n.startswith(("plc_agua_", "plc_s7_", "plc_dnp3_")))
    detalle = f"{len(presentes)}/{len(objetivo)} containers clave + {plcs} PLCs"
    status = "OK" if len(presentes) == len(objetivo) and plcs >= 3 else "FAIL"
    return ("Lab OT (containers clave + PLCs)", status, detalle)


@_check
def _c02_masquerade():
    out = run_cmd(
        "docker exec router_gw iptables -t nat -L POSTROUTING -n", check=False) or ""
    n = out.count("MASQUERADE")
    status = "OK" if n >= 3 else "FAIL"
    detalle = f"{n} reglas MASQUERADE (esperado ≥3)"
    if status == "FAIL":
        detalle += "  → bash monitorizacion/captura/preparar_router.sh"
    return ("iptables MASQUERADE en router_gw", status, detalle)


@_check
def _c03_ping_plcs():
    objetivos = {"Modbus": "192.168.10.10", "S7": "192.168.30.10", "DNP3": "192.168.40.10"}
    ok = []
    for proto, ip in objetivos.items():
        r = run_cmd(f"docker exec nodered_scada_1 ping -c1 -W2 {ip}",
                    check=False)
        if r is not None and "1 received" in r:
            ok.append(proto)
    status = "OK" if len(ok) == 3 else ("WARN" if ok else "FAIL")
    return ("SCADA → PLCs ping (10.10 / 30.10 / 40.10)", status,
            f"{len(ok)}/3 responden: {', '.join(ok) or 'ninguno'}")


@_check
def _c04_nodered():
    code = _http_code("http://localhost:1880", timeout=3)
    status = "OK" if code == 200 else "FAIL"
    return ("Node-RED UI (http://localhost:1880)", status, f"HTTP {code}")


@_check
def _c05_kali_mode():
    mode_file = RAIZ / "ataques" / ".mode"
    if not mode_file.exists():
        return ("Modo kali_nodo en ataques/.mode", "FAIL", "fichero no existe")
    modo = mode_file.read_text(encoding="utf-8").strip()
    if modo != "control":
        return ("Modo kali_nodo en ataques/.mode", "WARN",
                f"actual='{modo}', [8] fija 'control'")
    # ruta 10.0/24 en kali_nodo
    r = run_cmd("docker exec kali_nodo ip route", check=False) or ""
    tiene_ruta = "192.168.10.0/24" in r
    detalle = f"modo={modo}, ruta OT en kali_nodo={'sí' if tiene_ruta else 'NO'}"
    return ("Modo kali_nodo en ataques/.mode", "OK" if tiene_ruta else "WARN", detalle)


@_check
def _c06_wazuh_containers():
    out = run_cmd(
        'docker ps --filter name=wazuh --format "{{.Names}}"',
        check=False) or ""
    nombres = set(out.split())
    esperados = {"wazuh.manager", "wazuh.indexer", "wazuh.dashboard"}
    faltan = esperados - nombres
    status = "OK" if not faltan else "FAIL"
    detalle = f"{len(nombres & esperados)}/3 arriba"
    if faltan:
        detalle += f" (faltan: {', '.join(sorted(faltan))})"
    return ("Wazuh stack (manager + indexer + dashboard)", status, detalle)


@_check
def _c07_wazuh_dashboard():
    code = _http_code("https://localhost:5601", insecure=True, timeout=5)
    status = "OK" if code in (200, 302) else "FAIL"
    return ("Dashboard Wazuh HTTPS (localhost:5601)", status, f"HTTP {code}")


@_check
def _c08_alertas():
    # count de alertas rule.id:86601 (Suricata built-in)
    cmd = ('docker exec wazuh.indexer curl -k -s -u admin:SecretPassword '
           '"https://localhost:9200/wazuh-alerts-4.x-*/_count?q=rule.id:86601"')
    r = run_cmd(cmd, check=False) or ""
    # respuesta JSON: {"count":123,...}
    import re
    m = re.search(r'"count"\s*:\s*(\d+)', r)
    n = int(m.group(1)) if m else -1
    if n < 0:
        return ("Alertas Suricata indexadas (rule.id:86601)", "FAIL",
                "indexer no responde / credenciales inválidas")
    if n == 0:
        return ("Alertas Suricata indexadas (rule.id:86601)", "WARN",
                "0 (aún no has lanzado ataques → corre [9])")
    return ("Alertas Suricata indexadas (rule.id:86601)", "OK",
            f"{n} documentos")


@_check
def _c09_pcaps():
    base = RAIZ / "capturas pcap"
    if not base.exists():
        return ("PCAPs capturados en 'capturas pcap/'", "WARN", "directorio aún no existe")
    n = sum(1 for _ in base.rglob("*.pcap"))
    status = "OK" if n >= 4 else "WARN"
    return ("PCAPs capturados en 'capturas pcap/'", status, f"{n} pcaps")


@_check
def _c10_eve():
    base = MONITOR / "suricata" / "salida"
    n = sum(1 for _ in base.rglob("eve.json")) if base.exists() else 0
    status = "OK" if n >= 1 else "WARN"
    return ("eve.json procesados por Suricata offline", status, f"{n} ficheros")


@_check
def _c11_all_eve():
    f = WAZUH / "all_eve.json"
    if not f.exists():
        return ("Agregado all_eve.json para Wazuh", "WARN", "no existe (corre [9])")
    try:
        n = sum(1 for _ in f.open(encoding="utf-8"))
    except Exception:
        n = 0
    status = "OK" if n > 0 else "WARN"
    return ("Agregado all_eve.json para Wazuh", status, f"{n} líneas")


@_check
def _c12_flujos():
    base = MONITOR / "flujos" / "salida"
    n = sum(1 for _ in base.rglob("*.csv")) if base.exists() else 0
    status = "OK" if n >= 1 else "WARN"
    return ("Flujos IPFIX en flujos/salida/", status, f"{n} CSV")


@_check
def _c13_kb():
    kb = MONITOR / "kb"
    cdbs = [kb / x for x in ("comunicaciones_ok.cdb", "plcs.cdb",
                             "funciones_modbus_ok.cdb")]
    um = kb / "umbrales.json"
    presentes = [p.name for p in cdbs + [um] if p.exists() and p.stat().st_size > 0]
    status = "OK" if len(presentes) == 4 else "WARN"
    return ("KB generada (3 CDBs + umbrales.json)", status,
            f"{len(presentes)}/4 presentes")


@_check
def _c14_dashboard_ataques():
    code = _http_code("http://localhost:8888", timeout=3)
    if code == 200:
        return ("Dashboard de ataques (localhost:8888)", "OK", "HTTP 200")
    return ("Dashboard de ataques (localhost:8888)", "WARN",
            f"HTTP {code} (menú [6] para arrancarlo)")


@_check
def _c15_imagen_monitor():
    if _image_exists("tfm_monitor"):
        return ("Imagen Docker tfm_monitor construida", "OK", "presente")
    return ("Imagen Docker tfm_monitor construida", "WARN",
            "no existe (se construirá al correr pcap2flujos.sh)")


@_check
def _c16_inventario():
    """Inventario aprendido en [E] disponible y coherente."""
    kb = MONITOR / "kb"
    inv_path = kb / "inventario.json"
    titulo = "Inventario inferido (modo entrenamiento [E])"
    if not inv_path.exists():
        return (titulo, "WARN", "inventario.json no existe; corre [E] para generarlo")
    try:
        inv = json.loads(inv_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return (titulo, "FAIL", f"inventario.json corrupto: {e}")
    role_index = inv.get("role_index", {}) or {}
    md = inv.get("metadata", {}) or {}
    n_ips = md.get("n_ips_vistas", 0)
    tiene_scada  = bool(role_index.get("scada"))
    tiene_broker = bool(role_index.get("broker_mqtt"))
    tiene_plc = (bool(role_index.get("plc_modbus"))
                 or bool(role_index.get("plc_s7"))
                 or bool(role_index.get("plc_dnp3")))
    status = "OK" if (tiene_scada and tiene_broker and tiene_plc) else "WARN"
    detalle = (f"{n_ips} IPs | scada={len(role_index.get('scada', []))} "
               f"broker={len(role_index.get('broker_mqtt', []))} "
               f"plc_mb={len(role_index.get('plc_modbus', []))} "
               f"plc_s7={len(role_index.get('plc_s7', []))} "
               f"plc_dnp3={len(role_index.get('plc_dnp3', []))} "
               f"gw_dnp3={len(role_index.get('gateway_dnp3', []))}")
    return (titulo, status, detalle)


@_check
def _c17_suricata_live():
    """Suricata-IDS en vivo escribiendo eve.json."""
    titulo = "Suricata-IDS en vivo (contenedor suricata_ids)"
    if not _container_up("suricata_ids"):
        return (titulo, "FAIL", "suricata_ids no esta Up")
    eve = MONITOR / "suricata" / "salida" / "live" / "eve.json"
    if not eve.exists():
        return (titulo, "WARN",
                f"{eve} no existe (contenedor arriba pero sin trafico aun?)")
    try:
        mtime = eve.stat().st_mtime
    except OSError:
        return (titulo, "FAIL", f"no se pudo stat {eve}")
    edad = time.time() - mtime
    if edad < 60:
        return (titulo, "OK",
                f"eve.json actualizado hace {int(edad)}s (Suricata escribe)")
    return (titulo, "WARN",
            f"eve.json con {int(edad)}s de antiguedad (sin trafico reciente?)")


@_check
def _c18_dashboard_tfm():
    """Dashboard custom TFM OT importado en Wazuh."""
    titulo = "Dashboard TFM OT (saved_objects/dashboard/tfm-ot-dashboard)"
    # Login en host (POST pequeno con cookie, schannel OK) + GET saved object.
    ctx = ssl._create_unverified_context()
    cookies = []
    login_body = b'{"username":"admin","password":"SecretPassword"}'
    try:
        req = urllib.request.Request(
            "https://localhost:5601/auth/login?security_payload=true",
            data=login_body, method="POST")
        req.add_header("osd-xsrf", "true")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            for ck in r.headers.get_all("Set-Cookie") or []:
                cookies.append(ck.split(";", 1)[0])
    except (urllib.error.URLError, OSError) as e:
        return (titulo, "WARN", f"no se pudo loguear en el dashboard: {e}")

    if not cookies:
        return (titulo, "WARN", "login OK pero sin cookies; dashboard reiniciando?")

    try:
        req = urllib.request.Request(
            "https://localhost:5601/api/saved_objects/dashboard/tfm-ot-dashboard")
        req.add_header("Cookie", "; ".join(cookies))
        req.add_header("osd-xsrf", "true")
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            code = r.getcode()
    except urllib.error.HTTPError as e:
        code = e.code
    except (urllib.error.URLError, OSError) as e:
        return (titulo, "WARN", f"no se pudo consultar saved_object: {e}")

    if code == 200:
        return (titulo, "OK", "importado y accesible via /app/dashboards")
    if code == 404:
        return (titulo, "WARN",
                "no importado; corre `bash monitorizacion/wazuh/dashboards/importar_dashboard.sh`")
    return (titulo, "WARN", f"respuesta inesperada ({code})")


_CHECKS = [_c01_lab, _c02_masquerade, _c03_ping_plcs, _c04_nodered,
           _c05_kali_mode, _c06_wazuh_containers, _c07_wazuh_dashboard,
           _c08_alertas, _c09_pcaps, _c10_eve, _c11_all_eve, _c12_flujos,
           _c13_kb, _c14_dashboard_ataques, _c15_imagen_monitor,
           _c16_inventario, _c17_suricata_live, _c18_dashboard_tfm]


def verificar():
    """18 chequeos de salud. Devuelve 0 si no hay FAIL, 1 en caso contrario."""
    total = len(_CHECKS)
    print(f"""
======================================================================
  [A] Verificar estado del laboratorio — {total} chequeos
======================================================================
""")
    if not _docker_ok():
        print("[FAIL] Docker no responde. Arranca Docker Desktop.")
        return 1

    oks = warns = fails = 0
    for i, chk in enumerate(_CHECKS, 1):
        titulo, status, detalle = chk()
        marca = {"OK": "[ OK ]", "WARN": "[WARN]", "FAIL": "[FAIL]"}[status]
        print(f"  {marca}  {i:2d}/{total}  {titulo}")
        if detalle:
            print(f"             - {detalle}")
        oks += status == "OK"
        warns += status == "WARN"
        fails += status == "FAIL"

    print(f"\n----------------------------------------------------------------------")
    print(f"  Resultado: {oks}/{total} OK, {warns} warnings, {fails} fallos")
    print(f"----------------------------------------------------------------------")
    if fails == 0 and warns == 0:
        print("  Todo verde. Lab y pipeline operativos.")
    elif fails == 0:
        print("  Infraestructura OK; los warnings son fases del pipeline aún")
        print("  no ejecutadas (normal si no has corrido [9] todavía).")
    else:
        print("  Hay fallos. Revisa los mensajes '[FAIL]' arriba.")
    return 0 if fails == 0 else 1
