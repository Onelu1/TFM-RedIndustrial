"""Paquete que agrupa la lógica del orquestador del laboratorio Purdue.

Separa `main.py` (originalmente monolítico, ~950 líneas) en módulos cohesivos:

- :mod:`scenario.shell`        — utilidad `run_cmd` sobre subprocess.
- :mod:`scenario.docker_images` — compilación de imágenes Docker locales.
- :mod:`scenario.samba`         — pivote Samba y claves SSH vulnerables.
- :mod:`scenario.compose`       — generación de `docker-compose.generated.yml`,
  ACLs Modbus, `mosquitto.conf` y marcador `ataques/.mode`.
- :mod:`scenario.nodered_flow`  — construcción del flow Node-RED SCADA.
- :mod:`scenario.deploy`        — despliegue end-to-end y cambio de modo kali.
- :mod:`scenario.menu`          — interacción CLI (menú principal).

El entrypoint sigue siendo `python main.py`, que delega en :func:`scenario.menu.main_menu`.
Comportamiento preservado byte a byte: mismos ficheros generados, mismas rutas,
mismo menú `[0-7]`.
"""
