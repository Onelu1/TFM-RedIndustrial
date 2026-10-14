#!/usr/bin/env python3
"""Entrypoint CLI del laboratorio OT/ICS (TFM — modelo Purdue / ISA-95).

Toda la lógica vive ahora en el paquete `scenario/`:

- `scenario.shell`         — utilidad `run_cmd`.
- `scenario.docker_images` — build de imágenes Docker locales.
- `scenario.samba`         — pivote vulnerable (claves SSH + share).
- `scenario.compose`       — `docker-compose.generated.yml`, ACLs, `.mode`.
- `scenario.nodered_flow`  — flow SCADA Node-RED.
- `scenario.deploy`        — orquestación end-to-end + cambio de modo kali.
- `scenario.menu`          — menú interactivo `[0-7]`.

Mantengo re-exportados los nombres públicos que la receta manual del README de
`ataques/` consume (p. ej. `main.generate_docker_compose(3, 3, 3, kali_mode='control')`),
para no romper esa documentación tras la refactorización.
"""

# Compatibilidad: `python -c "import main; main.generate_docker_compose(...)"` y
# cualquier otro import previo que apuntara a `main.<símbolo>` sigue funcionando.
from scenario.compose import (  # noqa: F401
    generate_docker_compose,
    read_scenario_sizes,
    write_kali_mode_marker,
)
from scenario.deploy import (  # noqa: F401
    clean_environment,
    deploy_scenario,
    switch_kali_mode,
)
from scenario.docker_images import (  # noqa: F401
    build_openplc_image_if_needed,
    build_s7_image_if_needed,
)
from scenario.menu import ask_kali_mode, main_menu  # noqa: F401
from scenario.nodered_flow import (  # noqa: F401
    generate_nodered_flow,
    save_flows_file,
)
from scenario.samba import setup_vulnerable_samba  # noqa: F401
from scenario.shell import run_cmd  # noqa: F401


if __name__ == "__main__":
    main_menu()
