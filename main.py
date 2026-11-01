#!/usr/bin/env python3
"""Orquestador CLI del laboratorio OT/ICS (modelo Purdue). La lógica vive en
el paquete `scenario/`; este fichero solo lanza el menú y reexporta los
nombres públicos que consume la receta manual del README de `ataques/`."""

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
