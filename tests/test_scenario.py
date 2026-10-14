"""Tests de regresión del generador de escenario.

Garantizan que `scenario.compose.generate_docker_compose` y
`scenario.nodered_flow.save_flows_file` producen los mismos bytes que las
fixtures de referencia. Si un refactor cambia el output (aunque sea un espacio),
el test falla y hay que decidir si actualizar la fixture o rebotar el cambio.

Para regenerar fixtures a propósito, borra `tests/fixtures/` y ejecuta:
    python -m tests.regen_fixtures
"""

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


SCENARIOS = [
    # (nombre, num_modbus, num_s7, num_dnp3, kali_mode)
    ("mb1_s71_dnp1_empresa", 1, 1, 1, "empresa"),
    ("mb1_s71_dnp1_control", 1, 1, 1, "control"),
    ("mb3_s72_dnp0_empresa", 3, 2, 0, "empresa"),
    ("mb0_s70_dnp0_empresa", 0, 0, 0, "empresa"),
    ("mb3_s73_dnp3_control", 3, 3, 3, "control"),
]


@pytest.fixture
def chdir_root(monkeypatch):
    """Ejecuta cada test con cwd = raíz del proyecto (como main.py)."""
    monkeypatch.chdir(ROOT)


@pytest.fixture(params=SCENARIOS, ids=lambda c: c[0])
def scenario(request):
    name, nmb, ns7, ndnp, mode = request.param
    return {"name": name, "nmb": nmb, "ns7": ns7, "ndnp": ndnp, "mode": mode}


def _run_generation(scenario):
    from scenario.compose import generate_docker_compose
    from scenario.nodered_flow import save_flows_file

    save_flows_file(
        "nodered_data_scada_1/flows.json",
        scenario["nmb"], scenario["ns7"], scenario["ndnp"],
    )
    generate_docker_compose(
        scenario["nmb"], scenario["ns7"], scenario["ndnp"],
        kali_mode=scenario["mode"],
    )


def _read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def test_compose_matches_fixture(scenario, chdir_root):
    _run_generation(scenario)
    actual = _read_bytes("docker-compose.generated.yml")
    expected = _read_bytes(FIXTURES / scenario["name"] / "compose.yml")
    assert actual == expected, (
        f"compose cambió para {scenario['name']}: "
        f"{len(actual)} vs {len(expected)} bytes"
    )


def test_flows_matches_fixture(scenario, chdir_root):
    _run_generation(scenario)
    actual = _read_bytes("nodered_data_scada_1/flows.json")
    expected = _read_bytes(FIXTURES / scenario["name"] / "flows.json")
    assert actual == expected, (
        f"flows cambió para {scenario['name']}: "
        f"{len(actual)} vs {len(expected)} bytes"
    )


def test_mosquitto_matches_fixture(scenario, chdir_root):
    _run_generation(scenario)
    actual = _read_bytes("mosquitto.conf")
    expected = _read_bytes(FIXTURES / scenario["name"] / "mosquitto.conf")
    assert actual == expected


def test_mode_matches_fixture(scenario, chdir_root):
    _run_generation(scenario)
    actual = _read_bytes("ataques/.mode")
    expected = _read_bytes(FIXTURES / scenario["name"] / "mode")
    assert actual == expected


def test_read_scenario_sizes_roundtrip(chdir_root):
    """Lo que genera generate_docker_compose debe ser legible por read_scenario_sizes."""
    from scenario.compose import generate_docker_compose, read_scenario_sizes

    for nmb, ns7, ndnp in [(1, 1, 1), (3, 2, 0), (0, 0, 0), (3, 3, 3)]:
        generate_docker_compose(nmb, ns7, ndnp, kali_mode="empresa")
        got = read_scenario_sizes()
        assert got == (nmb, ns7, ndnp), f"roundtrip falló para ({nmb},{ns7},{ndnp}): got {got}"


def test_acl_files_are_written(chdir_root):
    """Cada PLC Modbus debe tener su ACL con `expected_uid = i`."""
    from scenario.compose import generate_docker_compose

    generate_docker_compose(3, 0, 0, kali_mode="empresa")
    for i in (1, 2, 3):
        p = ROOT / "openplc" / f"acl_plc_agua_{i}.conf"
        content = p.read_text(encoding="utf-8")
        assert f"expected_uid = {i}" in content


def test_main_reexports_public_api():
    """La receta manual del README de ataques/ (import main; main.generate_docker_compose(...))
    debe seguir funcionando."""
    import sys
    sys.path.insert(0, str(ROOT))
    import main  # noqa: E402

    for name in [
        "run_cmd", "build_s7_image_if_needed", "build_openplc_image_if_needed",
        "setup_vulnerable_samba", "generate_nodered_flow", "save_flows_file",
        "read_scenario_sizes", "write_kali_mode_marker", "generate_docker_compose",
        "deploy_scenario", "clean_environment", "switch_kali_mode", "ask_kali_mode",
        "main_menu",
    ]:
        assert hasattr(main, name), f"main.{name} debería estar expuesto"
