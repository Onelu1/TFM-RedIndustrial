"""Regenera las fixtures de tests/fixtures/ con el output actual.

Ejecutar solo cuando un cambio **intencional** modifica el output. Añade los
ficheros resultantes al commit del cambio.

Uso:
    python -m tests.regen_fixtures
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scenario.compose import generate_docker_compose  # noqa: E402
from scenario.nodered_flow import save_flows_file  # noqa: E402
from tests.test_scenario import SCENARIOS  # noqa: E402


def main():
    import os
    os.chdir(ROOT)
    for name, nmb, ns7, ndnp, mode in SCENARIOS:
        save_flows_file("nodered_data_scada_1/flows.json", nmb, ns7, ndnp)
        generate_docker_compose(nmb, ns7, ndnp, kali_mode=mode)
        fx = ROOT / "tests" / "fixtures" / name
        fx.mkdir(parents=True, exist_ok=True)
        pairs = [
            ("docker-compose.generated.yml", "compose.yml"),
            ("nodered_data_scada_1/flows.json", "flows.json"),
            ("mosquitto.conf", "mosquitto.conf"),
            ("ataques/.mode", "mode"),
        ]
        for src, dst in pairs:
            data = Path(src).read_bytes()
            (fx / dst).write_bytes(data)
        print(f"[fixture] {name}: {sum((fx / dst).stat().st_size for _, dst in pairs)} bytes")


if __name__ == "__main__":
    main()
