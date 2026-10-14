#!/usr/bin/env python3
"""
Entrypoint CLI del módulo S7, lanzable como subproceso.

Se invoca desde el dashboard así:
    [proxychains] python3 -m modules._cli.s7_cli <accion> --target <ip> ...

Imprime a stdout; es el dashboard (via runner.run_command) quien captura esa
salida y la vuelca al fichero de evidencia. Separarlo en subproceso es lo que
permite que `proxychains` intercepte los connect() de python-snap7 (C).
"""

import argparse
import os
import sys

# Permitir importar los módulos y config aunque el entrypoint se invoque como
# "python3 -m modules._cli.s7_cli" desde /ataques.
_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from modules import s7_snap7  # noqa: E402


def _sink(line):
    print(line, flush=True)


def main():
    p = argparse.ArgumentParser(prog="s7_cli")
    p.add_argument("action", choices=["read_db1", "write_setpoint", "write_marcha"])
    p.add_argument("--target", required=True)
    p.add_argument("--rack", type=int, default=0)
    p.add_argument("--slot", type=int, default=1)
    p.add_argument("--valor", default=None,
                    help="float para write_setpoint, true/false para write_marcha")
    args = p.parse_args()

    if args.action == "read_db1":
        s7_snap7._do_read_db1(args.target, args.rack, args.slot, sink=_sink)
    elif args.action == "write_setpoint":
        valor = float(args.valor) if args.valor is not None else 75.5
        s7_snap7._do_write_setpoint(args.target, args.rack, args.slot, valor, sink=_sink)
    elif args.action == "write_marcha":
        valor = args.valor if args.valor is not None else "true"
        s7_snap7._do_write_marcha(args.target, args.rack, args.slot, valor, sink=_sink)


if __name__ == "__main__":
    main()
