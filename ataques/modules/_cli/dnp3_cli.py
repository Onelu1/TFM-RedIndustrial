#!/usr/bin/env python3
"""
Entrypoint CLI del modulo DNP3, lanzable como subproceso con proxychains.
"""

import argparse
import os
import sys

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from modules import dnp3_pydnp3  # noqa: E402


def _sink(line):
    print(line, flush=True)


def main():
    p = argparse.ArgumentParser(prog="dnp3_cli")
    p.add_argument("action", choices=["read", "write"])
    p.add_argument("--target", required=True)
    p.add_argument("--port", type=int, default=20000)
    p.add_argument("--index", type=int, default=0)
    p.add_argument("--value", default="true")
    args = p.parse_args()

    if args.action == "read":
        dnp3_pydnp3._do_read(args.target, args.port, sink=_sink)
    elif args.action == "write":
        dnp3_pydnp3._do_write(
            args.target, args.port, args.index, args.value, sink=_sink)


if __name__ == "__main__":
    main()
