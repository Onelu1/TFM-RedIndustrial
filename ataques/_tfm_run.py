#!/usr/bin/env python3
"""Wrapper CLI para invocar funciones de modulos del toolkit sin tener que
escapar comillas en bash. Uso:

    python3 /ataques/_tfm_run.py <modulo> <funcion> [--target IP] [kw=val ...]

Ejemplos:
    python3 /ataques/_tfm_run.py recon modbus_discover --target 192.168.10.10
    python3 /ataques/_tfm_run.py modbus_msf write_register \\
        --target 192.168.10.10 port=502 data_address=20 data=9999 unit_id=1
"""
import importlib
import sys


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    sys.path.insert(0, "/ataques")

    modulo_nombre = sys.argv[1]
    funcion = sys.argv[2]
    kw = {"sink": print}
    i = 3
    while i < len(sys.argv):
        tok = sys.argv[i]
        if tok == "--target":
            kw["target"] = sys.argv[i + 1]
            i += 2
            continue
        if "=" in tok:
            k, v = tok.split("=", 1)
            # casting basico
            if v.lower() in ("true", "false"):
                v = v.lower() == "true"
            else:
                try:
                    v = int(v)
                except ValueError:
                    try:
                        v = float(v)
                    except ValueError:
                        pass
            kw[k] = v
        i += 1

    m = importlib.import_module(f"modules.{modulo_nombre}")
    f = getattr(m, funcion)
    f(**kw)


if __name__ == "__main__":
    main()
