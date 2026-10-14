#!/usr/bin/env python3
"""
Motor DNP3-over-TCP pure Python (IEEE 1815 / IEC 62351).

Implementa lo justo del protocolo DNP3 para realizar:
  1. Integrity Poll (Read Class 0 Static Data)
  2. Direct Operate CROB (Control Relay Output Block)

Solo usa socket + struct de la biblioteca estandar.  Funciona en cualquier
version de Python y es compatible con proxychains (intercepta connect()).

Referencia de direccionamiento por defecto (igual que gateway_dnp3.py):
  Master address  = 1
  Outstation addr = 10
  Puerto TCP      = 20000
"""

import socket
import struct
import time

# =========================================================================
# CRC-16/DNP  (poly 0x3D65, reflected 0xA6BC, init 0, xor-out 0xFFFF)
# =========================================================================

_CRC_TABLE = []


def _init_crc_table():
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
        _CRC_TABLE.append(crc & 0xFFFF)


_init_crc_table()


def _crc(data: bytes) -> int:
    crc = 0x0000
    for b in data:
        crc = _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFF


# =========================================================================
# Data-Link Layer
# =========================================================================

_START = b"\x05\x64"


def _build_frame(user_data: bytes, dest: int, src: int,
                 ctrl: int = 0xC4) -> bytes:
    length = 5 + len(user_data)
    hdr = struct.pack("<BBBBHH", 0x05, 0x64, length, ctrl, dest, src)
    frame = hdr + struct.pack("<H", _crc(hdr))
    off = 0
    while off < len(user_data):
        blk = user_data[off : off + 16]
        frame += blk + struct.pack("<H", _crc(blk))
        off += 16
    return frame



def _frame_total_bytes(user_data_len: int) -> int:
    full, rem = divmod(user_data_len, 16)
    return 10 + full * 18 + (rem + 2 if rem else 0)


def _strip_frame(raw: bytes) -> bytes:
    if len(raw) < 10 or raw[0:2] != _START:
        raise ValueError("Trama DNP3 invalida (cabecera)")
    hdr_crc = struct.unpack_from("<H", raw, 8)[0]
    if hdr_crc != _crc(raw[0:8]):
        raise ValueError("CRC de cabecera incorrecto")
    ud_len = raw[2] - 5
    if ud_len <= 0:
        return b""
    user_data = b""
    pos = 10
    rem = ud_len
    while rem > 0:
        bsz = min(rem, 16)
        if pos + bsz + 2 > len(raw):
            raise ValueError("Trama truncada")
        blk = raw[pos : pos + bsz]
        blk_crc = struct.unpack_from("<H", raw, pos + bsz)[0]
        if blk_crc != _crc(blk):
            raise ValueError("CRC de bloque de datos incorrecto")
        user_data += blk
        pos += bsz + 2
        rem -= bsz
    return user_data


# =========================================================================
# Recepcion de tramas desde un socket TCP
# =========================================================================

def _recv_frame(sock: socket.socket, timeout: float = 10) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while True:
        chunk = sock.recv(512)
        if not chunk:
            raise ConnectionError("Conexion cerrada por el outstation")
        buf += chunk
        idx = buf.find(_START)
        if idx >= 0:
            buf = buf[idx:]
            break
        if len(buf) > 2048:
            buf = buf[-2:]
    while len(buf) < 10:
        chunk = sock.recv(10 - len(buf))
        if not chunk:
            raise ConnectionError("Conexion cerrada (cabecera incompleta)")
        buf += chunk
    ud_len = buf[2] - 5
    if ud_len > 0:
        total = _frame_total_bytes(ud_len)
        while len(buf) < total:
            chunk = sock.recv(total - len(buf))
            if not chunk:
                raise ConnectionError("Conexion cerrada (datos incompletos)")
            buf += chunk
    return buf


def _try_recv_frame(sock: socket.socket, timeout: float = 2):
    """Intenta recibir una trama; devuelve None si no hay datos."""
    try:
        return _recv_frame(sock, timeout)
    except (socket.timeout, OSError):
        return None


# =========================================================================
# Application Layer: construccion
# =========================================================================

def _app_read_class0(seq: int = 0) -> bytes:
    ac = 0xC0 | (seq & 0x0F)
    return bytes([ac, 0x01, 0x3C, 0x01, 0x06])


def _app_confirm(seq: int, uns: bool = False) -> bytes:
    ac = 0xC0 | (seq & 0x0F)
    if uns:
        ac |= 0x10  # UNS bit required when confirming unsolicited
    return bytes([ac, 0x00])


def _app_direct_operate_crob(index: int, latch_on: bool, seq: int = 0) -> bytes:
    ac = 0xC0 | (seq & 0x0F)
    fc = 0x05
    code = 0x03 if latch_on else 0x04
    payload = struct.pack("<BB", ac, fc)
    payload += struct.pack("<BBB", 12, 1, 0x28)  # G12V1 qualifier
    payload += struct.pack("<H", 1)               # count = 1
    payload += struct.pack("<H", index)            # index prefix
    payload += struct.pack("<BB", code, 1)         # control code, CROB count
    payload += struct.pack("<I", 1000)             # on-time ms
    payload += struct.pack("<I", 1000)             # off-time ms
    payload += struct.pack("<B", 0)                # status
    return payload


# =========================================================================
# Sesion DNP3: handshake + transaccion
# =========================================================================

def _log(sink, msg):
    if sink:
        sink(msg)


def _describe_frame(raw: bytes) -> str:
    """Descripcion legible de una trama DLL cruda."""
    if len(raw) < 10:
        return f"[{len(raw)} bytes, demasiado corta]"
    ctrl = raw[3]
    dest = raw[4] | (raw[5] << 8)
    src = raw[6] | (raw[7] << 8)
    ud_len = raw[2] - 5
    parts = [f"DLL ctrl=0x{ctrl:02X} dest={dest} src={src} ud_len={ud_len}"]
    dir_bit = (ctrl >> 7) & 1
    prm = (ctrl >> 6) & 1
    fc = ctrl & 0x0F
    parts.append(f"DIR={dir_bit} PRM={prm} FC={fc}")
    if ud_len > 0:
        try:
            ud = _strip_frame(raw)
            if ud:
                transport = ud[0]
                app = ud[1:]
                parts.append(f"Transport=0x{transport:02X}")
                if len(app) >= 2:
                    parts.append(f"AppFC=0x{app[1]:02X}")
                    if len(app) >= 4:
                        parts.append(f"IIN=0x{app[2]:02X}{app[3]:02X}")
                parts.append(f"AppHex={app.hex()}")
        except ValueError as e:
            parts.append(f"CRC-err: {e}")
    return " | ".join(parts)


def _drain_unsolicited(sock, dest, src, sink=None, timeout=3):
    """Drena respuestas unsolicited pendientes tras conectar (sin Reset Link)."""
    _log(sink, "    [dnp3] Drenando datos pendientes del outstation...")
    drained = 0
    deadline = time.time() + timeout

    while time.time() < deadline:
        raw = _try_recv_frame(sock, timeout=min(1.5, deadline - time.time()))
        if raw is None:
            break

        drained += 1
        _log(sink, f"    [dnp3] DRAIN #{drained}: {_describe_frame(raw)}")

        ud_len = raw[2] - 5
        if ud_len > 0:
            try:
                ud = _strip_frame(raw)
                app = ud[1:] if len(ud) > 1 else b""
                if len(app) >= 2 and app[1] == 0x82:
                    seq = app[0] & 0x0F
                    con = bool(app[0] & 0x20)
                    if con:
                        cf = _app_confirm(seq, uns=True)
                        cf_frame = _build_frame(b"\xC0" + cf, dest, src)
                        sock.sendall(cf_frame)
                        _log(sink, f"    [dnp3] -> CONFIRM UNS (seq={seq})")
            except ValueError:
                pass

    _log(sink, f"    [dnp3] Drain completado ({drained} tramas)")


def _transact(sock, request_frame, dest, src, sink=None, timeout=8):
    """Envia un request y devuelve la app-layer de la respuesta solicitada."""
    _log(sink, f"    [dnp3] TX request: {request_frame.hex()}")
    sock.sendall(request_frame)

    deadline = time.time() + timeout
    attempts = 0

    while time.time() < deadline and attempts < 15:
        attempts += 1
        remaining = max(0.5, deadline - time.time())
        raw = _try_recv_frame(sock, timeout=remaining)
        if raw is None:
            break

        _log(sink, f"    [dnp3] RX frame #{attempts}: {_describe_frame(raw)}")

        ud_len = raw[2] - 5
        if ud_len <= 0:
            _log(sink, "    [dnp3]    (trama sin datos, ignorando)")
            continue

        try:
            ud = _strip_frame(raw)
        except ValueError as e:
            _log(sink, f"    [dnp3]    CRC error: {e}")
            continue

        app = ud[1:] if len(ud) > 1 else b""
        if len(app) < 2:
            continue

        fc = app[1]
        ac = app[0]
        uns = bool(ac & 0x10)
        con = bool(ac & 0x20)
        seq = ac & 0x0F

        # Unsolicited (FC=0x82 o bit UNS): confirmar y seguir
        if fc == 0x82 or uns:
            _log(sink, f"    [dnp3]    Unsolicited (seq={seq}), descartando")
            if con:
                cf = _app_confirm(seq, uns=True)
                cf_frame = _build_frame(b"\xC0" + cf, dest, src)
                sock.sendall(cf_frame)
                _log(sink, f"    [dnp3]    -> CONFIRM UNS (seq={seq})")
            continue

        # Solicited response (FC=0x81)
        if fc == 0x81:
            _log(sink, f"    [dnp3]    Solicited response OK ({len(app)} bytes)")
            return app

        _log(sink, f"    [dnp3]    FC=0x{fc:02X} inesperado, ignorando")

    raise TimeoutError("No se recibio respuesta solicitada del outstation")


# =========================================================================
# Application Layer: parsing de respuestas
# =========================================================================

def _parse_objects(app: bytes, sink=None) -> dict:
    if len(app) < 4:
        raise ValueError("Respuesta de aplicacion demasiado corta")
    fc = app[1]
    iin1, iin2 = app[2], app[3]
    res = {"fc": fc, "iin1": iin1, "iin2": iin2,
           "binary": {}, "analog": {},
           "binary_in": {}, "analog_in": {},
           "crob_status": None}

    _log(sink, f"    [parse] FC=0x{fc:02X} IIN=0x{iin1:02X}{iin2:02X}")

    if iin2 & 0x01:
        _log(sink, "    [parse] ERROR: funcion no soportada")
        return res
    if iin2 & 0x02:
        _log(sink, "    [parse] ERROR: objeto desconocido")
        return res

    pos = 4
    while pos + 2 < len(app):
        grp = app[pos]
        var = app[pos + 1]
        qual = app[pos + 2]
        pos += 3

        prefix_code = (qual >> 4) & 0x07
        range_code = qual & 0x0F
        prefix_sz = [0, 1, 2, 4][prefix_code] if prefix_code < 4 else 0

        _log(sink, f"    [parse] ObjHdr: G{grp}V{var} Q=0x{qual:02X} "
                    f"(prefix={prefix_sz}B, range_code={range_code})")

        start_idx = 0
        count = 0
        if range_code == 0:          # 1-byte start-stop
            if pos + 2 > len(app):
                break
            start_idx = app[pos]
            stop = app[pos + 1]
            count = stop - start_idx + 1
            pos += 2
            _log(sink, f"    [parse]   start={start_idx} stop={stop} count={count}")
        elif range_code == 1:        # 2-byte start-stop
            if pos + 4 > len(app):
                break
            start_idx = struct.unpack_from("<H", app, pos)[0]; pos += 2
            stop = struct.unpack_from("<H", app, pos)[0]; pos += 2
            count = stop - start_idx + 1
            _log(sink, f"    [parse]   start={start_idx} stop={stop} count={count}")
        elif range_code == 7:        # 1-byte count
            if pos + 1 > len(app):
                break
            count = app[pos]; pos += 1
            _log(sink, f"    [parse]   count={count}")
        elif range_code == 8:        # 2-byte count
            if pos + 2 > len(app):
                break
            count = struct.unpack_from("<H", app, pos)[0]; pos += 2
            _log(sink, f"    [parse]   count={count}")
        elif range_code == 6:        # all objects
            _log(sink, "    [parse]   qualifier=all, skipping")
            continue
        else:
            _log(sink, f"    [parse]   range_code={range_code} no soportado, parando")
            break

        # Determinar tamano de cada objeto segun grupo y variacion
        obj_sz = _object_size(grp, var)
        if obj_sz is None:
            _log(sink, f"    [parse]   G{grp}V{var} tamano desconocido, parando")
            break

        for i in range(count):
            idx = start_idx + i
            if prefix_sz:
                if pos + prefix_sz > len(app):
                    break
                if prefix_sz == 1:
                    idx = app[pos]
                elif prefix_sz == 2:
                    idx = struct.unpack_from("<H", app, pos)[0]
                else:
                    idx = struct.unpack_from("<I", app, pos)[0]
                pos += prefix_sz

            if pos + obj_sz > len(app):
                break

            # --- Binary Output Status (G10) ---
            if grp == 10 and var in (1, 2):
                flags = app[pos]; pos += 1
                val = bool(flags & 0x80)
                res["binary"][idx] = val
                _log(sink, f"    [parse]   BOUT[{idx}] flags=0x{flags:02X} -> {val}")

            # --- Analog Output Status (G40) ---
            elif grp == 40:
                flags = app[pos]; pos += 1
                if var in (1, 3):
                    val = struct.unpack_from("<i", app, pos)[0]; pos += 4
                elif var in (2, 4):
                    val = struct.unpack_from("<h", app, pos)[0]; pos += 2
                elif var == 5:
                    val = struct.unpack_from("<f", app, pos)[0]; pos += 4
                elif var == 6:
                    val = struct.unpack_from("<d", app, pos)[0]; pos += 8
                else:
                    pos += obj_sz - 1; continue
                res["analog"][idx] = float(val)
                _log(sink, f"    [parse]   AOUT[{idx}] = {val} flags=0x{flags:02X}")

            # --- Analog Input (G30) ---
            elif grp in (30, 32):
                flags = app[pos]; pos += 1
                if var in (1, 3):
                    val = struct.unpack_from("<i", app, pos)[0]; pos += 4
                elif var in (2, 4):
                    val = struct.unpack_from("<h", app, pos)[0]; pos += 2
                elif var == 5:
                    val = struct.unpack_from("<f", app, pos)[0]; pos += 4
                elif var == 6:
                    val = struct.unpack_from("<d", app, pos)[0]; pos += 8
                else:
                    pos += obj_sz - 1; continue
                res["analog_in"][idx] = float(val)
                _log(sink, f"    [parse]   AIN[{idx}] = {val} flags=0x{flags:02X}")

            # --- Binary Input (G1, G2) ---
            elif grp in (1, 2) and var == 2:
                flags = app[pos]; pos += 1
                val = bool(flags & 0x80)
                res["binary_in"][idx] = val
                _log(sink, f"    [parse]   BIN[{idx}] flags=0x{flags:02X} -> {val}")

            # --- CROB response (G12 V1) ---
            elif grp == 12 and var == 1:
                cc = app[pos]; pos += 1
                cnt = app[pos]; pos += 1
                pos += 4   # on-time
                pos += 4   # off-time
                st = app[pos]; pos += 1
                res["crob_status"] = st
                _log(sink, f"    [parse]   CROB cc=0x{cc:02X} status={st}")

            # --- Grupos que solo necesitamos saltar ---
            else:
                pos += obj_sz
                if i == 0:
                    _log(sink, f"    [parse]   G{grp}V{var} skipping {count} objects")

    _log(sink, f"    [parse] Resultado: binary={res['binary']} analog={res['analog']}")
    return res


def _object_size(grp, var):
    """Devuelve el tamano en bytes de un objeto DNP3 segun grupo y variacion."""
    # Binary points: 1 byte flags (var 2) or 1 byte packed (var 1)
    if grp in (1, 2, 3, 4, 10, 11) and var in (1, 2):
        return 1
    # Counters / Frozen Counters: flags + value
    if grp in (20, 21, 22, 23, 30, 32, 40, 42):
        if var in (1, 3):   return 5   # flags(1) + int32(4)
        if var in (2, 4):   return 3   # flags(1) + int16(2)
        if var == 5:        return 5   # flags(1) + float32(4)
        if var == 6:        return 9   # flags(1) + float64(8)
        if var == 7:        return 5   # flags(1) + uint32(4)
        if var == 8:        return 3   # flags(1) + uint16(2)
    # CROB (G12V1): 11 bytes
    if grp == 12 and var == 1:
        return 11
    # Time objects (G50/G51): skip
    if grp in (50, 51):
        if var in (1, 3):   return 6   # uint48 ms
        if var in (2, 4):   return 10  # uint48 + uint32 interval
    return None


# =========================================================================
# API publica
# =========================================================================

LABELS_BIN = {
    0: "Estado Bomba Principal (%QX0.0)",
    1: "Alarma Sobrepresion (%QX0.1)",
    2: "Modo Manual",
    3: "Comando Bomba (cmd_bomba)",
}
LABELS_ANA = {
    0: "Temp. Caldera 1 (%QW0)",
    1: "Temp. Caldera 2 (%QW1)",
}


def _gateway_name_for(ip):
    """Deriva el nombre del contenedor gateway_dnp3_X a partir de la IP del PLC."""
    try:
        last_octet = int(ip.rstrip().split(".")[-1])
        idx = last_octet - 9
        if 1 <= idx <= 10:
            return f"gateway_dnp3_{idx}"
    except (ValueError, IndexError):
        pass
    return None


def _docker_post(path, timeout=10):
    """POST al Docker Engine API via Unix socket (no requiere docker CLI)."""
    import socket as _s
    try:
        sock = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect("/var/run/docker.sock")
        req = f"POST {path} HTTP/1.0\r\nHost: localhost\r\n\r\n"
        sock.sendall(req.encode())
        resp = sock.recv(4096)
        sock.close()
        return b"204" in resp or b"304" in resp
    except Exception:
        return False


def _stop_gateway(ip, sink=None):
    """Para el gateway_dnp3 que ocupa la conexion al outstation."""
    name = _gateway_name_for(ip)
    if not name:
        return
    _log(sink, f"    [dnp3] Parando {name} para liberar conexion DNP3...")
    if _docker_post(f"/containers/{name}/stop?t=2"):
        _log(sink, f"    [dnp3] {name} parado.")
        time.sleep(1)
    else:
        _log(sink, f"    [dnp3] WARN: no se pudo parar {name} (sin Docker socket?)")


def _start_gateway(ip, sink=None):
    """Rearranca el gateway_dnp3 tras la operacion."""
    name = _gateway_name_for(ip)
    if not name:
        return
    if _docker_post(f"/containers/{name}/start"):
        _log(sink, f"    [dnp3] {name} rearrancado.")
    else:
        _log(sink, f"    [dnp3] WARN: no se pudo rearrancar {name}")


def dnp3_read(ip, port=20000, master_addr=1, outstation_addr=10,
              timeout=8, sink=None):
    """Integrity poll (Class 0) sobre un outstation DNP3."""
    _stop_gateway(ip, sink)
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            _drain_unsolicited(sock, outstation_addr, master_addr, timeout=3)

            app = _app_read_class0(seq=1)
            frame = _build_frame(b"\xC0" + app, outstation_addr, master_addr)

            app_resp = _transact(sock, frame, outstation_addr, master_addr,
                                 timeout=timeout)
            return _parse_objects(app_resp)
        finally:
            sock.close()
    finally:
        _start_gateway(ip, sink)


def dnp3_write_crob(ip, port=20000, index=0, latch_on=True,
                    master_addr=1, outstation_addr=10, timeout=8, sink=None):
    """Envia un Direct Operate CROB a un outstation DNP3."""
    _stop_gateway(ip, sink)
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            _drain_unsolicited(sock, outstation_addr, master_addr, timeout=3)

            app = _app_direct_operate_crob(index, latch_on, seq=1)
            frame = _build_frame(b"\xC0" + app, outstation_addr, master_addr)

            app_resp = _transact(sock, frame, outstation_addr, master_addr,
                                 timeout=timeout)
            result = _parse_objects(app_resp)
            return result.get("crob_status") == 0
        finally:
            sock.close()
    finally:
        _start_gateway(ip, sink)
