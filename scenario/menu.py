#!/usr/bin/env python3
"""Interfaz CLI del orquestador: menú principal y preguntas interactivas.

:func:`main_menu` es el bucle que lee la opción `[0-7]` y delega en los demás
módulos del paquete `scenario`. :func:`ask_kali_mode` es la única pregunta
compartida con `switch_kali_mode` (de ahí vivir en este módulo propio).
"""

import sys

from .deploy import clean_environment, deploy_scenario, switch_kali_mode
from .nodered_flow import save_flows_file
from .shell import run_cmd


def ask_kali_mode():
    """Pregunta al usuario dónde desplegar kali_nodo. Devuelve 'empresa' o 'control'."""
    print("""
   Ubicación de kali_nodo (nodo atacante):
     [a] red_empresa  (192.168.60.66) · atacante externo. Requiere pivote SSH
                       por srv_empresa para alcanzar los PLCs OT.
     [b] red_control  (192.168.20.66) · atacante dentro de SCADA. Acceso
                       directo a las zonas OT por router_gw.""")
    while True:
        v = input("   Elige [a/b] (por defecto a=empresa): ").strip().lower()
        if v in ("", "a", "empresa"):
            return "empresa"
        if v in ("b", "control"):
            return "control"
        print("   Opción no válida.")


def main_menu():
    while True:
        print("""
======================================================================
  ORQUESTADOR OT/ICS CON SEGMENTACIÓN PURDUE (TFM CIBERSEGURIDAD)
======================================================================
  [1] Desplegar Escenario Modbus TCP (Zona OT A)
  [2] Desplegar Escenario Siemens S7 (Zona OT B)
  [3] Desplegar Escenario DNP3 (Zona OT C)
  [4] Desplegar Escenario Híbrido Completo (S7 + Modbus + DNP3)
  [5] Limpiar Entorno (Detener contenedores)
  [6] Levantar dashboard de ataques (kali_nodo -> http://localhost:8888)
  [7] Cambiar modo kali_nodo (empresa <-> control) sin tocar los PLCs
  [0] Salir
======================================================================
        """)
        opt = input("Selecciona una opción [0-7]: ").strip()

        if opt == "1":
            n_mb = int(input("Número de PLCs Modbus TCP: "))
            kali_mode = ask_kali_mode()
            save_flows_file("nodered_data_scada_1/flows.json", num_modbus_a=n_mb, num_s7_b=0, num_dnp3_c=0)
            deploy_scenario(n_mb, 0, 0, kali_mode=kali_mode)
            input("\nPresiona ENTER para continuar...")

        elif opt == "2":
            n_s7 = int(input("Número de PLCs Siemens S7: "))
            kali_mode = ask_kali_mode()
            save_flows_file("nodered_data_scada_1/flows.json", num_modbus_a=0, num_s7_b=n_s7, num_dnp3_c=0)
            deploy_scenario(0, n_s7, 0, kali_mode=kali_mode)
            input("\nPresiona ENTER para continuar...")

        elif opt == "3":
            n_dnp3 = int(input("Número de PLCs DNP3: "))
            kali_mode = ask_kali_mode()
            save_flows_file("nodered_data_scada_1/flows.json", num_modbus_a=0, num_s7_b=0, num_dnp3_c=n_dnp3)
            deploy_scenario(0, 0, n_dnp3, kali_mode=kali_mode)
            input("\nPresiona ENTER para continuar...")

        elif opt == "4":
            n_mb = int(input("Número de PLCs Modbus TCP (Zona A): "))
            n_s7 = int(input("Número de PLCs Siemens S7 (Zona B): "))
            n_dnp3 = int(input("Número de PLCs DNP3 (Zona C): "))
            kali_mode = ask_kali_mode()
            save_flows_file("nodered_data_scada_1/flows.json", num_modbus_a=n_mb, num_s7_b=n_s7, num_dnp3_c=n_dnp3)
            deploy_scenario(n_mb, n_s7, n_dnp3, kali_mode=kali_mode)
            input("\nPresiona ENTER para continuar...")

        elif opt == "5":
            clean_environment()
            input("\nPresiona ENTER para continuar...")

        elif opt == "6":
            print("\n[*] Arrancando el dashboard de ataques dentro de kali_nodo...")
            # -d: detached, para no bloquear la terminal del menú
            run_cmd("docker exec -d kali_nodo python3 /ataques/web/app.py", check=False)
            print("[✔] Dashboard disponible en http://localhost:8888")
            print("    (Si falla, revisa que kali_nodo esté arriba y /ataques montado.)")
            input("\nPresiona ENTER para continuar...")

        elif opt == "7":
            switch_kali_mode()
            input("\nPresiona ENTER para continuar...")

        elif opt == "0":
            sys.exit(0)
