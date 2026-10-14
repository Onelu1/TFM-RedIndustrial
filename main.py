#!/usr/bin/env python3
"""
Orquestador CLI de Testbed OT/ICS (TFM)
Modelado de red segmentada según el Modelo Purdue (ISA-95).
Soporta Siemens S7, Modbus TCP, DNP3-MQTT y auto-configuración de SCADA Node-RED (Dashboard 2.0).
"""

import os
import sys
import json
import time
import subprocess

def run_cmd(cmd, check=True, capture=True):
    """Ejecuta comandos del sistema con captura de errores."""
    try:
        res = subprocess.run(
            cmd, shell=True, check=check, text=True, 
            encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None
        )
        return res.stdout.strip() if capture else ""
    except subprocess.CalledProcessError as e:
        if capture and e.stderr:
            print(f"[!] Error ejecutando el comando: {cmd}\n[!] {e.stderr.strip()}")
        return None

def build_s7_image_if_needed():
    image = run_cmd("docker images -q mi_plc_siemens")
    if not image:
        print("[*] Compilando imagen 'mi_plc_siemens' desde 'siemens_s7/Dockerfile'...")
        path_s7 = os.path.join(os.getcwd(), "siemens_s7")
        if not os.path.exists(path_s7):
            print(f"[!] ERROR: No existe el directorio {path_s7}")
            return False
        run_cmd(f"docker build -t mi_plc_siemens {path_s7}", capture=False)
        print("[✔] Imagen 'mi_plc_siemens' compilada correctamente.")
    return True

def build_openplc_image_if_needed():
    image = run_cmd("docker images -q mi_openplc")
    if not image:
        print("[*] Compilando imagen 'mi_openplc' desde 'openplc/Dockerfile' (puede llevar un tiempo)...")
        path_oplc = os.path.join(os.getcwd(), "openplc")
        if not os.path.exists(path_oplc):
            print(f"[!] ERROR: No existe el directorio {path_oplc}")
            return False
        run_cmd(f"docker build -t mi_openplc {path_oplc}", capture=False)
        print("[✔] Imagen 'mi_openplc' compilada correctamente.")
    return True

def setup_vulnerable_samba():
    """Genera el directorio compartido y las claves SSH para el escenario vulnerable."""
    path_keys = os.path.join(os.getcwd(), "recurso_compartido", "ssh_keys")
    os.makedirs(path_keys, exist_ok=True)
    
    if not os.path.exists(os.path.join(path_keys, "id_rsa")):
        print("[*] Generando claves SSH vulnerables para Samba...")
        run_cmd(f'ssh-keygen -t rsa -b 2048 -f {path_keys}/id_rsa -q -N ""', capture=False)

def generate_nodered_flow(num_modbus_a=0, num_s7_b=0, num_dnp3_c=0):
    flow = []
    
    tab_id = "tab_supervision_purdue"
    debug_id = "debug_telemetria_general"
    
    id_ui_base = "ui_base_dashboard"
    id_ui_theme = "ui_theme_default"
    id_ui_page_modbus = "ui_page_planta"
    id_ui_page_s7 = "ui_page_s7"
    
    flow.extend([
        {
            "id": tab_id, "type": "tab", "label": "Supervisión OT Multi-Protocolo (Purdue)", "disabled": False
        },
        {
            "id": debug_id, "type": "debug", "z": tab_id, "name": "Telemetría SCADA", "active": True, 
            "tosidebar": True, "complete": "payload", "x": 1050, "y": 80, "wires": []
        },
        # UI Base y Theme
        {
            "id": id_ui_base, "type": "ui-base", "name": "My Dashboard", "path": "/dashboard", 
            "includeClientData": True, "acceptsClientConfig": ["ui-notification", "ui-control"], 
            "showPathInSidebar": False, "navigationStyle": "default", "titleBarStyle": "default"
        },
        {
            "id": id_ui_theme, "type": "ui-theme", "name": "Default Theme", "colors": {
                "surface": "#fcfcfd", "primary": "#0d74ce", "bgPage": "#f9f9fb", "groupBg": "#ffffff", "groupOutline": "#d9d9e0"
            }, "sizes": {"density": "default", "pagePadding": "12px", "groupGap": "12px", "groupBorderRadius": "4px", "widgetGap": "12px"}
        },
        # Páginas
        {
            "id": id_ui_page_modbus, "type": "ui-page", "name": "Planta Modbus", "ui": id_ui_base, "path": "/page1", 
            "icon": "home", "layout": "grid", "theme": id_ui_theme, "order": 1, "className": "", "visible": "true", "disabled": "false"
        },
        {
            "id": id_ui_page_s7, "type": "ui-page", "name": "Planta S7", "ui": id_ui_base, "path": "/page2", 
            "icon": "home", "layout": "grid", "theme": id_ui_theme, "order": 2, "className": "", "visible": "true", "disabled": "false"
        }
    ])

    # ---------------------------------------------------------
    # ZONA OT A (MODBUS TCP)
    # ---------------------------------------------------------
    for i in range(1, num_modbus_a + 1):
        client_id = f"client_modbus_{i}"
        ip_addr = f"192.168.10.{9 + i}"
        y_base = (i - 1) * 600

        id_grupo_ctrl = f"ui_group_ctrl_{i}"
        id_grupo_temp = f"ui_group_temp_{i}"

        id_read = f"read_modbus_{i}"
        id_func = f"func_split_{i}"
        id_wr_em = f"wr_em_{i}"
        id_wr_pmp = f"wr_pmp_{i}"
        id_wr_rpm = f"wr_rpm_{i}"

        flow.append({
            "id": client_id, "type": "modbus-client", "name": f"PLC_Agua_{i}", "clienttype": "tcp",
            "tcpHost": ip_addr, "tcpPort": 502, "tcpType": "DEFAULT", "listenType": "multiple",
            "unit_id": i, "commandDelay": 1, "clientTimeout": 2000, "reconnectOnTimeout": True,
            "reconnectTimeout": 2000, "parallelUnitIdsAllowed": False, "showServerAddress": False,
            "showWarnings": True, "showErrors": True, "enableMsgQueue": True, "showLogQueue": False,
            "queueLogParallelQueues": 1, "bufferCommands": True, "stateLogEnabled": False,
            "queueLogEnabled": False, "failureLogEnabled": True, "logIOActivities": False,
            "serialPort": "/dev/ttyUSB0", "serialBaudrate": "9600", "serialDatabits": "8",
            "serialStopbits": "1", "serialParity": "none", "serialType": "RTU", "serialConnectionDelay": "100"
        })

        flow.extend([
            {"id": id_grupo_ctrl, "type": "ui-group", "name": f"Controles PLC {i}", "page": id_ui_page_modbus, "width": 6, "height": 1, "order": 1, "showTitle": True, "groupType": "default"},
            {"id": id_grupo_temp, "type": "ui-group", "name": f"Temperaturas PLC {i}", "page": id_ui_page_modbus, "width": 6, "height": 1, "order": 2, "showTitle": True, "groupType": "default"}
        ])

        flow.extend([
            {"id": id_read, "type": "modbus-read", "z": tab_id, "name": f"Leer Sensores MB {i}", "dataType": "HoldingRegister", "adr": 0, "quantity": 20, "rate": 2, "rateUnit": "s", "server": client_id, "showStatusActivities": False, "showErrors": False, "showWarnings": True, "unitid": i, "useIOFile": False, "ioFile": "", "useIOForPayload": False, "emptyMsgOnFail": False, "keepMsgProperties": False, "delayOnStart": False, "startDelayQty": 0, "x": 150, "y": y_base + 120, "wires": [[id_func], []]},
            {"id": id_func, "type": "function", "z": tab_id, "name": f"Separar Datos {i}", "func": "return [{ payload: msg.payload[0] }, { payload: msg.payload[1] }, { payload: msg.payload[15] }];", "outputs": 3, "x": 360, "y": y_base + 140, "wires": [[f"gauge_t1_{i}"], [f"gauge_t2_{i}"], [f"gauge_rpm_{i}"]]}
        ])

        segments_temp = [
            {"from": "0", "color": "#5cd65c", "text": "", "textType": "label"}, 
            {"from": "60", "color": "#ffc000", "text": "", "textType": "label"}, 
            {"from": "85", "color": "#ff3300", "text": "", "textType": "label"}
        ]
        segments_rpm = [
            {"from": "0", "color": "#5cd65c", "text": "", "textType": "label"}, 
            {"from": "1200", "color": "#ffc000", "text": "", "textType": "label"}, 
            {"from": "1800", "color": "#ff3300", "text": "", "textType": "label"}
        ]

        flow.extend([
            {
                "id": f"gauge_t1_{i}", "type": "ui-gauge", "z": tab_id, "name": "Temp caldera 1", 
                "group": id_grupo_temp, "order": 1, "width": 0, "height": 0, "gtype": "gauge-half", 
                "title": "Temp Caldera 1", "units": "ºC", "prefix": "", "suffix": "", 
                "segments": segments_temp, "min": 0, "max": 100, "value": "payload", "valueType": "msg",
                "alwaysShowTitle": False, "icon": "", "sizeThickness": 16, "sizeGap": 4, "sizeKeyThickness": 8, "className": "",
                "x": 580, "y": y_base + 100, "wires": [[]]
            },
            {
                "id": f"gauge_t2_{i}", "type": "ui-gauge", "z": tab_id, "name": "Temp caldera 2", 
                "group": id_grupo_temp, "order": 2, "width": 0, "height": 0, "gtype": "gauge-half", 
                "title": "Temp Caldera 2", "units": "ºC", "prefix": "", "suffix": "", 
                "segments": segments_temp, "min": 0, "max": 100, "value": "payload", "valueType": "msg",
                "alwaysShowTitle": False, "icon": "", "sizeThickness": 16, "sizeGap": 4, "sizeKeyThickness": 8, "className": "",
                "x": 580, "y": y_base + 140, "wires": [[]]
            },
            {
                "id": f"gauge_rpm_{i}", "type": "ui-gauge", "z": tab_id, "name": "RPM Bomba", 
                "group": id_grupo_ctrl, "order": 4, "width": 0, "height": 0, "gtype": "gauge-half", 
                "title": "RPM Actual", "units": "rpm", "prefix": "", "suffix": "", 
                "segments": segments_rpm, "min": 0, "max": 2000, "value": "payload", "valueType": "msg",
                "alwaysShowTitle": False, "icon": "", "sizeThickness": 16, "sizeGap": 4, "sizeKeyThickness": 8, "className": "",
                "x": 580, "y": y_base + 180, "wires": [[]]
            }
        ])

        flow.extend([
            {"id": f"sw_em_{i}", "type": "ui-switch", "z": tab_id, "name": "Parada emergencia", "label": "Parada Emergencia", "group": id_grupo_ctrl, "order": 1, "width": 0, "height": 0, "passthru": False, "topic": "topic", "topicType": "msg", "style": "", "onvalue": "true", "onvalueType": "bool", "offvalue": "false", "offvalueType": "bool", "x": 370, "y": y_base + 260, "wires": [[id_wr_em]]},
            {"id": f"sw_pmp_{i}", "type": "ui-switch", "z": tab_id, "name": "Parada bomba", "label": "Marcha/Paro Bomba", "group": id_grupo_ctrl, "order": 2, "width": 0, "height": 0, "passthru": False, "topic": "topic", "topicType": "msg", "style": "", "onvalue": "true", "onvalueType": "bool", "offvalue": "false", "offvalueType": "bool", "x": 390, "y": y_base + 320, "wires": [[id_wr_pmp]]},
            {"id": f"sl_rpm_{i}", "type": "ui-slider", "z": tab_id, "name": "Ajuste rpm", "label": "Consigna RPM", "group": id_grupo_ctrl, "order": 3, "width": 0, "height": 0, "min": 0, "max": 2000, "step": 50, "passthru": False, "outmost": "all", "topic": "topic", "topicType": "msg", "x": 350, "y": y_base + 380, "wires": [[id_wr_rpm]]}
        ])

        flow.extend([
            {"id": id_wr_em, "type": "modbus-write", "z": tab_id, "name": f"Escribir Parada MB {i}", "showStatusActivities": False, "showErrors": False, "showWarnings": True, "unitid": i, "dataType": "Coil", "adr": 0, "quantity": 1, "server": client_id, "emptyMsgOnFail": False, "keepMsgProperties": False, "delayOnStart": False, "startDelayQty": 0, "x": 600, "y": y_base + 260, "wires": [[], []]},
            {"id": id_wr_pmp, "type": "modbus-write", "z": tab_id, "name": f"Escribir Bomba MB {i}", "showStatusActivities": False, "showErrors": False, "showWarnings": True, "unitid": i, "dataType": "Coil", "adr": 1, "quantity": 1, "server": client_id, "emptyMsgOnFail": False, "keepMsgProperties": False, "delayOnStart": False, "startDelayQty": 0, "x": 600, "y": y_base + 320, "wires": [[], []]},
            {"id": id_wr_rpm, "type": "modbus-write", "z": tab_id, "name": f"Escribir RPM MB {i}", "showStatusActivities": False, "showErrors": False, "showWarnings": True, "unitid": i, "dataType": "HoldingRegister", "adr": 20, "quantity": 1, "server": client_id, "emptyMsgOnFail": False, "keepMsgProperties": False, "delayOnStart": False, "startDelayQty": 0, "x": 600, "y": y_base + 380, "wires": [[], []]}
        ])

    # ---------------------------------------------------------
    # ZONA OT B (SIEMENS S7)
    # ---------------------------------------------------------
    offset_y_s7 = num_modbus_a * 600

    for i in range(1, num_s7_b + 1):
        endpoint_id = f"s7_endpoint_{i}"
        ip_addr = f"192.168.30.{9 + i}"
        y_base = offset_y_s7 + ((i - 1) * 600)

        id_grupo_ctrl_s7 = f"ui_group_ctrl_s7_{i}"
        id_grupo_tele_s7 = f"ui_group_tele_s7_{i}"

        flow.append({
            "id": endpoint_id, "type": "s7 endpoint", "transport": "iso-on-tcp", "address": ip_addr, 
            "port": "102", "rack": "0", "slot": "1", "localtsaphi": "01", "localtsaplo": "00",
            "remotetsaphi": "01", "remotetsaplo": "00", "connmode": "rack-slot", "adapter": "",
            "busaddr": 2, "cycletime": 1000, "timeout": 2000, "name": f"PLC_S7_{i}",
            "vartable": [
                {"addr": "DB1,INT0", "name": "Temp"},
                {"addr": "DB1,INT2", "name": "Presion"},
                {"addr": "DB1,X4.0", "name": "Marcha"},
                {"addr": "DB1,X4.1", "name": "Parada"},
                {"addr": "DB1,REAL6", "name": "Setpoint"}
            ]
        })

        flow.extend([
            {"id": id_grupo_ctrl_s7, "type": "ui-group", "name": f"Control Motor S7 ({i})", "page": id_ui_page_s7, "width": 6, "height": 0, "order": 1, "showTitle": True, "groupType": "default"},
            {"id": id_grupo_tele_s7, "type": "ui-group", "name": f"Telemetría S7 ({i})", "page": id_ui_page_s7, "width": 6, "height": 0, "order": 2, "showTitle": True, "groupType": "default"}
        ])

        flow.extend([
            {"id": f"read_s7_temp_{i}", "type": "s7 in", "z": tab_id, "endpoint": endpoint_id, "mode": "single", "variable": "Temp", "diff": False, "name": f"Leer Temp S7 {i}", "x": 180, "y": y_base + 80, "wires": [[f"gauge_s7_temp_{i}"]]},
            {"id": f"read_s7_pres_{i}", "type": "s7 in", "z": tab_id, "endpoint": endpoint_id, "mode": "single", "variable": "Presion", "diff": False, "name": f"Leer Pres S7 {i}", "x": 180, "y": y_base + 140, "wires": [[f"gauge_s7_pres_{i}"]]},
            {"id": f"read_s7_run_{i}", "type": "s7 in", "z": tab_id, "endpoint": endpoint_id, "mode": "single", "variable": "Marcha", "diff": False, "name": f"Leer Marcha S7 {i}", "x": 180, "y": y_base + 200, "wires": [[f"text_s7_run_{i}"]]}
        ])

        segmentos_s7_temp = [
            {"from": "0", "color": "#5cd65c", "text": "", "textType": "label"},
            {"from": "60", "color": "#ffc800", "text": "", "textType": "label"},
            {"from": "80", "color": "#ea5353", "text": "", "textType": "label"}
        ]
        segmentos_s7_pres = [
            {"from": "0", "color": "#5cd65c", "text": "", "textType": "label"},
            {"from": "120", "color": "#ffc800", "text": "", "textType": "label"},
            {"from": "160", "color": "#ea5353", "text": "", "textType": "label"}
        ]
        
        flow.extend([
            {
                "id": f"gauge_s7_temp_{i}", "type": "ui-gauge", "z": tab_id, "name": "temp", "group": id_grupo_tele_s7, 
                "order": 1, "value": "payload", "valueType": "msg", "gtype": "gauge-half", "gstyle": "needle", 
                "title": "Temperatura", "units": "ºC", "segments": segmentos_s7_temp, "min": 0, "max": "100", 
                "sizeThickness": 16, "sizeGap": 4, "sizeKeyThickness": 8, "styleRounded": True, "x": 420, "y": y_base + 80, "wires": [[]]
            },
            {
                "id": f"gauge_s7_pres_{i}", "type": "ui-gauge", "z": tab_id, "name": "Presion", "group": id_grupo_tele_s7, 
                "order": 2, "value": "payload", "valueType": "msg", "gtype": "gauge-half", "gstyle": "needle", 
                "title": "Presión", "units": "bar", "segments": segmentos_s7_pres, "min": 0, "max": "200", 
                "sizeThickness": 16, "sizeGap": 4, "sizeKeyThickness": 8, "styleRounded": True, "x": 420, "y": y_base + 140, "wires": [[]]
            },
            {
                "id": f"text_s7_run_{i}", "type": "ui-text", "z": tab_id, "group": id_grupo_tele_s7, "order": 3, 
                "name": "Estado motor", "label": "Estado motor", "format": "{{msg.payload}}", "layout": "row-spread", 
                "fontSize": 16, "color": "#717171", "value": "payload", "valueType": "msg", "x": 420, "y": y_base + 200, "wires": []
            }
        ])

        flow.extend([
            {
                "id": f"btn_s7_em_{i}",
                "type": "ui-button",
                "z": tab_id,
                "group": id_grupo_ctrl_s7,
                "name": "Control Parada Emergencia",
                "label": "Botón parada de emergencia",
                "order": 1,
                "width": 0,
                "height": 0,
                "emulateClick": False,
                "tooltip": "",
                "color": "",
                "bgcolor": "",
                "className": "",
                "icon": "",
                "iconPosition": "left",
                "payload": "true",
                "payloadType": "bool",
                "topic": "topic",
                "topicType": "msg",
                "buttonColor": "",
                "textColor": "",
                "iconColor": "",
                "enableClick": True,
                "enablePointerdown": False,
                "pointerdownPayload": "",
                "pointerdownPayloadType": "str",
                "enablePointerup": False,
                "pointerupPayload": "",
                "pointerupPayloadType": "str",
                "x": 160,
                "y": y_base + 300,
                "wires": [[f"out_s7_em_{i}"]]
            },
            {
                "id": f"sw_s7_run_{i}",
                "type": "ui-switch",
                "z": tab_id,
                "name": "Control Marcha",
                "label": "Marcha",
                "group": id_grupo_ctrl_s7,
                "order": 2,
                "width": 0,
                "height": 0,
                "passthru": False,
                "decouple": False,
                "topic": "topic",
                "topicType": "msg",
                "style": "",
                "className": "",
                "layout": "row-spread",
                "clickableArea": "switch",
                "onvalue": "true",
                "onvalueType": "bool",
                "onicon": "",
                "oncolor": "",
                "offvalue": "false",
                "offvalueType": "bool",
                "officon": "",
                "offcolor": "",
                "x": 180,
                "y": y_base + 360,
                "wires": [[f"out_s7_run_{i}"]]
            },
            {
                "id": f"slider_s7_sp_{i}",
                "type": "ui-slider",
                "z": tab_id,
                "group": id_grupo_ctrl_s7,
                "name": "Control Setpoint",
                "label": "Control Setpoint",
                "tooltip": "",
                "order": 3,
                "width": 0,
                "height": 0,
                "passthru": False,
                "outs": "all",
                "topic": "topic",
                "topicType": "msg",
                "thumbLabel": "true",
                "showTicks": "always",
                "min": 0,
                "max": "60",
                "step": "5",
                "className": "",
                "iconPrepend": "",
                "iconAppend": "",
                "color": "",
                "colorTrack": "",
                "colorThumb": "",
                "showTextField": False,
                "x": 180,
                "y": y_base + 420,
                "wires": [[f"out_s7_sp_{i}"]]
            }
        ])

        flow.extend([
            {"id": f"out_s7_em_{i}", "type": "s7 out", "z": tab_id, "endpoint": endpoint_id, "variable": "Parada", "name": f"Escribir Parada {i}", "x": 440, "y": y_base + 300, "wires": []},
            {"id": f"out_s7_run_{i}", "type": "s7 out", "z": tab_id, "endpoint": endpoint_id, "variable": "Marcha", "name": f"Escribir Marcha {i}", "x": 440, "y": y_base + 360, "wires": []},
            {"id": f"out_s7_sp_{i}", "type": "s7 out", "z": tab_id, "endpoint": endpoint_id, "variable": "Setpoint", "name": f"Escribir Setpoint {i}", "x": 440, "y": y_base + 420, "wires": []}
        ])

    # ---------------------------------------------------------
    # ZONA OT C (DNP3 sobre MQTT)
    # ---------------------------------------------------------
    if num_dnp3_c > 0:
        broker_id = "mqtt_broker_local"
        flow.append({
            "id": broker_id, "type": "mqtt-broker", "name": "Mosquitto (Gateway DNP3)",
            "broker": "192.168.20.15", "port": "1883", "clientid": "NodeRED_SCADA",
            "autoConnect": True, "usetls": False, "protocolVersion": 4,
            "keepalive": 15, "cleansession": True
        })

        id_ui_page_dnp3 = "ui_page_dnp3"
        flow.append({
            "id": id_ui_page_dnp3, "type": "ui-page", "name": "Planta DNP3", "ui": id_ui_base,
            "path": "/page3", "icon": "home", "layout": "grid", "theme": id_ui_theme,
            "order": 3, "className": "", "visible": "true", "disabled": "false"
        })

        offset_y_dnp3 = (num_modbus_a * 600) + (num_s7_b * 600)

        for i in range(1, num_dnp3_c + 1):
            y_base = offset_y_dnp3 + ((i - 1) * 500)
            
            id_grupo_tele = f"ui_group_tele_dnp3_{i}"
            id_grupo_ctrl = f"ui_group_ctrl_dnp3_{i}"

            flow.extend([
                {"id": id_grupo_tele, "type": "ui-group", "name": f"Telemetría DNP3 {i}", "page": id_ui_page_dnp3, "width": 6, "height": 1, "order": 1, "showTitle": True, "groupType": "default"},
                {"id": id_grupo_ctrl, "type": "ui-group", "name": f"Control DNP3 {i}", "page": id_ui_page_dnp3, "width": 6, "height": 1, "order": 2, "showTitle": True, "groupType": "default"}
            ])

            id_func = f"func_dnp3_{i}"
            id_txt_bomba = f"txt_bomba_dnp3_{i}"
            id_txt_alarma = f"txt_alarma_dnp3_{i}"
            id_txt_manual = f"txt_manual_dnp3_{i}"
            id_txt_cmd = f"txt_cmd_dnp3_{i}"
            id_gauge_t1 = f"gauge_t1_dnp3_{i}"
            id_gauge_t2 = f"gauge_t2_dnp3_{i}"
            id_mqtt_out = f"mqtt_out_dnp3_{i}"

            func_code = (
                "var d = msg.payload || {};\n\n"
                "return [\n"
                "    { payload: d.bomba_principal ? \"ENCENDIDO\" : \"APAGADO\" },\n"
                "    { payload: d.alarma_sobrepresion ? \"¡ALARMA!\" : \"NORMAL\" },\n"
                "    { payload: d.modo_manual ? \"MANUAL\" : \"AUTOMÁTICO\" },\n"
                "    { payload: d.cmd_bomba ? \"ACTIVADO\" : \"DESACTIVADO\" },\n"
                "    { payload: Number(d.temp_caldera_1 || 0) },\n"
                "    { payload: Number(d.temp_caldera_2 || 0) }\n"
                "];"
            )

            flow.extend([
                {
                    "id": f"mqtt_in_dnp3_{i}", "type": "mqtt in", "z": tab_id, "name": f"Telemetría DNP3 {i}",
                    "topic": f"scada/dnp3/{i}/telemetria", "qos": "0", "datatype": "json", "broker": broker_id,
                    "x": 210, "y": y_base + 80, "wires": [[id_func]]
                },
                {
                    "id": id_func, "type": "function", "z": tab_id, "name": f"Procesar DNP3 {i}",
                    "func": func_code, "outputs": 6, "x": 620, "y": y_base + 80,
                    "wires": [[id_txt_bomba], [id_txt_alarma], [id_txt_manual], [id_txt_cmd], [id_gauge_t1], [id_gauge_t2]]
                },
                
                {"id": id_txt_bomba, "type": "ui-text", "z": tab_id, "group": id_grupo_tele, "order": 3, "name": "Estado bomba principal", "label": "Bomba principal", "format": "{{msg.payload}}", "layout": "row-spread", "fontSize": 16, "color": "#717171", "value": "payload", "valueType": "msg", "x": 1130, "y": y_base + 40, "wires": []},
                {"id": id_txt_alarma, "type": "ui-text", "z": tab_id, "group": id_grupo_tele, "order": 5, "name": "Estado alarma sobrepresión", "label": "Alarma sobrepresión", "format": "{{msg.payload}}", "layout": "row-spread", "fontSize": 16, "color": "#717171", "value": "payload", "valueType": "msg", "x": 1140, "y": y_base + 100, "wires": []},
                {"id": id_txt_manual, "type": "ui-text", "z": tab_id, "group": id_grupo_tele, "order": 6, "name": "Modo manual", "label": "Modo manual", "format": "{{msg.payload}}", "layout": "row-spread", "fontSize": 16, "color": "#717171", "value": "payload", "valueType": "msg", "x": 1120, "y": y_base + 160, "wires": []},
                {"id": id_txt_cmd, "type": "ui-text", "z": tab_id, "group": id_grupo_tele, "order": 4, "name": "Cambio manual bomba", "label": "Cambio manual bomba", "format": "{{msg.payload}}", "layout": "row-spread", "fontSize": 16, "color": "#717171", "value": "payload", "valueType": "msg", "x": 1130, "y": y_base + 220, "wires": []},
                
                {
                    "id": id_gauge_t1, "type": "ui-gauge", "z": tab_id, "name": "Temperatura caldera 1", "group": id_grupo_tele, "order": 1, "value": "payload", "valueType": "msg", "gtype": "gauge-half", "gstyle": "needle", "title": "Temperatura caldera 1", "min": 0, "max": "100", 
                    "segments": [{"from": "0", "color": "#5cd65c"}, {"from": "50", "color": "#ffc800"}, {"from": "75", "color": "#ea5353"}], "sizeThickness": 16, "sizeGap": 4, "sizeKeyThickness": 8, "styleRounded": True, "x": 1120, "y": y_base + 300, "wires": [[]]
                },
                {
                    "id": id_gauge_t2, "type": "ui-gauge", "z": tab_id, "name": "Temperatura caldera 2", "group": id_grupo_tele, "order": 2, "value": "payload", "valueType": "msg", "gtype": "gauge-half", "gstyle": "needle", "title": "Temperatura caldera 2", "min": 0, "max": "100", 
                    "segments": [{"from": "0", "color": "#5cd65c"}, {"from": "50", "color": "#ffc800"}, {"from": "75", "color": "#ea5353"}], "sizeThickness": 16, "sizeGap": 4, "sizeKeyThickness": 8, "styleRounded": True, "x": 1140, "y": y_base + 360, "wires": [[]]
                },

                {
                    "id": f"sw_manual_dnp3_{i}", "type": "ui-switch", "z": tab_id, "name": "Activación modo manual", "label": "Modo Manual", "group": id_grupo_ctrl, "order": 2, "topic": f"scada/dnp3/{i}/control/modo_manual", "topicType": "str", "onvalue": "true", "onvalueType": "bool", "offvalue": "false", "offvalueType": "bool", "x": 270, "y": y_base + 420, "wires": [[id_mqtt_out]]
                },
                {
                    "id": f"sw_bomba_dnp3_{i}", "type": "ui-switch", "z": tab_id, "name": "Activación bomba principal", "label": "Bomba principal", "group": id_grupo_ctrl, "order": 1, "topic": f"scada/dnp3/{i}/control/bomba_principal", "topicType": "str", "onvalue": "true", "onvalueType": "bool", "offvalue": "false", "offvalueType": "bool", "x": 280, "y": y_base + 480, "wires": [[id_mqtt_out]]
                },

                {
                    "id": id_mqtt_out, "type": "mqtt out", "z": tab_id, "name": f"Salida MQTT DNP3 {i}", "broker": broker_id, "x": 510, "y": y_base + 440, "wires": []
                }
            ])

    # 5. Configuración Global de Módulos
    flow.append({
        "id": "global_config_modules", "type": "global-config", "env": [],
        "modules": {
            "node-red-contrib-modbus": "5.60.2",
            "node-red-contrib-s7": "3.1.3",
            "@flowfuse/node-red-dashboard": "1.32.0"
        }
    })

    return flow

def save_flows_file(filepath="nodered_data_scada_1/flows.json", num_modbus_a=0, num_s7_b=0, num_dnp3_c=0):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    flows = generate_nodered_flow(num_modbus_a, num_s7_b, num_dnp3_c)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(flows, f, indent=4)
    print(f"[+] Flujos creados: {num_modbus_a} Modbus, {num_s7_b} Siemens, {num_dnp3_c} DNP3 en '{filepath}'.")

def read_scenario_sizes(compose_path="docker-compose.generated.yml"):
    """Lee el compose existente y devuelve (num_modbus, num_s7, num_dnp3).

    Si el fichero no existe o no se puede parsear, devuelve (None, None, None)
    y el que llame tendrá que preguntar al usuario.
    """
    try:
        with open(compose_path, "r", encoding="utf-8") as f:
            texto = f.read()
    except FileNotFoundError:
        return (None, None, None)
    import re
    n_mb = len(re.findall(r"container_name:\s*plc_agua_\d+", texto))
    n_s7 = len(re.findall(r"container_name:\s*plc_s7_\d+", texto))
    n_dnp3 = len(re.findall(r"container_name:\s*plc_dnp3_\d+", texto))
    return (n_mb, n_s7, n_dnp3)


def switch_kali_mode():
    """Cambia el modo de kali_nodo (empresa <-> control) sin tocar los PLCs.

    - Pregunta el nuevo modo.
    - Lee cuántos PLCs tiene el escenario (del compose actual) o los pide.
    - Regenera `docker-compose.generated.yml` con el nuevo kali_mode.
    - Recrea solo `kali_nodo` con `--force-recreate --no-deps`.
    - Si pasa a 'control', añade las 5 rutas inter-zona.
    - Reinicia el dashboard dentro del contenedor.
    """
    new_mode = ask_kali_mode()
    n_mb, n_s7, n_dnp3 = read_scenario_sizes()
    if n_mb is None:
        print("[!] No encuentro docker-compose.generated.yml. Introduce los números:")
        n_mb = int(input("Número de PLCs Modbus TCP (Zona A): "))
        n_s7 = int(input("Número de PLCs Siemens S7 (Zona B): "))
        n_dnp3 = int(input("Número de PLCs DNP3 (Zona C): "))
    else:
        print(f"[*] Escenario detectado: {n_mb} Modbus, {n_s7} S7, {n_dnp3} DNP3.")

    print(f"[*] Regenerando compose con kali_mode='{new_mode}'...")
    generate_docker_compose(n_mb, n_s7, n_dnp3, kali_mode=new_mode)

    print("[*] Recreando únicamente kali_nodo (los PLCs siguen arriba)...")
    run_cmd("docker compose -f docker-compose.generated.yml up -d --force-recreate --no-deps kali_nodo",
            capture=False)
    time.sleep(3)

    if new_mode == "control":
        print("[*] Añadiendo rutas inter-zona a kali_nodo...")
        for net in ("192.168.10.0/24", "192.168.30.0/24", "192.168.40.0/24",
                    "192.168.50.0/24", "192.168.60.0/24"):
            run_cmd(f"docker exec kali_nodo ip route add {net} via 192.168.20.254",
                    check=False)

    # Reiniciar dashboard para que recoja el nuevo .mode. Si todavía no hay
    # Flask (apt+pip en curso), el fuser falla silenciosamente y el usuario
    # tendrá que usar [6] cuando termine la instalación.
    print("[*] Reiniciando dashboard dentro de kali_nodo...")
    run_cmd("docker exec kali_nodo bash -c 'fuser -k 8888/tcp 2>/dev/null; sleep 1'",
            check=False)
    run_cmd("docker exec -d kali_nodo bash -c 'cd /ataques && python3 web/app.py > /tmp/dashboard.log 2>&1'",
            check=False)

    print(f"\n[OK] kali_nodo ahora corre en modo '{new_mode}'.")
    if new_mode == "control":
        print("     Rutas inter-zona añadidas; sin pivote. Dashboard sin tarjeta Samba.")
    else:
        print("     Sin rutas directas; prepara el túnel desde la tarjeta Samba del dashboard.")
    print("     Dashboard: http://localhost:8888")
    print("     Si no responde todavía, es que apt+pip aún no terminó;")
    print("     espera unos minutos y usa [6] para relanzarlo.")


def write_kali_mode_marker(kali_mode):
    """Deja un marcador en ataques/.mode que el dashboard lee al arrancar."""
    ataques_dir = os.path.join(os.getcwd(), "ataques")
    os.makedirs(ataques_dir, exist_ok=True)
    with open(os.path.join(ataques_dir, ".mode"), "w", encoding="utf-8") as f:
        f.write(kali_mode.strip())
    print(f"[+] Modo kali_nodo marcado como '{kali_mode}' en ataques/.mode")


def generate_docker_compose(num_modbus_a, num_s7_b, num_dnp3_c=0, incluir_kali=True,
                             kali_mode="empresa"):
    with open("mosquitto.conf", "w") as f:
        f.write("listener 1883\nallow_anonymous true\n")

    compose_content = f"""name: tfm-purdue-scenarios

networks:
  red_control:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.20.0/24
  red_ot_zona_a:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.10.0/24
  red_ot_zona_b:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.30.0/24
  red_ot_zona_c:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.40.0/24
  red_monitorizacion:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.50.0/24
  red_empresa:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.60.0/24

services:
  router_gw:
    image: alpine:latest
    container_name: router_gw
    sysctls:
      - net.ipv4.ip_forward=1
    command: tail -f /dev/null
    cap_add:
      - NET_ADMIN
    networks:
      red_control:
        ipv4_address: 192.168.20.254
      red_ot_zona_a:
        ipv4_address: 192.168.10.254
      red_ot_zona_b:
        ipv4_address: 192.168.30.254
      red_ot_zona_c:
        ipv4_address: 192.168.40.254
      red_monitorizacion:
        ipv4_address: 192.168.50.254
      red_empresa:
        ipv4_address: 192.168.60.254

  nodered_scada_1:
    image: nodered/node-red:latest
    container_name: nodered_scada_1
    cap_add:
      - NET_ADMIN
    networks:
      red_control:
        ipv4_address: 192.168.20.10
    ports:
      - "1880:1880"
    volumes:
      - ./nodered_data_scada_1:/data
    restart: always

  mosquitto:
    image: eclipse-mosquitto:2
    container_name: broker_mqtt
    ports:
      - "1883:1883"
    volumes:
      - ./mosquitto.conf:/mosquitto/config/mosquitto.conf:ro
    networks:
      red_control:
        ipv4_address: 192.168.20.15
 
  # --- ZONA C: RED DE EMPRESA (Pivote Vulnerable Samba) ---
  srv_empresa:
    image: dperson/samba
    container_name: srv_empresa
    cap_add:
      - NET_ADMIN
    networks:
      red_empresa:
        ipv4_address: 192.168.60.50
      red_control:
        ipv4_address: 192.168.20.50
    ports:
      - "2222:22"
    volumes:
      - ./recurso_compartido:/mount
    command: >
      sh -c "apk update && apk add openssh && ssh-keygen -A && 
      mkdir -p /root/.ssh && chmod 700 /root/.ssh && 
      cp /mount/ssh_keys/id_rsa.pub /root/.ssh/authorized_keys && 
      chmod 600 /root/.ssh/authorized_keys && 
      chmod 700 /root && 
      echo 'root:root' | chpasswd && 
      passwd -u root && 
      sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && 
      sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config && 
      sed -i 's/.*AllowTcpForwarding.*/AllowTcpForwarding yes/g' /etc/ssh/sshd_config && 
      sed -i 's/.*DisableForwarding.*/DisableForwarding no/g' /etc/ssh/sshd_config && 
      echo 'AllowTcpForwarding yes' >> /etc/ssh/sshd_config && 
      echo 'PubkeyAcceptedKeyTypes +ssh-rsa' >> /etc/ssh/sshd_config && 
      echo 'HostKeyAlgorithms +ssh-rsa' >> /etc/ssh/sshd_config && 
      /usr/sbin/sshd && 
      samba.sh -s 'Backups_SCADA;/mount;yes;no;yes;all;none' -p"
    restart: always

  # --- ZONA D: RED DE MONITORIZACIÓN ---
  srv_monitorizacion:
    image: dperson/samba
    container_name: srv_monitorizacion
    cap_add:
      - NET_ADMIN
    networks:
      red_monitorizacion:
        ipv4_address: 192.168.50.10
    command: '-s "logs;/share;yes;no;yes;all;none" -p'
    restart: always
"""

    if incluir_kali:
        # Red donde se ubica kali_nodo según el modo elegido:
        #   - "empresa": en red_empresa (atacante externo, requiere pivote SSH)
        #   - "control": en red_control (atacante dentro de SCADA, acceso directo)
        if kali_mode == "control":
            kali_net_block = """    networks:
      red_control:
        ipv4_address: 192.168.20.66"""
        else:
            kali_net_block = """    networks:
      red_empresa:
        ipv4_address: 192.168.60.66"""

        compose_content += f"""
  kali_nodo:
    image: kalilinux/kali-rolling
    container_name: kali_nodo
    cap_add:
      - NET_ADMIN
    command: /bin/sh -c "apt-get update && apt-get install -y nmap iputils-ping iproute2 openssh-client smbclient proxychains4 python3 python3-pip python3-dev build-essential cmake metasploit-framework && sed -i 's/socks4/socks5/' /etc/proxychains4.conf && pip3 install --break-system-packages flask python-snap7 requests pymodbus || true && tail -f /dev/null"
{kali_net_block}
    ports:
      - "8888:8888"
    volumes:
      - ./ataques:/ataques
      - /var/run/docker.sock:/var/run/docker.sock
"""

    for i in range(1, num_modbus_a + 1):
        # ACL Modbus: UID esperado por este PLC = i, coincidiendo con el
        # unit_id que usa Node-RED (ver generate_nodered_flow). El fichero se
        # monta como volumen de solo lectura en /etc/openplc/acl.conf y lo
        # consulta el parche uid_acl.patch aplicado en el Dockerfile.
        acl_path = os.path.join("openplc", f"acl_plc_agua_{i}.conf")
        with open(acl_path, "w", encoding="utf-8") as acl_f:
            acl_f.write(
                "# ACL Modbus TCP generada por main.py (NO EDITAR A MANO)\n"
                f"# UID aceptado para peticiones Modbus en plc_agua_{i}\n"
                f"expected_uid = {i}\n"
            )
        compose_content += f"""
  plc_agua_{i}:
    image: mi_openplc
    container_name: plc_agua_{i}
    environment:
      - PLC_MODE=MODBUS
    cap_add:
      - NET_ADMIN
    networks:
      red_ot_zona_a:
        ipv4_address: 192.168.10.{9 + i}
    ports:
      - "{8080 + i}:8080"
      - "{5020 + i}:502"
    volumes:
      - ./openplc/acl_plc_agua_{i}.conf:/etc/openplc/acl.conf:ro
    restart: always
"""

    for i in range(1, num_s7_b + 1):
        compose_content += f"""
  plc_s7_{i}:
    image: mi_plc_siemens
    container_name: plc_s7_{i}
    cap_add:
      - NET_ADMIN
    networks:
      red_ot_zona_b:
        ipv4_address: 192.168.30.{9 + i}
    ports:
      - "{1020 + i}:102"
    restart: always
"""

    for i in range(1, num_dnp3_c + 1):
        compose_content += f"""
  gateway_dnp3_{i}:
    build:
      context: ./dnp3
      dockerfile: Dockerfile.gateway
    container_name: gateway_dnp3_{i}
    environment:
      - MQTT_BROKER_IP=192.168.20.15
      - PLC_DNP3_IP=192.168.40.{9 + i}
      - PLC_ID={i}
    networks:
      red_control:
        ipv4_address: 192.168.20.{15 + i}
      red_ot_zona_c:
        ipv4_address: 192.168.40.{15 + i}
    depends_on:
      - mosquitto
    restart: always
"""
        compose_content += f"""
  plc_dnp3_{i}:
    image: mi_openplc
    container_name: plc_dnp3_{i}
    environment:
      - PLC_MODE=DNP3
    cap_add:
      - NET_ADMIN
    networks:
      red_ot_zona_c:
        ipv4_address: 192.168.40.{9 + i}
    ports:
      - "{8180 + i}:8080"
      - "{20000 + i}:20000"
    restart: always
"""
        
    with open("docker-compose.generated.yml", "w", encoding="utf-8") as f:
        f.write(compose_content)
    print("[+] Archivo 'docker-compose.generated.yml' generado.")
    if incluir_kali:
        write_kali_mode_marker(kali_mode)

def deploy_scenario(num_modbus_a, num_s7_b, num_dnp3_c=0, kali_mode="empresa"):
    if num_s7_b > 0 and not build_s7_image_if_needed():
        return
    if (num_modbus_a > 0 or num_dnp3_c > 0) and not build_openplc_image_if_needed():
        return

    print(f"\n[*] Generando archivos de configuración IaC (kali_mode={kali_mode})...")
    setup_vulnerable_samba()
    generate_docker_compose(num_modbus_a, num_s7_b, num_dnp3_c, kali_mode=kali_mode)

    print("\n[*] [1/4] Levantando contenedores con Docker Compose...")
    run_cmd("docker compose -f docker-compose.generated.yml up -d --build")

    print("[*] [2/4] Instalando paquetes de S7, Modbus y Dashboard en Node-RED...")
    run_cmd("docker exec nodered_scada_1 npm install --prefix /data node-red-contrib-modbus node-red-contrib-s7 @flowfuse/node-red-dashboard -qq")
    
    print("[*] [3/4] Reiniciando Node-RED para cargar los nuevos módulos...")
    run_cmd("docker restart nodered_scada_1")
    time.sleep(8)

    print("[*] [4/4] Instalando utilidades e inyectando rutas estáticas inter-zona...")
    
    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.10.0/24 via 192.168.20.254", check=False)
    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.30.0/24 via 192.168.20.254", check=False)
    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.40.0/24 via 192.168.20.254", check=False)
    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.50.0/24 via 192.168.20.254", check=False)
    run_cmd("docker exec -u root nodered_scada_1 ip route add 192.168.60.0/24 via 192.168.20.254", check=False)

    # kali_nodo: solo necesita rutas inter-zona cuando está dentro de red_control
    # (modo "control"). En modo "empresa" NO se añaden: el acceso a OT debe pasar
    # obligatoriamente por el túnel SSH SOCKS vía srv_empresa.
    if kali_mode == "control":
        print("[*] Añadiendo rutas inter-zona a kali_nodo (modo control)...")
        for net in ("192.168.10.0/24", "192.168.30.0/24", "192.168.40.0/24",
                    "192.168.50.0/24", "192.168.60.0/24"):
            run_cmd(f"docker exec kali_nodo ip route add {net} via 192.168.20.254", check=False)

    run_cmd("docker exec srv_monitorizacion ip route add 192.168.0.0/16 via 192.168.50.254", check=False)
    run_cmd("docker exec srv_empresa ip route add 192.168.0.0/16 via 192.168.20.254", check=False)

    for i in range(1, num_modbus_a + 1):
        run_cmd(f"docker exec plc_agua_{i} apt-get update -qq && docker exec plc_agua_{i} apt-get install -y iproute2 iputils-ping -qq", check=False)
        run_cmd(f"docker exec plc_agua_{i} ip route add 192.168.20.0/24 via 192.168.10.254", check=False)

    for i in range(1, num_s7_b + 1):
        run_cmd(f"docker exec plc_s7_{i} ip route add 192.168.20.0/24 via 192.168.30.254", check=False)

    for i in range(1, num_dnp3_c + 1):
        run_cmd(f"docker exec plc_dnp3_{i} apt-get update -qq && docker exec plc_dnp3_{i} apt-get install -y iproute2 iputils-ping -qq", check=False)
        run_cmd(f"docker exec plc_dnp3_{i} ip route add 192.168.20.0/24 via 192.168.40.254", check=False)

    print("\n[✔] Escenario Purdue desplegado y enrutado con éxito.")

def clean_environment():
    print("\n[*] Eliminando infraestructura activa...")
    if os.path.exists("docker-compose.generated.yml"):
        run_cmd("docker compose -f docker-compose.generated.yml down --remove-orphans", check=False)
    print("[✔] Entorno totalmente limpio.")

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

if __name__ == "__main__":
    main_menu()