#!/usr/bin/env python3
"""Construye el flow Node-RED SCADA (Modbus + S7 + DNP3) y lo serializa a
`nodered_data_scada_1/flows.json`."""

import json
import os


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
