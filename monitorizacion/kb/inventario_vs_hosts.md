# Validacion inferencia vs ground truth

- Ventana: `2026-10-16T07:50:19.907000+00:00` -> `2026-10-22T11:04:37.341000+00:00` (300s)
- Flujos leidos: 418  | tras dedup: 362  | descartados .254: 46  | excluidos kali: 0
- IPs vistas: 22  | silentes: 5  | excluidas: 1

## Precision por rol

| Rol esperado | Aciertos | Total | % |
|---|---|---|---|
| `broker_mqtt` | 1 | 1 | 100.0% |
| `gateway_dnp3` | 3 | 3 | 100.0% |
| `it_fileserver` | 0 | 2 | 0.0% |
| `plc_dnp3` | 3 | 3 | 100.0% |
| `plc_modbus` | 3 | 3 | 100.0% |
| `plc_s7` | 3 | 3 | 100.0% |
| `scada` | 1 | 1 | 100.0% |
| **TOTAL** | **14** | **16** | **87.5%** |

## Detalle por IP

| IP | Hostname (truth) | Rol esperado | Rol inferido | Estado |
|---|---|---|---|---|
| `192.168.10.10` | plc_agua_1 | `plc_modbus` | `plc_modbus` | OK |
| `192.168.10.11` | plc_agua_2 | `plc_modbus` | `plc_modbus` | OK |
| `192.168.10.12` | plc_agua_3 | `plc_modbus` | `plc_modbus` | OK |
| `192.168.20.10` | nodered_scada | `scada` | `scada` | OK |
| `192.168.20.15` | mosquitto | `broker_mqtt` | `broker_mqtt` | OK |
| `192.168.20.16` | gateway_dnp3_1 | `gateway_dnp3` | `gateway_dnp3` | OK |
| `192.168.20.17` | gateway_dnp3_2 | `gateway_dnp3` | `gateway_dnp3` | OK |
| `192.168.20.18` | gateway_dnp3_3 | `gateway_dnp3` | `gateway_dnp3` | OK |
| `192.168.20.50` | srv_empresa | `it_fileserver` | `SILENTE` | SILENTE |
| `192.168.30.10` | plc_s7_1 | `plc_s7` | `plc_s7` | OK |
| `192.168.30.11` | plc_s7_2 | `plc_s7` | `plc_s7` | OK |
| `192.168.30.12` | plc_s7_3 | `plc_s7` | `plc_s7` | OK |
| `192.168.40.10` | plc_dnp3_1 | `plc_dnp3` | `plc_dnp3` | OK |
| `192.168.40.11` | plc_dnp3_2 | `plc_dnp3` | `plc_dnp3` | OK |
| `192.168.40.12` | plc_dnp3_3 | `plc_dnp3` | `plc_dnp3` | OK |
| `192.168.60.50` | srv_empresa | `it_fileserver` | `SILENTE` | SILENTE |
| `192.168.60.66` | kali_nodo | `atacante` | `excluida/silente` | N/A (excluida del training) |

## Hosts silentes (esperados pero sin flujos)

- `192.168.20.50` (srv_empresa): sin flujos en la ventana de entrenamiento
- `192.168.50.10` (wazuh.manager): sin flujos en la ventana de entrenamiento
- `192.168.50.11` (wazuh.indexer): sin flujos en la ventana de entrenamiento
- `192.168.50.12` (wazuh.dashboard): sin flujos en la ventana de entrenamiento
- `192.168.60.50` (srv_empresa): sin flujos en la ventana de entrenamiento
