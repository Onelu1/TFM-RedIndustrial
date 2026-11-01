# Mapeo SID → ataque detectado

Las 25 reglas custom del TFM viven en [`rules/local.rules`](rules/local.rules) con SIDs reservados en el rango `2000000-2099999`. Esta tabla las resume para que puedas, viendo una alerta en Wazuh (dashboard "TFM OT - Deteccion ICS en vivo") saber al momento qué ataque la disparó y qué técnica MITRE ATT&CK ICS aplica.

Fuente de verdad: `monitorizacion/suricata/rules/local.rules` (regenera esta tabla con `grep -E 'sid:|msg:|mitre_technique_id' local.rules | ...`).

## Allowlist genérica (fases de reconocimiento / primer contacto)

| SID | Descripción | MITRE ICS |
|---|---|---|
| **2000001** | Conexión Modbus (TCP:502) desde origen no autorizado (!$SCADA_SERVERS) | T0846 Remote System Discovery, T0888 Remote System Information Discovery |
| **2000002** | Conexión S7 (TCP:102) desde origen no autorizado | T0846, T0888 |
| **2000003** | Conexión DNP3 (TCP:20000) desde origen no autorizado (!$DNP3_GATEWAYS) | T0846, T0888 |
| **2000020** | Pivote IT→OT desde `$ENTERPRISE` hacia PLCs | T0866 Exploitation of Remote Services, T1046 Network Service Discovery |
| **2000021** | Tráfico anómalo OT→Enterprise (posible exfiltración) | T0882 Theft of Operational Information |

## Reconocimiento específico de protocolos OT

| SID | Descripción | MITRE ICS |
|---|---|---|
| **2000100** | Modbus FC=43 Read Device Identification (nmap `modbus-discover`) | T0846, T0888 |
| **2000101** | Enumeración S7 (COTP + S7 identification handshake) | T0846, T0888 |
| **2000110** | Modbus FC=3 Read Holding Registers desde origen no-SCADA | T0861 Point & Tag Identification, T0888 |
| **2000170** | Modbus/502 a destino que NO es PLC Modbus (nmap sobre zona equivocada) | T0846, T0888 |
| **2000171** | S7/102 a destino que NO es PLC S7 (nmap S7 sobre zona Modbus/DNP3) | T0846, T0888 |
| **2000172** | DNP3/20000 a destino que NO es outstation DNP3 | T0846, T0888 |

## Escrituras y comandos destructivos (impact)

| SID | Descripción | MITRE ICS |
|---|---|---|
| **2000010** | Modbus FC=5 Write Single Coil desde origen no autorizado | T0855 Unauthorized Command Message |
| **2000011** | Modbus FC=6 Write Single Register desde origen no autorizado | T0836 Modify Parameter |
| **2000012** | Modbus FC=15 Write Multiple Coils desde origen no autorizado | T0855 |
| **2000013** | Modbus FC=16 Write Multiple Registers desde origen no autorizado | T0836 |
| **2000120** | Tráfico S7 desde origen no-SCADA (posible `write_setpoint`) | T0836, T0855 |
| **2000130** | DNP3 Operate / DirectOperate desde origen no autorizado | T0855, T0836 |
| **2000131** | DNP3 DirectOperate-NR (sin respuesta) desde origen no autorizado | T0855 |

## Pivote lateral IT ↔ OT

| SID | Descripción | MITRE ICS / Enterprise |
|---|---|---|
| **2000140** | Acceso Samba a `Backups_SCADA` desde fuera (robo de clave SSH) | T1039 Data from Network Shared Drive, T1552 Unsecured Credentials |
| **2000141** | SSH entrante a `srv_empresa` (apertura de túnel SOCKS/pivot) | T1078 Valid Accounts, T1090 Proxy |

## OpenPLC (web interface)

| SID | Descripción | MITRE ICS |
|---|---|---|
| **2000150** | Intento de login al webserver OpenPLC | T0812 Default Credentials |
| **2000151** | Subida de programa `.st` (modificación de lógica del PLC) | T0843 Program Download, T0821 Modify Controller Tasking, T0831 Manipulation of Control |

## Canal encubierto C2 FrostyGoop

Las tres reglas se disparan solo si `$C2_MAILBOX` apunta a un PLC concreto (editado manualmente en [`monitorizacion/kb/c2_mailbox.yaml`](../kb/c2_mailbox.yaml) antes del ejercicio). Por defecto vacío → never-match.

| SID | Descripción | MITRE ICS |
|---|---|---|
| **2000160** | Modbus Write a holding register ≥1000 → canal encubierto cliente→implante | T0869 Standard Application Layer Protocol, T1570 Lateral Tool Transfer |
| **2000161** | Modbus Read a holding register ≥1200 → respuesta del implante | T0869 |
| **2000162** | Polling periódico `srv_empresa` → `plc_agua_2:502` (beaconing C2) | T0869 |

## Cómo consultar esto desde el dashboard

El dashboard "TFM OT" trae un panel **"Top reglas disparadas (SID + descripción)"** que te muestra el SID + la propia `msg:` de la regla sin salir de Wazuh. Si quieres el detalle MITRE o el racional de la regla, abres este fichero.

## Correlación en Wazuh

Todas las reglas TFM se envuelven en la rule.id **86601** del decoder Suricata built-in de Wazuh. Para filtrar en el dashboard:

```
rule.groups:"suricata" AND data.alert.signature_id:>=2000000
```

Para una regla concreta:

```
data.alert.signature_id:2000011
```
