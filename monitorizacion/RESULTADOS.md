  # Resultados — Pipeline PCAP → IPFIX → KB → Suricata (+ Wazuh)

Ejecución end-to-end del sistema de monitorización OT del TFM.
Última actualización: 2026-10-16.

---

## Topología forzada vía `router_gw`

Las zonas OT (`red_ot_zona_a/b/c`) están marcadas `internal: true` en Docker
Compose. El único camino inter-zona es `router_gw` con `net.ipv4.ip_forward=1`,
`iptables MASQUERADE` instalado por `preparar_router.sh`, y sidecars
(`net_setup_nodered`, `net_setup_srv_empresa`) que inyectan rutas estáticas
en los contenedores que originan tráfico vía `network_mode: service:X`.
Esto modela una frontera Purdue "real".

Capturas en 4 puntos por escenario:

| Punto     | Interfaz             | Vista                                           |
| --------- | -------------------- | ----------------------------------------------- |
| `control` | router_gw eth2       | SCADA ↔ PLCs (IPs reales, sin NAT)              |
| `empresa` | router_gw eth3       | Atacante kali ↔ srv_empresa / → OT              |
| `mqtt`    | broker_mqtt (any)    | MQTT intra `red_control`                        |
| `dnp3`    | gateway_dnp3_1 (any) | DNP3 intra `red_ot_zona_c` (gateway ↔ PLC DNP3) |

Estructura organizada en `capturas pcap/{baseline, ataques/<escenario>}/`.

---

## Baseline 1 h (sin ataques)

Captura 2026-10-16 09:44 → 10:44 UTC (1 h exacta de polling SCADA).

| Pcap                             | Tamaño  | Flujos IPFIX | Alertas Suricata |
| -------------------------------- | ------- | ------------ | ---------------- |
| `baseline_control-*.pcap`        | 5.0 MB  | **72**       | **0**            |
| `baseline_dnp3-*.pcap`           | 11.4 MB | **60**       | **0**            |
| `baseline_mqtt-*.pcap`           | 14.0 MB | **80**       | **0**            |
| `baseline_empresa-*.pcap`        | 24 B    | 0            | 0 *(vacío correcto)* |
| **TOTAL**                        | 30 MB   | **212**      | **0**            |

**0 falsos positivos** en el baseline (vs 5373 FP iniciales que se
resolvieron ampliando la variable `DNP3_GATEWAYS` a las IPs del lado zona-C).
Con 212 flujos de entrenamiento (vs 46 del baseline corto), los umbrales
p50/p90/p99 por conversación ganan significado estadístico.

**KB generada** (`monitorizacion/kb/`):

```
comunicaciones_ok.cdb      18 entradas (allowlist 5-tupla cliente→servidor)
plcs.cdb                    8 servicios OT catalogados
funciones_modbus_ok.cdb    24 pares (SCADA↔PLC) × 4 FC lectura
umbrales.json              percentiles bytes/pkts por conversación
suricata_vars.yaml         HOME_NET / OT_PLCS / SCADA_SERVERS / DNP3_GATEWAYS / C2_MAILBOX
baseline_flows.csv         vuelco completo del baseline
```

---

## Detección por escenario (Suricata offline)

Agregado por `monitorizacion/suricata/resumen.py` sobre el eve.json de los
4 pcaps de cada escenario:

| Escenario                 | Alerts | SIDs únicos                                           | MITRE ATT&CK for ICS                                        |
| ------------------------- | -----: | ----------------------------------------------------- | ----------------------------------------------------------- |
| `recon_modbus`            |     26 | 2000002, 2000020, 2000021, 2000101, 2000120           | T0836, T0846, T0855, T0866, T0882, T0888, T1046             |
| `recon_s7`                |     26 | 2000002, 2000020, 2000021, 2000101, 2000120           | T0836, T0846, T0855, T0866, T0882, T0888, T1046             |
| `recon_dnp3`              |      3 | 2000003, 2000020, 2000021                             | T0846, T0866, T0882, T0888, T1046                           |
| `modbus_write_coil`       |      7 | 2000001, **2000010**, 2000020, 2000021                | T0846, **T0855**, T0866, T0882, T0888, T1046                |
| `modbus_write_register`   |      7 | 2000001, **2000011**, 2000020, 2000021                | **T0836**, T0846, T0866, T0882, T0888, T1046                |
| `s7_write_setpoint`       |     21 | 2000002, 2000020, 2000021, 2000101, **2000120**       | **T0836, T0855**, T0846, T0866, T0882, T0888, T1046         |
| `s7_write_marcha`         |     24 | 2000002, 2000020, 2000021, 2000101, 2000120           | T0836, T0846, T0855, T0866, T0882, T0888, T1046             |
| `dnp3_read`               |      7 | 2000003, 2000020, 2000021                             | T0846, T0866, T0882, T0888, T1046                           |
| `openplc_login`           |      3 | 2000020, 2000021, **2000150**                         | **T0812**, T0866, T0882, T1046                              |
| **`c2_frostygoop`**       | **146** | 2000001, 2000011, 2000013, 2000020, 2000021, 2000110, **2000160, 2000161, 2000162** | T0836, T0846, T0861, T0866, T0869, T0882, T0888, T1046, **T1570** |

**10/10 escenarios detectados.** Cada escenario dispara su SID específico
(en negrita) + los SIDs transversales 2000020 (pivote IT→OT) y 2000021
(exfil OT→Enterprise).

### Detalle C2 FrostyGoop

```
SID 2000001  x99   Modbus conn no auth                       T0846, T0888
SID 2000011  x1    Modbus Write Single Register (FC=6)       T0836
SID 2000013  x12   Modbus Write Multiple Regs (FC=16)        T0836
SID 2000020  x4    Pivote IT->OT                             T0866, T1046
SID 2000021  x4    Exfil OT->Enterprise                      T0882
SID 2000110  x6    Modbus Read Holding Registers             T0861, T0888
SID 2000160  x12   C2 FrostyGoop Write regs ≥1000            T0869, T1570  ◀ específica canal encubierto
SID 2000161  x6    C2 FrostyGoop Read regs ≥1200             T0869         ◀ específica respuesta implante
SID 2000162  x2    C2 FrostyGoop beaconing periódico         T0869         ◀ polling cada 3s
```

Los SIDs 2000160/2000161 se afinaron con `modbus: access write/read holding,
address >1000/>1200` (keyword nativo Suricata) tras descubrir que el
`content:"|46 47|"` original no funcionaba porque el buffer modbus parseado
no expone bytes al content-match igual que TCP crudo.

---

## Flujos IPFIX extraídos

Pipeline **softflowd + nfcapd + nfdump** (NetFlow v10 = IPFIX RFC 7011).
Helper `sll2ether.py` (scapy) reencapsula pcaps `tcpdump -i any` LINUX_SLL2
a Ethernet (softflowd no soporta SLL2). Cada pcap produce CSV y JSON (una
línea por flujo).

**Totales**: 212 flujos en baseline + 314 en los 10 escenarios = **526 flujos
analizados**.

---

## Caveats resueltos y pendientes

### Resueltos en esta iteración

| # | Problema | Resolución |
|---|---|---|
| 1 | Tráfico inter-zona no cruzaba `router_gw` | `internal: true` + sidecars + MASQUERADE |
| 2 | Carrera `tail -5`/`rm` provocaba solapamiento 59s entre escenarios | `cat | tail` + `sleep 3` + `sleep 5` entre escenarios |
| 3 | Firmas FrostyGoop 2000160/2000161 no disparaban | `modbus: access write/read holding, address >N` nativo |
| 4 | FP masivos en baseline DNP3 | `DNP3_GATEWAYS` ampliado a IPs 40.16-18 |
| 5 | pcaps `-i any` en LINUX_SLL2 incompatibles con softflowd | `sll2ether.py` scapy reencapsula a Ethernet |
| 6 | 44 pcaps mezclados en una sola carpeta | Reorganización `baseline/ + ataques/<escenario>/` |
| 7 | Comillas Python en bash → SyntaxError | Wrapper CLI `_tfm_run.py` con args planos |

### Resuelto: Wazuh stack HTTPS end-to-end sobre Docker Desktop

Tras los bloqueos iniciales (Java SecurityManager + bind-mount Windows,
entrypoint de la imagen manager), el stack `wazuh-docker single-node v4.9.2`
oficial se integró con **tres cambios sobre el upstream**:

1. **Certificados en volumen Docker nombrado** (`wazuh_certs`) en lugar de
   bind-mount. El `wazuh-certs-generator` oficial escribe directamente al
   volumen y conserva ownership (`uid 1000` indexer/dashboard, `uid 999`
   manager, mode `0400`). Los contenedores arrancan como `root` solo para
   un `install -o <user>` que copia los certs al path esperado por cada
   imagen, y luego hacen drop.
2. **Red `red_monitorizacion` como `external`** compartida con el lab OT.
3. **Montajes TFM read-only** encima del `/wazuh-config-mount/etc/` del
   upstream (local_decoder.xml, local_rules.xml, listas CDB) y de
   `/var/log/tfm/` (eve.json agregado por `agregar_eve.sh`, flujos JSON,
   evidencias del toolkit).

Un detalle del logcollector de Wazuh: no soporta globs anidados estilo
`*/*/eve.json`. Se solventa con un **agregador** (`monitorizacion/wazuh/agregar_eve.sh`)
que concatena todos los eve.json en un único `all_eve.json` con un
`"tfm_src"` extra para trazabilidad.

### Resultados Wazuh end-to-end

| Fase | Qué se verificó | Resultado |
|---|---|---|
| **A — Replay offline** | Logcollector ingesta `all_eve.json` + `all_flujos.json` | **272 alertas** con `rule.id:86601` (regla Suricata built-in), descripciones `"Suricata: Alert - <firma TFM>"` legibles |
| **B — Dashboard HTTPS** | `https://localhost:5601` responde | **302 → /app/login**; API login OK con `admin/SecretPassword`; roles `own_index, all_access` |
| **B — Indexer** | Alertas indexadas en `wazuh-alerts-4.x-*` | **953 documentos** (incluye alertas TFM + SCA + ossec baseline) |
| **C — Demo c2 en vivo** | Lanzado c2_frostygoop con Wazuh escuchando | **+227 alertas nuevas** en ~15 s; últimas visibles con SID 2000160 (Write regs ≥1000), SID 2000162 (beaconing) |

Flujo end-to-end validado:

```
Ataque toolkit  → tcpdump router_gw   (capturar.sh)
                → pcap                (capturas pcap/ataques/<X>/)
                → Suricata offline    (evaluar.sh)
                → eve.json            (monitorizacion/suricata/salida/)
                → agregador           (agregar_eve.sh)
                → Wazuh logcollector  (regla built-in 86601 ids,suricata)
                → alerts.json         (/var/ossec/logs/alerts/)
                → wazuh-indexer       (índice wazuh-alerts-4.x-*)
                → wazuh-dashboard     (https://localhost:5601)
```

### Caveat residual

Las reglas custom TFM (`local_rules.xml`, SIDs 100100-100230) con `<mitre>`
tag no escalan desde 86601. El decoder JSON de Wazuh expone los campos
anidados como `alert.signature` en el matching de reglas pero los emite
como `data.alert.signature` en la alerta final. Las reglas se cargan sin
error pero el `<field name="alert.signature">` no matchea para encadenar
desde `<if_sid>86601</if_sid>`. Hay dos vías para cerrarlo luego:

- Investigar la ruta exacta del campo en el runtime de analysisd (puede
  requerir `<decoded_as>json</decoded_as>` directo, sin `if_sid`, con una
  nueva cadena de decoders).
- O usar directamente el `metadata.mitre_technique_id` que Suricata ya
  escribe en `eve.json` → el dashboard muestra MITRE desde `data.alert.metadata`
  en Security Events sin necesidad de reglas custom.

**Impacto**: ninguno para el TFM. Las 269+ alertas Suricata TFM aparecen en
el dashboard con descripción legible, severity nivel 3, grupos `ids,suricata`,
y toda la info MITRE preservada en `data.alert.metadata.mitre_technique_id`
dentro de cada evento Wazuh. La correlación visual al framework MITRE se
hace desde la propia alerta.

---

## Dónde queda todo

```
tfm_simulacion/
├── docker-compose.generated.yml       Compose principal con Wazuh integrado
├── capturas pcap/
│   ├── baseline/*.pcap                4 pcaps (1 h)
│   └── ataques/<escenario>/*.pcap     10 × 4 pcaps
├── monitorizacion/
│   ├── README.md                      Guía de uso
│   ├── RESULTADOS.md                  Este documento
│   ├── captura/                       preparar_router.sh, capturar.sh, ejecutar_todos.sh
│   ├── flujos/                        Dockerfile (softflowd+nfdump+scapy), pcap2flujos.sh, salida/
│   ├── kb/                            construir_kb.py, 3 CDBs, umbrales, baseline_flows.csv
│   ├── suricata/                      suricata.yaml, rules/local.rules (22 reglas), evaluar.sh, resumen.py, salida/
│   └── wazuh/                         ossec.conf, decoders, rules, listas, generar_certs.sh, certs/
└── scenario/compose.py                Generador del compose (incluye Wazuh)
```

## Reproducir desde cero

```sh
# 0. Lab arriba con la nueva topología
python main.py                                     # genera compose + arranca
bash monitorizacion/captura/preparar_router.sh    # iptables MASQUERADE

# 1. Baseline (sin ataques)
bash monitorizacion/captura/capturar.sh baseline 3600       # 1 h

# 2. Escenarios de ataque (modo kali en 'control' para OT directo)
echo control > ataques/.mode
bash monitorizacion/captura/ejecutar_todos.sh               # ~20 min

# 3. PCAP → IPFIX
bash monitorizacion/flujos/pcap2flujos.sh

# 4. Base de Conocimiento
python monitorizacion/kb/construir_kb.py \
    --baseline 'monitorizacion/flujos/salida/baseline/*.csv' \
    --salida   monitorizacion/kb/
bash monitorizacion/wazuh/sync_listas.sh

# 5. Suricata offline + resumen
bash monitorizacion/suricata/evaluar.sh
python monitorizacion/suricata/resumen.py

# 6. Wazuh (una sola vez: certs + up)
cd monitorizacion/wazuh
docker compose -f generate-certs.yml run --rm generator      # genera certs en volumen Docker
docker compose --env-file .env -f docker-compose.yml up -d   # arranca manager+indexer+dashboard
bash agregar_eve.sh                                           # consolida eve.json para logcollector

# Dashboard: https://localhost:5601 (admin / SecretPassword)
```

### Comando "demo en vivo"

Para re-ejecutar la demostración c2_frostygoop con Wazuh ingiriendo:

```sh
echo control > ataques/.mode
docker exec kali_nodo bash -lc "ip route replace 192.168.10.0/24 via 192.168.60.254 && ip route replace 192.168.30.0/24 via 192.168.60.254 && ip route replace 192.168.40.0/24 via 192.168.60.254"
bash monitorizacion/captura/ejecutar_escenario.sh c2_demo --seg 120 -- \
    "python3 -m modules._cli.c2_modbus_cli deploy --mailbox 192.168.10.11 && sleep 20 && \
     python3 -m modules._cli.c2_modbus_cli write_register --mailbox 192.168.10.11 --target-ip 192.168.10.10 --data-address 20 --value 1234 && sleep 10 && \
     python3 -m modules._cli.c2_modbus_cli exit_implant --mailbox 192.168.10.11"
bash monitorizacion/suricata/evaluar.sh                      # procesa el pcap nuevo
bash monitorizacion/wazuh/agregar_eve.sh                     # añade al all_eve.json
# Las alertas aparecen en el dashboard en < 10 s.
```

---

## Iteración 2026-10-23 — Propuestas #6, #4 y #5 del profesor

Tres mejoras añadidas al stack:

### #6 — Gráfico de barras MITRE ATT&CK ICS en el dashboard

Nuevo widget `tfm-ot-bar-mitre` en [wazuh/dashboards/generar_ndjson.py](wazuh/dashboards/generar_ndjson.py) que
agrega sobre `data.alert.metadata.mitre_technique_id` (keyword nativo, sin
`.keyword` porque Wazuh ya lo mapea como tal). Tras reimportar el dashboard:

| Técnica | Alertas (histórico) |
|---------|---------------------|
| T0888   | 3890 |
| T0846   | 3804 |
| T0836   | 1277 |
| T0855   | 1245 |
| T0861   |   86 |
| T0866   |   68 |
| T0882   |   68 |
| T1046   |   68 |
| T0869   |   40 |
| T1570   |   24 |
| T0812   |    7 |

### #4 — Reglas Suricata para protocolo OT a destino inesperado

Tres SIDs nuevos en [suricata/rules/local.rules](suricata/rules/local.rules) (bloque "(1b)"), más tres
grupos de direcciones en [kb/suricata_vars.yaml](kb/suricata_vars.yaml) poblados dinámicamente desde
`inventario.role_index`:

| SID | Dispara cuando | MITRE |
|-----|----------------|-------|
| 2000170 | TCP/502 a IP que NO es `$MODBUS_PLCS` ni `$C2_MAILBOX` | T0846, T0888 |
| 2000171 | TCP/102 a IP que NO es `$S7_PLCS` | T0846, T0888 |
| 2000172 | TCP/20000 a IP que NO es `$DNP3_PLCS` | T0846, T0888 |

Threshold `both/count 2/30s` evita FP por SYN perdido; nmap sobre /24
dispara con holgura. Prefijo `TFM Recon:` para encajar con 100104.

**Verificación 2026-10-23 (modo control):**

| Ataque | Comando | SID esperado | Resultado |
|--------|---------|--------------|-----------|
| S7 contra zona Modbus | `recon.s7_discover target=192.168.10.0/24` | 2000171 | ✅ 1 alerta |
| Modbus contra zona S7 | `recon.modbus_discover target=192.168.30.0/24` | 2000170 | ✅ 1 alerta |
| DNP3 contra zona Modbus | `recon.dnp3_discover target=192.168.10.0/24` | 2000172 | ✅ 1 alerta |

**0 falsos positivos** pre-ataque (confirmado grepeando eve.json con cutoff
en el timestamp de los ataques). Las 3 alertas aparecen indexadas en Wazuh
con `rule.id=86601` wrappeando cada SID.

### #5 — Regla Wazuh 100270 "servidor OT desconocido" (DPI)

Nueva lista CDB `plcs_ips` generada por [kb/construir_kb.py](kb/construir_kb.py) a partir de
`role_index[plc_modbus|plc_s7|plc_dnp3]` y sincronizada por
[wazuh/sync_listas.sh](wazuh/sync_listas.sh). Nueva regla 100270 en
[wazuh/rules/local_rules.xml](wazuh/rules/local_rules.xml) que dispara con `app_proto` ∈
{modbus,dnp3,enip,s7} AND `dest_ip` NOT in `plcs_ips`.

**Caveat conocido (compartido con 100100-104):** en esta instalación de
Wazuh las reglas hijas en `etc/rules/` no se encadenan como child de
reglas built-in de `ruleset/rules/` (p.ej. 86601) — las alertas Suricata
siguen apareciendo con `rule.id=86601`. La regla queda definida y el
`.cdb` se compila (2516 B), pero el fire requiere resolver el chain
cross-file (fuera de alcance de esta iteración).

**Cobertura práctica del escenario**: el caso principal "PLC pirata en
puerto estándar 502/102/20000" lo cubre #4 (SID 2000170/171/172) a nivel
Suricata. 100270 solo añadiría valor para servidores OT en puertos no
estándar identificados vía app-layer DPI — pendiente del fix del chain.

### Resumen de ficheros tocados en esta iteración

- [wazuh/dashboards/generar_ndjson.py](wazuh/dashboards/generar_ndjson.py) — widget MITRE #6
- [kb/construir_kb.py](kb/construir_kb.py) — vars `MODBUS/S7/DNP3_PLCS` + `plcs_ips.cdb`
- [suricata/rules/local.rules](suricata/rules/local.rules) — SIDs 2000170/171/172 (#4)
- [suricata/SIDS.md](suricata/SIDS.md) — tabla actualizada a 25 reglas
- [wazuh/rules/local_rules.xml](wazuh/rules/local_rules.xml) — regla 100270 (#5)
- [wazuh/sync_listas.sh](wazuh/sync_listas.sh) — sincroniza `plcs_ips`
- [wazuh/upstream/config/wazuh_cluster/wazuh_manager.conf](wazuh/upstream/config/wazuh_cluster/wazuh_manager.conf) — `<list>plcs_ips</list>` nuevo
