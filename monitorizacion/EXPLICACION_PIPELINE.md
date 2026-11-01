# Pipeline de detección OT del TFM — explicación completa

> Documento técnico que describe, paso a paso, todo lo construido sobre el
> laboratorio ICS/OT desde la captura de PCAP hasta la alerta en Wazuh. Para
> cada fichero y cada decisión se indica **qué hace**, **por qué está así** y,
> cuando aplica, **qué viene "de caja"** (built-in) frente a **qué se ha
> configurado a mano**. Al final hay una traza end-to-end de una alerta real.

## 0. Visión global

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  tcpdump en  │   │   softflowd  │   │  construir   │   │   Suricata   │
│  router_gw   │─▶│  + nfcapd +  │─▶│    KB.py     │  │   offline    │
│ (4 puntos)   │   │    nfdump    │   │ (allowlists) │   │  (modbus,    │
└──────────────┘   └──────────────┘   └──────────────┘   │   dnp3,…)    │
      │                   │                   │          └──────┬───────┘
      ▼                   ▼                   ▼                 ▼
  capturas pcap/     flujos/salida/   kb/*.cdb +            suricata/salida/
                     *.csv, *.json    umbrales.json +       <esc>/eve.json
                                      suricata_vars.yaml
                                                                 │
                                   ┌─────────────────────────────┘
                                   ▼
                            agregar_eve.sh
                               │  concatena todos los eve.json
                               │  + añade "tfm_src" por línea
                               ▼
                            wazuh/all_eve.json
                               │  Wazuh logcollector lee este fichero
                               ▼
                 ┌─────────────────────────────────┐
                 │  Wazuh manager                  │
                 │   · decoder JSON (built-in)     │
                 │   · regla 86601 (built-in)      │
                 │   · <label tfm.capa=dpi>        │
                 │   · <label tfm.fuente=suricata> │
                 └────────────────┬────────────────┘
                                  ▼
                        filebeat → wazuh.indexer
                                  ▼
                        wazuh-alerts-4.x-YYYY.MM.DD
                                  ▼
                        wazuh.dashboard (OpenSearch)
                        https://localhost:5601
```

El pipeline tiene **dos niveles complementarios** por diseño:

- **Nivel 1 — Flujos L3/L4 (IPFIX)**: resumen por conversación, útil para
  detectar anomalías volumétricas y comunicaciones fuera de allowlist, sin
  pagar el coste de DPI. Es la fuente de la **Base de Conocimiento**.
- **Nivel 2 — DPI (Deep Packet Inspection) con Suricata**: parseo de los
  protocolos OT (`modbus`, `dnp3`, `enip`) para detectar operaciones
  semánticamente anómalas (p. ej. "escritura a un holding register fuera
  del rango usado por la planta").

Ambos niveles acaban en Wazuh como SIEM: índice único, un dashboard, filtros
por `tfm.capa`, `tfm.fuente` y `tfm_src` para trazar al pcap original.

## 1. Captura PCAP

### 1.1 Topología forzada (Purdue "real")

El `docker-compose.generated.yml` declara las tres zonas OT como
`internal: true`. Esto hace que las subredes `192.168.10.0/24`,
`192.168.30.0/24` y `192.168.40.0/24` **no tengan salida directa**: el único
camino inter-zona pasa por `router_gw` (un contenedor Alpine con
`net.ipv4.ip_forward=1`). Es la frontera Purdue que separa:

- **Enterprise (nivel 4)**: `192.168.60.0/24` → `kali_nodo`, `srv_empresa`.
- **Control (nivel 3)**: `192.168.20.0/24` → `nodered_scada`, broker MQTT,
  gateways DNP3.
- **OT (nivel 2)**: zonas A/B/C con los PLCs.
- **Monitorización**: `192.168.50.0/24` → stack Wazuh.

**Importante**: sin la MASQUERADE que se instala en el paso siguiente, el
bridge Docker de las redes `internal` descarta los paquetes reenviados cuyo
`SRC` no sea de la propia subred. Por eso hay que inyectar las reglas tras
cada `docker compose up`.

### 1.2 `preparar_router.sh` — iptables + mapeo de interfaces

Fichero: [monitorizacion/captura/preparar_router.sh](captura/preparar_router.sh)

Qué hace (idempotente):

1. Instala `tcpdump` + `iptables` dentro de `router_gw` y `broker_mqtt`
   (`apk add --no-cache …`).
2. Detecta los nombres `ethN` dinámicos del router (cambian entre reinicios)
   a partir de las IPs conocidas (ej. `192.168.20.254` = red_control).
3. Instala **tres reglas MASQUERADE** en `router_gw`:
   ```
   -t nat -A POSTROUTING -d 192.168.10.0/24 -o $IF_MOD -j MASQUERADE
   -t nat -A POSTROUTING -d 192.168.30.0/24 -o $IF_S7  -j MASQUERADE
   -t nat -A POSTROUTING -d 192.168.40.0/24 -o $IF_DNP -j MASQUERADE
   ```
   Esto asegura que el paquete que entra por `red_control` y sale a una
   zona OT lleve como `SRC` la IP del router en la zona de destino.
4. Escribe `captura/.ifaces.env` con los nombres de interfaz detectados,
   para que `capturar.sh` sepa dónde pinchar el tcpdump.

**Por qué así**: capturar en las interfaces externas al NAT (eth2 = control,
eth3 = empresa) preserva las IPs originales de cliente — exactamente las que
necesitan Suricata y la KB. Capturar en las interfaces OT del router
mostraría paquetes ya SNATeados.

### 1.3 `capturar.sh` — tcpdump en 4 puntos simultáneos

Fichero: [monitorizacion/captura/capturar.sh](captura/capturar.sh)

Lanza cuatro `tcpdump` en paralelo con el mismo timestamp y los recoge por
`stdout` al host, para que no haya que montar volúmenes a nivel contenedor:

| Punto     | Interfaz             | Qué ve                                          |
| --------- | -------------------- | ----------------------------------------------- |
| `control` | router_gw eth2       | SCADA ↔ PLCs, srv_empresa dual-homed, gateways  |
| `empresa` | router_gw eth3       | Atacante kali ↔ srv_empresa / → OT             |
| `mqtt`    | broker_mqtt (any)    | MQTT intra `red_control` (no cruza el router)   |
| `dnp3`    | gateway_dnp3_1 (any) | DNP3 intra `red_ot_zona_c`                      |

Modos:
- `baseline [SEG]` → captura limpia de SEG segundos en `capturas pcap/baseline/`.
- `escenario NOMBRE [SEG]` → captura del ataque en `capturas pcap/ataques/<NOMBRE>/`.

### 1.4 `ejecutar_escenario.sh` — captura + ataque sincronizados

Fichero: [monitorizacion/captura/ejecutar_escenario.sh](captura/ejecutar_escenario.sh)

Arranca `capturar.sh` en background, espera 10 s de pre-roll para que
tcpdump esté estable, lanza el módulo de ataque dentro de `kali_nodo` con
`docker exec kali_nodo bash -lc "cd /ataques && …"`, y al terminar el
atacante espera a que la captura cierre su ventana temporal. Pensado para
que un escenario completo quede autocontenido en un pcap etiquetado por
nombre + timestamp.

### 1.5 `ejecutar_todos.sh` — secuenciador de los 10 escenarios

Fichero: [monitorizacion/captura/ejecutar_todos.sh](captura/ejecutar_todos.sh)

Encadena los 10 módulos del toolkit (`recon_modbus`, `recon_s7`,
`recon_dnp3`, `modbus_write_coil`, `modbus_write_register`,
`s7_write_setpoint`, `s7_write_marcha`, `dnp3_read`, `openplc_login`,
`c2_frostygoop`) con 5 s de margen entre ellos para que los `tcpdump` de un
escenario no solapen con los del siguiente. Requisito: `ataques/.mode =
control` (kali en la red SCADA, con acceso directo a OT).

## 2. PCAP → IPFIX (flujos)

### 2.1 Imagen `tfm_monitor`

Fichero: [monitorizacion/flujos/Dockerfile](flujos/Dockerfile) · Debian slim con
`softflowd` + `nfdump` + `tcpdump` + `tshark` + `python3-scapy`.

Decisión histórica: el plan inicial era usar **YAF + super_mediator + SiLK**
(stack CERT/NetSA), pero no está empaquetado en los repos de Debian
Bookworm. Se migró a **softflowd + nfcapd + nfdump**, que produce **NetFlow
v10 = IPFIX RFC 7011** (mismo formato, menos semántica OT; la semántica OT
la pone Suricata en el nivel 2).

### 2.2 `pcap2flujos.sh` — un `docker run` por pcap

Fichero: [monitorizacion/flujos/pcap2flujos.sh](flujos/pcap2flujos.sh)

Para cada pcap:

1. **Normalización LINUX_SLL2**: `tcpdump -i any` guarda link-type SLL/SLL2
   para registrar la interfaz. Softflowd no entiende SLL2, así que se usa el
   helper `sll2ether.py` (scapy) para reencapsular los paquetes como
   Ethernet. Es el motivo del archivo `sll2ether.py` en la carpeta.
2. **Colector**: lanza `nfcapd -D -b 127.0.0.1 -p 9995 -w /tmp/nf` en
   background. Es el daemon colector de IPFIX escribiendo bloques nfcapd
   binarios cada 5 s.
3. **Exportador**: `softflowd -r <pcap> -n 127.0.0.1:9995 -v 10 -t
   maxlife=120 -a`. Lee el pcap y exporta flujos v10 al colector local.
4. **Flush + conversión**: `pkill SIGTERM nfcapd` cierra el bloque, y luego:
   - `nfdump -r /tmp/nf -o csv` → CSV (una línea por flujo + cabecera).
   - `nfdump -r /tmp/nf -o json` → JSON (una línea por flujo) para Wazuh,
     filtrando sólo entradas `type == FLOW` con un filtro Python.

La salida espeja la estructura `capturas pcap/` en `flujos/salida/`:

```
flujos/salida/baseline/baseline_control-….csv
flujos/salida/baseline/baseline_control-….json
flujos/salida/ataques/c2_frostygoop/atk_c2_frostygoop_empresa-….csv
flujos/salida/ataques/c2_frostygoop/atk_c2_frostygoop_empresa-….json
```

### 2.3 ¿Por qué dos formatos (CSV + JSON)?

- **CSV**: lo consume `construir_kb.py` para generar la base de conocimiento
  (allowlists y umbrales).
- **JSON una-línea-por-flujo**: lo consume el logcollector de Wazuh. Un flujo
  por evento SIEM; permite filtrar por `src_ip`, `dest_port`, `bytes` en el
  dashboard.

## 3. Construcción de la Base de Conocimiento (KB)

Fichero: [monitorizacion/kb/construir_kb.py](kb/construir_kb.py)

Entrada: el **CSV del baseline** limpio (`flujos/salida/baseline/*.csv`),
que debe representar el laboratorio operando sin ataques — SCADA sondeando
PLCs, gateways DNP3 hablando con `plc_dnp3_*`, MQTT normal.

Salidas (en `kb/`):

| Fichero                     | Contenido                                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------- |
| `comunicaciones_ok.cdb`     | Allowlist 5-tupla (`sip:dip:dport/proto` → `ok`). 18 entradas en el baseline final.                     |
| `plcs.cdb`                  | Catálogo `ip:puerto:rol:proto` (8 servicios OT).                                                        |
| `funciones_modbus_ok.cdb`   | Pares (SCADA → PLC_Modbus) × 4 function codes de **lectura** (FC 1,2,3,4). 24 entradas.                 |
| `umbrales.json`             | Percentiles p50/p90/p99 de bytes/paquetes por conversación.                                             |
| `suricata_vars.yaml`        | Variables HOME_NET, OT_PLCS, SCADA_SERVERS, DNP3_GATEWAYS, C2_MAILBOX, ENTERPRISE a inyectar.           |
| `baseline_flows.csv`        | Vuelco completo del baseline (trazabilidad).                                                            |

**El principio**: en una planta OT real, la matriz de comunicaciones es
*casi* estática. SCADA habla con sus PLCs en puertos conocidos; nadie más
debería hablar con los PLCs. La KB captura ese "normal" y lo convierte en
listas que Suricata (vía variables) y Wazuh (vía listas CDB) consultan.

**Formato CDB** (Wazuh Constant Database): fichero plano `clave:valor` por
línea; Wazuh lo convierte internamente a un `.cdb` binario con hash en el
primer arranque. Es la forma oficial de Wazuh de consultar listas grandes
en reglas sin impacto de rendimiento.

## 4. Suricata — motor DPI

### 4.1 `suricata.yaml`

Fichero: [monitorizacion/suricata/suricata.yaml](suricata/suricata.yaml) (101 líneas)

Lo relevante:

- **Variables** (`vars.address-groups`) con las subredes OT y las IPs
  significativas (`SCADA_SERVERS`, `OT_PLCS`, `DNP3_GATEWAYS`, `C2_MAILBOX`,
  `ENTERPRISE`). Son las que usan las reglas con `$NAME`.
- **`app-layer.protocols`**: habilitado para `modbus:502`, `dnp3:20000`,
  `enip:44818`. Con esto Suricata parsea los PDU y expone `data.modbus.*`,
  `data.dnp3.*`, etc. en los eventos de alert. **Esta es la razón por la
  que el eve.json incluye `function_code: WrMultRegs`, `unit_id: 2`,
  `write.address: 1000`** — es el parser de Suricata, no una regla.
- **`outputs.eve-log`**: emite `eve.json` con tipos `alert`, `anomaly`,
  `http`, `dns`, `tls`, `flow`, `netflow`, `stats`. El `metadata: yes` en
  `alert` hace que incluya los campos `metadata:` de cada regla (es el
  mecanismo con el que se emite el mapeo MITRE).
- **`pcap-file.checksum-checks: no`**: necesario para el modo offline
  porque algunos pcaps capturados por tcpdump dentro de contenedores llevan
  checksums TCP incorrectos (offload).

### 4.2 Reglas custom: `local.rules`

Fichero: [monitorizacion/suricata/rules/local.rules](suricata/rules/local.rules)
(222 líneas, 22 reglas, SIDs 2000001-2000162, todas revisión ≥1).

Dos bloques:

**(1) Allowlist OT** (SIDs 2000001-2000021). La idea es *disparar por
cualquier cosa que no esté en la matriz esperada*:

| SID        | Qué castiga                                                                           |
| ---------- | ------------------------------------------------------------------------------------- |
| `2000001`  | TCP a puerto Modbus (502) desde origen NO SCADA y NO gateway DNP3.                    |
| `2000002`  | TCP a puerto S7 (102) desde origen NO SCADA.                                          |
| `2000003`  | TCP a puerto DNP3 (20000) desde origen NO gateway DNP3.                               |
| `2000010-13` | PDU Modbus FC=5/6/15/16 (escrituras) desde origen NO SCADA. El baseline no tiene ninguna escritura, así que cualquiera es anómala. |
| `2000020`  | Cualquier paquete `red_empresa → OT_PLCS` (pivote IT→OT).                             |
| `2000021`  | Cualquier paquete `OT_PLCS → red_empresa` (exfiltración).                             |

**(2) Firmas específicas por módulo del toolkit** (SIDs 2000100-2000162):

| SID        | Castiga                                                                                                                        |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `2000100`  | Modbus FC=43 (Read Device Identification) → patrón `nmap modbus-discover`.                                                     |
| `2000101`  | COTP+S7 identification → `nmap s7-info`.                                                                                       |
| `2000110`  | FC=3 (Read Holding Registers) masivo desde origen NO SCADA, con `threshold:count 3, seconds 10`.                               |
| `2000120`  | Tráfico TCP:102 desde origen NO SCADA → setpoint/marcha S7.                                                                    |
| `2000130-31` | DNP3 Operate/DirectOperate desde no-gateway.                                                                                 |
| `2000140-41` | Acceso SMB a `Backups_SCADA` y login SSH entrante a `srv_empresa` (pivote).                                                  |
| `2000150-51` | OpenPLC login HTTP + upload `.st`.                                                                                           |
| `2000160`  | **C2 FrostyGoop — write**: `modbus: access write holding, address >1000` → `$C2_MAILBOX` (`plc_agua_2`).                       |
| `2000161`  | **C2 FrostyGoop — read**: `modbus: access read holding, address >1200`.                                                        |
| `2000162`  | **C2 FrostyGoop — beaconing**: TCP a `C2_MAILBOX:502` con `threshold:type both, track by_src, count 5, seconds 20`.            |

Cada regla incluye:
- `classtype:` → categoría Suricata (p. ej. `trojan-activity`,
  `policy-violation`, `attempted-admin`, `attempted-recon`).
- `metadata: mitre_tactic_id … mitre_technique_id …` → el mapeo MITRE
  ATT&CK for ICS. Cuando llega a Wazuh, estos campos quedan en
  `data.alert.metadata.mitre_tactic_id` y `data.alert.metadata.mitre_technique_id`.

**Detalle importante sobre las firmas FrostyGoop**: en versiones iniciales
estaban escritas con `content:"|46 47|"` (bytes "FG" del magic FrostyGoop).
No disparaban porque Suricata, cuando `app-layer: modbus` está activo,
expone el buffer **parseado** (campos semánticos) y no permite content-match
sobre bytes crudos del payload Modbus. La solución fue reescribirlas usando
el keyword nativo `modbus: access <read|write> holding, address >N`, que es
la forma correcta en Suricata ≥6 de condicionar por dirección de registro.

### 4.3 `evaluar.sh` — Suricata offline sobre cada pcap

Fichero: [monitorizacion/suricata/evaluar.sh](suricata/evaluar.sh)

Para cada pcap bajo `capturas pcap/`:

1. Copia el pcap a un directorio plano `suricata/pcaps_in/` (los subdirs
   chocarían al montar como volumen).
2. Ejecuta un contenedor efímero con la imagen `jasonish/suricata:latest` y
   monta la configuración y las reglas:
   ```
   docker run --rm \
       -v pcaps_in:/pcaps:ro \
       -v suricata.yaml:/etc/suricata/suricata.yaml:ro \
       -v rules:/etc/suricata/rules:ro \
       -v salida/<escenario>/<pcap>:/var/log/suricata \
       jasonish/suricata suricata -c suricata.yaml -S local.rules \
                                   -r /pcaps/<nombre>.pcap -l /var/log/suricata
   ```
3. Deja `eve.json` en `monitorizacion/suricata/salida/<baseline|ataques/
   escenario>/<pcap>/eve.json` + imprime el conteo de alertas.

Se usa imagen oficial `jasonish/suricata` (no se build-ea una propia) para
tener Suricata 7.x con todos los parsers OT compilados.

### 4.4 `resumen.py` — tabla escenario × SID × MITRE

Fichero: [monitorizacion/suricata/resumen.py](suricata/resumen.py). Recorre
`salida/`, agrega las alertas por escenario y genera dos vistas:

1. Una tabla pivot con `escenario → total alertas, SIDs únicos, MITRE únicos`.
2. Un detalle por escenario con `SID × N × firma × MITRE`.

Es la base de la tabla "Detección por escenario" de
[RESULTADOS.md](RESULTADOS.md).

## 5. Agregador para Wazuh

### 5.1 `agregar_eve.sh`

Fichero: [monitorizacion/wazuh/agregar_eve.sh](wazuh/agregar_eve.sh)

**El problema**: el `logcollector` de Wazuh no soporta globs anidados
(`*/*/eve.json`). Sólo acepta un patrón plano por `<location>`.

**La solución**: concatenar todos los `eve.json` producidos por Suricata en
un único fichero `all_eve.json`, añadiendo a cada línea el campo
`"tfm_src":"<ruta_relativa_al_pcap>"`. El sed usado es:

```bash
echo "${line%\}},\"tfm_src\":\"${rel}\"}" >> "$OUT_EVE"
```

Es decir: tomar la línea JSON, borrar el último `}`, pegar
`,"tfm_src":"..."` y recomponer el `}`. Rápido y sin dependencias de `jq`.

Hace lo mismo con los flujos nfdump (`all_flujos.json`).

### 5.2 `sync_listas.sh`

Fichero: [monitorizacion/wazuh/sync_listas.sh](wazuh/sync_listas.sh). Copia
los `.cdb` que produjo `construir_kb.py` desde `kb/` a `wazuh/listas/`
(sin extensión; Wazuh añade `.cdb` cuando compila el binario). Es un paso
puro de sincronización.

## 6. Wazuh — SIEM

### 6.1 Despliegue: `upstream/` + `generate-certs.yml` + `docker-compose.yml`

Fichero principal: [monitorizacion/wazuh/docker-compose.yml](wazuh/docker-compose.yml)

Partimos de `wazuh-docker/single-node v4.9.2` oficial (clonado intacto en
`upstream/`) y aplicamos **tres cambios mínimos**:

**(A) Certificados en volumen Docker nombrado `wazuh_certs`**, no en
bind-mount. En Docker Desktop Windows, el *Java SecurityManager* de
OpenSearch deniega la lectura de bind-mounts porque los uids/gids del host
no coinciden con los del contenedor (indexer corre como `uid 1000`, manager
como `uid 999`). Los volúmenes nombrados viven dentro de la VM WSL2 de
Docker Desktop y conservan ownership nativamente.

El fichero `generate-certs.yml` lanza una sola vez el contenedor oficial
`wazuh-certs-generator`, que escribe los certs al volumen con permisos
`0400 root:root` o `0400 wazuh:wazuh` según el certificado.

**(B) `red_monitorizacion` como external**: en vez de crear su propia red,
el stack Wazuh entra en la red del lab para poder resolver nombres de los
contenedores OT (si alguna vez se añaden agentes). IPs fijas: `.10`
manager, `.11` indexer, `.12` dashboard.

**(C) Montajes TFM encima del `wazuh-config-mount`** (bind-mounts
read-only, no sufren el bug (A) porque no requieren escritura):

| Montaje host                       | Destino en el contenedor manager                            |
| ---------------------------------- | ----------------------------------------------------------- |
| `upstream/config/wazuh_cluster/wazuh_manager.conf` | `/wazuh-config-mount/etc/ossec.conf`         |
| `decoders/local_decoder.xml`       | `/wazuh-config-mount/etc/decoders/local_decoder.xml`        |
| `rules/local_rules.xml`            | `/wazuh-config-mount/etc/rules/local_rules.xml`             |
| `listas/`                          | `/wazuh-config-mount/etc/lists/tfm`                         |
| `../flujos/salida` (ro)            | `/var/log/tfm/flujos`                                       |
| `../suricata/salida` (ro)          | `/var/log/tfm/suricata`                                     |
| `../../ataques/evidencias` (ro)    | `/var/log/tfm/ataques`                                      |
| `.` (ro)                           | `/var/log/tfm/wazuh_in` (donde está `all_eve.json`)         |

Entrypoint custom en los tres servicios: arranca como `root`, copia los
certs del volumen al path esperado por cada imagen (`/etc/ssl/*.pem` en el
manager, por ejemplo), hace `install -o <user>` para quedarse con el
ownership correcto, y luego ejecuta el entrypoint oficial (`exec /init`,
`exec /entrypoint.sh opensearchwrapper`, dashboard con `--allow-root`).

### 6.2 `wazuh_manager.conf` — los `<localfile>` que lo cambian todo

Fichero: [monitorizacion/wazuh/upstream/config/wazuh_cluster/wazuh_manager.conf](wazuh/upstream/config/wazuh_cluster/wazuh_manager.conf)

Los bloques críticos del TFM están entre las líneas 316-345:

```xml
<!-- Alertas Suricata eve.json (agregado por agregar_eve.sh) -->
<localfile>
    <log_format>json</log_format>
    <location>/var/log/tfm/wazuh_in/all_eve.json</location>
    <label key="tfm.capa">dpi</label>
    <label key="tfm.fuente">suricata</label>
</localfile>

<!-- Flujos IPFIX en JSON -->
<localfile>
    <log_format>json</log_format>
    <location>/var/log/tfm/wazuh_in/all_flujos.json</location>
    <label key="tfm.capa">flujo</label>
    <label key="tfm.fuente">nfdump</label>
</localfile>

<!-- Evidencias del toolkit (ground truth) -->
<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/tfm/ataques/*.log</location>
    <label key="tfm.capa">ground_truth</label>
    <label key="tfm.fuente">toolkit_tfm</label>
</localfile>
```

**Qué hace cada etiqueta**: los `<label key="...">` son una característica
built-in de Wazuh. El `logcollector` adjunta esos pares clave/valor a cada
evento ingerido antes de que llegue al `analysisd`. Son los que aparecen
luego en las alertas como `data.tfm.capa`, `data.tfm.fuente` — permiten
filtrar en el dashboard por la **capa de detección** (DPI, flujo o ground
truth) sin tener que escribir reglas custom.

Más abajo en el fichero (`<ruleset>`), se declara también la carga de las
listas CDB sincronizadas por `sync_listas.sh`:

```xml
<list>etc/lists/tfm/comunicaciones_ok</list>
<list>etc/lists/tfm/plcs</list>
<list>etc/lists/tfm/funciones_modbus_ok</list>
```

### 6.3 `local_decoder.xml` — decoders custom

Fichero: [monitorizacion/wazuh/decoders/local_decoder.xml](wazuh/decoders/local_decoder.xml)

**No afecta a las alertas de Suricata** (ésas las decodifica el decoder
built-in `json` sin ayuda). Define dos decoders propios:

- `tfm-flujos-ipfix` / `-campos`: identifica los eventos JSON del
  `all_flujos.json` por el campo `sourceIPv4Address` (nombre nfdump) y los
  pasa por el `JSON_Decoder` plugin. Esto expone cada campo del flujo como
  `data.sourceIPv4Address`, `data.destinationIPv4Address`, etc., filtrables.
- `tfm-toolkit` / `-accion`: para los logs libres del toolkit de ataques
  (`YYYY-MM-DD_HH-MM-SS_<modulo>_<accion>.log`), extrae `modulo` y `accion`
  con una regex. Sirve para construir el "ground truth": qué ataque se
  lanzó y a qué hora, para correlacionar más tarde con las alertas.

### 6.4 `local_rules.xml` — reglas custom (caveat conocido)

Fichero: [monitorizacion/wazuh/rules/local_rules.xml](wazuh/rules/local_rules.xml)

Define 5 reglas 100xxx que intentaban escalar sobre la 86601 built-in
cuando el `data.alert.signature_id` coincide con alguna firma TFM concreta,
para subir el nivel de severidad y añadir el `<mitre>` tag:

```xml
<rule id="100160" level="12">
    <if_sid>86601</if_sid>
    <field name="alert.signature">...FrostyGoop...</field>
    <mitre>
      <id>T0869</id>
      <id>T1570</id>
    </mitre>
    <description>C2 FrostyGoop detectado - canal encubierto Modbus</description>
</rule>
```

**Caveat residual** (ya en [RESULTADOS.md](RESULTADOS.md)): estas reglas no
disparan por un detalle del runtime de `analysisd`. El decoder JSON de
Wazuh expone los campos como `alert.signature` para el matching de reglas,
pero los emite como `data.alert.signature` en la alerta final. El
`<field name="alert.signature">` del XML no matchea para encadenar desde
`<if_sid>86601</if_sid>`.

**Impacto**: ninguno para el TFM. La información MITRE sigue llegando al
dashboard dentro de `data.alert.metadata.mitre_technique_id` (lo escribió
Suricata). Se puede filtrar en Security Events por ese campo directamente,
sin necesidad de reglas custom.

## 7. Qué es "de caja" vs qué está configurado a mano

| Pieza                                                 | Origen                                                               |
| ----------------------------------------------------- | -------------------------------------------------------------------- |
| **Suricata**                                          |                                                                      |
| Parser Modbus/DNP3/ENIP (extracción de FC, address…)  | Built-in Suricata                                                    |
| Keyword `modbus: access <read\|write>, address >N`    | Built-in Suricata                                                    |
| Formato eve.json con `alert`, `flow`, `anomaly`       | Built-in Suricata                                                    |
| **Las 22 reglas de `local.rules`** (SIDs 2000001-162) | **TFM** · escritas desde cero mapeando a MITRE ATT&CK for ICS        |
| Variables `$C2_MAILBOX`, `$OT_PLCS`, …                | **TFM** · derivadas del baseline por `construir_kb.py`               |
| `suricata.yaml` con `app-layer` + outputs             | **TFM** · adaptado al laboratorio                                    |
| **Pipeline PCAP → IPFIX**                             |                                                                      |
| softflowd, nfcapd, nfdump                             | Debian / NetFlow community                                           |
| `pcap2flujos.sh`, imagen `tfm_monitor`, `sll2ether.py` | **TFM**                                                             |
| **Base de Conocimiento**                              |                                                                      |
| `construir_kb.py` + `.cdb` resultantes                | **TFM**                                                              |
| Formato CDB                                           | Built-in Wazuh                                                       |
| **Wazuh — stack**                                     |                                                                      |
| Imágenes manager / indexer / dashboard                | Oficiales Wazuh 4.9.2 (upstream intacto)                             |
| Regla 86601 "Suricata: Alert - …"                     | Built-in Wazuh (`0470-suricata_rules.xml`)                           |
| Decoder JSON built-in                                 | Built-in Wazuh                                                       |
| Dashboard OpenSearch                                  | Built-in Wazuh                                                       |
| **Wazuh — configuración TFM**                         |                                                                      |
| 3 bloques `<localfile>` + `<label tfm.*>`             | **TFM** · en `wazuh_manager.conf`                                    |
| Compose propio con 3 cambios (certs, red, montajes)   | **TFM**                                                              |
| `local_decoder.xml` (IPFIX + toolkit)                 | **TFM**                                                              |
| `local_rules.xml` (SIDs 100xxx)                       | **TFM** · definidas pero no encadenan (caveat residual)              |
| `agregar_eve.sh`, `sync_listas.sh`                    | **TFM**                                                              |

**Resumen**: Wazuh y Suricata aportan **el motor**; toda la **inteligencia
OT** (firmas, mapeo MITRE, allowlists, trazabilidad, etiquetas por capa)
es trabajo propio del TFM.

## 8. Flujo end-to-end de UNA alerta

Trazamos la alerta de ejemplo real (`SID 2000160` — C2 FrostyGoop Write a
holding register ≥1000) desde que el atacante teclea el comando hasta que
aparece como fila en el dashboard.

```
         Atacante (red_empresa)                     plc_agua_2 (red_ot_zona_a)
      192.168.60.66:60378                             192.168.10.11:502
             │                                                  │
             │   TCP SYN                                        │
             │ ───────────────────────▶ router_gw ───────────▶ │
             │                       (iptables MASQUERADE)      │
             │                                                  │
             │   Modbus FC=16 Write Multiple Registers          │
             │   unit_id=2, start=1000, qty=1, data=1           │
             │ ─────────────────────────────────────────────▶ │
             │                                                  │
             │   Modbus response: FC=16 OK                      │
             │ ◀───────────────────────────────────────────── │
```

### Paso 1 — Captura

- `monitorizacion/captura/ejecutar_escenario.sh c2_frostygoop …` arranca
  `capturar.sh escenario c2_frostygoop 180`, que a su vez lanza 4
  `tcpdump` en paralelo. El relevante es el del **punto `empresa`** (eth3
  de `router_gw`), que ve el paquete con `SRC=192.168.60.66:60378`.
- Se graba en `capturas pcap/ataques/c2_frostygoop/atk_c2_frostygoop_empresa-20261016-001227.pcap`.

### Paso 2 — Suricata offline

- `evaluar.sh` lo detecta en su `find` recursivo, arranca un contenedor
  `jasonish/suricata` con `-r /pcaps/atk_c2_frostygoop_empresa-…pcap`.
- Suricata **habilita el app-layer Modbus** (puerto 502) → parsea el PDU
  y expone campos semánticos: `function_code: WrMultRegs`, `unit_id: 2`,
  `write.address: 1000`, `write.quantity: 1`.
- La regla 2000160 (`modbus: access write holding, address >1000`) matchea
  porque dest=`$C2_MAILBOX` (192.168.10.11) y address=1000.
- Suricata escribe una línea JSON en el `eve.json` del escenario:
  `monitorizacion/suricata/salida/ataques/c2_frostygoop/atk_c2_frostygoop_empresa-…/eve.json`
  con `event_type=alert`, `alert.signature_id=2000160`, el bloque `modbus`
  parseado, el `flow`, y `alert.metadata.mitre_tactic_id=["TA0011"]` +
  `mitre_technique_id=["T0869","T1570"]`.

### Paso 3 — Agregado

- `agregar_eve.sh` corre después de la evaluación. Recorre todos los
  `eve.json` de `suricata/salida/` y escribe en `wazuh/all_eve.json` una
  línea por evento, añadiendo `"tfm_src":"ataques/c2_frostygoop/
  atk_c2_frostygoop_empresa-20261016-001227"` al final del JSON.

### Paso 4 — Ingesta en Wazuh manager

- El `logcollector` del manager tiene configurado el bloque:
  ```xml
  <localfile>
      <log_format>json</log_format>
      <location>/var/log/tfm/wazuh_in/all_eve.json</location>
      <label key="tfm.capa">dpi</label>
      <label key="tfm.fuente">suricata</label>
  </localfile>
  ```
  Como el bind-mount `.:/var/log/tfm/wazuh_in:ro` apunta a la carpeta
  `monitorizacion/wazuh/`, el fichero del host llega al contenedor.
- El logcollector hace *tail* del fichero, lee la línea nueva, le adjunta
  las dos labels `tfm.capa=dpi` y `tfm.fuente=suricata`, y la envía al
  `analysisd`.

### Paso 5 — Decodificación y matching

- `analysisd` reconoce el log como JSON (`<log_format>json</log_format>`).
  Aplica el **decoder built-in `json`** → cada campo del eve.json queda
  anidado bajo `data.*`:
  ```
  data.event_type       = "alert"
  data.src_ip           = "192.168.60.66"
  data.dest_ip          = "192.168.10.11"
  data.alert.signature_id = "2000160"
  data.alert.signature  = "TFM C2 FrostyGoop: Modbus Write a holding..."
  data.alert.metadata.mitre_technique_id = ["T1570","T0869"]
  data.modbus.request.write.address = "1000"
  data.tfm_src          = "ataques/c2_frostygoop/..."
  data.tfm.capa         = "dpi"
  data.tfm.fuente       = "suricata"
  ```
- `analysisd` ejecuta las reglas en orden. La primera que matchea es la
  **regla built-in 86601** (`<decoded_as>json</decoded_as>` + `<field
  name="alert.signature">`), que convierte el evento en una "alerta
  Wazuh" con:
  - `rule.id = "86601"`
  - `rule.level = 3`
  - `rule.description = "Suricata: Alert - <signature>"` (compuesta a
    partir del template de la regla)
  - `rule.groups = ["ids","suricata"]`
- Las reglas custom 100xxx **se intentan** evaluar pero no encadenan por el
  caveat residual del path `alert.signature`. El evento se queda con
  `rule.id=86601` y nivel 3.

### Paso 6 — Persistencia + indexado

- `analysisd` escribe el evento en `/var/ossec/logs/alerts/alerts.json`.
- `filebeat` (dentro del manager) hace *tail* del fichero, lo envía por
  HTTPS mutuamente autenticado al `wazuh.indexer` (OpenSearch).
- El indexer lo escribe en el índice rolling diario
  `wazuh-alerts-4.x-2026.10.16` con un `_id` único.
- `wazuh.dashboard` consulta ese índice vía la API del indexer y pinta la
  alerta en **Security Events** con la descripción legible, los campos
  filtrables y los pivots a MITRE.

### Resultado visible

En Discover / Security Events del dashboard, con filtro
`rule.id:86601 AND data.alert.signature_id:2000160`, aparece la fila:

| timestamp (ingest) | rule.description | src_ip | dest_ip | MITRE | tfm_src |
|---|---|---|---|---|---|
| 2026-10-16 22:55:51 | Suricata: Alert - TFM C2 FrostyGoop: Modbus Write a holding register >=1000 | 192.168.60.66 | 192.168.10.11 | T1570, T0869 | ataques/c2_frostygoop/atk_c2_frostygoop_empresa-… |

En menos de 15 s desde que `agregar_eve.sh` toca el fichero.

---

## 9. Cómo reproducirlo todo desde cero

Resumen operativo, apoyado en el orquestador integrado en `main.py`:

```sh
# Terminal, en tfm_simulacion/
python main.py
# → [8]  arranca lab OT + MASQUERADE + Wazuh (unos 3-5 min la 1ª vez)
# → [9]  pipeline completo
#        · pregunta: pcaps nuevos (a) o reusar existentes (b)
#        · si (a) pregunta: baseline 1h previo
#        · encadena: capturar.sh baseline → ejecutar_todos.sh →
#          pcap2flujos.sh → construir_kb.py → sync_listas.sh →
#          evaluar.sh → resumen.py → agregar_eve.sh
# → [A]  15 chequeos de salud; debe salir 15/15 OK tras completar [9]
# → navegador: https://localhost:5601 (admin / SecretPassword)
```

El código del orquestador vive en
[scenario/orquestador.py](../scenario/orquestador.py); los scripts bash
siguen siendo invocables uno a uno para pruebas puntuales.
