# Monitorización — Cadena de detección OT

## Arranque rápido (menú de `main.py`)

Las tres opciones nuevas del menú de `python main.py` orquestan todo el
pipeline sin tocar scripts a mano:

| Opción | Qué hace |
|--------|----------|
| `[8]`  | Arranca **lab OT (Purdue) + MASQUERADE + Wazuh** (3+3+3 PLCs por defecto, kali_mode=`control`). Idempotente: si parte del stack ya está arriba, pregunta antes de recrearlo. |
| `[9]`  | **Pipeline completo**: baseline (opcional, 1 h) → 10 escenarios de ataque → PCAP→IPFIX → KB → Suricata offline → `agregar_eve.sh` para Wazuh logcollector. Requiere que `[8]` haya corrido antes. |
| `[A]`  | **15 chequeos de salud** (containers, iptables, pings SCADA→PLC, HTTP de Node-RED/dashboards, alertas indexadas, pcaps, flujos, KB, …). Imprime `[OK]/[WARN]/[FAIL]` por check y un recuento final. Devuelve exit code 0 (sin fallos) o 1. |

Flujo típico de demo:

```sh
python main.py
# → [8]  arranca lab + Wazuh (~3-5 min la primera vez)
# → [A]  verifica 15/15 (los chequeos 8-13 saldrán WARN hasta correr [9])
# → [9]  pipeline completo (~15-20 min con los 10 ataques)
# → [A]  confirma que ahora hay alertas indexadas
# → navegador: https://localhost:5601 (admin / SecretPassword)
```

La lógica vive en [scenario/orquestador.py](../scenario/orquestador.py); los scripts bash de abajo
siguen siendo invocables directamente para casos avanzados.

---

Capa de monitorización añadida al laboratorio del TFM:
una cadena **PCAP → IPFIX → Base de Conocimiento → Suricata + Wazuh** con
dos niveles complementarios (flujos L3/L4 y DPI de protocolo OT) y mapeo a
MITRE ATT&CK for ICS.

```
┌─ Fase 1 ─ Captura ──────────────────────────────────────────────┐
│ tcpdump en router_gw eth2 (control), eth3 (empresa),            │
│          broker_mqtt (MQTT intra-red_control),                  │
│          gateway_dnp3_1 (DNP3 intra-red_ot_zona_c)              │
│ → capturas pcap/{baseline,ataques/<escenario>}/*.pcap           │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─ Fase 2 ─ Flujos IPFIX ─────────────────────────────────────────┐
│ contenedor `tfm_monitor`: softflowd + nfcapd + nfdump           │
│                           (NetFlow v10 = IPFIX RFC 7011)        │
│ helper `sll2ether.py` (scapy) reencapsula LINUX_SLL2 → Ethernet │
│ pcap → *.csv (flujos) + *.json (una línea/flujo, para Wazuh)    │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─ Fase 3 ─ Base de Conocimiento (allowlist OT) ──────────────────┐
│ construir_kb.py: deriva listas CDB desde el baseline limpio     │
│ · comunicaciones_ok · plcs · funciones_modbus_ok · umbrales     │
└─────────────────────────────────────────────────────────────────┘
                                │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
┌─ Fase 4 ─ Suricata (DPI) ──────────┐  ┌─ Fase 5 ─ Wazuh (SIEM) ─────┐
│ app-layer modbus/dnp3/enip         │  │ manager + indexer +         │
│ reglas allowlist + firmas ataques  │  │ dashboard en red_monitori-  │
│ → eve.json por escenario           │  │ zacion (sustituye a         │
│                                    │  │ srv_monitorizacion)         │
│ (22 reglas, SIDs 2000001-2000162)  │  │ Decoders + listas CDB       │
│                                    │  │ Dashboard https://:5601     │
└────────────────────────────────────┘  └─────────────────────────────┘
```

## Estructura de directorios

```
tfm_simulacion/
├── capturas pcap/                   ← pcap reorganizados
│   ├── baseline/
│   │   ├── baseline_control-*.pcap
│   │   ├── baseline_dnp3-*.pcap
│   │   ├── baseline_empresa-*.pcap
│   │   └── baseline_mqtt-*.pcap
│   └── ataques/
│       ├── recon_modbus/
│       │   ├── atk_recon_modbus_control-*.pcap
│       │   └── ... (4 pcaps: control/empresa/mqtt/dnp3)
│       └── <otros 9 escenarios>/
│
└── monitorizacion/
    ├── README.md                    ← este fichero
    ├── RESULTADOS.md                ← resultados end-to-end
    ├── captura/
    │   ├── preparar_router.sh       instala iptables + MASQUERADE + mapeo iface
    │   ├── capturar.sh              baseline <seg> | escenario <nombre> <seg>
    │   ├── ejecutar_escenario.sh    captura + ataque + espera
    │   ├── ejecutar_todos.sh        los 10 escenarios en secuencia
    │   └── .ifaces.env              mapeo iface→red (auto-generado)
    ├── flujos/
    │   ├── Dockerfile               imagen tfm_monitor (softflowd+nfdump+scapy)
    │   ├── sll2ether.py             helper reencapsulación SLL2→Ethernet
    │   ├── pcap2flujos.sh           recorre capturas pcap/ recursivamente
    │   └── salida/                  ← espeja la jerarquía de capturas pcap
    │       ├── baseline/*.{csv,json}
    │       └── ataques/<escenario>/*.{csv,json}
    ├── kb/
    │   ├── construir_kb.py          CSV baseline → listas CDB + umbrales + vars Suricata
    │   ├── comunicaciones_ok.cdb    allowlist 5-tupla (sip->dip:dport/proto:ok)
    │   ├── plcs.cdb                 catálogo servicios OT (ip:puerto:rol:proto=X)
    │   ├── funciones_modbus_ok.cdb  function codes Modbus permitidos
    │   ├── umbrales.json            percentiles p50/p90/p99 bytes/pkts
    │   ├── suricata_vars.yaml       HOME_NET/OT_PLCS/SCADA_SERVERS para suricata.yaml
    │   ├── baseline_flows.csv       vuelco completo (trazabilidad)
    │   └── README.md
    ├── suricata/
    │   ├── Dockerfile
    │   ├── suricata.yaml            app-layer modbus/dnp3/enip + vars del lab
    │   ├── rules/local.rules        22 reglas (SIDs 2000001-2000162) con <mitre>
    │   ├── evaluar.sh               `find` recursivo + salida en jerarquía
    │   ├── resumen.py               agrega alertas por escenario + MITRE
    │   └── salida/
    │       ├── baseline/<pcap>/eve.json
    │       └── ataques/<escenario>/<pcap>/eve.json
    └── wazuh/
        ├── README.md
        ├── .env.example / .env      contraseñas (local, no en git)
        ├── decoders/local_decoder.xml
        ├── rules/local_rules.xml    SIDs Wazuh 100100-100230 con <mitre>
        ├── ossec.conf.d/
        │   ├── 10-tfm-logcollector.conf (glob recursivo a los 3 montajes)
        │   └── 20-tfm-lists.conf
        ├── listas/                  CDBs sincronizados desde kb/
        └── sync_listas.sh           kb/*.cdb → wazuh/listas/
```

## Flujo de ejecución

```sh
# 0. Lab arriba con la nueva topología (Wazuh ya integrado en compose principal)
python main.py                                     # genera compose + arranca
# o manualmente:
docker compose -f docker-compose.generated.yml up -d
bash monitorizacion/captura/preparar_router.sh    # tcpdump + iptables MASQUERADE

# 1. Baseline (sin ataques en curso)
bash monitorizacion/captura/capturar.sh baseline 3600       # 1 h

# 2. Escenarios de ataque (modo kali en 'control' para acceso directo a OT)
echo control > ataques/.mode
bash monitorizacion/captura/ejecutar_todos.sh               # ~15 min

# 3. PCAP → IPFIX (CSV + JSON)
bash monitorizacion/flujos/pcap2flujos.sh

# 4. Base de Conocimiento
python monitorizacion/kb/construir_kb.py \
    --baseline 'monitorizacion/flujos/salida/baseline/*.csv' \
    --salida   monitorizacion/kb/
bash monitorizacion/wazuh/sync_listas.sh          # kb/*.cdb → wazuh/listas/

# 5. Suricata offline por pcap + resumen
bash monitorizacion/suricata/evaluar.sh
python monitorizacion/suricata/resumen.py

# 6. Wazuh (ya levantado en el compose principal; dashboard en https://localhost:5601)
#    Si necesitas reiniciar el manager tras cambiar reglas:
docker exec wazuh.manager /var/ossec/bin/wazuh-control restart
```

## Datos producidos (vista rápida)

| Carpeta | Qué hay | Formato | Vol. estimado |
|---|---|---|---|
| `capturas pcap/baseline/`           | 4 pcaps del baseline            | pcap (ethernet/sll2) | ~5–50 MB (depende duración) |
| `capturas pcap/ataques/<X>/`        | 4 pcaps por escenario (10 esc.) | pcap                 | ~500 KB cada uno           |
| `monitorizacion/flujos/salida/`     | CSV + JSON uno por pcap         | nfdump CSV / JSON    | ~5–10 KB por pcap          |
| `monitorizacion/kb/`                | 3 listas CDB + umbrales + vars  | key:value / JSON     | ~5 KB                      |
| `monitorizacion/suricata/salida/`   | eve.json por pcap               | JSON por línea       | ~10–200 KB por escenario   |
| `monitorizacion/wazuh/listas/`      | copias binarias de los CDBs     | CDB                  | ~5 KB                      |

## Qué consultar para la memoria

- [RESULTADOS.md](RESULTADOS.md) — Resultados end-to-end con tabla Escenario × SID × MITRE y los caveats resueltos.
