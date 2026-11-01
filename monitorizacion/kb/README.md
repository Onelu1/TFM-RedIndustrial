# Base de Conocimiento (allowlist OT) — ahora **dinámica**

Esta KB es un **allowlist** derivado del baseline limpio: todo lo que no esté
aquí es sospechoso. Es el paradigma estándar en OT porque el tráfico es
determinista (Node-RED pollea los mismos PLCs cada 2 s). Alimenta tanto a
Suricata (variables) como a Wazuh (listas CDB).

**Novedad 2026-10-21 (modo entrenamiento)**: los roles de los dispositivos
(SCADA, broker MQTT, PLCs Modbus/S7/DNP3, gateways DNP3, fileserver) ya **no**
están hardcodeados. Se aprenden por comportamiento del tráfico durante una
ventana de entrenamiento disparada con la opción `[E]` del menú. Es la misma
"learning phase" que usan Nozomi/Claroty en producción.

## Flujo de datos

```
[E] captura 30 min sin ataques → NDJSON de flujos → inferir_roles.py
                                                           ↓
                                                   inventario.json
                                                           ↓
                                                   construir_kb.py
                                                           ↓
                   ┌───────────────────────────────────────┼───────────────────────┐
                   ↓                                       ↓                       ↓
      kb/suricata_vars.yaml                        kb/*.cdb (allowlist)      umbrales.json
                   ↓                                       ↓
      suricata/vars_kb.yaml (espejo)              wazuh/listas/ (sync)
                   ↓
      suricata.yaml → include: vars_kb.yaml
                   ↓
      $SCADA_SERVERS, $MQTT_BROKER,
      $DNP3_GATEWAYS, $ENTERPRISE
      = lo que se infirió del baseline
```

## Uso

### 1) Modo entrenamiento (opción `[E]`, duración por defecto 30 min)

Lanza el ciclo completo. Pausa `kali_nodo`, captura 4 puntos (control/empresa/
mqtt/dnp3), convierte a NDJSON, infiere roles, construye KB y propaga las
variables a Suricata.

```sh
# Desde el menú: [8] → arrancar lab → [E] → esperar 30 min.
# O directamente desde CLI:
bash monitorizacion/entrenamiento/entrenar.sh 1800
```

Al terminar, revisa:
- `monitorizacion/kb/inventario.json` — fuente única de verdad del lab.
- `monitorizacion/kb/inventario_vs_hosts.md` — reporte precisión vs ground truth.
- `monitorizacion/suricata/vars_kb.yaml` — variables Suricata regeneradas.

### 2) Pipeline completo (opción `[9]`)

Reutiliza el inventario ya entrenado — no re-infiere. Si no hay inventario,
cae automáticamente a `--legacy-hardcoded` (tabla antigua) con aviso.

### 3) Edición manual del buzón C2 (ejercicio FrostyGoop)

Edita [c2_mailbox.yaml](c2_mailbox.yaml) descomentando la IP del PLC que
quieras marcar como buzón C2 antes de lanzar el escenario. Fuera de ese
ejercicio, déjalo vacío — así `$C2_MAILBOX` queda como never-match y las
reglas 2000160/61/62 no disparan.

## Ficheros que produce `construir_kb.py`

| Fichero                     | Clave : Valor                         | Origen                                                      |
| --------------------------- | ------------------------------------- | ----------------------------------------------------------- |
| `comunicaciones_ok.cdb`     | `sip->dip:dport/proto` : `ok`         | Set de 5-tuplas únicas vistas en baseline                   |
| `plcs.cdb`                  | `ip:puerto` : `rol:proto=X`           | Destinos observados en puerto OT (502/102/20000/1883)       |
| `funciones_modbus_ok.cdb`   | `sip->dip:fc` : `ok`                  | Pareja + function code Modbus permitido (lecturas 1/2/3/4)  |
| `umbrales.json`             | `sip->dip:dport` : {p50,p90,p99…}     | Percentiles de bytes/pkts por 5-tupla                       |
| `suricata_vars.yaml`        | `HOME_NET`, `SCADA_SERVERS`, …        | Variables Suricata, **ahora derivadas del inventario**      |
| `baseline_flows.csv`        | tabla legible                         | Vuelco completo del baseline con roles inferidos            |

## Reglas de inferencia de rol (resumen)

Las reglas se evalúan en orden; la primera que encaja gana. Se basan en
**comportamiento**, no en la subred Docker (que solo sube/baja la confianza).

| # | Rol             | Condición necesaria                                             |
|---|-----------------|------------------------------------------------------------------|
| R1 | `broker_mqtt`   | escucha `:1883` con ≥2 clientes y ≥10 flujos entrantes          |
| R2 | `scada`         | cliente de ≥3 de `{502,102,20000,1883}` + ≥3 peers              |
| R3 | `gateway_dnp3`  | conecta a `:20000` **y** publica a `:1883` (dual-role)          |
| R4 | `plc_modbus`    | escucha `:502` con ≥3 flujos entrantes y payload medio <300B    |
| R5 | `plc_s7`        | escucha `:102` con ≥3 flujos entrantes                          |
| R6 | `plc_dnp3`      | escucha `:20000` con ≥3 flujos entrantes                        |
| R7 | `it_fileserver` | escucha `:445` o `:139` (SMB)                                   |
| R8 | fallback        | `desconocido_<subred>`                                           |

**Kali** se excluye explícitamente del training (su IP se obtiene de
`docker inspect kali_nodo`); durante `[E]` queda además pausada.

Umbrales ajustables en CLI:
```sh
python inferir_roles.py --flujos "..." --salida . \
    --umbral-broker-peers 2 \
    --umbral-scada-puertos 3 \
    --umbral-scada-stdev-polling 1.0 \
    --umbral-plc-flujos-in 3 \
    --umbral-modbus-bytes-mean 300
```

## Ground truth (sanity-check)

El fichero [ground_truth_hosts.py](ground_truth_hosts.py) contiene la tabla
estática de los 17 hosts conocidos del lab 3+3+3. **No se usa en producción**:
solo `inferir_roles.py` lo importa para generar `inventario_vs_hosts.md` (el
reporte "precisión por rol" que valida que el aprendizaje reproduce el mapa
esperado), y `construir_kb.py --legacy-hardcoded` como escape de emergencia.

## Qué se asume

- En el baseline **sólo** hay polling SCADA → PLCs (Node-RED, cada 2 s) y
  mensajes MQTT de los gateways DNP3 → broker.
- **No** hay escrituras Modbus (FC=5/6/15/16) ni comandos DNP3 Operate /
  DirectOperate durante el baseline: cualquier aparición debe alertar.
- `kali_nodo` nunca aparece en el baseline (pausado durante `[E]` + excluido
  por IP). Cualquier flujo originado en él durante operación dispara regla.
- `plc_agua_2` (192.168.10.11) puede marcarse manualmente como buzón C2
  FrostyGoop editando `c2_mailbox.yaml`; su tráfico de flujos es idéntico al
  de un `plc_modbus` normal — la anomalía la detecta Suricata por los
  **registros** (FC=16 a regs ≥1000, FC=3 a regs ≥1200).

## Verificación

El chequeo `_c16_inventario` del menú `[A]` comprueba que:

- `inventario.json` existe y es JSON válido.
- Hay al menos `scada`, `broker_mqtt` y algún `plc_*` en el `role_index`.

Si falla, relanza `[E]` con una ventana más larga.
