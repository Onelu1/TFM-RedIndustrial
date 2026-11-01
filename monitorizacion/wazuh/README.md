# Wazuh - SIEM del laboratorio

## Arranque

1. **Preparar credenciales**:
   ```sh
   cp .env.example .env
   # editar .env y poner contrasenas fuertes
   ```

2. **Sincronizar listas CDB** (requiere haber corrido antes `kb/construir_kb.py`):
   ```sh
   bash sync_listas.sh
   ```

3. **Levantar el stack**:
   ```sh
   # Nota: la primera vez Docker descarga ~3 GB de imagenes.
   docker compose up -d
   ```

4. **Abrir dashboard**: <https://localhost:5601>
   - usuario: `admin`
   - password: la que pusieras en `INDEXER_PASSWORD`
   - (acepta el certificado autofirmado)

## Que ve Wazuh

Los contenedores manager/dashboard/indexer leen tres fuentes montadas como
volumenes de solo lectura (ver `docker-compose.yml`):

| Fuente                             | Camino en el manager            | Formato      |
| ---------------------------------- | ------------------------------- | ------------ |
| Flujos IPFIX (super_mediator)      | `/var/log/tfm/flujos/*.json`    | json linea   |
| Alertas Suricata                   | `/var/log/tfm/suricata/*/eve.json` | json linea |
| Evidencias del toolkit de ataques  | `/var/log/tfm/ataques/*.log`    | syslog-ish   |

Las reglas (`rules/local_rules.xml`) correlacionan:
- Alertas Suricata `TFM OT:`/`TFM C2 FrostyGoop:`/`TFM OpenPLC:`/`TFM Pivote:`/`TFM Recon:` -> SID Wazuh 100100-100104 con etiqueta `<mitre>`.
- Flujos IPFIX con 5-tupla fuera de la **allowlist** (lista CDB `comunicaciones_ok`) -> SID 100210.
- Flujos con origen en enterprise hacia puertos OT -> SID 100220 (pivote).
- Flujos hacia el buzon C2 FrostyGoop desde origen no SCADA -> SID 100230.

## Verificar que ingiere

```sh
# dentro del manager
docker exec -it wazuh.manager tail -F /var/ossec/logs/alerts/alerts.json | jq .
```

Deberias ver eventos con `rule.id` 100100+, 100200+, y el campo `mitre.id` relleno.

## Reiniciar reglas sin recrear contenedor

```sh
docker exec -it wazuh.manager /var/ossec/bin/wazuh-control restart
```

## Dashboard: vistas utiles

- **Security events** filtrado por `rule.groups: tfm` -> vista general TFM.
- **MITRE ATT&CK** -> mapea las alertas sobre el framework (requiere que las
  reglas lleven `<mitre>` como las nuestras; ya lo hacen).
- **Rule ID** 100100-100230 -> tabla escenario x detectado.
