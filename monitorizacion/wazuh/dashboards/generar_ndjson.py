#!/usr/bin/env python3
"""generar_ndjson.py - Genera `tfm_ot_dashboard.ndjson` con los widgets del
dashboard TFM OT/ICS. Ejecutar una vez para regenerar el fichero NDJSON tras
cualquier cambio en la definicion de los widgets.

El NDJSON resultante se importa en Wazuh Dashboard via el script
`importar_dashboard.sh` (que a su vez usa /api/saved_objects/_import).

Widgets producidos:
  1. KPI "Alertas totales"             (metric, filtro: rule.groups:suricata)
  2. KPI "Alertas en vivo"             (metric, filtro: labels.tfm.fuente:suricata_live)
  3. KPI "PLCs unicos atacados"        (metric, unique count sobre dest_ip)
  4. KPI "Escrituras / impacto"        (metric, filtro: SIDs de escritura 2000010-13/120/130-31)
  5. Top PLCs atacados                 (horizontal bar, terms sobre dest_ip)
  6. Protocolo atacado                 (pie, filters por dest_port -> Modbus/S7/DNP3/MQTT)
  7. Security alerts                   (saved search, tabla columnas timestamp/sig/src/dst)
  8. Top tecnicas MITRE ATT&CK ICS     (horizontal bar, terms sobre metadata.mitre_technique_id)
  9. Dashboard "TFM OT - Deteccion ICS en vivo"  (grid que agrupa los widgets)
"""
from __future__ import annotations

import json
from pathlib import Path


INDEX_PATTERN = "wazuh-alerts-*"
INDEX_REF = {
    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
    "type": "index-pattern",
    "id": INDEX_PATTERN,
}
# Wazuh Dashboard 4.9.2 = fork de OpenSearch Dashboards 1.x (= Kibana 7.10).
# Si subes el migrationVersion por encima de 7.10 el _import devuelve 422.
MIG_VIS = {"visualization": "7.9.3"}
MIG_SEARCH = {"search": "7.9.3"}
MIG_DASH = {"dashboard": "7.9.3"}


def _search_source(kuery: str) -> str:
    return json.dumps({
        "query": {"query": kuery, "language": "kuery"},
        "filter": [],
        "indexRefName": INDEX_REF["name"],
    })


def viz_metric(obj_id: str, titulo: str, kuery: str,
               agg_type: str = "count", agg_field: str | None = None,
               label: str = "") -> dict:
    """Construye una visualization tipo 'metric' (numero grande)."""
    agg = {"id": "1", "enabled": True, "type": agg_type,
           "schema": "metric", "params": {}}
    if agg_field:
        agg["params"]["field"] = agg_field
    if label:
        agg["params"]["customLabel"] = label
    vis_state = {
        "title": titulo,
        "type": "metric",
        "aggs": [agg],
        "params": {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": "Green to Red",
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": True},
                "invertColors": False,
                "style": {
                    "bgFill": "#000",
                    "bgColor": False,
                    "labelColor": False,
                    "subText": "",
                    "fontSize": 36,
                },
            },
        },
    }
    return _wrap_visualization(obj_id, titulo, vis_state, kuery)


def viz_bar_horizontal(obj_id: str, titulo: str, kuery: str,
                       bucket_field: str, size: int = 10) -> dict:
    """Horizontal bar con terms aggregation sobre bucket_field."""
    vis_state = {
        "title": titulo,
        "type": "horizontal_bar",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count",
             "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms",
             "schema": "segment",
             "params": {
                 "field": bucket_field,
                 "orderBy": "1",
                 "order": "desc",
                 "size": size,
                 "otherBucket": False,
                 "missingBucket": False,
                 "customLabel": "",
             }},
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{
                "id": "CategoryAxis-1", "type": "category", "position": "left",
                "show": True, "style": {}, "scale": {"type": "linear"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 200},
                "title": {},
            }],
            "valueAxes": [{
                "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                "position": "bottom", "show": True, "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": True, "truncate": 100},
                "title": {"text": "Alertas"},
            }],
            "seriesParams": [{
                "show": True, "type": "histogram", "mode": "normal",
                "data": {"label": "Alertas", "id": "1"},
                "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                "showCircles": True,
            }],
            "addTooltip": True,
            "addLegend": False,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
            "labels": {"show": True},
        },
    }
    return _wrap_visualization(obj_id, titulo, vis_state, kuery)


def viz_area_timeseries(obj_id: str, titulo: str, kuery: str,
                        split_field: str, split_size: int = 5) -> dict:
    """Area chart apilado: timestamp en X, series apiladas por `split_field`
    (top-N por count). Perfecto para visualizar 'cuando' aparecen los ataques.
    """
    vis_state = {
        "title": titulo,
        "type": "area",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count",
             "schema": "metric", "params": {"customLabel": "Alertas"}},
            {"id": "2", "enabled": True, "type": "date_histogram",
             "schema": "segment",
             "params": {
                 "field": "timestamp",
                 "timeRange": {"from": "now-24h", "to": "now"},
                 "useNormalizedEsInterval": True,
                 "interval": "auto",
                 "drop_partials": False,
                 "min_doc_count": 1,
                 "extended_bounds": {},
             }},
            {"id": "3", "enabled": True, "type": "terms",
             "schema": "group",
             "params": {
                 "field": split_field,
                 "orderBy": "1", "order": "desc", "size": split_size,
                 "otherBucket": True, "otherBucketLabel": "Otras",
                 "missingBucket": False,
                 "customLabel": "SID",
             }},
        ],
        "params": {
            "type": "area",
            "grid": {"categoryLines": False},
            "categoryAxes": [{
                "id": "CategoryAxis-1", "type": "category", "position": "bottom",
                "show": True, "style": {},
                "scale": {"type": "linear"},
                "labels": {"show": True, "truncate": 100},
                "title": {},
            }],
            "valueAxes": [{
                "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                "position": "left", "show": True, "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Alertas"},
            }],
            "seriesParams": [{
                "show": True, "type": "area", "mode": "stacked",
                "data": {"label": "Alertas", "id": "1"},
                "drawLinesBetweenPoints": True,
                "showCircles": True,
                "interpolate": "linear",
                "valueAxis": "ValueAxis-1",
            }],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
        },
    }
    return _wrap_visualization(obj_id, titulo, vis_state, kuery)


def viz_data_table(obj_id: str, titulo: str, kuery: str,
                   bucket_fields: list[tuple[str, str]], size: int = 20) -> dict:
    """Tabla de datos con 1 o varios buckets terms anidados.

    bucket_fields: lista de (field, label). Primer elemento = columna
    principal, resto = columnas secundarias (split-rows). Siempre + columna
    count al final.
    """
    aggs = [
        {"id": "1", "enabled": True, "type": "count",
         "schema": "metric", "params": {"customLabel": "Alertas"}},
    ]
    for i, (field, label) in enumerate(bucket_fields, start=2):
        aggs.append({
            "id": str(i), "enabled": True, "type": "terms",
            "schema": "bucket",
            "params": {
                "field": field,
                "orderBy": "1", "order": "desc", "size": size,
                "otherBucket": False, "missingBucket": False,
                "customLabel": label,
            },
        })
    vis_state = {
        "title": titulo,
        "type": "table",
        "aggs": aggs,
        "params": {
            "perPage": size,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "showTotal": False,
            "totalFunc": "sum",
            "percentageCol": "",
        },
    }
    return _wrap_visualization(obj_id, titulo, vis_state, kuery)


def viz_pie_filters(obj_id: str, titulo: str, kuery: str,
                    filtros: list[tuple[str, str]]) -> dict:
    """Pie chart con bucket tipo 'filters' (etiquetas custom por filtro).

    filtros: lista de (etiqueta, kuery_filtro).
    """
    vis_state = {
        "title": titulo,
        "type": "pie",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count",
             "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "filters",
             "schema": "segment",
             "params": {
                 "filters": [
                     {"input": {"query": q, "language": "kuery"},
                      "label": lbl}
                     for lbl, q in filtros
                 ],
             }},
        ],
        "params": {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": True,
            "labels": {
                "show": True,
                "values": True,
                "last_level": True,
                "truncate": 100,
            },
        },
    }
    return _wrap_visualization(obj_id, titulo, vis_state, kuery)


def saved_search(obj_id: str, titulo: str, kuery: str,
                 columnas: list[str]) -> dict:
    """Saved search (tabla de documentos). Se renderiza como tabla en el
    dashboard mostrando `columnas`.
    """
    return {
        "id": obj_id,
        "type": "search",
        "attributes": {
            "title": titulo,
            "description": "",
            "hits": 0,
            "columns": columnas,
            "sort": [["timestamp", "desc"]],
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": _search_source(kuery),
            },
        },
        "references": [INDEX_REF],
        "migrationVersion": MIG_SEARCH,
    }


def _wrap_visualization(obj_id: str, titulo: str,
                        vis_state: dict, kuery: str) -> dict:
    return {
        "id": obj_id,
        "type": "visualization",
        "attributes": {
            "title": titulo,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": _search_source(kuery),
            },
        },
        "references": [INDEX_REF],
        "migrationVersion": MIG_VIS,
    }


def dashboard(obj_id: str, titulo: str, panels: list[dict]) -> dict:
    """Construye el saved_object dashboard. `panels` es la lista de
    (vis_or_search_id, type, x, y, w, h)."""
    panels_json = []
    references = []
    for i, p in enumerate(panels, start=1):
        obj_ref_name = f"panel_{i}"
        panels_json.append({
            "version": "2.0.0",
            "type": p["type"],
            "gridData": {"x": p["x"], "y": p["y"],
                         "w": p["w"], "h": p["h"], "i": str(i)},
            "panelIndex": str(i),
            "embeddableConfig": {},
            "panelRefName": obj_ref_name,
        })
        references.append({
            "name": obj_ref_name,
            "type": p["type"],
            "id": p["id"],
        })

    return {
        "id": obj_id,
        "type": "dashboard",
        "attributes": {
            "title": titulo,
            "description": ("Dashboard TFM OT/ICS - alertas Suricata en vivo + "
                            "offline, consumidas desde wazuh-alerts-*."),
            "panelsJSON": json.dumps(panels_json),
            "optionsJSON": json.dumps({
                "useMargins": True,
                "syncColors": False,
                "hidePanelTitles": False,
            }),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-24h",
            # Auto-refresh pausado por defecto: con refresh cada 10s la tabla
            # cerraba automaticamente el flyout de detalle del log al abrir.
            # El usuario pulsa "Refresh" manualmente cuando quiera actualizar.
            "refreshInterval": {"pause": True, "value": 60000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": [],
                }),
            },
        },
        "references": references,
        "migrationVersion": MIG_DASH,
    }


def main():
    KUERY_SURICATA = 'rule.groups:"suricata"'
    # Wazuh labels no se propagan al indexer. Distinguimos live/offline por
    # el campo `location` que trae el logcollector (ruta del fichero origen).
    KUERY_LIVE = ('rule.groups:"suricata" and '
                  'location:"/var/log/tfm/suricata/live/eve.json"')
    KUERY_ESCRITURAS = (
        'rule.groups:"suricata" and '
        '(data.alert.signature_id:2000010 or data.alert.signature_id:2000011 or '
        'data.alert.signature_id:2000012 or data.alert.signature_id:2000013 or '
        'data.alert.signature_id:2000120 or data.alert.signature_id:2000130 or '
        'data.alert.signature_id:2000131)'
    )

    objetos = [
        viz_metric("tfm-ot-kpi-total",
                   "Alertas Suricata TFM (total)",
                   KUERY_SURICATA, label="Alertas totales"),
        viz_metric("tfm-ot-kpi-plcs",
                   "PLCs atacados (IPs destino unicas)",
                   KUERY_SURICATA,
                   agg_type="cardinality", agg_field="data.dest_ip",
                   label="PLCs unicos"),

        viz_bar_horizontal("tfm-ot-bar-plcs",
                           "Top PLCs atacados",
                           KUERY_SURICATA,
                           bucket_field="data.dest_ip",
                           size=10),

        # Tecnicas MITRE ATT&CK for ICS mas disparadas. El campo viene en la
        # metadata de las firmas Suricata (`metadata:mitre_technique_id Txxxx`)
        # y Wazuh lo pasa tal cual al indexer bajo
        # data.alert.metadata.mitre_technique_id, mapeado directamente como
        # keyword (array). No se agrega con .keyword — el mapping ya es
        # keyword nativo.
        viz_bar_horizontal("tfm-ot-bar-mitre",
                           "Top tecnicas MITRE ATT&CK ICS",
                           kuery=(KUERY_SURICATA
                                  + ' and data.alert.metadata.mitre_technique_id:*'),
                           bucket_field="data.alert.metadata.mitre_technique_id",
                           size=15),

        viz_pie_filters("tfm-ot-pie-proto",
                        "Protocolo OT atacado",
                        KUERY_SURICATA,
                        filtros=[
                            ("Modbus (502)", "data.dest_port:502"),
                            ("S7 (102)",     "data.dest_port:102"),
                            ("DNP3 (20000)", "data.dest_port:20000"),
                        ]),

        # Timeline: alertas por minuto, apiladas por SID top-5. Pico claro
        # cuando se lanza un ataque. Util para la defensa oral y la memoria.
        viz_area_timeseries("tfm-ot-timeline-sids",
                            "Alertas por minuto (top 5 SIDs)",
                            KUERY_SURICATA,
                            split_field="data.alert.signature_id",
                            split_size=5),

        # Pie "origen del ataque" por IP. Mantener etiquetas = IP pura (sin
        # el nombre del contenedor) para simular un entorno real donde un
        # analista solo ve direcciones y mapea por si mismo.
        viz_pie_filters("tfm-ot-pie-origen",
                        "Origen del ataque (src_ip)",
                        KUERY_SURICATA,
                        filtros=[
                            ("192.168.60.66",            "data.src_ip:192.168.60.66"),
                            ("192.168.20.66",            "data.src_ip:192.168.20.66"),
                            ("192.168.20.10",            "data.src_ip:192.168.20.10"),
                            ("192.168.20.50 / 60.50",    "data.src_ip:(192.168.20.50 or 192.168.60.50)"),
                        ]),

        # Tabla "top reglas": SID + descripcion (signature) + nº alertas.
        # El usuario mapea aqui mismo que ataque detecta cada SID.
        viz_data_table("tfm-ot-tabla-reglas",
                       "Top reglas disparadas (SID + descripcion)",
                       KUERY_SURICATA,
                       bucket_fields=[
                           ("data.alert.signature_id",  "SID"),
                           ("data.alert.signature",     "Descripcion"),
                       ],
                       size=25),

        saved_search("tfm-ot-tabla-alertas",
                     "Alertas Suricata TFM (tabla)",
                     KUERY_SURICATA,
                     columnas=[
                         "timestamp",
                         "data.alert.signature_id",
                         "data.alert.signature",
                         "data.src_ip",
                         "data.dest_ip",
                         "data.dest_port",
                         "location",
                     ]),
    ]

    # Layout del dashboard. OpenSearch Dashboards usa grid de 48 columnas.
    # Fila 1 (y=0,  h=8):  2 KPIs grandes (24 col cada uno)
    # Fila 2 (y=8,  h=12): timeline area chart ancho completo
    # Fila 3 (y=20, h=15): bar PLCs | pie protocolo | pie origen
    # Fila 4 (y=35, h=15): bar MITRE ATT&CK (ancho completo)
    # Fila 5 (y=50, h=18): top reglas (24) | tabla alertas (24)
    panels = [
        {"id": "tfm-ot-kpi-total",      "type": "visualization",
         "x":  0, "y":  0, "w": 24, "h": 8},
        {"id": "tfm-ot-kpi-plcs",       "type": "visualization",
         "x": 24, "y":  0, "w": 24, "h": 8},

        {"id": "tfm-ot-timeline-sids",  "type": "visualization",
         "x":  0, "y":  8, "w": 48, "h": 12},

        {"id": "tfm-ot-bar-plcs",       "type": "visualization",
         "x":  0, "y": 20, "w": 16, "h": 15},
        {"id": "tfm-ot-pie-proto",      "type": "visualization",
         "x": 16, "y": 20, "w": 16, "h": 15},
        {"id": "tfm-ot-pie-origen",     "type": "visualization",
         "x": 32, "y": 20, "w": 16, "h": 15},

        {"id": "tfm-ot-bar-mitre",      "type": "visualization",
         "x":  0, "y": 35, "w": 48, "h": 15},

        {"id": "tfm-ot-tabla-reglas",   "type": "visualization",
         "x":  0, "y": 50, "w": 24, "h": 18},
        {"id": "tfm-ot-tabla-alertas",  "type": "search",
         "x": 24, "y": 50, "w": 24, "h": 18},
    ]

    objetos.append(dashboard("tfm-ot-dashboard",
                             "TFM OT - Deteccion ICS en vivo",
                             panels))

    aqui = Path(__file__).parent
    salida = aqui / "tfm_ot_dashboard.ndjson"
    with open(salida, "w", encoding="utf-8", newline="\n") as f:
        for obj in objetos:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        # Al final, metadata obligatoria del _import endpoint.
        f.write(json.dumps({
            "exportedCount": len(objetos),
            "missingRefCount": 0,
            "missingReferences": [],
        }) + "\n")

    print(f"[OK] Escrito {salida} con {len(objetos)} saved objects")


if __name__ == "__main__":
    main()
