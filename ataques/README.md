# Toolkit de ataques OT/ICS — TFM

Herramienta auxiliar para reproducir, con un solo clic, los ataques ya probados a mano y
documentados en `TFM.pdf` sobre el escenario Purdue que levanta
[`tfm_simulacion/main.py`](../main.py).

Está pensado para ejecutarse **dentro del contenedor `kali_nodo`** del laboratorio (ya
desplegado por `main.py`) y expone un **panel web Flask** en `http://localhost:8888` con una
tarjeta por módulo, formulario de parámetros y consola con salida en vivo.

> ⚠️ **Alcance estricto**: cada módulo verifica (`core/runner.assert_lab_target`) que la IP
> objetivo pertenezca a las subredes del laboratorio
> (`192.168.10/20/30/40/50/60.0/24` y loopback). Si tecleas por error una IP fuera de ese
> rango, el toolkit se niega a ejecutar. **Solo pruebas controladas en tu propia red.**

## Modos de despliegue (empresa / control)

`main.py` deja escoger dónde desplegar `kali_nodo` antes de levantar el escenario y escribe
el modo elegido en `ataques/.mode`. El dashboard lo lee al arrancar y adapta su
comportamiento.

| Aspecto                            | **empresa** (atacante externo) | **control** (atacante en SCADA) |
|------------------------------------|--------------------------------|---------------------------------|
| IP de `kali_nodo`                  | 192.168.60.66 (`red_empresa`)  | 192.168.20.66 (`red_control`)   |
| Rutas inter-zona (`ip route add`)  | **No** se añaden               | **Sí**, hacia 10/30/40/50/60    |
| Acceso a PLCs OT                   | Solo por **túnel SSH SOCKS**   | **Directo** por `router_gw`     |
| Prefijo de los comandos            | `proxychains` (todos los OT)   | ninguno                          |
| Tarjeta "Pivoting Samba"           | Visible y **obligatoria**      | **Oculta**                       |
| Banner superior                    | ámbar, con chip de estado del túnel | verde                        |

### Modo empresa — preparar el túnel

El túnel **no se abre automáticamente**. Antes de cualquier ataque OT, en orden:

1. `Pivoting Samba → Descargar clave SSH` (anónimo contra `//192.168.60.50/Backups_SCADA`).
2. `Pivoting Samba → Levantar túnel SOCKS` (`ssh -D 9050` contra `root@192.168.60.50`).

El chip del banner cambia a verde ("Túnel OK") cuando `127.0.0.1:9050` está escuchando. Si
pulsas una acción OT con el túnel caído, el comando fallará (`Host unreachable`, timeout,
etc.) y la salida se guarda igualmente en `evidencias/` para la memoria.

### Cambiar de modo

Lo más cómodo es la opción `[7] Cambiar modo kali_nodo` del menú de `main.py`:

- Detecta cuántos PLCs tiene el escenario (del compose actual) y pregunta solo
  el nuevo modo (`a` empresa / `b` control).
- Regenera el YAML, recrea **solo** `kali_nodo`, añade las rutas inter-zona si
  pasa a control, y reinicia el dashboard dentro del contenedor.
- Los PLCs y Node-RED no se tocan.

Si prefieres hacerlo a mano, equivale a:

```powershell
python -c "import main; main.generate_docker_compose(3, 3, 3, kali_mode='control')"
docker compose -f docker-compose.generated.yml up -d --force-recreate --no-deps kali_nodo
```

### DNP3 experimental y pydnp3

`pydnp3` (último release de 2019) no es compatible con Python 3.14 de kali-rolling
y falla al compilar con cmake. Si falta, el dashboard **oculta automáticamente**
las dos acciones `DNP3 → Lectura/Escritura experimental` pero mantiene el
`DNP3 → Descubrir red (nmap)` que no necesita pydnp3 y es la única DNP3 validada
en el PDF original (T0888). Para la memoria del TFM esto es suficiente.

## Puesta en marcha

## Puesta en marcha

1. Despliega el escenario híbrido completo desde `tfm_simulacion/main.py` (opción 4 del menú).
2. `main.py` ya monta esta carpeta como `/ataques` dentro de `kali_nodo` y publica el puerto
   `8888` en el host. Para arrancar el panel:

   ```powershell
   docker exec -d kali_nodo python3 /ataques/web/app.py
   ```

   O usa la opción `[6] Levantar dashboard de ataques` del menú de `main.py`.

3. Abre en el navegador del host: <http://localhost:8888>

Cada ejecución deja un fichero en `ataques/evidencias/` con timestamp (listo para capturas de
la memoria del TFM).

## C2 encubierto sobre Modbus TCP (estilo FrostyGoop)

Módulo que implementa un canal de Command & Control usando un PLC del
laboratorio como «buzón» (_storage covert channel_). Inspirado en
**FrostyGoop** (S1165, 2024) — el primer malware documentado que usó
Modbus TCP como protocolo de C2 en un ataque real contra
infraestructura de calefacción en Lviv (Ucrania).

**Técnica MITRE principal:** T0869 — Standard Application Layer Protocol.

### Arquitectura

```
┌────────────┐   FC=16 (write)   ┌────────────┐   FC=3 (read)    ┌─────────────┐
│  OPERADOR  │ ─────────────────>│ PLC-BUZÓN  │<──────────────── │  IMPLANTE   │
│ (kali_nodo)│   regs 1000-1105  │ plc_agua_2 │  regs 1000-1105 │(srv_empresa)│
│            │                   │192.168.10.11│                  │             │
│            │   FC=3 (read)     │  puerto 502 │  FC=16 (write)  │             │
│            │ <─────────────────│             │─────────────────>│             │
│            │   regs 1200-1324  │             │  regs 1200-1324 │             │
└────────────┘                   └────────────┘                  └─────────────┘
```

- El PLC-buzón (`plc_agua_2`) usa holding registers 1000+ que no están
  mapeados a I/O del programa ST — escribir en ellos no afecta al proceso.
- El operador (kali_nodo) escribe comandos codificados con FC=16 y lee
  respuestas con FC=3.
- El implante hace polling periódico, ejecuta la orden (shell o ataque OT)
  y publica la respuesta.
- **Todo el tráfico es Modbus TCP sintácticamente válido** — invisible a
  reglas Snort/DPI estándar.

### Opcodes del protocolo C2

| Opcode | Nombre          | Descripción                                    |
|--------|-----------------|------------------------------------------------|
| 0x01   | shell           | Ejecuta un comando de sistema en el implante   |
| 0x02   | write_coil      | Dispara Modbus WRITE_COIL (FC=5) contra un PLC |
| 0x03   | write_register  | Dispara Modbus WRITE_REGISTER (FC=6)           |
| 0x04   | s7_setpoint     | Escribe setpoint S7 (DB1.DBD6) vía snap7       |
| 0xFF   | exit            | El implante se detiene                          |

### Escenario de prueba (modo empresa)

1. **Pivoting**: Samba → Descargar clave SSH → Levantar túnel SOCKS
2. **Desplegar implante**: C2 → Desplegar implante (SCP + nohup en srv_empresa)
3. **Shell**: C2 → Comando shell → `whoami` → recibe "root"
4. **Ataque OT**: C2 → WRITE_COIL → el implante escribe un coil en plc_agua_1
5. **Captura**: `tcpdump port 502` en plc_agua_2 → solo FC=3/FC=16 legítimo

## Mapeo módulo → acción → MITRE ATT&CK for ICS

| Módulo             | Acción                        | Técnica MITRE         |
|--------------------|-------------------------------|-----------------------|
| `recon`            | `modbus_discover`             | T0846, T0888          |
| `recon`            | `s7_discover`                 | T0846, T0888          |
| `recon`            | `dnp3_discover`               | T0846, T0888          |
| `modbus_msf`       | `findunitid`                  | T0888                 |
| `modbus_msf`       | `uid_contrast`                | T0888, T0861          |
| `modbus_msf`       | `detect`                      | T0846, T0888          |
| `modbus_msf`       | `read_coils` / `read_registers` | T0861               |
| `modbus_msf`       | `write_coil`                  | T0855                 |
| `modbus_msf`       | `write_register`              | T0836                 |
| `s7_snap7`         | `read_db1`                    | T0861                 |
| `s7_snap7`         | `write_setpoint`              | T0836                 |
| `s7_snap7`         | `write_marcha`                | T0855                 |
| `dnp3_pydnp3`      | `discover`                    | T0846, T0888          |
| `dnp3_pydnp3`      | `read_experimental`           | T0861 (experimental)  |
| `dnp3_pydnp3`      | `write_experimental`          | T0855 (experimental)  |
| `samba_pivot`      | `download_key`                | T1039, T1552.004      |
| `samba_pivot`      | `open_tunnel`                 | T1078.003, T1090      |
| `samba_pivot`      | `scan_via_tunnel`             | T1046                 |
| `openplc_rce`      | `default_login`               | T0812                 |
| `openplc_rce`      | `cve_2026_71268`              | T0843, T0873          |
| `openplc_rce`      | `get_current_program`         | T0888, T0845          |
| `openplc_rce`      | `upload_run`                  | T0843, T0821, T0831   |
| `c2_modbus`        | `deploy_implant`              | T0869, T1570          |
| `c2_modbus`        | `shell`                       | T0869, T0807          |
| `c2_modbus`        | `trigger_write_coil`          | T0869, T0855          |
| `c2_modbus`        | `trigger_write_register`      | T0869, T0836          |
| `c2_modbus`        | `trigger_s7_setpoint`         | T0869, T0836          |
| `c2_modbus`        | `exit`                        | T0869                 |

## Estructura

```
ataques/
├── config.py              # IPs/puertos por defecto (del docker-compose)
├── requirements.txt
├── core/
│   ├── runner.py          # subprocess en vivo + assert_lab_target
│   └── evidence.py        # ficheros de log con timestamp
├── modules/
│   ├── recon.py
│   ├── modbus_msf.py      # genera .rc y lanza msfconsole -r
│   ├── s7_snap7.py        # snap7 (DB1 read / setpoint / marcha)
│   ├── dnp3_pydnp3.py     # recon + pydnp3 (experimental)
│   ├── samba_pivot.py     # smbclient + ssh -D + proxychains nmap
│   ├── openplc_rce.py     # login por defecto + CVE-2026-71268
│   ├── c2_modbus.py       # C2 encubierto: operador (pymodbus)
│   └── c2_modbus_implant.py  # C2: implante autocontenido
├── web/
│   ├── app.py             # Flask + SSE
│   ├── templates/index.html
│   └── static/style.css
├── resource_scripts/      # .rc generados para Metasploit
├── work/                  # claves descargadas, .st, etc.
└── evidencias/            # salidas de cada ejecución (timestamp)
```

## Notas por módulo

- **Modbus (Metasploit)**: usa `msfconsole -q -r <script.rc>`. El contenedor `kali_nodo`
  instala `metasploit-framework` en el arranque (es la instalación pesada que ya mencionas en
  el PDF).
- **Modbus — Comparativa UID (`uid_contrast`)**: encadena en una única sesión de
  msfconsole `modbus_findunitid` y `modbusclient READ_REGISTERS` iterando el
  mismo rango de UIDs, y añade al final del fichero de evidencia un VEREDICTO
  parseado (tabla `UID | findunitid | modbusclient | ¿realmente válido?`) con
  contador de falsos positivos. Pensado para evidenciar en la memoria que, con
  la ACL del parche `uid_acl.patch` activa, el PLC responde con excepción
  Modbus `0x0B` a UIDs no autorizados; `modbus_findunitid` solo mira la
  cabecera MBAP y los marca como "correct", mientras que `modbusclient`
  interpreta la excepción y los reporta como "Unknown error".
- **S7 (snap7)**: reutiliza la lógica de los dos scripts del PDF (lectura de DB1 y escritura
  de setpoint REAL + bit de marcha con patrón read-modify-write).
- **DNP3**: solo el `nmap -p 20000` está validado con capturas en el PDF. La lectura/
  escritura con `pydnp3` queda marcada como **[EXPERIMENTAL]**; si pydnp3 no se puede
  instalar, el módulo informa y sigue adelante sin tirar el dashboard.
- **Samba**: necesita que `srv_empresa` esté arriba y que la clave `id_rsa` esté publicada
  en el share (lo prepara `main.py` → `setup_vulnerable_samba`).
- **OpenPLC — CVE-2026-71268 (PoC path traversal)**: sube un `.st` que contiene una
  directiva embebida `(*FILE:...*)` con path traversal (`../`). Al compilar, la función
  `compile_program` de OpenPLC v3 escribe el contenido fuera de `./core`, demostrando
  la vulnerabilidad CWE-22 documentada en el advisory de INCIBE-CERT (CVSS 9.9).
  El payload por defecto (`work/cve_2026_71268_poc.st`) escribe un fichero de marca
  inocuo en `/tmp/pwn_tfm.txt` dentro del contenedor. Técnicas MITRE: T0843, T0873.
- **OpenPLC — Leer programa activo (`get_current_program`)**: se autentica con las
  credenciales por defecto, parsea `/dashboard` para localizar el programa en
  ejecución ("Running: &lt;Name&gt;"), extrae de `/programs` el `table_id` y el
  fichero asociado, e intenta descargar el `.st`. **Hallazgo del TFM**: en el
  fork OpenPLC_v3 pineado en el laboratorio (SHA `b5d4135...`, último master
  antes del archivado del proyecto) **ninguna ruta HTTP devuelve el `.st`** de
  un programa cargado — `/update-program?id=<id>` solo renderiza un formulario
  para sobrescribirlo, no muestra el código original; no hay `/download-program`
  ni `/st-files` servida; `/program/<id>` tampoco existe. Verificable leyendo
  `webserver/webserver.py` del commit en GitHub (ver listado de `@app.route`).
  En consecuencia la acción guarda, como mínimo, un fichero `.metadata.txt`
  con nombre, fichero, `table_id` y fecha del programa activo — exfiltración
  parcial de la configuración del controlador (T0888, T0845 limitado).
- **OpenPLC — `upload_run`**: sube un `.st` benigno, lo compila y lo arranca, con
  dos pasos adicionales respecto a `cve_2026_71268`:
  (a) antes del upload descarga el `.st` activo a `work/backup_<ip>_<ts>_<nombre>.st`,
  y (b) después de `/compile-program` llama a `/start_plc` para que el runtime
  pase a ejecutar el nuevo programa. Técnicas MITRE: T0843, T0821, T0831.
