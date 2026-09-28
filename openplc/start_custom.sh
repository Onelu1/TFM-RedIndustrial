#!/bin/bash
cd /work/OpenPLC_v3/webserver/scripts

if [ "$PLC_MODE" = "DNP3" ]; then
    echo "[*] Compilando y configurando para DNP3..."
    ./compile_program.sh planta.st
    sqlite3 ../openplc.db "DELETE FROM Programs;"
    sqlite3 ../openplc.db "INSERT INTO Programs (Name, Description, File, Date_upload) VALUES ('SimuladorPlanta', 'Simulador DNP3', 'planta.st', strftime('%s', 'now'));"
    
    # Configuramos los puertos: Activamos DNP3 y desactivamos Modbus
    sqlite3 ../openplc.db "UPDATE Settings SET Value = '20000' WHERE Key = 'Dnp3_port';"
    sqlite3 ../openplc.db "UPDATE Settings SET Value = 'disabled' WHERE Key = 'Modbus_port';"
    echo "planta.st" > ../active_program
else
    echo "[*] Compilando y configurando para Modbus TCP..."
    ./compile_program.sh programa_sensores.st
    sqlite3 ../openplc.db "DELETE FROM Programs;"
    sqlite3 ../openplc.db "INSERT INTO Programs (Name, Description, File, Date_upload) VALUES ('SensoresModbus', 'Simulador Modbus', 'programa_sensores.st', strftime('%s', 'now'));"
    
    # Configuramos los puertos: Activamos Modbus y desactivamos DNP3
    sqlite3 ../openplc.db "UPDATE Settings SET Value = '502' WHERE Key = 'Modbus_port';"
    sqlite3 ../openplc.db "UPDATE Settings SET Value = 'disabled' WHERE Key = 'Dnp3_port';"
    echo "programa_sensores.st" > ../active_program
fi

# Ajustes comunes (Establecer programa activo y Autoarranque)
sqlite3 ../openplc.db "UPDATE Settings SET Value = (SELECT Prog_ID FROM Programs LIMIT 1) WHERE Key = 'Loaded_Program';"
sqlite3 ../openplc.db "UPDATE Settings SET Value = 'true' WHERE Key = 'Start_run_mode';"

# Arrancar OpenPLC
cd /work/OpenPLC_v3
exec ./start_openplc.sh