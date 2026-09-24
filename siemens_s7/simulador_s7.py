import snap7
from snap7.type import SrvArea
from snap7.util import set_int, set_bool, set_real, get_bool, get_real
import ctypes
import time
import threading
import sys

# Crea el buffer de memoria para DB1 (256 bytes)
size = 256
db1_buffer = (ctypes.c_uint8 * size)()

def simulador_fisica_s7():
    """Hilo secundario que simula el proceso industrial en tiempo real."""
    tick = 0
    print("Motor S7 iniciado en segundo plano...")
    
    while True:
        tick = (tick + 1) % 100
        
        # Leer mandos de control escritos por SCADA / Atacante
        marcha = get_bool(db1_buffer, 4, 0)
        parada_emerg = get_bool(db1_buffer, 4, 1)
        setpoint_hz = get_real(db1_buffer, 6)

        if parada_emerg:
            # Estado de fallos / Parada forzada
            temp = 20
            presion = 0
            set_bool(db1_buffer, 4, 0, False) # Apagar marcha
        elif marcha:
            # Proceso en funcionamiento
            temp = int(40 + (tick * 0.4))
            presion = int(100 + (tick * 0.5))
        else:
            # Estado Standby
            temp = 25
            presion = 10

        # Escribir lecturas de sensores en el buffer de DB1
        set_int(db1_buffer, 0, temp)       # DB1.DBW0: Temperatura
        set_int(db1_buffer, 2, presion)    # DB1.DBW2: Presión
        
        time.sleep(0.5)

def main():
    try:
        server = snap7.server.Server()
        
        # Asignar valores por defecto iniciales
        set_int(db1_buffer, 0, 25)          # Temp = 25ºC
        set_int(db1_buffer, 2, 10)          # Presión = 10 bar
        set_bool(db1_buffer, 4, 0, False)   # Marcha = OFF
        set_bool(db1_buffer, 4, 1, False)   # Parada = OFF
        set_real(db1_buffer, 6, 50.0)       # Setpoint = 50.0 Hz

        # Registrar DB1
        server.register_area(SrvArea.DB, 1, db1_buffer)

        print("Iniciando servidor Siemens S7 en el puerto 102...")
        server.start()
        print("Servidor Siemens S7 escuchando peticiones S7Comm.")

        # Iniciar simulación en segundo plano
        hilo_sim = threading.Thread(target=simulador_fisica_s7, daemon=True)
        hilo_sim.start()

        # Mantener el contenedor con vida
        while True:
            time.sleep(1)

    except Exception as e:
        print(f"Error en el servidor S7: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()