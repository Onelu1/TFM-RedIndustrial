import snap7
from snap7.type import SrvArea
import ctypes
import time
import sys

try:
    # Instancia el servidor
    server = snap7.server.Server()

    # Crea buffer de memoria para DB1 (256 bytes)
    size = 256
    db_data = (ctypes.c_uint8 * size)()

    # Registra el DB1 con el Enum oficial de la librería (SrvArea)
    server.register_area(SrvArea.DB, 1, db_data)

    print("Iniciando servidor Siemens S7 en el puerto 102...")
    server.start()
    print("Servidor Siemens S7 escuchando correctamente")

    # Mantener el proceso vivo
    while True:
        time.sleep(1)

except Exception as e:
    print(f"Error crítico al arrancar el servidor S7: {e}", file=sys.stderr)
    sys.exit(1)