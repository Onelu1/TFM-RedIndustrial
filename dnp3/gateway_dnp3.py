import time
import os
import json
import paho.mqtt.client as mqtt

# Importaciones de dnp3-python
from pydnp3 import opendnp3, asiodnp3, asiopal, openpal

# Configuraciones
BROKER_IP = os.getenv("MQTT_BROKER_IP", "192.168.20.15")
PLC_DNP3_IP = os.getenv("PLC_DNP3_IP", "192.168.40.10")
DNP3_PORT = 20000

print(f"[*] Iniciando Gateway DNP3-MQTT...")
print(f"[*] Destino MQTT: {BROKER_IP}")
print(f"[*] Objetivo DNP3: {PLC_DNP3_IP}:{DNP3_PORT}")

# --- 1. CONFIGURACIÓN MQTT ---
mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="Gateway_DNP3")
datos_planta = {
    "bomba_principal": False,
    "alarma_sobrepresion": False,
    "temp_caldera_1": 0,
    "temp_caldera_2": 0
}

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("[+] Conectado al Broker MQTT")
        client.subscribe("scada/dnp3/control/#")
    else:
        print(f"[-] Error MQTT: {rc}")

mqtt_client.on_connect = on_connect
mqtt_client.connect(BROKER_IP, 1883, 60)
mqtt_client.loop_start()

# --- 2. CONFIGURACIÓN DNP3 (SOE Handler) ---
# Esta clase recibe los datos del PLC cada vez que cambian o son sondeados
class DataHandler(opendnp3.ISOEHandler):
    def __init__(self):
        super(DataHandler, self).__init__()
        self.hubo_cambios = False

    def Start(self):
        # Se ejecuta al iniciar una ráfaga de datos
        self.hubo_cambios = False

    def Process(self, info, values):
        tipo = type(values).__name__

        # Captura binarios (Bomba y Alarma)
        if "Binary" in tipo:
            def process_binary(item):
                val = item.value.value
                if hasattr(val, 'name'):
                    estado = (val.name == 'ON')
                elif type(val).__name__ == 'DoubleBit':
                    estado = ('ON' in str(val))
                else:
                    estado = bool(val)

                if item.index == 0:
                    datos_planta["bomba_principal"] = estado
                elif item.index == 1:
                    datos_planta["alarma_sobrepresion"] = estado
                self.hubo_cambios = True

            values.ForeachItem(process_binary)

        # Captura analógicos (Ignoramos valores 0.0 de grupos secundarios/no mapeados)
        elif "Analog" in tipo:
            def process_analog(item):
                val = float(item.value.value)
                if val != 0.0:  # Evitamos que ráfagas vacías pisen la lectura real
                    if item.index == 0:
                        datos_planta["temp_caldera_1"] = val
                    elif item.index == 1:
                        datos_planta["temp_caldera_2"] = val
                    self.hubo_cambios = True

            values.ForeachItem(process_analog)

    def End(self):
        # Se ejecuta SOLO cuando se ha procesado todo el lote de datos
        if self.hubo_cambios:
            payload = json.dumps(datos_planta)
            mqtt_client.publish("scada/dnp3/telemetria", payload)
            print(f"[->] MQTT Publicado (Lote Completo): {payload}")

# --- 3. INICIO DEL CANAL DNP3 ---
# Inicializamos el gestor de hilos de DNP3
manager = asiodnp3.DNP3Manager(1, asiodnp3.ConsoleLogger().Create())
retry = asiopal.ChannelRetry().Default()

# Creamos el canal TCP hacia el PLC
channel = manager.AddTCPClient(
    "dnp3_client", 
    opendnp3.levels.NORMAL,
    retry, 
    PLC_DNP3_IP,  # Host remoto (texto)
    "0.0.0.0",    # Adaptador local (texto)
    DNP3_PORT,    # Puerto (entero)
    asiodnp3.PrintingChannelListener().Create()
)

# Configuración del Maestro (Gateway)
master_stack_config = asiodnp3.MasterStackConfig()
master_stack_config.link.LocalAddr = 1   # ID del Gateway
master_stack_config.link.RemoteAddr = 10 # ID de OpenPLC por defecto

# Guardamos las instancias en variables para evitar 
# que el recolector de basura de Python las elimine de la memoria
soe_handler = DataHandler()
master_app = asiodnp3.DefaultMasterApplication().Create()

# Añadimos el maestro al canal usando las variables instanciadas
master = channel.AddMaster(
    "dnp3_master", 
    soe_handler, 
    master_app, 
    master_stack_config
)

# Configuramos el escaneo (Polling) cada 2 segundos (Class 0 lee todo)
scan = master.AddClassScan(
    opendnp3.ClassField.AllClasses(), 
    openpal.TimeDuration.Seconds(2), 
    opendnp3.TaskConfig().Default()
)

master.Enable()

# Bucle infinito para mantener vivo el contenedor
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("[*] Apagando Gateway...")
finally:
    master.Disable()
    channel.Shutdown()
    manager.Shutdown()
    mqtt_client.loop_stop()