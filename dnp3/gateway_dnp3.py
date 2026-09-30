import time
import os
import json
import paho.mqtt.client as mqtt

# Importaciones de pydnp3
from pydnp3 import opendnp3, asiodnp3, asiopal, openpal


# Función global para evitar que C++ choque con la memoria de Python
def global_command_callback(result):
    print(f"[+] Respuesta del PLC (Comando): {result.summary}")

# Configuraciones de red
BROKER_IP = os.getenv("MQTT_BROKER_IP", "192.168.20.15")
PLC_DNP3_IP = os.getenv("PLC_DNP3_IP", "192.168.40.10")
DNP3_PORT = 20000

print(f"[*] Iniciando Gateway DNP3-MQTT (Bidireccional)...")
print(f"[*] Destino MQTT: {BROKER_IP}")
print(f"[*] Objetivo DNP3: {PLC_DNP3_IP}:{DNP3_PORT}")

# Estado global de la planta
datos_planta = {
    "bomba_principal": False,
    "alarma_sobrepresion": False,
    "modo_manual": False,      # Para pruebas
    "cmd_bomba": False,        # Para pruebas
    "temp_caldera_1": 0.0,
    "temp_caldera_2": 0.0
}

# Referencia global al objeto master DNP3 para usarlo desde los callbacks de MQTT
master = None

# --- 1. CONFIGURACIÓN MQTT ---
mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="Gateway_DNP3")

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("[+] Conectado al Broker MQTT")
        # Suscripción a comandos de control
        client.subscribe("scada/dnp3/control/#")
        print("[+] Suscrito a 'scada/dnp3/control/#'")
    else:
        print(f"[-] Error de conexión MQTT. Código: {rc}")

def on_message(client, userdata, msg):
    global master
    if master is None:
        print("[-] Error: El canal DNP3 no está inicializado todavía.")
        return

    try:
        topic = msg.topic.strip()
        payload_raw = msg.payload.decode('utf-8').strip().lower()
        print(f"[<-] Comando MQTT recibido en [{topic}]: {payload_raw}")

        # 1. Mapeo directo de tópicos a índices DNP3
        TOPIC_TO_INDEX = {
            "scada/dnp3/control/modo_manual": 2,      # Va a %QX0.2
            "scada/dnp3/control/bomba_principal": 3,  # Va a %QX0.3
        }

        if topic not in TOPIC_TO_INDEX:
            print(f"[-] Tópico no reconocido o no mapeado: {topic}")
            return
            
        target_index = TOPIC_TO_INDEX[topic]

        # 2. Interpretar el payload (si mandas JSON o texto plano)
        target_val = None
        if payload_raw in ["true", "1", "on"]:
            target_val = True
        elif payload_raw in ["false", "0", "off"]:
            target_val = False
        else:
            # Intentar extraer el valor si viene en formato JSON {"value": true}
            try:
                val_json = json.loads(payload_raw)
                if isinstance(val_json, dict):
                    target_val = bool(val_json.get("state", val_json.get("value", True)))
            except Exception:
                pass

        if target_val is None:
            print(f"[-] Payload no válido para evaluar ON/OFF: {payload_raw}")
            return

        # 3. Enviar comando DNP3
        op_code = opendnp3.ControlCode.LATCH_ON if target_val else opendnp3.ControlCode.LATCH_OFF
        crob = opendnp3.ControlRelayOutputBlock(op_code)

        # Transmisión del comando DirectOperate usando el callback global
        master.DirectOperate(crob, target_index, global_command_callback)
        print(f"[->] DNP3 CROB Enviado a PLC: Indice={target_index}, Acción={'LATCH_ON' if target_val else 'LATCH_OFF'}")

    except Exception as e:
        print(f"[-] Excepción procesando comando MQTT: {e}")

mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message
mqtt_client.connect(BROKER_IP, 1883, 60)
mqtt_client.loop_start()

# --- 2. CONFIGURACIÓN DNP3 (SOE Handler - Lectura) ---
class DataHandler(opendnp3.ISOEHandler):
    def __init__(self):
        super(DataHandler, self).__init__()
        self.hubo_cambios = False

    def Start(self):
        self.hubo_cambios = False

    def Process(self, info, values):
        tipo = type(values).__name__

        # Captura binarios
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
                elif item.index == 2:
                    datos_planta["modo_manual"] = estado
                elif item.index == 3:
                    datos_planta["cmd_bomba"] = estado
                self.hubo_cambios = True

            values.ForeachItem(process_binary)

        # Captura analógicos
        elif "Analog" in tipo:
            def process_analog(item):
                val = float(item.value.value)
                if val != 0.0:
                    if item.index == 0:
                        datos_planta["temp_caldera_1"] = val
                    elif item.index == 1:
                        datos_planta["temp_caldera_2"] = val
                    self.hubo_cambios = True

            values.ForeachItem(process_analog)

    def End(self):
        if self.hubo_cambios:
            payload = json.dumps(datos_planta)
            mqtt_client.publish("scada/dnp3/telemetria", payload)
            print(f"[->] Telemetría enviada a MQTT: {payload}")

# --- 3. INICIALIZACIÓN DEL MAESTRO DNP3 ---
manager = asiodnp3.DNP3Manager(1, asiodnp3.ConsoleLogger().Create())
retry = asiopal.ChannelRetry().Default()

channel = manager.AddTCPClient(
    "dnp3_client",
    opendnp3.levels.NORMAL,
    retry,
    PLC_DNP3_IP,
    "0.0.0.0",
    DNP3_PORT,
    asiodnp3.PrintingChannelListener().Create()
)

master_stack_config = asiodnp3.MasterStackConfig()
master_stack_config.link.LocalAddr = 1   # ID del Gateway
master_stack_config.link.RemoteAddr = 10 # ID del PLC OpenPLC

soe_handler = DataHandler()
master_app = asiodnp3.DefaultMasterApplication().Create()

master = channel.AddMaster(
    "dnp3_master",
    soe_handler,
    master_app,
    master_stack_config
)

# Polling continuo cada 2 segundos
scan = master.AddClassScan(
    opendnp3.ClassField.AllClasses(),
    openpal.TimeDuration.Seconds(2),
    opendnp3.TaskConfig().Default()
)

master.Enable()

# Bucle de ejecución
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("[*] Apagando Gateway DNP3...")
finally:
    master.Disable()
    channel.Shutdown()
    manager.Shutdown()
    mqtt_client.loop_stop()