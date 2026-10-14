import time
import sys
from pydnp3 import opendnp3, asiodnp3, asiopal, openpal

# Parametrización según gateway_dnp3.py y OpenPLC
PLC_DNP3_IP = "192.168.40.10"
DNP3_PORT = 20000
MASTER_ADDR = 1    # ID del Maestro DNP3
OUTSTATION_ADDR = 10 # ID del PLC OpenPLC (Outstation)

class AuditSOEHandler(opendnp3.ISOEHandler):
    """Procesador de eventos y estados de telemetría DNP3 (Sequence of Events)."""
    def __init__(self):
        super(AuditSOEHandler, self).__init__()

    def Start(self):
        pass

    def Process(self, info, values):
        tipo = type(values).__name__

        # Procesamiento de Entradas/Salidas Binarias (Índices 0 a 3)
        if "Binary" in tipo:
            def process_binary(item):
                val = item.value.value
                estado = (val.name == 'ON') if hasattr(val, 'name') else bool(val)
                
                etiquetas_binarias = {
                    0: "Estado Bomba Principal (%QX0.0)",
                    1: "Alarma Sobrepresión    (%QX0.1)",
                    2: "Modo Manual",
                    3: "Comando Bomba (cmd_bomba)"
                }
                desc = etiquetas_binarias.get(item.index, f"Binario Desconocido ({item.index})")
                print(f" [BIN] Índice {item.index} | {desc}: {'ON' if estado else 'OFF'}")

            values.ForeachItem(process_binary)

        # Procesamiento de Entradas/Salidas Analógicas (Índices 0 y 1)
        elif "Analog" in tipo:
            def process_analog(item):
                val = float(item.value.value)
                etiquetas_analogicas = {
                    0: "Temp. Caldera 1 (%QW0)",
                    1: "Temp. Caldera 2 (%QW1)"
                }
                desc = etiquetas_analogicas.get(item.index, f"Analógico Desconocido ({item.index})")
                print(f" [ANA] Índice {item.index} | {desc}: {val:.2f} ºC")

            values.ForeachItem(process_analog)

    def End(self):
        pass

def main():
    print(f"[*] Iniciando Maestro DNP3 de auditoría...")
    print(f"[*] Destino: {PLC_DNP3_IP}:{DNP3_PORT} | Master ID: {MASTER_ADDR} -> Outstation ID: {OUTSTATION_ADDR}")

    # Inicializar gestor DNP3
    manager = asiodnp3.DNP3Manager(1, asiodnp3.ConsoleLogger().Create())
    retry = asiopal.ChannelRetry().Default()

    # Añadir canal TCP Client
    channel = manager.AddTCPClient(
        "dnp3_audit_channel",
        opendnp3.levels.NORMAL,
        retry,
        PLC_DNP3_IP,
        "0.0.0.0",
        DNP3_PORT,
        asiodnp3.PrintingChannelListener().Create()
    )

    # Configuración de Direccionamiento de Capa de Enlace
    config = asiodnp3.MasterStackConfig()
    config.link.LocalAddr = MASTER_ADDR
    config.link.RemoteAddr = OUTSTATION_ADDR

    soe_handler = AuditSOEHandler()
    master_app = asiodnp3.DefaultMasterApplication().Create()

    master = channel.AddMaster(
        "dnp3_audit_master",
        soe_handler,
        master_app,
        config
    )

    # Polling cíclico de todas las clases de datos cada 1000 ms
    master.AddClassScan(
        opendnp3.ClassField.AllClasses(),
        openpal.TimeDuration.Milliseconds(1000),
        opendnp3.TaskConfig().Default()
    )

    master.Enable()
    time.sleep(3) # Tiempo para completar el handshake DNP3 y recibir la primera ráfaga de datos

    # --- DEMOSTRACIÓN DE COMANDO CROB (Control Relay Output Block) ---
    # Enviar comando LATCH_ON al Índice 2 (Modo Manual)
    print("\n[+] Enviando comando DNP3 CROB (LATCH_ON) a Modo Manual (Índice 2)...")
    crob = opendnp3.ControlRelayOutputBlock(opendnp3.ControlCode.LATCH_ON)
    
    def command_callback(result):
        print(f"[+] Respuesta del PLC a CROB Índice 2: {result.summary}")

    master.DirectOperate(crob, 2, command_callback)
    
    time.sleep(5) # Mantener ejecución para observar las lecturas post-comando

    # Cierre de sesión
    master.Disable()
    channel.Shutdown()
    manager.Shutdown()
    print("[+] Sesión DNP3 finalizada.")

if __name__ == "__main__":
    main()