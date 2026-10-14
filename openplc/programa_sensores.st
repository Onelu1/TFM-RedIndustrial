 PROGRAM SimuladorPlanta
  VAR_EXTERNAL
    Sensor_Temp_Caldera_1    : INT; 
    Sensor_Temp_Caldera_2    : INT; 
    Sensor_Temp_Ambiente     : INT; 
    Sensor_Temp_Refrigerante : INT; 
    Sensor_Temp_Salida       : INT; 

    Sensor_Presion_Linea_A   : INT; 
    Sensor_Presion_Linea_B   : INT; 
    Sensor_Presion_Vapor     : INT; 
    Sensor_Presion_Entrada   : INT; 
    Sensor_Presion_Salida    : INT; 

    Sensor_Nivel_Tanque_Agua : INT; 
    Sensor_Nivel_Tanque_Quim : INT; 
    Sensor_Nivel_Reserva     : INT; 
    Sensor_Flujo_Entrada     : INT; 
    Sensor_Flujo_Salida      : INT; 

    Sensor_RPM_Bomba_1       : INT; 
    Sensor_RPM_Bomba_2       : INT; 
    Sensor_Consumo_KW        : INT; 
    Contador_Piezas_OK       : INT; 
    Contador_Alertas_Fail    : INT; 

    (* Actuadores y Setpoints externos *)
    Comando_Parada_Emergencia : BOOL;
    Comando_Marcha_Bomba_1    : BOOL;
    Setpoint_Max_RPM_Bomba_1  : INT;
  END_VAR
  
  VAR
    tick : INT := 0;
  END_VAR

  tick := tick + 1;
  IF tick > 100 THEN
    tick := 0;
  END_IF;

  (* ------------------------------------------------------------- *)
  (* LÓGICA PARADA DE EMERGENCIA (FC05 en %QX0.0)                  *)
  (* ------------------------------------------------------------- *)
  IF Comando_Parada_Emergencia THEN
    (* Estado Crítico: Se fuerzan las salidas físicas a 0 *)
    Sensor_RPM_Bomba_1       := 0;
    Sensor_RPM_Bomba_2       := 0;
    Sensor_Flujo_Entrada     := 0;
    Sensor_Flujo_Salida      := 0;
    Sensor_Presion_Linea_A   := 0;
    Sensor_Presion_Linea_B   := 0;
    Sensor_Presion_Vapor     := 0;
    Sensor_Consumo_KW        := 2; (* Consumo en standby *)

    IF (tick MOD 10) = 0 THEN
      Contador_Alertas_Fail  := Contador_Alertas_Fail + 1;
    END_IF;

  ELSE
    (* ----------------------------------------------------------- *)
    (* LÓGICA DE OPERACIÓN                                         *)
    (* ----------------------------------------------------------- *)
    
    (* Control de Bomba 1 (FC05 en %QX0.1 y Setpoint FC06 en %QW20) *)
    IF Comando_Marcha_Bomba_1 THEN
      Sensor_RPM_Bomba_1 := 1400 + (tick MOD 100);
      
      (* Acotación por Setpoint escrito externamente *)
      IF Sensor_RPM_Bomba_1 > Setpoint_Max_RPM_Bomba_1 THEN
        Sensor_RPM_Bomba_1 := Setpoint_Max_RPM_Bomba_1;
      END_IF;
    ELSE
      Sensor_RPM_Bomba_1 := 0;
    END_IF;

    (* Bomba 2 en ciclo automático *)
    IF tick > 50 THEN
      Sensor_RPM_Bomba_2 := 1450;
    ELSE
      Sensor_RPM_Bomba_2 := 0;
    END_IF;

    (* Caudales y Presiones *)
    Sensor_Flujo_Entrada     := 15 + (tick MOD 30);
    Sensor_Flujo_Salida      := 10 + (tick MOD 30);
    Sensor_Presion_Linea_A   := 100 + (tick MOD 50);
    Sensor_Presion_Linea_B   := 90 + ((100 - tick) MOD 20);
    Sensor_Presion_Vapor     := 200 + (tick MOD 50);

    Sensor_Consumo_KW        := 15 + (tick MOD 20);
    Contador_Piezas_OK       := Contador_Piezas_OK + 1;

    IF (tick MOD 25) = 0 THEN
      Contador_Alertas_Fail  := Contador_Alertas_Fail + 1;
    END_IF;
  END_IF;

  (* Sensores pasivos que evolucionan de forma continua *)
  Sensor_Temp_Caldera_1    := 20 + (tick * 75 / 100);
  Sensor_Temp_Caldera_2    := 85 - (tick * 60 / 100);
  Sensor_Temp_Ambiente     := 22 + (tick MOD 3);
  Sensor_Temp_Refrigerante := 5 + (tick MOD 10);
  Sensor_Temp_Salida       := 40 + (tick MOD 20);

  Sensor_Presion_Entrada   := 50 + (tick MOD 10);
  Sensor_Presion_Salida    := 40 + (tick MOD 10);

  Sensor_Nivel_Tanque_Agua := tick * 10;
  Sensor_Nivel_Tanque_Quim := 1000 - (tick * 10);
  Sensor_Nivel_Reserva      := 750 + (tick MOD 5);
END_PROGRAM

CONFIGURATION Config0
  VAR_GLOBAL
    (* Lectura: Holding Registers (FC03) *)
    Sensor_Temp_Caldera_1    AT %QW0  : INT; 
    Sensor_Temp_Caldera_2    AT %QW1  : INT; 
    Sensor_Temp_Ambiente     AT %QW2  : INT; 
    Sensor_Temp_Refrigerante AT %QW3  : INT; 
    Sensor_Temp_Salida       AT %QW4  : INT; 

    Sensor_Presion_Linea_A   AT %QW5  : INT; 
    Sensor_Presion_Linea_B   AT %QW6  : INT; 
    Sensor_Presion_Vapor     AT %QW7  : INT; 
    Sensor_Presion_Entrada   AT %QW8  : INT; 
    Sensor_Presion_Salida    AT %QW9  : INT; 

    Sensor_Nivel_Tanque_Agua AT %QW10 : INT; 
    Sensor_Nivel_Tanque_Quim AT %QW11 : INT; 
    Sensor_Nivel_Reserva     AT %QW12 : INT; 
    Sensor_Flujo_Entrada     AT %QW13 : INT; 
    Sensor_Flujo_Salida      AT %QW14 : INT; 

    Sensor_RPM_Bomba_1       AT %QW15 : INT; 
    Sensor_RPM_Bomba_2       AT %QW16 : INT; 
    Sensor_Consumo_KW        AT %QW17 : INT; 
    Contador_Piezas_OK       AT %QW18 : INT; 
    Contador_Alertas_Fail    AT %QW19 : INT; 

    (* Escritura / Control: Coils (FC01/FC05) *)
    Comando_Parada_Emergencia AT %QX0.0 : BOOL := FALSE;
    Comando_Marcha_Bomba_1    AT %QX0.1 : BOOL := TRUE; 

    (* Escritura / Control: Holding Register (FC03/FC06) *)
    Setpoint_Max_RPM_Bomba_1  AT %QW20  : INT := 1500;
  END_VAR

  RESOURCE Res0 ON PLC
    TASK TaskMain(INTERVAL := T#100ms, PRIORITY := 0);
    PROGRAM Inst0 WITH TaskMain : SimuladorPlanta;
  END_RESOURCE
END_CONFIGURATION