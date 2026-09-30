PROGRAM SimuladorPlanta
  VAR_EXTERNAL
    Sensor_Temp_Caldera_1 : INT; 
    Sensor_Temp_Caldera_2 : INT; 
    Estado_Bomba_Principal : BOOL;
    Alarma_Sobrepresion : BOOL;
    Modo_Manual : BOOL;
    Cmd_Bomba : BOOL;
  END_VAR
  
  VAR
    tick : INT := 0;
  END_VAR

  (* Simulador de dinámica del proceso *)
  tick := tick + 1;
  IF tick > 100 THEN
    tick := 0;
  END_IF;

  (* Generación de temperaturas simuladas *)
  Sensor_Temp_Caldera_1 := 20 + (tick * 75 / 100);
  Sensor_Temp_Caldera_2 := 85 - (tick * 60 / 100);

  (* LÓGICA DE CONTROL DE LA BOMBA *)
  IF Modo_Manual THEN
    (* MODO MANUAL: Mando directo por MQTT *)
    Estado_Bomba_Principal := Cmd_Bomba;
  ELSE
    (* MODO AUTOMÁTICO: Basado en temperatura real del proceso *)
    IF Sensor_Temp_Caldera_1 > 80 THEN
      Estado_Bomba_Principal := TRUE;  (* Enfriar si calienta demasiado *)
    ELSIF Sensor_Temp_Caldera_1 < 30 THEN
      Estado_Bomba_Principal := FALSE; (* Apagar si ya está fría *)
    END_IF;
  END_IF;

  (* Alarma de sobrepresión *)
  IF Sensor_Temp_Caldera_1 > 85 THEN
    Alarma_Sobrepresion := TRUE;
  ELSE
    Alarma_Sobrepresion := FALSE;
  END_IF;

END_PROGRAM

CONFIGURATION Config0
  VAR_GLOBAL
    Sensor_Temp_Caldera_1  AT %QW0  : INT; 
    Sensor_Temp_Caldera_2  AT %QW1  : INT; 
    
    Estado_Bomba_Principal AT %QX0.0 : BOOL;
    Alarma_Sobrepresion    AT %QX0.1 : BOOL;
    Modo_Manual            AT %QX0.2 : BOOL;
    Cmd_Bomba              AT %QX0.3 : BOOL;
  END_VAR
  
  RESOURCE Res0 ON PLC
    TASK TaskMain(INTERVAL := T#100ms, PRIORITY := 0);
    PROGRAM Inst0 WITH TaskMain : SimuladorPlanta;
  END_RESOURCE
END_CONFIGURATION