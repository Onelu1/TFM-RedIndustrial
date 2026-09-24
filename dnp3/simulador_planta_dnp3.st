PROGRAM SimuladorPlanta
  VAR_EXTERNAL
    Sensor_Temp_Caldera_1 : INT; 
    Sensor_Temp_Caldera_2 : INT; 
    Estado_Bomba_Principal : BOOL;
    Alarma_Sobrepresion : BOOL;
  END_VAR
  
  VAR
    tick : INT := 0;
  END_VAR

  tick := tick + 1;
  IF tick > 100 THEN
    tick := 0;
  END_IF;

  (* Analogicas *)
  Sensor_Temp_Caldera_1 := 20 + (tick * 75 / 100);
  Sensor_Temp_Caldera_2 := 85 - (tick * 60 / 100);

  (* Discretas - Estados ON/OFF *)
  IF tick > 50 THEN
    Estado_Bomba_Principal := TRUE;
  ELSE
    Estado_Bomba_Principal := FALSE;
  END_IF;

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
  END_VAR
  
  RESOURCE Res0 ON PLC
    TASK TaskMain(INTERVAL := T#100ms, PRIORITY := 0);
    PROGRAM Inst0 WITH TaskMain : SimuladorPlanta;
  END_RESOURCE
END_CONFIGURATION