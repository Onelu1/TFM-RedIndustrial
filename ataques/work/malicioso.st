PROGRAM main
  VAR
    heartbeat : BOOL := FALSE;
  END_VAR

  heartbeat := NOT heartbeat;
END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#100ms, PRIORITY := 0);
    PROGRAM instance0 WITH task0 : main;
  END_RESOURCE
END_CONFIGURATION
