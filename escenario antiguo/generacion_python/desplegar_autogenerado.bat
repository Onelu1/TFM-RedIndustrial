@echo off
echo ===================================================
echo   DESPLIEGUE AUTOMÁTICO DE ESCENARIO PARAMETRIZADO
echo ===================================================

echo.
echo [1/5] Levantando contenedores con Docker Compose...
docker compose -f docker-compose.generated.yml up -d

echo.
echo [2/5] Instalando paquetes Modbus en nodos SCADA...
docker exec nodered_scada_1 npm install --prefix /data node-red-contrib-modbus -qq
docker restart nodered_scada_1 > NUL

echo.
echo [3/5] Esperando 15 segundos al inicio de los servicios...
timeout /t 15 /nobreak > NUL

echo.
echo [4/5] Instalando iproute2 en contenedores PLC...
docker exec plc_agua_1 apt-get update -qq && docker exec plc_agua_1 apt-get install -y iproute2 iputils-ping -qq
docker exec plc_agua_2 apt-get update -qq && docker exec plc_agua_2 apt-get install -y iproute2 iputils-ping -qq
docker exec plc_agua_3 apt-get update -qq && docker exec plc_agua_3 apt-get install -y iproute2 iputils-ping -qq
docker exec plc_bombeo_1 apt-get update -qq && docker exec plc_bombeo_1 apt-get install -y iproute2 iputils-ping -qq
docker exec plc_bombeo_2 apt-get update -qq && docker exec plc_bombeo_2 apt-get install -y iproute2 iputils-ping -qq
docker exec plc_bombeo_3 apt-get update -qq && docker exec plc_bombeo_3 apt-get install -y iproute2 iputils-ping -qq

echo.
echo [5/5] Inyectando rutas estaticas para evitar el bypass de Docker...

:: Rutas desde SCADAs hacia Zonas OT
docker exec -u root nodered_scada_1 ip route add 192.168.10.0/24 via 192.168.20.254
docker exec -u root nodered_scada_1 ip route add 192.168.30.0/24 via 192.168.20.254
docker exec kali_nodo ip route add 192.168.10.0/24 via 192.168.20.254
docker exec kali_nodo ip route add 192.168.30.0/24 via 192.168.20.254

:: Rutas desde Zonas OT hacia Red de Control
docker exec plc_agua_1 ip route add 192.168.20.0/24 via 192.168.10.254
docker exec plc_agua_2 ip route add 192.168.20.0/24 via 192.168.10.254
docker exec plc_agua_3 ip route add 192.168.20.0/24 via 192.168.10.254
docker exec plc_bombeo_1 ip route add 192.168.20.0/24 via 192.168.30.254
docker exec plc_bombeo_2 ip route add 192.168.20.0/24 via 192.168.30.254
docker exec plc_bombeo_3 ip route add 192.168.20.0/24 via 192.168.30.254

echo.
echo ===================================================
echo   ENTORNO DESPLEGADO Y ENRUTADO CORRECTAMENTE.
echo ===================================================
pause
