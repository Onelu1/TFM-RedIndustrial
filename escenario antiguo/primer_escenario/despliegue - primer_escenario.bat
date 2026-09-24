@echo off
echo ===================================================
echo   INICIANDO SIMULADOR DE RED INDUSTRIAL (TFM)
echo ===================================================

echo.
echo [1/5] Levantando la infraestructura (Docker Compose)...
docker compose up -d

echo.
echo [2/5] Instalando nodos industriales en Node-RED...
docker exec nodered_scada npm install --prefix /data node-red-contrib-modbus -qq
docker restart nodered_scada > NUL

echo.
echo [3/5] Esperando 15 segundos a que los servicios arranquen...
timeout /t 15 /nobreak > NUL

echo.
echo [4/5] Inyectando herramientas de red en OpenPLC...
docker exec openplc_nodo apt-get update -qq
docker exec openplc_nodo apt-get install -y iproute2 iputils-ping -qq

echo.
echo [5/5] Configurando el enrutamiento inter-VLAN...
docker exec kali_nodo ip route add 192.168.10.0/24 via 192.168.20.254
docker exec openplc_nodo ip route add 192.168.20.0/24 via 192.168.10.254
docker exec -u root nodered_scada ip route add 192.168.10.0/24 via 192.168.20.254

echo.
echo ===================================================
echo   DESPLIEGUE COMPLETADO. EL ENTORNO ESTA LISTO.
echo ===================================================
pause