@echo off
echo ===================================================
echo   DETENIENDO Y LIMPIANDO ESCENARIO INDUSTRIAL
echo ===================================================
echo.
docker compose -f docker-compose.generated.yml down --remove-orphans
echo.
echo [OK] Escenario detenido y redes eliminadas.
pause
