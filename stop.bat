@echo off
title ReachPrioritizer - Stop
echo Stopping ReachPrioritizer ...
rem Stop whatever is listening on the API (8000) and website (5173) ports
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-NetTCPConnection -LocalPort 8000,5173 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }"
rem Close the two server windows opened by start.bat
taskkill /FI "WINDOWTITLE eq ReachPrioritizer API*" /T /F >nul 2>nul
taskkill /FI "WINDOWTITLE eq ReachPrioritizer Website*" /T /F >nul 2>nul
echo Done. The API and the website have been stopped.
timeout /t 3 >nul
