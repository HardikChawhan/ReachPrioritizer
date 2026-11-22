@echo off
setlocal EnableExtensions
title ReachPrioritizer - Launcher
cd /d "%~dp0"
set "ROOT=%~dp0"
set "VPY=%ROOT%.venv\Scripts\python.exe"

echo.
echo  ==========================================================
echo    Starting ReachPrioritizer
echo  ==========================================================
echo.

rem ---- make sure setup.bat was run
if not exist "%VPY%" goto :needsetup
if not exist "%ROOT%node_modules\@babel\parser" goto :needsetup
if not exist "%ROOT%frontend\node_modules" goto :needsetup

rem ---- backend (API) on http://127.0.0.1:8000
call :isup http://127.0.0.1:8000/health
if errorlevel 1 (
  echo  Starting the API server          ^(new window "ReachPrioritizer API"^)
  start "ReachPrioritizer API" /D "%ROOT%backend" cmd /k ""%VPY%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
) else (
  echo  API server is already running.
)

rem ---- frontend (website) on http://localhost:5173
call :isup http://localhost:5173
if errorlevel 1 (
  echo  Starting the website             ^(new window "ReachPrioritizer Website"^)
  start "ReachPrioritizer Website" /D "%ROOT%frontend" cmd /k "npm run dev"
) else (
  echo  Website is already running.
)

echo.
echo  Waiting for both to be ready ^(usually 5-15 seconds^) ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$end=(Get-Date).AddSeconds(90); while((Get-Date) -lt $end){ try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://127.0.0.1:8000/health' | Out-Null; Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://localhost:5173' | Out-Null; exit 0 } catch { Start-Sleep -Milliseconds 700 } }; exit 1"
if errorlevel 1 (
  echo.
  echo  [!] It is taking longer than expected. Look at the two new windows for errors.
  echo      Opening the browser anyway - refresh the page in a few seconds.
) else (
  echo  Ready!
)

start "" "http://localhost:5173"
echo.
echo  ==========================================================
echo    ReachPrioritizer is running:
echo      Website   http://localhost:5173
echo      API docs  http://127.0.0.1:8000/docs
echo.
echo    To stop it: run stop.bat, or close the two server windows.
echo  ==========================================================
echo.
timeout /t 8 >nul
exit /b 0

:needsetup
echo  [X] The project is not set up yet on this computer.
echo      Run setup.bat first (only needed once), then run start.bat again.
echo.
pause
exit /b 1

:isup
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 '%~1' | Out-Null; exit 0 } catch { exit 1 }"
exit /b %errorlevel%
