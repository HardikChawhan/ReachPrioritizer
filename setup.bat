@echo off
setlocal EnableExtensions EnableDelayedExpansion
title ReachPrioritizer - Setup
cd /d "%~dp0"

echo.
echo  ==========================================================
echo    ReachPrioritizer - one-time setup
echo    Installs everything the project needs. Takes 2-5 minutes.
echo  ==========================================================
echo.

rem ------------------------------------------------------------ 1. Node.js
echo [1/6] Checking Node.js ...
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo  [X] Node.js was not found.
  echo      Install the LTS version from https://nodejs.org  ^(Node 18 or newer^)
  echo      then close this window and run setup.bat again.
  goto :fail
)
for /f "tokens=1 delims=." %%v in ('node -p "process.versions.node"') do set "NODE_MAJOR=%%v"
if !NODE_MAJOR! LSS 18 (
  echo  [X] Node.js !NODE_MAJOR! is too old. Install Node.js 18 or newer from https://nodejs.org
  goto :fail
)
echo      OK - Node.js !NODE_MAJOR!

rem ------------------------------------------------------------ 2. Python
echo [2/6] Checking Python ...
set "PY="
for %%V in (3.12 3.11 3.13 3.10 3.14) do (
  if not defined PY (
    py -%%V -c "import sys" >nul 2>nul && set "PY=py -%%V"
  )
)
if not defined PY (
  python -c "import sys; sys.exit(0 if (3,10) <= sys.version_info[:2] <= (3,14) else 1)" >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo.
  echo  [X] Python 3.10 - 3.13 was not found.
  echo      Install Python 3.12 from https://www.python.org/downloads/
  echo      and tick "Add python.exe to PATH" during installation,
  echo      then close this window and run setup.bat again.
  goto :fail
)
for /f "delims=" %%v in ('!PY! -c "import platform; print(platform.python_version())"') do set "PY_VER=%%v"
echo      OK - Python !PY_VER!  ^(!PY!^)

rem ------------------------------------------------------------ 3. Python virtual environment
echo [3/6] Preparing the Python environment ^(.venv^) ...
if exist ".venv\Scripts\python.exe" (
  echo      Using the existing .venv
) else (
  !PY! -m venv .venv
  if errorlevel 1 (
    echo  [X] Could not create the virtual environment.
    goto :fail
  )
)
set "VPY=%~dp0.venv\Scripts\python.exe"

echo [4/6] Installing backend + AI packages ^(FastAPI, scikit-learn, ...^) ...
"%VPY%" -m pip install --upgrade pip --disable-pip-version-check -q
"%VPY%" -m pip install -r backend\requirements.txt --disable-pip-version-check
if errorlevel 1 (
  echo  [X] pip install failed. Check your internet connection.
  echo      If you use a very new Python, install Python 3.12, delete the .venv folder and run setup.bat again.
  goto :fail
)

rem ------------------------------------------------------------ 4. Node packages
echo [5/6] Installing the analysis engine and website packages ^(npm^) ...
call npm install --no-audit --no-fund
if errorlevel 1 (
  echo  [X] npm install failed in the project folder.
  goto :fail
)
pushd frontend
call npm install --no-audit --no-fund
if errorlevel 1 (
  popd
  echo  [X] npm install failed in the frontend folder.
  goto :fail
)
popd

rem ------------------------------------------------------------ 5. Self-check
echo [6/6] Checking that everything works ...
node analyzer\analyze.js --project test-applications\mixed-app --output "%TEMP%\reachprioritizer_check.json" >nul 2>nul
if errorlevel 1 (
  echo  [X] The analysis engine could not run.
  goto :fail
)
"%VPY%" -c "import fastapi, uvicorn, sklearn, joblib" >nul 2>nul
if errorlevel 1 (
  echo  [X] The Python packages are not importable.
  goto :fail
)
echo      OK - analysis engine and backend are ready

echo.
echo  ==========================================================
echo    Setup complete.
echo    Double-click start.bat to launch ReachPrioritizer.
echo  ==========================================================
echo.
pause
exit /b 0

:fail
echo.
echo  Setup did NOT finish. Fix the problem above and run setup.bat again.
echo.
pause
exit /b 1
