@echo off
setlocal
set "PYTHON_EXE=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
if not exist "%PYTHON_EXE%" (
  echo Python was not found at:
  echo %PYTHON_EXE%
  echo Install Python or update PYTHON_EXE in this file.
  pause
  exit /b 1
)
cd /d "%~dp0"
echo Starting PKI Security backend from %~dp0
echo Keep this window open while using the frontend.
"%PYTHON_EXE%" -u "%~dp0frontend\server.py"
echo Backend stopped. If an error appeared above, copy it for troubleshooting.
pause
