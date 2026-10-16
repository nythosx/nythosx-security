@echo off
title sec-checker web UI
cd /d "%~dp0"

if not defined SEC_CHECKER_VAULT_KEY if exist "configs\.vault_key" set /p SEC_CHECKER_VAULT_KEY=<configs\.vault_key

echo Starting sec-checker web UI...
echo Opening http://127.0.0.1:8900 in your browser.
echo Close this window (or press Ctrl+C) to stop the server.
start "" "http://127.0.0.1:8900"
python run.py web --port 8900

if errorlevel 1 (
  echo.
  echo [sec-checker] server exited with error code %errorlevel% - see the message above.
  echo This window will stay open so you can read it.
  pause
)
