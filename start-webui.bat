@echo off
title sec-checker web UI
cd /d "%~dp0"
echo Starting sec-checker web UI...
echo Opening http://127.0.0.1:8900 in your browser.
echo Close this window (or press Ctrl+C) to stop the server.
start "" "http://127.0.0.1:8900"
python run.py web --port 8900
