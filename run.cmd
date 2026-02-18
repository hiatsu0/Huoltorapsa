@echo off
cd /d "%~dp0"

where python3 >nul 2>nul
if %errorlevel%==0 goto RUN

echo Python not found. Installing...
winget install --id Python.Python.3 --exact --silent --accept-package-agreements --accept-source-agreements

:RUN
python3.exe server.py
