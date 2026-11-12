@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Environment not set up. Run setup_windows.bat first.
  pause
  exit /b 1
)
echo Starting Network Penetration Testing Tool...
echo Open http://127.0.0.1:5000 in your browser.
".venv\Scripts\python.exe" web_app.py
pause
