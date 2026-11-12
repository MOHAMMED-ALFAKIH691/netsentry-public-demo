@echo off
setlocal
cd /d "%~dp0"
echo [1/4] Checking Python launcher...
where py >nul 2>&1
if errorlevel 1 (
  echo ERROR: Python was not found. Install Python 3.11 or newer from https://www.python.org/downloads/windows/
  echo During installation, enable "Add python.exe to PATH".
  pause
  exit /b 1
)
py -3 --version
if errorlevel 1 (
  echo ERROR: Python 3 could not be started.
  pause
  exit /b 1
)
echo [2/4] Creating virtual environment...
if not exist ".venv\Scripts\python.exe" py -3 -m venv .venv
if errorlevel 1 (
  echo ERROR: Could not create the virtual environment.
  pause
  exit /b 1
)
echo [3/4] Installing Python dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :failed
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :failed
if not exist reports mkdir reports
echo [4/4] Checking Nmap...
where nmap >nul 2>&1
if errorlevel 1 (
  echo NOTE: Nmap is not installed. The web dashboard and Demo mode will work.
  echo Live scans require Nmap for Windows: https://nmap.org/download.html
) else (
  nmap --version
)
echo.
echo Setup complete. Run run_windows.bat to start the dashboard.
pause
exit /b 0
:failed
echo ERROR: Dependency installation failed. Check your internet connection and Python installation.
pause
exit /b 1
