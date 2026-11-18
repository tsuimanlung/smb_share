@echo off
setlocal
cd /d "%~dp0"

rem Requires Python with tkinter (Store Python has it; some embedded builds do not)
set "PY=C:\Users\lewisx\AppData\Local\Microsoft\WindowsApps\python.exe"
if not exist "%PY%" set "PY=python"

"%PY%" -c "import tkinter, PyInstaller" >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Python needs tkinter and PyInstaller. Run:
  echo   "%PY%" -m pip install pyinstaller Pillow
  pause
  exit /b 1
)

rem Generate icon: reuse staff.ico, convert staff_1024.jpg, or draw a built-in one
"%PY%" make_icon.py
if not exist "staff.ico" (
  echo [ERROR] Icon generation failed. Install Pillow:
  echo   "%PY%" -m pip install Pillow
  pause
  exit /b 1
)

"%PY%" -m PyInstaller --onefile --noconsole --clean --noconfirm --name SMBScanner --icon staff.ico --add-data "staff.ico;." --hidden-import printer_scanner --distpath dist --workpath build --specpath . smb_scanner.py
if errorlevel 1 (
  echo [ERROR] PyInstaller failed
  pause
  exit /b 1
)
copy /y dist\SMBScanner.exe SMBScanner.exe >nul
echo [OK] SMBScanner.exe created
pause
