@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

rem 需要带 tkinter 的 Python（本机内置 Python 不带 tkinter，Store 版自带）
set "PY=C:\Users\lewisx\AppData\Local\Microsoft\WindowsApps\python.exe"
if not exist "%PY%" set "PY=python"

"%PY%" -c "import tkinter, PyInstaller" >nul 2>&1
if errorlevel 1 (
  echo [错误] 当前 Python 缺少 tkinter 或 PyInstaller，请先执行：
  echo   "%PY%" -m pip install pyinstaller
  pause
  exit /b 1
)

rem 由 staff_1024.jpg 生成多尺寸 ico（已有 staff.ico 则跳过）
if not exist "staff.ico" (
  "%PY%" -c "from PIL import Image; im=Image.open('staff_1024.jpg'); im.save('staff.ico', format='ICO', sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)])"
)
if not exist "staff.ico" (
  echo [错误] 未找到 staff.ico 且无法从 staff_1024.jpg 生成
  pause
  exit /b 1
)

"%PY%" -m PyInstaller --onefile --noconsole --clean --noconfirm --name SMBScanner --icon staff.ico --add-data "staff.ico;." --hidden-import printer_scanner --distpath dist --workpath build --specpath . smb_scanner.py
if errorlevel 1 (
  echo [失败] 打包出错
  pause
  exit /b 1
)
copy /y dist\SMBScanner.exe SMBScanner.exe >nul
echo [完成] 已生成 SMBScanner.exe
pause
