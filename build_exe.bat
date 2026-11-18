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

rem 生成图标：本机有 staff.ico 直接用，刚 clone 的仓库会自动画一个内置图标
"%PY%" make_icon.py
if not exist "staff.ico" (
  echo [错误] 图标生成失败，请先安装 Pillow：
  echo   "%PY%" -m pip install Pillow
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
