@echo off
setlocal

set PYTHON_EXE=C:\Program Files\Python313\python.exe

powershell -ExecutionPolicy Bypass -File "%~dp0build_pyinstaller_onefile.ps1" -PythonExe "%PYTHON_EXE%"
if errorlevel 1 (
  echo.
  echo Build failed.
  exit /b 1
)

echo.
echo Build finished: dist_pyinstaller\mini_httpserver_pyinstaller.exe
