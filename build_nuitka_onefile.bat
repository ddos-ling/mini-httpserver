@echo off
setlocal

set PYTHON_EXE=C:\Program Files\Python313\python.exe

powershell -ExecutionPolicy Bypass -File "%~dp0build_nuitka_onefile.ps1" -PythonExe "%PYTHON_EXE%"
if errorlevel 1 (
  echo.
  echo Build failed.
  exit /b 1
)

echo.
echo Build finished: dist_nuitka\mini_httpserver_nuitka.exe
