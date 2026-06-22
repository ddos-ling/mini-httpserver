@echo off
setlocal

set TOOL=%~1

if "%TOOL%"=="" (
  echo.
  echo ======================================
  echo  Onefile Build Menu
  echo ======================================
  echo  [1] Nuitka
  echo  [2] PyInstaller
  echo.
  choice /c 12 /n /m "Please select build tool (1/2): "
  if errorlevel 2 set TOOL=pyinstaller
  if errorlevel 1 set TOOL=nuitka
)

if /I "%TOOL%"=="n" set TOOL=nuitka
if /I "%TOOL%"=="p" set TOOL=pyinstaller

if /I not "%TOOL%"=="nuitka" if /I not "%TOOL%"=="pyinstaller" (
  echo.
  echo Invalid tool: %TOOL%
  echo Usage: build_onefile.bat [nuitka^|pyinstaller^|n^|p]
  exit /b 1
)

set PYTHON_EXE=C:\Program Files\Python313\python.exe

powershell -ExecutionPolicy Bypass -File "%~dp0build_onefile.ps1" -Tool "%TOOL%" -PythonExe "%PYTHON_EXE%"
if errorlevel 1 (
  echo.
  echo Build failed with tool: %TOOL%
  exit /b 1
)

echo.
echo Build finished with tool: %TOOL%
