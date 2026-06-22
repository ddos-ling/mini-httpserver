param(
    [string]$Tool = "nuitka",
    [string]$PythonExe = "C:/Program Files/Python313/python.exe"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$normalizedTool = $Tool.ToLowerInvariant()
if ($normalizedTool -eq "n") { $normalizedTool = "nuitka" }
if ($normalizedTool -eq "p") { $normalizedTool = "pyinstaller" }

if ($normalizedTool -notin @("nuitka", "pyinstaller")) {
    throw "Invalid -Tool value '$Tool'. Allowed values: nuitka, pyinstaller, n, p"
}

switch ($normalizedTool) {
    "nuitka" {
        & (Join-Path $ProjectRoot "build_nuitka_onefile.ps1") -PythonExe $PythonExe
    }
    "pyinstaller" {
        & (Join-Path $ProjectRoot "build_pyinstaller_onefile.ps1") -PythonExe $PythonExe
    }
}
