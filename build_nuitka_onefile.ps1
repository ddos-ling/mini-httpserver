param(
    [string]$PythonExe = "C:/Program Files/Python313/python.exe"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

function Update-BuildMetadata {
    param(
        [string]$TargetFile,
        [string]$ToolName
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $content = Get-Content -Path $TargetFile -Raw -Encoding UTF8
    $content = [regex]::Replace($content, '^(BUILD_TIMESTAMP\s*=\s*).*$', ('$1"' + $timestamp + '"'), [System.Text.RegularExpressions.RegexOptions]::Multiline)
    $content = [regex]::Replace($content, '^(BUILDBY\s*=\s*).*$', ('$1"' + $ToolName + '"'), [System.Text.RegularExpressions.RegexOptions]::Multiline)
    Set-Content -Path $TargetFile -Value $content -Encoding UTF8

    Write-Host "Build metadata updated: BUILDBY=$ToolName, BUILD_TIMESTAMP=$timestamp" -ForegroundColor Cyan
}

function Restore-OriginalContent {
    param(
        [string]$TargetFile,
        [string]$OriginalContent
    )

    Set-Content -Path $TargetFile -Value $OriginalContent -Encoding UTF8
    Write-Host "Source metadata restored: $TargetFile" -ForegroundColor DarkGray
}

$EntryFile = Join-Path $ProjectRoot "mini_httpserver.py"
$OriginalContent = Get-Content -Path $EntryFile -Raw -Encoding UTF8

try {
    Update-BuildMetadata -TargetFile $EntryFile -ToolName "Nuitka"

    # Nuitka onefile build for mini_httpserver.py
    # --lto and zstandard usually improve runtime/startup characteristics for onefile output.
    & $PythonExe -m nuitka `
        --onefile `
        --assume-yes-for-downloads `
        --output-dir=dist_nuitka `
        --output-filename=mini_httpserver_nuitka.exe `
        --remove-output `
        --lto=yes `
        --show-progress `
        --enable-plugin=anti-bloat `
        mini_httpserver.py

    Write-Host "\nBuild complete. Output: dist_nuitka/mini_httpserver_nuitka.exe" -ForegroundColor Green
}
finally {
    Restore-OriginalContent -TargetFile $EntryFile -OriginalContent $OriginalContent
}
