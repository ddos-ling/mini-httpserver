param(
    [string]$PythonExe = "C:/Program Files/Python313/python.exe"
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Write-TextFileExact {
    param(
        [string]$Path,
        [string]$Content
    )

    # 按原字符串精确写回，避免 Set-Content 自动补终止换行。
    [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
}

function Update-BuildMetadata {
    param(
        [string]$TargetFile,
        [string]$ToolName
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $content = Get-Content -Path $TargetFile -Raw -Encoding UTF8
    $content = [regex]::Replace($content, '^(BUILD_TIMESTAMP\s*=\s*).*$', ('$1"' + $timestamp + '"'), [System.Text.RegularExpressions.RegexOptions]::Multiline)
    $content = [regex]::Replace($content, '^(BUILDBY\s*=\s*).*$', ('$1"' + $ToolName + '"'), [System.Text.RegularExpressions.RegexOptions]::Multiline)
    Write-TextFileExact -Path $TargetFile -Content $content

    Write-Host "Build metadata updated: BUILDBY=$ToolName, BUILD_TIMESTAMP=$timestamp" -ForegroundColor Cyan
}

function Restore-OriginalContent {
    param(
        [string]$TargetFile,
        [string]$OriginalContent
    )

    Write-TextFileExact -Path $TargetFile -Content $OriginalContent
    Write-Host "Source metadata restored: $TargetFile" -ForegroundColor DarkGray
}

$EntryFile = Join-Path $ProjectRoot "mini_httpserver.py"
$OriginalContent = Get-Content -Path $EntryFile -Raw -Encoding UTF8

try {
    Update-BuildMetadata -TargetFile $EntryFile -ToolName "PyInstaller"

    if (Test-Path "dist_pyinstaller") {
        Remove-Item -Recurse -Force "dist_pyinstaller"
    }
    if (Test-Path "build_pyinstaller") {
        Remove-Item -Recurse -Force "build_pyinstaller"
    }

    & $PythonExe -m PyInstaller `
        --noconfirm `
        --clean `
        --onefile `
        --name mini_httpserver_pyinstaller `
        --distpath dist_pyinstaller `
        --workpath build_pyinstaller `
        --specpath build_pyinstaller `
        mini_httpserver.py

    Write-Host "\nBuild complete. Output: dist_pyinstaller/mini_httpserver_pyinstaller.exe" -ForegroundColor Green
}
finally {
    Restore-OriginalContent -TargetFile $EntryFile -OriginalContent $OriginalContent
}
