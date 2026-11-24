#requires -Version 5.1
<#
.SYNOPSIS
    PowerShell wrapper for WinLongUptimeOptimizer (winopt CLI).
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CliArgs
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ScriptDir

$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $PythonExe = "C:\Python313\python.exe"
}

if (-not (Test-Path -LiteralPath $PythonExe)) {
    Write-Error "Python executable not found: $PythonExe"
    exit 1
}

if (-not $CliArgs -or $CliArgs.Count -eq 0) {
    $CliArgs = @("diagnose")
}

& $PythonExe -m winopt.cli @CliArgs
$exitCode = $LASTEXITCODE

if ($exitCode -eq 0 -and $env:WINOPT_DISABLE_GIT_SYNC -ne "1") {
    $SyncScript = Join-Path $ScriptDir "scripts\git_auto_sync.ps1"
    if (Test-Path -LiteralPath $SyncScript) {
        try {
            & $SyncScript -Quiet
        } catch {
            Write-Warning "Git auto-sync warning: $_"
        }
    }
}

exit $exitCode
