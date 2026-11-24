#requires -Version 5.1
<#
.SYNOPSIS
    Auto-commit and push non-ignored code, config, test, and documentation changes for winopt.
#>
[CmdletBinding()]
param(
    [string]$RepoPath = "",
    [string]$CommitMessage = "",
    [switch]$DryRun,
    [switch]$Quiet
)

$ErrorActionPreference = "Continue"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not $RepoPath) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $RepoPath = Split-Path -Parent $ScriptDir
}
$RepoPath = (Resolve-Path -LiteralPath $RepoPath).Path

function Write-SyncLog {
    param([string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssK")
    $line = "[$ts] $Message"
    $dataDir = Join-Path $RepoPath "data"
    if (-not (Test-Path -LiteralPath $dataDir)) {
        New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    }
    $logFile = Join-Path $dataDir "git_auto_sync.log"
    [System.IO.File]::AppendAllText($logFile, $line + "`n", (New-Object System.Text.UTF8Encoding($false)))
    if (-not $Quiet) {
        Write-Output $line
    }
}

# Prepend Visual Studio Git / Git for Windows and GitHub CLI directories if present
$ExtraPaths = @(
    "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\cmd",
    "C:\Program Files\Git\cmd",
    "C:\Program Files\GitHub CLI",
    (Join-Path $env:LOCALAPPDATA "Programs\GitHub CLI")
)
$CurrentParts = @($env:PATH -split ";")
$PrefixParts = @()
foreach ($p in $ExtraPaths) {
    if ((Test-Path -LiteralPath $p) -and ($CurrentParts -notcontains $p)) {
        $PrefixParts += $p
    }
}
if ($PrefixParts.Count -gt 0) {
    $env:PATH = ($PrefixParts -join ";") + ";" + $env:PATH
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-SyncLog "SKIP: git executable not found in PATH."
    exit 0
}

$GitDir = Join-Path $RepoPath ".git"
if (-not (Test-Path -LiteralPath $GitDir)) {
    Write-SyncLog "SKIP: .git directory not initialized at $RepoPath."
    exit 0
}

foreach ($lockRel in @("index.lock", "MERGE_HEAD", "rebase-merge", "rebase-apply")) {
    if (Test-Path -LiteralPath (Join-Path $GitDir $lockRel)) {
        Write-SyncLog "SKIP: active git lock or operation detected ($lockRel)."
        exit 0
    }
}

$StatusLines = @(& git -C $RepoPath status --porcelain 2>&1)
if ($LASTEXITCODE -ne 0) {
    $errText = ($StatusLines | Out-String).Trim()
    Write-SyncLog "ERROR: git status failed: $errText"
    exit 1
}
$ChangedLines = @($StatusLines | Where-Object { $_ -and $_.ToString().Trim().Length -gt 0 })
if ($ChangedLines.Count -eq 0) {
    Write-SyncLog "NOOP: working tree clean, nothing to sync."
    exit 0
}

if ($DryRun) {
    Write-SyncLog ("DRY-RUN: detected {0} pending change(s): {1}" -f $ChangedLines.Count, ($ChangedLines -join "; "))
    exit 0
}

$AddOut = @(& git -C $RepoPath add -A 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-SyncLog ("ERROR: git add failed: {0}" -f (($AddOut | Out-String).Trim()))
    exit 1
}

$StagedFiles = @(& git -C $RepoPath diff --cached --name-only 2>&1 | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
if ($StagedFiles.Count -eq 0) {
    Write-SyncLog "NOOP: nothing staged after git add -A."
    exit 0
}

# Privacy safety guard: never allow runtime data/ or reports/ artifacts to be committed
$Blocked = @($StagedFiles | Where-Object { $_ -match '^(data|reports)/' })
if ($Blocked.Count -gt 0) {
    & git -C $RepoPath reset -q 2>&1 | Out-Null
    Write-SyncLog ("ABORT: blocked staged sensitive/runtime paths: {0}" -f ($Blocked -join ", "))
    exit 1
}

if (-not $CommitMessage) {
    $PreviewList = @($StagedFiles | Select-Object -First 4) -join ", "
    if ($StagedFiles.Count -gt 4) {
        $PreviewList += ", ..."
    }
    if ($PreviewList.Length -gt 72) {
        $PreviewList = $PreviewList.Substring(0, 69) + "..."
    }
    $CommitMessage = "chore(auto-sync): update $($StagedFiles.Count) file(s) ($PreviewList)"
}

$CommitOut = @(& git -C $RepoPath commit -m $CommitMessage 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-SyncLog ("ERROR: git commit failed: {0}" -f (($CommitOut | Out-String).Trim()))
    exit 1
}

$PushOut = @(& git -C $RepoPath push origin HEAD:main 2>&1)
if ($LASTEXITCODE -ne 0) {
    $RebaseOut = @(& git -C $RepoPath pull --rebase --autostash origin main 2>&1)
    if ($LASTEXITCODE -ne 0) {
        Write-SyncLog ("ERROR: git push and pull --rebase failed: {0} | {1}" -f (($PushOut | Out-String).Trim()), (($RebaseOut | Out-String).Trim()))
        exit 1
    }
    $RetryOut = @(& git -C $RepoPath push origin HEAD:main 2>&1)
    if ($LASTEXITCODE -ne 0) {
        Write-SyncLog ("ERROR: git push retry failed: {0}" -f (($RetryOut | Out-String).Trim()))
        exit 1
    }
}

$HeadSha = (& git -C $RepoPath rev-parse --short HEAD 2>$null).ToString().Trim()
Write-SyncLog ("PUSHED: {0} ({1} file(s): {2})" -f $HeadSha, $StagedFiles.Count, ($StagedFiles -join ", "))
exit 0
