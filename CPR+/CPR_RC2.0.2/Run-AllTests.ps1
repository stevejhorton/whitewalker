# Run-AllTests.ps1 - runs every *.Tests.ps1 (tests\ and the release root) with Pester 5.
# Discovers files automatically; no suite list to maintain.
#   .\Run-AllTests.ps1                      # all tests, summary + failures
#   .\Run-AllTests.ps1 -Detailed            # every test name
#   .\Run-AllTests.ps1 -File ExitReason     # only files whose name contains the text
#   .\Run-AllTests.ps1 -TestName 'exit'     # only tests whose full name matches (wildcard)
#   .\Run-AllTests.ps1 -LogFile .\r.log     # also write the output to a file
#   .\Run-AllTests.ps1 -CI                  # exit code 1 if anything failed
# Known: a few Windows-only runner tests and the WebHelper-301 group may fail; see support_files\dev_linux_test\README.md.
param(
    [switch]$Detailed,
    [string]$File = '',
    [string]$TestName = '',
    [string]$LogFile = '',
    [switch]$CI
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$pester = Get-Module -Name Pester -ListAvailable | Where-Object { $_.Version -ge [version]'5.0.0' } | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester) { Write-Host 'Pester 5+ not found. Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -Force -SkipPublisherCheck' -ForegroundColor Red; exit 2 }
Import-Module $pester.Path -Force

$files = @(Get-ChildItem -Path (Join-Path $root 'tests'), $root -Filter '*.Tests.ps1' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*$File*" } | Sort-Object FullName -Unique)
if (-not $files) { Write-Host "No test files match '$File'." -ForegroundColor Yellow; exit 2 }
if ($LogFile) { Start-Transcript -Path $LogFile -Force | Out-Null }
Write-Host ("Pester {0}  host {1}  files {2}" -f $pester.Version, $env:COMPUTERNAME, $files.Count) -ForegroundColor Cyan

$cfg = New-PesterConfiguration
$cfg.Run.Path = @($files.FullName)
$cfg.Run.PassThru = $true
$cfg.Output.Verbosity = $(if ($Detailed) { 'Detailed' } else { 'Normal' })
if ($TestName) { $cfg.Filter.FullName = "*$TestName*" }
$r = Invoke-Pester -Configuration $cfg

Write-Host ''
Write-Host ("TOTAL  passed={0}  failed={1}  skipped={2}  not-run={3}" -f $r.PassedCount, $r.FailedCount, $r.SkippedCount, $r.NotRunCount) -ForegroundColor $(if ($r.FailedCount -or $r.FailedContainersCount) { 'Yellow' } else { 'Green' })
if ($r.FailedContainersCount) { Write-Host ("{0} test file(s) failed to load - scroll up for the parse/discovery error." -f $r.FailedContainersCount) -ForegroundColor Red }
if ($LogFile) { Stop-Transcript | Out-Null }
if ($CI -and ($r.FailedCount -or $r.FailedContainersCount)) { exit 1 }
