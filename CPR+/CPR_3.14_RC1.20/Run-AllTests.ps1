# Run-AllTests.ps1
# Master test runner for WhiteWalker / CPR+ RC1.19
# Wraps all individual test suites into a single run.
# Author: steve.horton@optum.com
# 10-Jun-26
#
# Usage:
#   .\Run-AllTests.ps1                          # Run all suites, normal output
#   .\Run-AllTests.ps1 -Detailed                # Verbose test output
#   .\Run-AllTests.ps1 -CodeCoverage            # Include coverage report
#   .\Run-AllTests.ps1 -Suite WW               # Run WW suite only
#   .\Run-AllTests.ps1 -Suite Haystack         # Run HayStack suite only
#   .\Run-AllTests.ps1 -TestName "Test-DC"     # Filter by test name across all suites
#   .\Run-AllTests.ps1 -CI                     # CI mode - exit 1 on any failure
#   .\Run-AllTests.ps1 -LogFile .\results.log  # Capture output to file

param(
    [switch]$Detailed,
    [switch]$CodeCoverage,
    [string]$TestName   = "",
    [switch]$CI,
    [string]$LogFile    = "",
    [ValidateSet("All","WW","Haystack","CapPortal","TestDC","")]
    [string]$Suite      = "All"
)

# -- Transcript ----------------------------------------------------------------
if ($LogFile) {
    $logDir = Split-Path $LogFile -Parent
    if ($logDir -and -not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    try {
        Start-Transcript -Path $LogFile -Force -ErrorAction Stop
        Write-Host "Output also captured to: $LogFile" -ForegroundColor DarkCyan
        Write-Host ""
    } catch {
        Write-Host "WARNING: Could not start transcript: $_" -ForegroundColor Yellow
        $LogFile = ""
    }
}

# -- Header --------------------------------------------------------------------
Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   WhiteWalker / CPR+ RC1.19 -- Master Test Run" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  Date   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "  Host   : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "  Suite  : $Suite" -ForegroundColor Gray
if ($TestName) {
    Write-Host "  Filter : $TestName" -ForegroundColor Yellow
}
Write-Host ""

# -- Pester check -------------------------------------------------------------
$pesterModule = Get-Module -Name Pester -ListAvailable |
    Where-Object { $_.Version -ge [version]"5.0.0" } |
    Select-Object -First 1

if (-not $pesterModule) {
    Write-Host "ERROR: Pester 5.x not found." -ForegroundColor Red
    Write-Host "Install with: Install-Module -Name Pester -Force -SkipPublisherCheck" -ForegroundColor Yellow
    if ($LogFile) { Stop-Transcript }
    exit 1
}
Write-Host "Pester : $($pesterModule.Version)" -ForegroundColor Green
Write-Host ""

# -- Suite definitions ---------------------------------------------------------
$TestSuites = @(
    @{
        Name         = "WW Main"
        TestFiles    = @("$PSScriptRoot\WW_Tests_Main.ps1")
        CoverageFiles= @("$PSScriptRoot\WW_main.ps1")
        CoverageOut  = "$PSScriptRoot\coverage_ww_main.xml"
        Tag          = "WW"
    }
    @{
        Name         = "Cap Portal Runner"
        TestFiles    = @(
            "$PSScriptRoot\WW_Tests_CapPortalRunner.ps1",
            "$PSScriptRoot\WW_cap_portal_runner.Tests.ps1"
        )
        CoverageFiles= @("$PSScriptRoot\WW_cap_portal_runner.ps1")
        CoverageOut  = "$PSScriptRoot\coverage_cap_portal.xml"
        Tag          = "CapPortal"
    }
    @{
        Name         = "HayStack"
        TestFiles    = @(
            "$PSScriptRoot\WW_Tests_Haystack.ps1",
            "$PSScriptRoot\HaystackStandalone.Tests.ps1"
        )
        CoverageFiles= @(
            "$PSScriptRoot\haystack.ps1",
            "$PSScriptRoot\haystack_action.ps1"
        )
        CoverageOut  = "$PSScriptRoot\coverage_haystack.xml"
        Tag          = "Haystack"
    }
    @{
        Name         = "Test-DC"
        TestFiles    = @("$PSScriptRoot\WW_Tests_TestDC.ps1")
        CoverageFiles= @("$PSScriptRoot\WW_main.ps1")
        CoverageOut  = "$PSScriptRoot\coverage_testdc.xml"
        Tag          = "TestDC"
    }
)

# Filter by -Suite param
if ($Suite -ne "All" -and $Suite -ne "") {
    $TestSuites = $TestSuites | Where-Object { $_.Tag -eq $Suite }
    if (-not $TestSuites) {
        Write-Host "ERROR: No suite found matching '$Suite'" -ForegroundColor Red
        if ($LogFile) { Stop-Transcript }
        exit 1
    }
}

# -- Run each suite ------------------------------------------------------------
$grandTotal   = 0
$grandPassed  = 0
$grandFailed  = 0
$grandSkipped = 0
$suiteResults = @()

foreach ($ts in $TestSuites) {

    # Skip suites with no test files present (graceful - new files may not exist yet)
    $existingFiles = $ts.TestFiles | Where-Object { Test-Path $_ }
    if (-not $existingFiles) {
        Write-Host "  [$($ts.Name)] SKIPPED - no test files found" -ForegroundColor DarkYellow
        Write-Host ""
        continue
    }

    Write-Host "--------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  Suite: $($ts.Name)" -ForegroundColor Cyan
    Write-Host "--------------------------------------------------" -ForegroundColor DarkCyan

    $config = New-PesterConfiguration
    $config.Run.Path     = $existingFiles
    $config.Run.Exit     = $false
    $config.Run.PassThru = $true
    $config.Output.Verbosity = if ($Detailed) { 'Detailed' } else { 'Normal' }

    if ($TestName) {
        $config.Filter.FullName = "*$TestName*"
    }

    if ($CodeCoverage) {
        $existingCov = $ts.CoverageFiles | Where-Object { Test-Path $_ }
        if ($existingCov) {
            $config.CodeCoverage.Enabled      = $true
            $config.CodeCoverage.Path         = $existingCov
            $config.CodeCoverage.OutputPath   = $ts.CoverageOut
            $config.CodeCoverage.OutputFormat = 'JaCoCo'
        }
    }

    $result = Invoke-Pester -Configuration $config

    if ($result) {
        $grandTotal   += $result.TotalCount
        $grandPassed  += $result.PassedCount
        $grandFailed  += $result.FailedCount
        $grandSkipped += $result.SkippedCount

        $status = if ($result.FailedCount -gt 0) { "FAILED" } else { "PASSED" }
        $color  = if ($result.FailedCount -gt 0) { "Red"   } else { "Green"  }

        $suiteResults += [PSCustomObject]@{
            Suite   = $ts.Name
            Total   = $result.TotalCount
            Passed  = $result.PassedCount
            Failed  = $result.FailedCount
            Skipped = $result.SkippedCount
            Status  = $status
        }

        if ($CodeCoverage -and $result.CodeCoverage -and $result.CodeCoverage.CommandsAnalyzedCount -gt 0) {
            $pct = [math]::Round(($result.CodeCoverage.CommandsExecutedCount / $result.CodeCoverage.CommandsAnalyzedCount) * 100, 1)
            $covColor = if ($pct -ge 80) { "Green" } elseif ($pct -ge 60) { "Yellow" } else { "Red" }
            Write-Host "  Coverage: $pct%  -> $($ts.CoverageOut)" -ForegroundColor $covColor
        }
    }
    Write-Host ""
}

# -- Grand Summary -------------------------------------------------------------
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "                   MASTER SUMMARY" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""

# Per-suite table
$suiteResults | ForEach-Object {
    $color = if ($_.Failed -gt 0) { "Red" } else { "Green" }
    $line  = "  {0,-28} T:{1,4}  P:{2,4}  F:{3,4}  S:{4,4}  [{5}]" -f `
        $_.Suite, $_.Total, $_.Passed, $_.Failed, $_.Skipped, $_.Status
    Write-Host $line -ForegroundColor $color
}

Write-Host ""
Write-Host "  -------------------------------------------------" -ForegroundColor DarkGray
$totalColor = if ($grandFailed -gt 0) { "Red" } else { "Green" }
Write-Host ("  TOTAL: {0} tests  |  Passed: {1}  |  Failed: {2}  |  Skipped: {3}" -f `
    $grandTotal, $grandPassed, $grandFailed, $grandSkipped) -ForegroundColor $totalColor
Write-Host ""

if ($grandFailed -gt 0) {
    Write-Host "  *** TESTS FAILED ***" -ForegroundColor Red
} else {
    Write-Host "  *** ALL TESTS PASSED ***" -ForegroundColor Green
}
Write-Host ""

if ($LogFile) { Stop-Transcript }
if ($CI) { exit $(if ($grandFailed -gt 0) { 1 } else { 0 }) }
