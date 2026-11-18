# Run-HaystackTests.ps1
# Test runner for HayStack v1.0.0
# Author: steve.horton@optum.com
# 14-May-26

param(
    [switch]$Detailed,        # Show detailed test output
    [switch]$CodeCoverage,    # Generate code coverage report
    [string]$TestName = "",   # Run specific test by name
    [switch]$CI,              # CI mode (exit with error code on failure)
    [string]$LogFile = ""     # Capture all output to this file (in addition to console)
)

# ---- Output capture setup ----
# If -LogFile specified, tee all output there. We do this by redirecting the
# entire script body through Start-Transcript so color codes don't pollute the file.
if ($LogFile) {
    $logDir = Split-Path $LogFile -Parent
    if ($logDir -and -not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    try {
        Start-Transcript -Path $LogFile -Force -ErrorAction Stop
        Write-Host "Output also being captured to: $LogFile" -ForegroundColor DarkCyan
        Write-Host ""
    } catch {
        Write-Host "WARNING: Could not start transcript to '$LogFile': $_" -ForegroundColor Yellow
        $LogFile = ""  # fall through without transcript
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "HayStack v1.0.0 Test Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for Pester
$pesterModule = Get-Module -Name Pester -ListAvailable |
    Where-Object { $_.Version -ge [version]"5.0.0" } |
    Select-Object -First 1

if (-not $pesterModule) {
    Write-Host "ERROR: Pester 5.x not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Install Pester with:" -ForegroundColor Yellow
    Write-Host "  Install-Module -Name Pester -Force -SkipPublisherCheck" -ForegroundColor Yellow
    Write-Host ""
    if ($LogFile) { Stop-Transcript }
    exit 1
}

Write-Host "Using Pester version: $($pesterModule.Version)" -ForegroundColor Green
Write-Host ""

$testPaths = @("$PSScriptRoot\WW_Tests_Haystack.ps1")

# Build Pester configuration
$config = New-PesterConfiguration

# Test discovery
$config.Run.Path = $testPaths
$config.Run.Exit = $false
$config.Run.PassThru = $true

# Output settings
if ($Detailed) {
    $config.Output.Verbosity = 'Detailed'
} else {
    $config.Output.Verbosity = 'Normal'
}

# Filter by test name if specified
if ($TestName) {
    $config.Filter.FullName = "*$TestName*"
    Write-Host "Running tests matching: $TestName" -ForegroundColor Yellow
    Write-Host ""
}

# Code coverage
if ($CodeCoverage) {
    $config.CodeCoverage.Enabled = $true
    $config.CodeCoverage.Path = @(
        "$PSScriptRoot\haystack.ps1",
        "$PSScriptRoot\haystack_action.ps1"
    )
    $config.CodeCoverage.OutputPath = "$PSScriptRoot\haystack_coverage.xml"
    $config.CodeCoverage.OutputFormat = 'JaCoCo'

    Write-Host "Code coverage enabled for:" -ForegroundColor Yellow
    Write-Host "  - haystack.ps1" -ForegroundColor Yellow
    Write-Host "  - haystack_action.ps1" -ForegroundColor Yellow
    Write-Host ""
}

# Run tests
$result = Invoke-Pester -Configuration $config

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($result) {
    Write-Host "Total:   $($result.TotalCount)" -ForegroundColor White
    Write-Host "Passed:  $($result.PassedCount)" -ForegroundColor Green
    Write-Host "Failed:  $($result.FailedCount)" -ForegroundColor $(if ($result.FailedCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Skipped: $($result.SkippedCount)" -ForegroundColor Yellow
} else {
    Write-Host "ERROR: No test results returned" -ForegroundColor Red
}

if ($CodeCoverage -and $result -and $result.CodeCoverage) {
    $coverage = $result.CodeCoverage

    if ($coverage.CommandsAnalyzedCount -gt 0) {
        $coveragePercent = [math]::Round(($coverage.CommandsExecutedCount / $coverage.CommandsAnalyzedCount) * 100, 2)

        Write-Host ""
        Write-Host "Code Coverage: $coveragePercent%" -ForegroundColor $(
            if ($coveragePercent -ge 80) { "Green" }
            elseif ($coveragePercent -ge 60) { "Yellow" }
            else { "Red" }
        )
        Write-Host "  Commands Executed: $($coverage.CommandsExecutedCount)" -ForegroundColor White
        Write-Host "  Commands Analyzed: $($coverage.CommandsAnalyzedCount)" -ForegroundColor White
        Write-Host ""
        Write-Host "  Coverage report: haystack_coverage.xml" -ForegroundColor Cyan
    } else {
        Write-Host ""
        Write-Host "Code Coverage: N/A (no analyzable commands)" -ForegroundColor Yellow
    }
}

Write-Host ""

if ($result -and $result.FailedCount -gt 0) {
    Write-Host "TESTS FAILED!" -ForegroundColor Red
    if ($LogFile) { Stop-Transcript }
    if ($CI) { exit 1 }
} else {
    Write-Host "ALL TESTS PASSED!" -ForegroundColor Green
    if ($LogFile) { Stop-Transcript }
    if ($CI) { exit 0 }
}
