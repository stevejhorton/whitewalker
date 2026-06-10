# Run-WhiteWalkerTests.ps1
# Test runner for WhiteWalker v3.13.0
# Author: steve.horton@optum.com

param(
    [switch]$Detailed,        # Show detailed test output
    [switch]$CodeCoverage,    # Generate code coverage report
    [string]$TestName = "",   # Run specific test by name
    [switch]$CI               # CI mode (exit with error code on failure)
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "WhiteWalker v3.13.0 Test Suite" -ForegroundColor Cyan
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
    exit 1
}

Write-Host "Using Pester version: $($pesterModule.Version)" -ForegroundColor Green
Write-Host ""

# Build Pester configuration
$config = New-PesterConfiguration

# Test discovery
$config.Run.Path = "$PSScriptRoot\WW_Tests.ps1"
$config.Run.Exit = $CI.IsPresent  # Convert SwitchParameter to bool

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
    $config.CodeCoverage.Path = "$PSScriptRoot\WW_main.ps1"
    $config.CodeCoverage.OutputPath = "$PSScriptRoot\coverage.xml"
    $config.CodeCoverage.OutputFormat = 'JaCoCo'
    
    Write-Host "Code coverage enabled - will analyze WW_main.ps1" -ForegroundColor Yellow
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

if ($CodeCoverage) {
    $coverage = $result.CodeCoverage
    $coveragePercent = [math]::Round(($coverage.CommandsExecutedCount / $coverage.CommandsAnalyzedCount) * 100, 2)
    
    Write-Host ""
    Write-Host "Code Coverage: $coveragePercent%" -ForegroundColor $(
        if ($coveragePercent -ge 80) { "Green" }
        elseif ($coveragePercent -ge 60) { "Yellow" }
        else { "Red" }
    )
    Write-Host "  Commands Executed: $($coverage.CommandsExecutedCount)" -ForegroundColor White
    Write-Host "  Commands Analyzed: $($coverage.CommandsAnalyzedCount)" -ForegroundColor White
    Write-Host "  Coverage report: coverage.xml" -ForegroundColor Cyan
}

Write-Host ""

if ($result.FailedCount -gt 0) {
    Write-Host "TESTS FAILED!" -ForegroundColor Red
    if (-not $CI) {
        exit 1
    }
} else {
    Write-Host "ALL TESTS PASSED!" -ForegroundColor Green
    if (-not $CI) {
        exit 0
    }
}
