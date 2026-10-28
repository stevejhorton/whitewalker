# Run-WhiteWalkerTests.ps1
# Test runner for WhiteWalker v3.14.0_RC1.x
# Author: steve.horton@optum.com
# 1-May-26

param(
    [switch]$Detailed,        # Show detailed test output
    [switch]$CodeCoverage,    # Generate code coverage report
    [string]$TestName = "",   # Run specific test by name
    [switch]$CI,              # CI mode (exit with error code on failure)
    [switch]$RC1Only          # Run RC1.x tests only
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "WhiteWalker v3.14.0_RC1.x Test Suite" -ForegroundColor Cyan
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

# Build test file list
if ($RC1Only) {
    $testPaths = @("$PSScriptRoot\WW_Tests_Main.ps1")
    Write-Host "Running RC1.x tests only" -ForegroundColor Yellow
} else {
    $testPaths = @(
        "$PSScriptRoot\WW_Tests_Main.ps1",
        "$PSScriptRoot\WW_Tests_CapPortalRunner.ps1"
    )
}

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

# Code coverage - WW_main.ps1 only for now
# Set-VpnHostsEntry.ps1 needs refactoring to be testable (it's a script, not a library)
if ($CodeCoverage) {
    $config.CodeCoverage.Enabled = $true
    $config.CodeCoverage.Path = @(
        "$PSScriptRoot\WW_main.ps1",
	"$PSScriptRoot\WW_cap_portal_runner.ps1"
    )
    $config.CodeCoverage.OutputPath = "$PSScriptRoot\coverage.xml"
    $config.CodeCoverage.OutputFormat = 'JaCoCo'
    
    Write-Host "Code coverage enabled for:" -ForegroundColor Yellow
    Write-Host "  - WW_main.ps1" -ForegroundColor Yellow
    Write-Host "  - WW_cap_portal_runnner.ps1" -ForegroundColor Yellow
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
        
        # Show per-file breakdown - Pester 5.x structure
        Write-Host ""
        Write-Host "Coverage by file:" -ForegroundColor Cyan
        
        # Try to extract per-file stats from AnalyzedFiles
        if ($coverage.AnalyzedFiles) {
            foreach ($file in $coverage.AnalyzedFiles) {
                if ($file) {
                    try {
                        $fileName = Split-Path $file -Leaf
                        Write-Host "  $fileName" -ForegroundColor White
                    } catch {
                        Write-Host "  (unable to parse file path)" -ForegroundColor Gray
                    }
                }
            }
        } else {
            Write-Host "  (per-file breakdown not available in this Pester version)" -ForegroundColor Gray
        }
        
        Write-Host ""
        Write-Host "  Coverage report: coverage.xml" -ForegroundColor Cyan
    } else {
        Write-Host ""
        Write-Host "Code Coverage: N/A (no analyzable commands)" -ForegroundColor Yellow
        Write-Host "  Coverage report: coverage.xml" -ForegroundColor Cyan
    }
}

Write-Host ""

if ($result -and $result.FailedCount -gt 0) {
    Write-Host "TESTS FAILED!" -ForegroundColor Red
    if ($CI) {
        exit 1
    }
} else {
    Write-Host "ALL TESTS PASSED!" -ForegroundColor Green
    if ($CI) {
        exit 0
    }
}
