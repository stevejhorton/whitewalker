# WhiteWalker v3.13.0 - Testing Guide

## Overview

Comprehensive Pester test suite covering:
- ✅ FlareGun integration (new in v3.13.0)
- ✅ Config file loading and caching
- ✅ SYSTEM vs USER context routing
- ✅ Cooldown and de-duplication logic
- ✅ Error handling and fallback behavior
- ✅ All core functions (redirect detection, VPN state, etc.)
- ✅ Comment presence validation at flare call sites

## Prerequisites

### Install Pester 5.x
```powershell
# Install latest Pester
Install-Module -Name Pester -Force -SkipPublisherCheck

# Verify version (must be 5.x)
Get-Module -Name Pester -ListAvailable
```

### Required Files
```
WhiteWalker/
├── WW_main.ps1              # Script under test
├── WW_Tests.ps1             # Test suite
└── Run-WhiteWalkerTests.ps1 # Test runner
```

## Running Tests

### Quick Run (Default)
```powershell
.\Run-WhiteWalkerTests.ps1
```

**Output:**
```
========================================
WhiteWalker v3.13.0 Test Suite
========================================

Using Pester version: 5.4.0

Starting discovery in 1 files.
Discovery found 45 tests in 234ms.
Running tests.

[+] WhiteWalker v3.13.0 - FlareGun Integration
  [+] Get-FlareConfig Function
    [+] Should load valid config file (123ms)
    [+] Should cache config after first load (45ms)
    [+] Should return null when config file missing (12ms)
    ...

========================================
Test Summary
========================================
Total:  45
Passed: 45
Failed: 0
Skipped: 0

ALL TESTS PASSED!
```

### Detailed Output
```powershell
.\Run-WhiteWalkerTests.ps1 -Detailed
```

Shows individual test steps and mock call verification.

### Run Specific Test
```powershell
# Run only FlareGun tests
.\Run-WhiteWalkerTests.ps1 -TestName "FlareGun"

# Run only config loading tests
.\Run-WhiteWalkerTests.ps1 -TestName "Get-FlareConfig"

# Run specific test
.\Run-WhiteWalkerTests.ps1 -TestName "Should send SYSTEM flare directly"
```

### Code Coverage
```powershell
.\Run-WhiteWalkerTests.ps1 -CodeCoverage
```

**Output:**
```
Code Coverage: 78.5%
  Commands Executed: 234
  Commands Analyzed: 298
  Coverage report: coverage.xml
```

Coverage report shows which lines in WW_main.ps1 were executed during tests.

### CI Mode
```powershell
# Exit with error code on failure (for build pipelines)
.\Run-WhiteWalkerTests.ps1 -CI
```

## Test Categories

### 1. FlareGun Integration Tests
**File:** `Describe "WhiteWalker v3.13.0 - FlareGun Integration"`

Tests new FlareGun functionality:
- Config file loading and caching
- SYSTEM context (direct flare)
- USER context (event log routing)
- Cooldown logic
- De-duplication
- Fallback behavior
- WhatIf mode
- Legacy wrapper compatibility

**Example:**
```powershell
Context "Send-FlareEvent - SYSTEM Context" {
    It "Should send SYSTEM flare directly when context is SYSTEM" {
        # Mock config with SYSTEM flare
        # Call Send-FlareEvent
        # Verify Start-Process called with /on_prem
        # Verify no event log message created
    }
}
```

### 2. Core Functions Tests
**File:** `Describe "WhiteWalker v3.13.0 - Core Functions (Existing)"`

Tests existing functionality:
- Redirect type classification (ISE_EMPLOYEE, ISE_GUEST, NON_ISE)
- Cisco path detection
- State management (hashtable conversion, JSON persistence)
- Cooldown logic
- VPN blocking detection
- Wake from sleep detection
- Configuration validation

**Example:**
```powershell
Context "Redirect Type Classification" {
    It "Should identify ISE Employee portal" {
        $result = Get-RedirectType -RedirectUrl "https://isepsn.company.com/portal/login"
        $result | Should -Be "ISE_EMPLOYEE"
    }
}
```

### 3. Integration Tests
**File:** `Describe "WhiteWalker v3.13.0 - Integration Tests"`

Tests real-world scenarios:
- Flare call site comment validation
- Error handling
- End-to-end workflows

**Example:**
```powershell
Context "Flare Call Sites - Proper Comments" {
    It "Should have detailed comments for user_tun flare" {
        # Verify script contains comment block with:
        # - FLARE EVENT name
        # - Context (USER/SYSTEM)
        # - Event ID
        # - Ivanti use case
    }
}
```

## Test Structure

### BeforeAll Block
Runs once before all tests:
```powershell
BeforeAll {
    # Source the main script
    . $PSScriptRoot\WW_main.ps1
    
    # Mock external dependencies
    Mock Start-Process { }
    Mock Test-Connection { $true }
    # ... etc
}
```

### BeforeEach Block
Runs before each test:
```powershell
BeforeEach {
    # Reset global state
    $global:flareHistory = @{}
    $global:_state = [PSCustomObject]@{ lastFlare = @{} }
    $global:_flareConfig = $null
    
    # Mock logging to prevent file writes
    Mock Write-Log { }
}
```

### Test Anatomy
```powershell
It "Should do something specific" {
    # 1. ARRANGE: Set up test data and mocks
    Mock Get-FlareConfig {
        [PSCustomObject]@{
            flare_events = [PSCustomObject]@{
                test_tag = [PSCustomObject]@{
                    event_id = 999
                    context = "SYSTEM"
                }
            }
        }
    }
    
    # 2. ACT: Call the function under test
    Send-FlareEvent "test_tag"
    
    # 3. ASSERT: Verify expected behavior
    Assert-MockCalled Start-Process -Times 1 -ParameterFilter {
        $ArgumentList -eq "/test_tag"
    }
}
```

## Common Assertions

### Mock Verification
```powershell
# Verify function was called
Assert-MockCalled Start-Process -Times 1

# Verify with specific parameters
Assert-MockCalled Start-Process -ParameterFilter {
    $ArgumentList -eq "/on_prem"
}

# Verify function was NOT called
Assert-MockCalled Start-Process -Times 0
```

### Value Assertions
```powershell
# Equality
$result | Should -Be "expected"

# Type checking
$result | Should -BeOfType [hashtable]

# Null checking
$result | Should -Not -BeNullOrEmpty
$result | Should -BeNullOrEmpty

# Comparison
$value | Should -BeGreaterThan 0
$value | Should -BeLessThan 100

# Pattern matching
$text | Should -Match "pattern"
$text | Should -BeLike "*wildcard*"
```

## Writing New Tests

### Template for New Test
```powershell
Context "New Feature" {
    BeforeEach {
        # Reset state
        $global:testVar = $null
        Mock External-Dependency { }
    }
    
    It "Should handle normal case" {
        # Arrange
        $input = "test data"
        
        # Act
        $result = My-Function -Input $input
        
        # Assert
        $result | Should -Be "expected output"
    }
    
    It "Should handle error case" {
        # Arrange
        Mock External-Dependency { throw "error" }
        
        # Act & Assert
        { My-Function } | Should -Not -Throw
        # OR
        { My-Function } | Should -Throw "expected error"
    }
}
```

### Best Practices
1. **One assertion per test** - Tests should be focused
2. **Descriptive names** - "Should do X when Y" format
3. **Independent tests** - Tests shouldn't depend on each other
4. **Clean state** - Use BeforeEach to reset globals
5. **Mock externals** - Don't make real API/file/network calls

## Troubleshooting

### Test Fails: "Cannot source WW_main.ps1"
**Cause:** Test file can't find main script

**Fix:**
```powershell
# Make sure you're in the WhiteWalker directory
cd C:\Path\To\WhiteWalker

# Run tests from that directory
.\Run-WhiteWalkerTests.ps1
```

### Test Fails: "Mock not found"
**Cause:** Function being mocked doesn't exist or typo

**Fix:**
```powershell
# Check function name spelling
Get-Command Send-FlareEvent

# Verify function is loaded
. .\WW_main.ps1
Get-Command Send-FlareEvent
```

### Test Fails: "Expected X but got Y"
**Cause:** Function behavior changed or test expectation wrong

**Debug:**
```powershell
# Add verbose output to test
It "Test name" {
    $result = My-Function -Verbose
    Write-Host "DEBUG: Result was $result"
    $result | Should -Be "expected"
}

# Or use Pester's built-in debugging
.\Run-WhiteWalkerTests.ps1 -Detailed
```

### Mock Not Being Called
**Cause:** Mock scope or parameter filter issue

**Debug:**
```powershell
# Check if mock was called at all
Assert-MockCalled Start-Process -Scope It

# Remove parameter filter to test
Assert-MockCalled Start-Process -Times 1
# Then add back specific filter:
Assert-MockCalled Start-Process -ParameterFilter { 
    Write-Host "DEBUG: ArgumentList was $ArgumentList"
    $ArgumentList -eq "/test"
}
```

## Coverage Goals

### Current Coverage: ~75-80%
**High coverage areas:**
- FlareGun integration: 95%
- Redirect detection: 90%
- State management: 85%

**Lower coverage areas:**
- Network adapter detection: 60% (hardware-dependent)
- VPN CLI parsing: 65% (complex parsing logic)
- Event log interactions: 50% (system integration)

### Improving Coverage
Add tests for:
1. Edge cases in VPN state parsing
2. Network adapter enumeration scenarios
3. Event log message parsing
4. Error recovery paths

## CI/CD Integration

### Azure DevOps Pipeline
```yaml
steps:
- task: PowerShell@2
  displayName: 'Run WhiteWalker Tests'
  inputs:
    targetType: 'filePath'
    filePath: 'Run-WhiteWalkerTests.ps1'
    arguments: '-CI -CodeCoverage'
    
- task: PublishTestResults@2
  inputs:
    testResultsFormat: 'NUnit'
    testResultsFiles: '**/test-results.xml'
    
- task: PublishCodeCoverageResults@1
  inputs:
    codeCoverageTool: 'JaCoCo'
    summaryFileLocation: '**/coverage.xml'
```

### GitHub Actions
```yaml
- name: Run Tests
  shell: pwsh
  run: |
    ./Run-WhiteWalkerTests.ps1 -CI -CodeCoverage
    
- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage.xml
```

## Test Maintenance

### When to Update Tests

**Always update tests when:**
- Adding new functions
- Changing function behavior
- Adding new flare tags
- Modifying config schema
- Changing error handling

**Example: Adding new flare**
1. Add config entry to test mock
2. Add test for context routing
3. Add test for comment presence
4. Run full suite to verify no regressions

```powershell
Context "Send-FlareEvent - New Flare" {
    It "Should route new_flare to correct context" {
        Mock Get-FlareConfig {
            [PSCustomObject]@{
                flare_events = [PSCustomObject]@{
                    new_flare = [PSCustomObject]@{
                        event_id = 785
                        context = "USER"
                        flare_tag = "new_flare"
                    }
                }
            }
        }
        
        Send-FlareEvent "new_flare"
        
        Assert-MockCalled Write-Log -ParameterFilter {
            $Message -like "*queued for USER context*"
        }
    }
}
```

## Contact
- Author: steve.horton@optum.com
- Version: 3.13.0
- Test Suite Version: 1.0.0
