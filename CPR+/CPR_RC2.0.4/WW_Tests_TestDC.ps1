# WW_Tests_TestDC.ps1
# Pester tests for Test-DC suffix classification logic
# Author: steve.horton@optum.com
# Updated: 10-Jun-2026 - RC1.19 compat: [OK]/[!!] markers, DiagnosticMode, Resolve-DnsName mock

BeforeAll {
    $script:mainPath = Join-Path $PSScriptRoot 'WW_main.ps1'
    $null = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $script:mainPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw "Failed to parse WW_main.ps1"
    }

    $script:testDcDefinition = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Test-DC'
    }, $true).Extent.Text -replace '^function\s+Test-DC', 'function script:Test-DC'

    function Initialize-TestDcHarness {
        foreach ($fn in @('Test-DC','Write-Log','Get-DnsClientGlobalSetting',
                          'Test-Connection','Resolve-DnsName','Add-LogLine')) {
            if (Test-Path "Function:\$fn") { Remove-Item "Function:\$fn" -Force }
        }

        $script:LogEntries = @()

        function script:Write-Log {
            param([string]$Message, [string]$Level = 'INFO')
            $script:LogEntries += [pscustomobject]@{ Message = $Message; Level = $Level }
        }
        function script:Add-LogLine { param([string]$Line = "") }

        # Default stubs - overridden per test as needed
        function script:Get-DnsClientGlobalSetting {
            throw 'Stubbed - override in each test'
        }
        function script:Test-Connection {
            param([string]$ComputerName, [int]$Count, [switch]$Quiet, $ErrorAction)
            return $true
        }
        function script:Resolve-DnsName {
            param([string]$Name, [string]$Type, $ErrorAction)
            return @([pscustomobject]@{ IPAddress = '10.1.1.1' })
        }

        # Set diagnostic mode so log messages fire
        $script:TestDC_DiagnosticMode = $true
        Set-Variable -Name TestDC_DiagnosticMode -Value $true -Scope Script

        Invoke-Expression $script:testDcDefinition
    }
}

Describe "Test-DC diagnostic suffix classification" {

    BeforeEach {
        Initialize-TestDcHarness
        # Expose DiagnosticMode to the invoked function scope
        $global:TestDC_DiagnosticMode = $true
    }

    AfterEach {
        foreach ($fn in @('Test-DC','Write-Log','Get-DnsClientGlobalSetting',
                          'Test-Connection','Resolve-DnsName','Add-LogLine')) {
            if (Test-Path "Function:\$fn") { Remove-Item "Function:\$fn" -Force }
        }
        Remove-Variable -Name TestDC_DiagnosticMode -Scope Global -ErrorAction SilentlyContinue
    }

    It "returns true when DC is reachable and only corporate suffixes are present" {
        function script:Get-DnsClientGlobalSetting {
            [pscustomobject]@{ SuffixSearchList = @('ms.ds.uhc.com', 'foo.uhc.com') }
        }
        function script:Resolve-DnsName {
            param([string]$Name, [string]$Type, $ErrorAction)
            return @([pscustomobject]@{ IPAddress = '10.1.1.1' })
        }

        $result = Test-DC -hostname 'ms.ds.uhc.com'

        $result | Should -Be $true
        ($script:LogEntries.Message -join "`n") | Should -Match 'DNS SUFFIX DIAGNOSTIC REPORT'
        ($script:LogEntries.Message -join "`n") | Should -Match "\[OK\] CORPORATE: 'foo\.uhc\.com' matches pattern 'uhc\.com'"
        ($script:LogEntries.Message -join "`n") | Should -Match 'RETURNING: TRUE \(on-prem confirmed\)'
    }

    It "returns false when any non-corporate suffix is present alongside corporate suffixes" {
        function script:Get-DnsClientGlobalSetting {
            [pscustomobject]@{ SuffixSearchList = @('ms.ds.uhc.com', 'home', 'comcast.net') }
        }

        $result = Test-DC -hostname 'ms.ds.uhc.com'

        $result | Should -Be $false
        ($script:LogEntries.Message -join "`n") | Should -Match "\[!!\] NON-CORPORATE: 'home'"
        ($script:LogEntries.Message -join "`n") | Should -Match 'Non-corporate suffixes found: 2'
        ($script:LogEntries.Message -join "`n") | Should -Match 'RETURNING: FALSE \(non-corporate suffixes \+ corporate\)'
    }

    It "returns false when DC is reachable but no DNS suffixes can be collected" {
        function script:Get-DnsClientGlobalSetting {
            [pscustomobject]@{ SuffixSearchList = @() }
        }

        $result = Test-DC -hostname 'ms.ds.uhc.com'

        $result | Should -Be $false
        ($script:LogEntries.Message -join "`n") | Should -Match 'Total Suffixes Found: 0'
        ($script:LogEntries.Message -join "`n") | Should -Match 'RETURNING: FALSE \(off-prem assumed\)'
    }

    It "returns false when DC ping fails" {
        function script:Test-Connection {
            param([string]$ComputerName, [int]$Count, [switch]$Quiet, $ErrorAction)
            return $false
        }
        function script:Get-DnsClientGlobalSetting {
            [pscustomobject]@{ SuffixSearchList = @('ms.ds.uhc.com') }
        }

        $result = Test-DC -hostname 'ms.ds.uhc.com'

        $result | Should -Be $false
        ($script:LogEntries.Message -join "`n") | Should -Match 'DC not reachable'
    }

    It "returns false when Resolve-DnsName fails after corp-only suffixes (stale suffix guard)" {
        function script:Get-DnsClientGlobalSetting {
            [pscustomobject]@{ SuffixSearchList = @('ms.ds.uhc.com') }
        }
        function script:Resolve-DnsName {
            param([string]$Name, [string]$Type, $ErrorAction)
            throw "DNS resolution failed"
        }

        $result = Test-DC -hostname 'ms.ds.uhc.com'

        $result | Should -Be $false
        ($script:LogEntries.Message -join "`n") | Should -Match 'suffix data may be stale'
    }
}
