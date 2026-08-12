BeforeAll {
    $script:mainPath = Join-Path $PSScriptRoot 'WW_main.ps1'
    $null = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:mainPath, [ref]$null, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) {
        throw "Failed to parse WW_main.ps1"
    }

    $script:testDcDefinition = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-DC'
    }, $true).Extent.Text -replace '^function\s+Test-DC', 'function script:Test-DC'

    function Initialize-TestDcHarness {
        if (Test-Path Function:\Test-DC) {
            Remove-Item Function:\Test-DC -Force
        }
        if (Test-Path Function:\Write-Log) {
            Remove-Item Function:\Write-Log -Force
        }
        if (Test-Path Function:\Get-DnsClientGlobalSetting) {
            Remove-Item Function:\Get-DnsClientGlobalSetting -Force
        }
        if (Test-Path Function:\Test-Connection) {
            Remove-Item Function:\Test-Connection -Force
        }

        $script:LogEntries = @()
        function script:Write-Log {
            param([string]$Message, [string]$Level = 'INFO')
            $script:LogEntries += [pscustomobject]@{
                Message = $Message
                Level   = $Level
            }
        }
        function script:Get-DnsClientGlobalSetting {
            throw 'Stubbed for tests'
        }

        Invoke-Expression $script:testDcDefinition
    }
}

Describe "Test-DC diagnostic suffix classification" {
    BeforeEach {
        Initialize-TestDcHarness
    }

    AfterEach {
        if (Test-Path Function:\Test-DC) {
            Remove-Item Function:\Test-DC -Force
        }
        if (Test-Path Function:\Write-Log) {
            Remove-Item Function:\Write-Log -Force
        }
        if (Test-Path Function:\Get-DnsClientGlobalSetting) {
            Remove-Item Function:\Get-DnsClientGlobalSetting -Force
        }
        if (Test-Path Function:\Test-Connection) {
            Remove-Item Function:\Test-Connection -Force
        }
    }

    It "returns true when DC is reachable and only corporate suffixes are present" {
        function script:Test-Connection { $true }
        function script:Get-DnsClientGlobalSetting {
            [pscustomobject]@{
                SuffixSearchList = @('ms.ds.uhc.com', 'foo.uhc.com')
            }
        }

        $result = Test-DC -hostname 'ms.ds.uhc.com'

        $result | Should -Be $true
        ($script:LogEntries.Message -join "`n") | Should -Match 'DNS SUFFIX DIAGNOSTIC REPORT'
        ($script:LogEntries.Message -join "`n") | Should -Match "✓ CORPORATE: 'foo\.uhc\.com' matches pattern 'uhc\.com'"
        ($script:LogEntries.Message -join "`n") | Should -Match 'RETURNING: TRUE \(on-prem confirmed\)'
    }

    It "returns false when any non-corporate suffix is present alongside corporate suffixes" {
        function script:Test-Connection { $true }
        function script:Get-DnsClientGlobalSetting {
            [pscustomobject]@{
                SuffixSearchList = @('ms.ds.uhc.com', 'home', 'comcast.net')
            }
        }

        $result = Test-DC -hostname 'ms.ds.uhc.com'

        $result | Should -Be $false
        ($script:LogEntries.Message -join "`n") | Should -Match "✗ NON-CORPORATE: 'home'"
        ($script:LogEntries.Message -join "`n") | Should -Match 'Non-corporate suffixes found: 2'
        ($script:LogEntries.Message -join "`n") | Should -Match 'RETURNING: FALSE \(non-corporate suffixes \+ corporate\)'
    }

    It "returns false when DC is reachable but no DNS suffixes can be collected" {
        function script:Test-Connection { $true }
        function script:Get-DnsClientGlobalSetting {
            [pscustomobject]@{
                SuffixSearchList = @()
            }
        }

        $result = Test-DC -hostname 'ms.ds.uhc.com'

        $result | Should -Be $false
        ($script:LogEntries.Message -join "`n") | Should -Match 'Total Suffixes Found: 0'
        ($script:LogEntries.Message -join "`n") | Should -Match 'RETURNING: FALSE \(off-prem assumed\)'
    }
}
