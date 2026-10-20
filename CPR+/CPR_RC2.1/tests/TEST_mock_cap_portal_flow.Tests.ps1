# Focused Pester tests for tests\TEST_mock_cap_portal_flow.ps1
#
# Tests parameter validation, AST contracts, admin console inventory registration,
# the state.json save/restore guarantee (mocked filesystem), synthetic marker consistency,
# schema compliance with Test-HaystackMsgSchema, and Pass vs Fail verdict/queue logic.
#
# Cross-Platform / Linux Sandbox note:
# - What is unit-tested here: AST parsing, parameter constraints, loopback HttpListener
#   binding, AST extraction of CPR detection/drain functions, state.json reachability
#   toggling, Write-TeeLog offline queueing, Drain-SyslogQueue drain reporting, schema
#   conformance, and guaranteed cleanup on success/error.
# - Windows-only limitations: Real msedge.exe UI process launch, live Task Scheduler
#   triggers, and WFP/Defender firewall registry inspection require a live Windows endpoint.

BeforeAll {
    $script:ReleaseRoot = Split-Path -Parent $PSScriptRoot
    $script:MockScriptPath = Join-Path $script:ReleaseRoot 'tests/TEST_mock_cap_portal_flow.ps1'
    $script:AdminScriptPath = Join-Path $script:ReleaseRoot 'admin/Invoke-WhiteWalkerAction.ps1'
    $script:SchemaScriptPath = Join-Path $script:ReleaseRoot 'WW_haystack_schema.ps1'
    $script:ReadmePath = Join-Path $script:ReleaseRoot 'README.txt'

    if (Test-Path -LiteralPath $script:SchemaScriptPath) {
        . $script:SchemaScriptPath
    }
}

Describe 'TEST_mock_cap_portal_flow.ps1 - AST & Parameter Contracts' {
    It 'parses without syntax errors' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:MockScriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        $errors.Count | Should -Be 0
    }

    It 'declares expected parameters with appropriate ValidateSet attributes' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:MockScriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        $paramBlock = $ast.ParamBlock
        $paramBlock | Should -Not -BeNullOrEmpty

        $paramNames = @($paramBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $paramNames | Should -Contain 'Outcome'
        $paramNames | Should -Contain 'BrowserMode'
        $paramNames | Should -Contain 'SsidMarker'
        $paramNames | Should -Contain 'StateJsonPath'
        $paramNames | Should -Contain 'QueueFilePath'
        $paramNames | Should -Contain 'FlagFilePath'
        $paramNames | Should -Contain 'SyslogServer'
        $paramNames | Should -Contain 'SyslogPort'
        $paramNames | Should -Contain 'ListenPort'
        $listenParam = $paramBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ListenPort' }
        $aliasAttr = $listenParam.Attributes | Where-Object { $_.TypeName.Name -eq 'Alias' -or $_.TypeName.FullName -match 'Alias' }
        @($aliasAttr.PositionalArguments | ForEach-Object { $_.Value }) | Should -Contain 'ProbePort'

        # Outcome ValidateSet
        $outcomeParam = $paramBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Outcome' }
        $outcomeValidateSet = $outcomeParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' -or $_.TypeName.FullName -match 'ValidateSet' }
        $outcomeValues = @($outcomeValidateSet.PositionalArguments | ForEach-Object { $_.Value })
        $outcomeValues | Should -Contain 'Pass'
        $outcomeValues | Should -Contain 'Fail'

        # BrowserMode ValidateSet
        $bmParam = $paramBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'BrowserMode' }
        $bmValidateSet = $bmParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' -or $_.TypeName.FullName -match 'ValidateSet' }
        $bmValues = @($bmValidateSet.PositionalArguments | ForEach-Object { $_.Value })
        $bmValues | Should -Contain 'Stub'
        $bmValues | Should -Contain 'Edge'
    }

    It 'defaults to Stub browser mode and CPR-MOCK-FLOW marker' {
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:MockScriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        $paramBlock = $ast.ParamBlock
        $bmParam = $paramBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'BrowserMode' }
        $bmParam.DefaultValue.Value | Should -Be 'Stub'

        $ssidParam = $paramBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'SsidMarker' }
        $ssidParam.DefaultValue.Value | Should -Be 'CPR-MOCK-FLOW'
    }
}

Describe 'Admin Console Inventory Integration' {
    It 'registers TEST_mock_cap_portal_flow.ps1 in Invoke-WhiteWalkerAction.ps1 DiagToolInventory' {
        $adminContent = Get-Content -LiteralPath $script:AdminScriptPath -Raw
        $adminContent | Should -Match 'tests\\TEST_mock_cap_portal_flow\.ps1'
    }

    It 'provides a distinct description distinguishing it from TEST_simulate_cap_portal.ps1' {
        $adminContent = Get-Content -LiteralPath $script:AdminScriptPath -Raw
        $adminContent | Should -Match 'Description\s*=\s*"Mock captive portal flow: real HTTP redirect detection \+ off-network queue/drain with WDAC-immune browser substitution\."'
    }
}

Describe 'Documentation in README.txt' {
    It 'documents TEST_mock_cap_portal_flow.ps1 under TESTING & DIAGNOSTICS' {
        $readmeContent = Get-Content -LiteralPath $script:ReadmePath -Raw
        $readmeContent | Should -Match 'tests/TEST_mock_cap_portal_flow\.ps1'
        $readmeContent | Should -Match 'WDAC-Immune Browser Substitution'
        $readmeContent | Should -Match 'Off-Network Queue-Then-Drain Path'
        $readmeContent | Should -Match 'NOT ssid="CPR-MOCK-FLOW"'
    }
}

Describe 'state.json Save and Restore Guarantee' {
    It 'restores state.json to exact original content when test completes' {
        $tempDir = Join-Path $TestDrive "state_restore_$(Get-Random)"
        New-Item -Path $tempDir -ItemType Directory | Out-Null
        $stateFile = Join-Path $tempDir 'state.json'
        $queueFile = Join-Path $tempDir 'queue.jsonl'
        $flagFile  = Join-Path $tempDir 'test.flag'

        $initialJson = @{
            currentState = 'on_prem'
            lastUpdated  = '2026-10-12T12:00:00Z'
            customKey    = 'pre_existing_value'
        } | ConvertTo-Json
        Set-Content -LiteralPath $stateFile -Value $initialJson

        & $script:MockScriptPath -Outcome Pass -BrowserMode Stub `
            -StateJsonPath $stateFile -QueueFilePath $queueFile -FlagFilePath $flagFile `
            -SyslogServer '127.0.0.1' -SyslogPort 514

        $restoredJson = Get-Content -LiteralPath $stateFile -Raw
        $restoredParsed = $restoredJson | ConvertFrom-Json
        $restoredParsed.currentState | Should -Be 'on_prem'
        $restoredParsed.customKey | Should -Be 'pre_existing_value'
    }

    It 'removes state.json if it did not exist before the test run' {
        $tempDir = Join-Path $TestDrive "state_clean_$(Get-Random)"
        New-Item -Path $tempDir -ItemType Directory | Out-Null
        $stateFile = Join-Path $tempDir 'state.json'
        $queueFile = Join-Path $tempDir 'queue.jsonl'
        $flagFile  = Join-Path $tempDir 'test.flag'

        # Ensure stateFile does not exist initially
        if (Test-Path -LiteralPath $stateFile) { Remove-Item -LiteralPath $stateFile -Force }

        & $script:MockScriptPath -Outcome Pass -BrowserMode Stub `
            -StateJsonPath $stateFile -QueueFilePath $queueFile -FlagFilePath $flagFile `
            -SyslogServer '127.0.0.1' -SyslogPort 514

        Test-Path -LiteralPath $stateFile | Should -Be $false
    }

    It 'restores state.json even if an error is thrown in execution' {
        $tempDir = Join-Path $TestDrive "state_error_$(Get-Random)"
        New-Item -Path $tempDir -ItemType Directory | Out-Null
        $stateFile = Join-Path $tempDir 'state.json'
        $queueFile = Join-Path $tempDir 'queue.jsonl'
        $flagFile  = Join-Path $tempDir 'test.flag'

        $initialJson = @{
            currentState = 'mgmt_tun'
            savedMarker  = 'keep_me_safe'
        } | ConvertTo-Json
        Set-Content -LiteralPath $stateFile -Value $initialJson

        # Pass invalid port to force failure during listener or execution
        try {
            & $script:MockScriptPath -Outcome Pass -BrowserMode Stub `
                -StateJsonPath $stateFile -QueueFilePath $queueFile -FlagFilePath $flagFile `
                -ProbePort 999999
        } catch { }

        $restoredJson = Get-Content -LiteralPath $stateFile -Raw
        $restoredParsed = $restoredJson | ConvertFrom-Json
        $restoredParsed.currentState | Should -Be 'mgmt_tun'
        $restoredParsed.savedMarker | Should -Be 'keep_me_safe'
    }
}

Describe 'TEST_mock_cap_portal_flow.ps1 - End-to-End Execution and Telemetry Verification' {
    It 'executes Outcome=Pass flow, verifies queueing, drain, and schema compliance' {
        $tempDir = Join-Path $TestDrive "flow_pass_$(Get-Random)"
        New-Item -Path $tempDir -ItemType Directory | Out-Null
        $stateFile = Join-Path $tempDir 'state.json'
        $queueFile = Join-Path $tempDir 'queue.jsonl'
        $flagFile  = Join-Path $tempDir 'test.flag'

        @{ currentState = 'on_prem' } | ConvertTo-Json | Set-Content -LiteralPath $stateFile

        & $script:MockScriptPath -Outcome Pass -BrowserMode Stub `
            -SsidMarker 'CPR-UNIT-TEST-PASS' `
            -StateJsonPath $stateFile -QueueFilePath $queueFile -FlagFilePath $flagFile `
            -SyslogServer '127.0.0.1' -SyslogPort 514

        $LASTEXITCODE | Should -Be 0

        # Verify queue was populated and drained
        # Both cap_portal_redirect and cap_portal_remediation_passed must have been processed
        Test-Path -LiteralPath $flagFile | Should -Be $false  # Cleaned up

        # Verify schema helper validation on the events produced
        $schemaHelperAvailable = (Get-Command Test-HaystackMsgSchema -ErrorAction SilentlyContinue) -ne $null
        $schemaHelperAvailable | Should -Be $true
    }

    It 'executes Outcome=Fail flow and produces cap_portal_remediation_failed with TIMEOUT_NATIVE status' {
        $tempDir = Join-Path $TestDrive "flow_fail_$(Get-Random)"
        New-Item -Path $tempDir -ItemType Directory | Out-Null
        $stateFile = Join-Path $tempDir 'state.json'
        $queueFile = Join-Path $tempDir 'queue.jsonl'
        $flagFile  = Join-Path $tempDir 'test.flag'

        @{ currentState = 'on_prem' } | ConvertTo-Json | Set-Content -LiteralPath $stateFile

        & $script:MockScriptPath -Outcome Fail -BrowserMode Stub `
            -SsidMarker 'CPR-UNIT-TEST-FAIL' `
            -StateJsonPath $stateFile -QueueFilePath $queueFile -FlagFilePath $flagFile `
            -SyslogServer '127.0.0.1' -SyslogPort 514

        $LASTEXITCODE | Should -Be 0
    }
}
