# Focused tests for the CPR RC2 DEFENDER rule-name matcher:
#   - haystack_action.ps1 : runtime presence check (Invoke-DefenderNeedleCheck)
#   - haystack.ps1        : parser-side validation of RuleNameMatch
#
# Both scripts carry their own self-contained copy of the normalization helpers
# (haystack_action.ps1 must never dot-source haystack.ps1), so these tests also
# assert the two copies remain character-identical.
#
# Loading mirrors WW_Tests_Haystack_Action.ps1 / CPR_RC2.HeaderNeedle.Tests.ps1:
# function bodies are extracted and Invoke-Expression'd so neither script's
# entry point ever executes.
#
# WINDOWS-ONLY LIMITATION: the real check reads
# HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\
# Mdm\FirewallRules. Those registry APIs do not exist on Linux/macOS, so the
# registry item is faked here. These tests prove the matching/parsing contract,
# NOT live registry behavior on a managed Windows endpoint.

BeforeAll {
    $script:ReleaseRoot = Split-Path -Parent $PSScriptRoot

    $script:HaystackActionPath = Join-Path $script:ReleaseRoot 'haystack_action.ps1'
    $script:HaystackPath       = Join-Path $script:ReleaseRoot 'haystack.ps1'

    # --- haystack_action.ps1 functions ---
    $haContent = Get-Content -LiteralPath $script:HaystackActionPath -Raw
    $haPre     = ($haContent -split '(?ms)^# =+\r?\n# Main')[0]
    Invoke-Expression $haPre.Substring($haPre.IndexOf('function Write-HALog'))

    # --- haystack.ps1 parser functions (its Read-NeedleFile copy wins so the
    #     parser tests below can mock Write-HSLog) ---
    $hsContent = Get-Content -LiteralPath $script:HaystackPath -Raw
    $hsPre     = ($hsContent -split '(?ms)^# =+\r?\n# Entry Point')[0]
    Invoke-Expression $hsPre.Substring($hsPre.IndexOf('function Write-HSLog'))

    if (-not (Get-Command Invoke-SyslogSend -ErrorAction SilentlyContinue)) {
        function Invoke-SyslogSend { param([string]$Payload, [string]$ExtraInfo = '') }
    }
    if (-not (Get-Command Get-LoggedOnUser -ErrorAction SilentlyContinue)) {
        function Get-LoggedOnUser { return 'DOMAIN\TestUser' }
    }

    $script:DefenderCheckIntervalHours = 6

    function Get-DefenderHelperSource {
        # AST extraction - compares the two self-contained copies by their own
        # parsed function definitions rather than by brittle text slicing.
        param([string]$Path, [string[]]$Names)

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        if ($errors -and $errors.Count -gt 0) {
            throw "Parse errors in '$Path': $($errors[0].Message)"
        }

        $found = [ordered]@{}
        foreach ($name in $Names) {
            $fn = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true) | Where-Object { $_.Name -eq $name }

            if (-not $fn) { throw "Function '$name' not found in '$Path'" }
            $found[$name] = (@($fn)[0]).Extent.Text
        }
        return $found
    }

    function New-FakeFwRegistryItem {
        param([hashtable]$Values)

        $item = [pscustomobject]@{ Values = $Values }
        $item | Add-Member ScriptMethod GetValueNames { @($this.Values.Keys) }
        $item | Add-Member ScriptMethod GetValue { param($name) $this.Values[$name] }
        return $item
    }
}

Describe 'Test-DefenderRuleNameMatch - normalized literal substring matching' {
    It 'matches the confirmed false-MISSING case (spaces around the hyphen)' {
        Test-DefenderRuleNameMatch -RuleName 'V2-MsWebView2 Any Out' -RuleNameMatch 'V2 - MsWebView2 Any Out' |
            Should -BeTrue
    }

    It 'matches in the opposite direction too' {
        Test-DefenderRuleNameMatch -RuleName 'V2 - MsWebView2 Any Out' -RuleNameMatch 'V2-MsWebView2 Any Out' |
            Should -BeTrue
    }

    It 'is case-insensitive' {
        Test-DefenderRuleNameMatch -RuleName 'v2-MSWEBVIEW2 any out' -RuleNameMatch 'V2 - MsWebView2 Any Out' |
            Should -BeTrue
    }

    It 'tolerates <Separator> separators' -ForEach @(
        @{ Separator = 'underscore';          RuleName = 'V2_MsWebView2_Any_Out' }
        @{ Separator = 'slash';               RuleName = 'V2/MsWebView2/Any/Out' }
        @{ Separator = 'dot';                 RuleName = 'V2.MsWebView2.Any.Out' }
        @{ Separator = 'repeated whitespace'; RuleName = "V2  -   MsWebView2`tAny   Out" }
        @{ Separator = 'none at all';         RuleName = 'V2MsWebView2AnyOut' }
    ) {
        Test-DefenderRuleNameMatch -RuleName $RuleName -RuleNameMatch 'V2 - MsWebView2 Any Out' |
            Should -BeTrue
    }

    It 'still matches a configured value that is only a substring of the rule name' {
        Test-DefenderRuleNameMatch -RuleName 'V2 - MsWebView2 Any Out' -RuleNameMatch 'MsWebView2' |
            Should -BeTrue
    }

    It 'does not match a clearly different rule' {
        Test-DefenderRuleNameMatch -RuleName 'V2 - Teams Any Out' -RuleNameMatch 'V2 - MsWebView2 Any Out' |
            Should -BeFalse
        Test-DefenderRuleNameMatch -RuleName 'Block Legacy SMB Inbound' -RuleNameMatch 'MsWebView2' |
            Should -BeFalse
    }

    It 'rejects an empty/whitespace-only configured match instead of matching everything' -ForEach @(
        @{ Needle = '' }
        @{ Needle = '   ' }
        @{ Needle = $null }
        @{ Needle = '---' }
        @{ Needle = ' _ / . ' }
    ) {
        Test-DefenderRuleNameMatch -RuleName 'V2 - MsWebView2 Any Out' -RuleNameMatch $Needle |
            Should -BeFalse
    }

    It 'does not match when the rule name itself normalizes away' {
        Test-DefenderRuleNameMatch -RuleName '---' -RuleNameMatch 'MsWebView2' | Should -BeFalse
    }

    It 'treats the configured value as literal text, not a regex' {
        Test-DefenderRuleNameMatch -RuleName 'V2 - MsWebView2 Any Out' -RuleNameMatch 'MsWeb.iew2' |
            Should -BeFalse
        Test-DefenderRuleNameMatch -RuleName 'Rule (Any) Out' -RuleNameMatch '(Any)' |
            Should -BeTrue
    }
}

Describe 'ConvertTo-DefenderRuleNameKey' {
    It 'collapses to a lowercase alphanumeric token form' {
        ConvertTo-DefenderRuleNameKey -Text 'V2 - MsWebView2 Any Out' | Should -Be 'v2mswebview2anyout'
    }

    It 'returns an empty key for empty, whitespace-only, or punctuation-only text' -ForEach @(
        @{ Text = '' }
        @{ Text = '    ' }
        @{ Text = '-_/.' }
    ) {
        ConvertTo-DefenderRuleNameKey -Text $Text | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-DefenderNeedleCheck - runtime presence check' {
    BeforeEach {
        $script:DefenderFwRegPath = 'HKLM:\Test\FirewallRules'
        $script:HaystackLogFile   = Join-Path $TestDrive 'haystack.log'
        $script:CapturedPayload   = $null
        $script:Needle = [pscustomobject]@{
            Type='DEFENDER'; RuleNameMatch='V2 - MsWebView2 Any Out'; IntervalHours=6
            Label='WebView2_FW_Allow'; ExtendedLogging='all'; Source='local'
        }
        Mock Write-HALog {}
        Mock Get-LoggedOnUser { 'DOMAIN\User1' }
        Mock Invoke-SyslogSend { param($Payload) $script:CapturedPayload = $Payload }
        Mock Write-DefenderFlag {}
        Mock Test-DefenderCheckDue { $true }
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -eq $script:DefenderFwRegPath }
    }

    It 'reports PRESENT when only the separator convention differs' {
        $item = New-FakeFwRegistryItem -Values @{
            '{guid}' = 'v2.30|Action=Allow|Name=V2-MsWebView2 Any Out|Dir=Out|Protocol=6|'
        }
        Mock Get-Item { $item } -ParameterFilter { $LiteralPath -eq $script:DefenderFwRegPath }

        $hits = Invoke-DefenderNeedleCheck -Needles @($script:Needle)

        $hits | Should -Be 1
        $script:CapturedPayload | Should -Match 'rule_state="PRESENT"'
        (Get-Content -LiteralPath $script:HaystackLogFile -Raw) | Should -Match '\[NEEDLE_HIT\].*PRESENT'
        Assert-MockCalled Write-DefenderFlag -Times 1 -Exactly -ParameterFilter { $LastState -eq 'PRESENT' }
    }

    It 'reports PRESENT for case and separator variations of the deployed name' -ForEach @(
        @{ Deployed = 'v2_mswebview2_any_out' }
        @{ Deployed = 'V2 / MsWebView2 / Any / Out' }
        @{ Deployed = 'V2.MsWebView2.Any.Out' }
        @{ Deployed = 'V2   -    MsWebView2  Any   Out' }
    ) {
        $item = New-FakeFwRegistryItem -Values @{
            '{guid}' = "v2.30|Action=Allow|Name=$Deployed|Dir=Out|Protocol=6|"
        }
        Mock Get-Item { $item } -ParameterFilter { $LiteralPath -eq $script:DefenderFwRegPath }

        Invoke-DefenderNeedleCheck -Needles @($script:Needle) | Should -Be 1
        $script:CapturedPayload | Should -Match 'rule_state="PRESENT"'
    }

    It 'still reports MISSING for a clearly different rule' {
        $item = New-FakeFwRegistryItem -Values @{
            '{guid}' = 'v2.30|Action=Allow|Name=V2 - Teams Any Out|Dir=Out|Protocol=6|'
        }
        Mock Get-Item { $item } -ParameterFilter { $LiteralPath -eq $script:DefenderFwRegPath }

        Invoke-DefenderNeedleCheck -Needles @($script:Needle) | Should -Be 1
        $script:CapturedPayload | Should -Match 'rule_state="MISSING"'
        Assert-MockCalled Write-DefenderFlag -Times 1 -Exactly -ParameterFilter { $LastState -eq 'MISSING' }
    }

    It 'reports MISSING rather than matching everything when the configured value normalizes away' {
        $script:Needle.RuleNameMatch = ' - '
        $item = New-FakeFwRegistryItem -Values @{
            '{guid}' = 'v2.30|Action=Allow|Name=V2 - MsWebView2 Any Out|Dir=Out|Protocol=6|'
        }
        Mock Get-Item { $item } -ParameterFilter { $LiteralPath -eq $script:DefenderFwRegPath }

        Invoke-DefenderNeedleCheck -Needles @($script:Needle) | Should -Be 1
        $script:CapturedPayload | Should -Match 'rule_state="MISSING"'
    }
}

Describe 'Read-NeedleFile - DEFENDER RuleNameMatch validation' {
    BeforeEach {
        $script:NeedleFile = Join-Path $TestDrive 'needles_defender.cfg'
        $script:LogBuffer  = [System.Collections.Generic.List[object]]::new()
        Mock Write-HSLog {
            param($Message, $Level)
            $script:LogBuffer.Add([pscustomobject]@{ Message = $Message; Level = $Level })
        }
    }

    It 'keeps the existing spaced-hyphen entry parseable with no manual renaming' {
        'DEFENDER|V2 - MsWebView2 Any Out|6|WebView2_FW_Allow|all' |
            Set-Content -Path $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local')

        $result.Count                | Should -Be 1
        $result[0].Type              | Should -Be 'DEFENDER'
        $result[0].RuleNameMatch     | Should -Be 'V2 - MsWebView2 Any Out'
        $result[0].IntervalHours     | Should -Be 6
        $result[0].Label             | Should -Be 'WebView2_FW_Allow'
        $result[0].ExtendedLogging   | Should -Be 'all'
    }

    It 'skips a RuleNameMatch that contains no letters or digits' {
        'DEFENDER|---|6|Bogus_Rule|all' | Set-Content -Path $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local')

        $result.Count | Should -Be 0
        ($script:LogBuffer | Where-Object { $_.Message -match 'contains no letters or digits' }).Count |
            Should -BeGreaterThan 0
    }

    It 'skips an empty RuleNameMatch' {
        'DEFENDER||6|Bogus_Rule|all' | Set-Content -Path $script:NeedleFile -Encoding UTF8

        @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local').Count | Should -Be 0
        ($script:LogBuffer | Where-Object { $_.Message -match 'RuleNameMatch is empty' }).Count |
            Should -BeGreaterThan 0
    }
}

Describe 'Self-contained copies stay consistent (AST source contract)' {
    It 'defines character-identical <Function> in haystack.ps1 and haystack_action.ps1' -ForEach @(
        @{ Function = 'ConvertTo-DefenderRuleNameKey' }
        @{ Function = 'Test-DefenderRuleNameMatch' }
    ) {
        $fromAction = Get-DefenderHelperSource -Path $script:HaystackActionPath -Names @($Function)
        $fromReroll = Get-DefenderHelperSource -Path $script:HaystackPath       -Names @($Function)

        $fromAction[$Function] | Should -Be $fromReroll[$Function]
    }

    It 'no longer escapes RuleNameMatch into a regex in the runtime check' {
        $actionText = Get-Content -LiteralPath $script:HaystackActionPath -Raw
        $actionText | Should -Not -Match '\[regex\]::Escape\(\[string\]\$needle\.RuleNameMatch\)'
        $actionText | Should -Match 'Test-DefenderRuleNameMatch -RuleName \$nameMatch\.Groups\[1\]\.Value'
    }
}
