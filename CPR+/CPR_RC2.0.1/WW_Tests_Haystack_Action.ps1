BeforeAll {
    $scriptPath = "$PSScriptRoot/haystack_action.ps1"

    $content = Get-Content -LiteralPath $scriptPath -Raw
    $mainPattern = '(?ms)^# =+\r?\n# Main'
    $preMain = ($content -split $mainPattern)[0]
    $funcStart = $preMain.IndexOf('function Write-HALog')
    $funcContent = $preMain.Substring($funcStart)
    Invoke-Expression $funcContent

    if (-not (Get-Command Invoke-SyslogSend -ErrorAction SilentlyContinue)) {
        function Invoke-SyslogSend { param([string]$Payload, [string]$ExtraInfo = '') }
    }
    if (-not (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)) {
        function Get-WinEvent { param([hashtable]$FilterHashtable, [int]$MaxEvents, [string]$ErrorAction) }
    }
    if (-not (Get-Command Get-LoggedOnUser -ErrorAction SilentlyContinue)) {
        function Get-LoggedOnUser { return 'DOMAIN\TestUser' }
    }

    function New-FakeEvent {
        param(
            [int]$Id = 10000,
            [string]$LogName = 'Application',
            [string]$ProviderName = 'Cisco Secure Client',
            [string]$MachineName = 'WORKSTATION01',
            [datetime]$TimeCreated = [datetime]::Parse('2026-09-10T14:09:32.681Z'),
            [string]$FormattedMessage = 'Base event message'
        )

        $evt = [pscustomobject]@{
            Id = $Id
            LogName = $LogName
            ProviderName = $ProviderName
            MachineName = $MachineName
            TimeCreated = $TimeCreated
            FormattedMessage = $FormattedMessage
        }
        $evt | Add-Member -MemberType ScriptMethod -Name FormatDescription -Value { $this.FormattedMessage }
        return $evt
    }
}

Describe 'Write-HaystackHit syslog payload' {
    BeforeEach {
        $script:HaystackLogFile = Join-Path $TestDrive 'haystack.log'
        $script:CapturedPayload = $null

        Mock Invoke-SyslogSend {
            param($Payload)
            $script:CapturedPayload = $Payload
        }

        Mock Write-HALog {}
        Mock Get-WinEvent {}
    }

    It 'omits body when extended logging is disabled or missing' {
        $event = New-FakeEvent
        $needle = [pscustomobject]@{
            Type = 'NEEDLE'
            LogName = 'Application'
            EventID = 10000
            Label = 'Network_Connected'
            ExtendedLogging = $false
        }

        Write-HaystackHit -Label 'Network_Connected' -Event $event -Needle $needle

        $script:CapturedPayload | Should -Match 'action=needle_hit'
        $script:CapturedPayload | Should -Not -Match ' body="'
        Assert-MockCalled Get-WinEvent -Times 0 -Exactly
    }

    It 'appends truncated 128-char body when extended logging is enabled' {
        $event = New-FakeEvent
        $longBody = ('A' * 140)
        $needle = [pscustomobject]@{
            Type = 'NEEDLE'
            LogName = 'Application'
            EventID = 10000
            Label = 'Network_Connected'
            ExtendedLogging = '1'
        }

        Mock Get-WinEvent {
            [pscustomobject]@{ Message = $longBody }
        }

        Write-HaystackHit -Label 'Network_Connected' -Event $event -Needle $needle

        $expectedBody = $longBody.Substring(0, 128)
        $script:CapturedPayload | Should -Match ' body="'
        $script:CapturedPayload | Should -Match ([regex]::Escape(("body=""{0}""" -f $expectedBody)))
        Assert-MockCalled Get-WinEvent -Times 1 -Exactly
    }

    It 'appends full sanitized body when extended logging mode is all' {
        $event = New-FakeEvent
        $rawBody = "first line`r`nsecond ""quoted"" line"
        $needle = [pscustomobject]@{
            Type = 'NEEDLE'
            LogName = 'Application'
            EventID = 10000
            Label = 'Network_Connected'
            ExtendedLogging = ' All '
        }

        Mock Get-WinEvent {
            [pscustomobject]@{ Message = $rawBody }
        }

        Write-HaystackHit -Label 'Network_Connected' -Event $event -Needle $needle

        $expectedBody = "first line | second 'quoted' line"
        $script:CapturedPayload | Should -Match ([regex]::Escape(("body=""{0}""" -f $expectedBody)))
        Assert-MockCalled Get-WinEvent -Times 1 -Exactly
    }
}

Describe 'DEFENDER needle parser' {
    BeforeEach {
        $script:NeedleFile = Join-Path $TestDrive 'defender_needles.cfg'
        Mock Write-HALog {}
    }

    It 'parses valid and default-interval DEFENDER directives independently' {
        @(
            'DEFENDER|V2 - MsWebView2 Any Out|6|WebView2_FW_Allow|all'
            'DEFENDER|Fallback Rule||FallbackRule'
        ) | Set-Content -LiteralPath $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local')

        $result.Count | Should -Be 2
        $result[0].IntervalHours | Should -Be 6
        $result[0].ExtendedLogging | Should -Be 'all'
        $result[1].IntervalHours | Should -BeNullOrEmpty
        $result[1].ExtendedLogging | Should -Be '0'
    }
}

Describe 'Test-DefenderCheckDue' {
    BeforeEach {
        $script:DefenderFlagDir = Join-Path $TestDrive 'defender_flags'
        New-Item -Path $script:DefenderFlagDir -ItemType Directory -Force | Out-Null
        $script:Needle = [pscustomobject]@{ Label = 'WebView2_FW_Allow' }
        $script:FlagPath = Join-Path $script:DefenderFlagDir 'WebView2_FW_Allow.flag'
        Mock Write-HALog {}
    }

    It 'is due when the flag is missing' {
        Test-DefenderCheckDue -Needle $script:Needle | Should -BeTrue
    }

    It 'is due when the flag is expired' {
        @{ LastCheck=(Get-Date).AddHours(-7).ToString('o'); NextCheck=(Get-Date).AddMinutes(-1).ToString('o'); LastState='PRESENT' } |
            ConvertTo-Json | Set-Content -LiteralPath $script:FlagPath

        Test-DefenderCheckDue -Needle $script:Needle | Should -BeTrue
    }

    It 'is not due when the flag is valid and unexpired' {
        @{ LastCheck=(Get-Date).ToString('o'); NextCheck=(Get-Date).AddHours(1).ToString('o'); LastState='MISSING' } |
            ConvertTo-Json | Set-Content -LiteralPath $script:FlagPath

        Test-DefenderCheckDue -Needle $script:Needle | Should -BeFalse
    }

    It 'is due when the flag is corrupt' {
        '{not-json' | Set-Content -LiteralPath $script:FlagPath

        Test-DefenderCheckDue -Needle $script:Needle | Should -BeTrue
    }
}

Describe 'Write-DefenderFlag' {
    BeforeEach {
        $script:DefenderFlagDir = Join-Path $TestDrive 'defender_flags'
        $script:DefenderCheckIntervalHours = 6
        Mock Write-HALog {}
    }

    It 'writes the state and uses the global interval when the needle interval is null' {
        $before = [datetimeoffset]::Now
        $needle = [pscustomobject]@{ Label='WebView2_FW_Allow'; IntervalHours=$null }

        Write-DefenderFlag -Needle $needle -LastState MISSING

        $flag = Get-Content -LiteralPath (Join-Path $script:DefenderFlagDir 'WebView2_FW_Allow.flag') -Raw | ConvertFrom-Json
        $flag.LastState | Should -Be 'MISSING'
        ([datetimeoffset]::Parse($flag.NextCheck) - [datetimeoffset]::Parse($flag.LastCheck)).TotalHours | Should -Be 6
        [datetimeoffset]::Parse($flag.LastCheck) | Should -BeGreaterThan $before.AddSeconds(-1)
    }
}

Describe 'Invoke-DefenderNeedleCheck' {
    BeforeEach {
        $script:DefenderFwRegPath = 'HKLM:\Test\FirewallRules'
        $script:HaystackLogFile = Join-Path $TestDrive 'haystack.log'
        $script:CapturedPayload = $null
        $script:Needle = [pscustomobject]@{
            Type='DEFENDER'; RuleNameMatch='V2 - MsWebView2 Any Out'; IntervalHours=6
            Label='WebView2_FW_Allow'; ExtendedLogging='all'; Source='local'
        }
        Mock Write-HALog {}
        Mock Get-LoggedOnUser { 'DOMAIN\User1' }
        Mock Invoke-SyslogSend { param($Payload) $script:CapturedPayload = $Payload }
        Mock Write-DefenderFlag {}
        Mock Test-DefenderCheckDue { $true }
        Mock Get-Item {}
    }

    It 'reports PRESENT, includes extended rule data, and refreshes the flag' {
        $script:RegistryItem = [pscustomobject]@{
            Values = @{ '{guid}' = 'v2.30|Action=Allow|Name=V2 - MsWebView2 Any Out|Dir=Out|Protocol=6|' }
        }
        $script:RegistryItem | Add-Member ScriptMethod GetValueNames { @($this.Values.Keys) }
        $script:RegistryItem | Add-Member ScriptMethod GetValue { param($name) $this.Values[$name] }
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -eq $script:DefenderFwRegPath }
        Mock Get-Item { $script:RegistryItem } -ParameterFilter { $LiteralPath -eq $script:DefenderFwRegPath }

        $hits = Invoke-DefenderNeedleCheck -Needles @($script:Needle)

        $hits | Should -Be 1
        $script:CapturedPayload | Should -Match 'rule_state="PRESENT"'
        $script:CapturedPayload | Should -Match 'body=".*Name=V2 - MsWebView2 Any Out'
        (Get-Content -LiteralPath $script:HaystackLogFile -Raw) | Should -Match '\[NEEDLE_HIT\].*PRESENT'
        Assert-MockCalled Write-DefenderFlag -Times 1 -Exactly -ParameterFilter { $LastState -eq 'PRESENT' }
        Assert-MockCalled Get-Item -Times 1 -Exactly
    }

    It 'reports MISSING and refreshes the flag when the registry key is absent' {
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -eq $script:DefenderFwRegPath }

        $hits = Invoke-DefenderNeedleCheck -Needles @($script:Needle)

        $hits | Should -Be 1
        $script:CapturedPayload | Should -Match 'rule_state="MISSING"'
        $script:CapturedPayload | Should -Not -Match ' body="'
        Assert-MockCalled Get-Item -Times 0 -Exactly
        Assert-MockCalled Write-DefenderFlag -Times 1 -Exactly -ParameterFilter { $LastState -eq 'MISSING' }
    }

    It 'does no registry read, send, or flag write when the check is gated' {
        Mock Test-DefenderCheckDue { $false }

        $hits = Invoke-DefenderNeedleCheck -Needles @($script:Needle)

        $hits | Should -Be 0
        Assert-MockCalled Get-Item -Times 0 -Exactly
        Assert-MockCalled Invoke-SyslogSend -Times 0 -Exactly
        Assert-MockCalled Write-DefenderFlag -Times 0 -Exactly
    }

    It 'retries next wake without reporting MISSING when an existing key cannot be read' {
        Mock Test-Path { $true } -ParameterFilter { $LiteralPath -eq $script:DefenderFwRegPath }
        Mock Get-Item { throw 'transient registry failure' } -ParameterFilter { $LiteralPath -eq $script:DefenderFwRegPath }

        $hits = Invoke-DefenderNeedleCheck -Needles @($script:Needle)

        $hits | Should -Be 0
        Assert-MockCalled Invoke-SyslogSend -Times 0 -Exactly
        Assert-MockCalled Write-DefenderFlag -Times 0 -Exactly
    }
}
