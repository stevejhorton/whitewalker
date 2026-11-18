# exit_reason = <reason>:<state> convention (docs/EXIT_REASON_AND_FLARE_DESIGN.md). Pester 5.
# Functions come from the real source via AST, so these test the shipped code.

Describe 'CPR exit reason convention' {
    BeforeAll {
        $script:root = Split-Path -Parent $PSScriptRoot
        $script:stateSrc = Get-Content -LiteralPath (Join-Path $root 'main\Main.State.ps1') -Raw
        $want = 'Get-CprExitType','Set-CprRunExit','Get-CprExitState','Get-CprExitReasonPart','Send-CprExitFlare'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'main\Main.State.ps1'), [ref]$null, [ref]$null)
        foreach ($d in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $want }, $true)) { . ([scriptblock]::Create($d.Extent.Text)) }
        $script:CprExitStates = @('on_prem','user_tun','mgmt_tun','off_prem_no_vpn','vpn_connecting','captive_portal','no_net_transient','cpr_error')
        function Write-Log { param($m, $l) }
        $script:DC_FQDN = 'dc.example.invalid'
        $script:sent = New-Object System.Collections.Generic.List[string]
        function Send-FlareEvent { param([string]$Tag) $script:sent.Add($Tag) }
        $script:flavor = 'None'; $script:dcOk = $false; $script:ssidOk = $false
        function Get-VpnTunnelFlavor { $script:flavor }
        function Test-DC { param($hostname) $script:dcOk }
        function Test-SsidTrusted { param($NetworkInfo) $script:ssidOk }
        $script:ni = [pscustomobject]@{ SSID = 'x'; ConnectionType = 'WiFi' }
        $script:srcFiles = Get-ChildItem -LiteralPath (Join-Path $root 'main') -Filter '*.ps1'
    }
    BeforeEach { $script:exitReason = $null; $script:sent.Clear(); $script:flavor = 'None'; $script:dcOk = $false; $script:ssidOk = $false }

    Context 'Set-CprRunExit' {
        It 'joins reason and state' {
            Set-CprRunExit -Reason 'vpn_connected' -State 'user_tun'
            $script:exitReason | Should -Be 'vpn_connected:user_tun'
        }
        It 'strips a colon a caller put in the reason, so the state is always the last segment' {
            Set-CprRunExit -Reason 'x:y' -State 'on_prem'
            $script:exitReason | Should -Be 'x:on_prem'
        }
        It 'falls back to cpr_error for a state outside the vocabulary' {
            Set-CprRunExit -Reason 'x' -State 'bogus'
            $script:exitReason | Should -Be 'x:cpr_error'
        }
    }

    Context 'Get-CprExitType (derived, never state.json)' {
        It 'returns the tunnel flavor when a tunnel is up' {
            $script:flavor = 'mgmt_tun'
            Get-CprExitType -NetworkInfo $script:ni | Should -Be 'mgmt_tun'
        }
        It 'returns on_prem only when the DC is reachable AND the path is trusted' {
            $script:dcOk = $true; $script:ssidOk = $true
            Get-CprExitType -NetworkInfo $script:ni | Should -Be 'on_prem'
        }
        It 'returns off_prem_no_vpn when the DC answers on an untrusted path' {
            $script:dcOk = $true; $script:ssidOk = $false
            Get-CprExitType -NetworkInfo $script:ni | Should -Be 'off_prem_no_vpn'
        }
        It 'returns off_prem_no_vpn when the DC is unreachable' {
            Get-CprExitType -NetworkInfo $script:ni | Should -Be 'off_prem_no_vpn'
        }
        It 'returns off_prem_no_vpn with no network info' {
            $script:dcOk = $true; $script:ssidOk = $true
            Get-CprExitType | Should -Be 'off_prem_no_vpn'
        }
        It 'derives the state when Set-CprRunExit is given none (ISE over a tunnel vs on-prem differ)' {
            $script:flavor = 'user_tun'
            Set-CprRunExit -Reason 'ise_employee_compliant' -NetworkInfo $script:ni
            $script:exitReason | Should -Be 'ise_employee_compliant:user_tun'
            $script:flavor = 'None'; $script:dcOk = $true; $script:ssidOk = $true
            Set-CprRunExit -Reason 'ise_employee_compliant' -NetworkInfo $script:ni
            $script:exitReason | Should -Be 'ise_employee_compliant:on_prem'
        }
    }

    Context 'parsing' {
        It 'splits state from the LAST colon and reason from the first segment' {
            Get-CprExitState 'vpn_connected:user_tun' | Should -Be 'user_tun'
            Get-CprExitReasonPart 'vpn_connected:user_tun' | Should -Be 'vpn_connected'
            Get-CprExitState 'untrusted:off_prem_no_vpn' | Should -Be 'off_prem_no_vpn'
        }
        It 'returns empty for a legacy or unknown value' {
            Get-CprExitState 'on_prem' | Should -Be ''
            Get-CprExitState 'x:notastate' | Should -Be ''
            Get-CprExitState '' | Should -Be ''
        }
    }

    Context 'Send-CprExitFlare' {
        It 'sends the state flare for the exit state' {
            Send-CprExitFlare 'ise_employee_compliant:on_prem'
            @($script:sent) | Should -Be @('on_prem')
        }
        It 'sends nothing when there is no valid state' {
            Send-CprExitFlare 'unknown'
            @($script:sent).Count | Should -Be 0
        }
    }

    Context 'source rules' {
        It 'assigns $script:exitReason only inside Set-CprRunExit' {
            $hits = foreach ($f in $script:srcFiles) {
                Select-String -LiteralPath $f.FullName -Pattern '\$script:exitReason\s*=' | ForEach-Object { "$($f.Name):$($_.LineNumber)" }
            }
            @($hits) | Should -Be @("Main.State.ps1:$((Select-String -LiteralPath (Join-Path $script:root 'main\Main.State.ps1') -Pattern '\$script:exitReason\s*=').LineNumber)")
        }
        It 'never puts a state word inside a reason, and every literal state is in the vocabulary' {
            $calls = foreach ($f in $script:srcFiles) {
                Select-String -LiteralPath $f.FullName -Pattern 'Set-CprRunExit\s+-Reason\s+(\S+|\$\(.*?\))' -AllMatches |
                    ForEach-Object { $_.Line.Trim() }
            }
            @($calls).Count | Should -BeGreaterThan 30
            foreach ($line in $calls) {
                $m = [regex]::Match($line, "-Reason\s+(?:'([^']+)'|""([^""]+)"")")
                if ($m.Success) {
                    $reason = if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
                    foreach ($st in $script:CprExitStates) { $reason | Should -Not -Match "(^|_)$st(_|$)" -Because $line }
                }
                $s = [regex]::Match($line, "-State\s+'([^']+)'")
                if ($s.Success) { $s.Groups[1].Value | Should -BeIn $script:CprExitStates -Because $line }
            }
        }
        It 'sends the exit flare from the run finally block' {
            (Get-Content -LiteralPath (Join-Path $script:root 'main\Main.Entry.ps1') -Raw) | Should -Match '(?s)finally \{\s*#[^\n]*\n\s*Send-CprExitFlare \$script:exitReason'
        }
        It 'decides maintenance offline from the parsed exit reason, not exact legacy strings' {
            (Get-Content -LiteralPath (Join-Path $script:root 'main\Main.Entry.ps1') -Raw) | Should -Match "Get-CprExitState \`$ExitReason\) -eq 'no_net_transient'"
        }
    }

    Context 'flare vocabulary' {
        It 'has every exit state in $StateFlares and in WW_flaregun_config.json with unique event IDs' {
            $cfg = (Get-Content -LiteralPath (Join-Path $script:root 'WW_flaregun_config.json') -Raw | ConvertFrom-Json).flare_events
            foreach ($st in $script:CprExitStates) {
                $cfg.PSObject.Properties.Name | Should -Contain $st
                $script:stateSrc | Should -Match "StateFlares = @\([^)]*'$st'"
            }
            $ids = @($cfg.PSObject.Properties | ForEach-Object { $_.Value.event_id })
            @($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        }
        It 'retired off_prem_untrusted_ssid as a state' {
            $script:stateSrc | Should -Not -Match "StateFlares = @\([^)]*off_prem_untrusted_ssid"
        }
    }
}
