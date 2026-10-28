# CPR_RC2.CapPortalDispatchRecovery.Tests.ps1
#
# RC2.2 recovery coverage for the two FATAL runtime errors proven by live
# xfinitywifi evidence (CPR v3.14.0_RC2.0, runner_mode=base), where detection
# worked perfectly and the run then aborted:
#
#   [ERROR] Failed to trigger captive portal event: The term
#           'Test-MainSkipCiscoBrowserKill' is not recognized ...
#   [ERROR] Error in main execution: Method invocation failed because
#           [System.Collections.Specialized.OrderedDictionary] does not
#           contain a method named 'ContainsKey'.
#   RUN END run_id=... exit_reason="error_exception"
#
#   A  the browser-kill resolver is defined ONCE, at file scope, and resolves
#      from BOTH the walled-garden path and the remediation path.
#   B  safe key access works for hashtable AND ordered-dictionary inputs.
#   C  an authoritative-redirect-detected base-mode run reaches
#      Send-FlareEvent 'captive_portal_browser_base' (Event 778) and returns
#      cleanly, with no unresolved-command or OrderedDictionary exception.
#
# Required C exercises the REAL Invoke-CaptivePortalRemediation body (loaded
# from source), not a reimplementation; only out-of-scope collaborators
# (FlareGun dispatch, VPN, flag waits, tee queue) are stubbed.

function global:Get-CprFunctionSource {
    param([string]$Path, [string[]]$Names)

    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Failed to parse $Path" }

    $found = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $Names -contains $node.Name
    }, $true)

    return (($found | ForEach-Object { $_.Extent.Text }) -join "`n`n")
}

function global:Get-CprTopLevelFunctionNames {
    param([string]$Path)

    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Failed to parse $Path" }

    $names = @()
    foreach ($fn in $ast.FindAll({
            param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true)) {
        $parent = $fn.Parent
        $nested = $false
        while ($parent) {
            if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $nested = $true; break }
            $parent = $parent.Parent
        }
        if (-not $nested) { $names += $fn.Name }
    }
    return $names
}

BeforeAll {
    $script:root        = Split-Path $PSScriptRoot -Parent
    $script:capPath     = Join-Path $script:root 'main/Main.CaptivePortal.ps1'
    $script:entryPath   = Join-Path $script:root 'main/Main.Entry.ps1'
    $script:commonPath  = Join-Path $script:root 'main/Main.Common.ps1'
    $script:loaderPath  = Join-Path $script:root 'WW_main.ps1'
    $script:capSource   = Get-Content $script:capPath -Raw
    $script:entrySource = Get-Content $script:entryPath -Raw
    $script:loaderSource = Get-Content $script:loaderPath -Raw
}

# =============================================================================
# Required A - Test-MainSkipCiscoBrowserKill resolvable from EVERY call site
# =============================================================================
Describe 'Required A - browser-kill resolver availability' {
    BeforeAll {
        . $script:commonPath
        Invoke-Expression (Get-CprFunctionSource -Path $script:capPath -Names @('Test-MainSkipCiscoBrowserKill'))
    }

    It 'is defined exactly once across the whole active tree' {
        $definitions = Select-String -Path (Join-Path $script:root 'main/*.ps1'), `
            (Join-Path $script:root 'WW_*.ps1'), (Join-Path $script:root 'admin/*.ps1') `
            -Pattern '^\s*function\s+Test-MainSkipCiscoBrowserKill\b' -ErrorAction SilentlyContinue
        @($definitions).Count | Should -Be 1
    }

    It 'is defined at FILE scope, not nested inside another function' {
        Get-CprTopLevelFunctionNames -Path $script:capPath | Should -Contain 'Test-MainSkipCiscoBrowserKill'
    }

    It 'is loaded before every file that calls it (walled garden AND remediation)' {
        $order = [regex]::Match($script:loaderSource, '\$mainFiles\s*=\s*@\(([\s\S]*?)\)').Groups[1].Value
        $capIndex   = $order.IndexOf('Main.CaptivePortal.ps1')
        $entryIndex = $order.IndexOf('Main.Entry.ps1')
        $capIndex   | Should -BeGreaterThan 0
        $capIndex   | Should -BeLessThan $entryIndex
    }

    It 'is called from BOTH the walled-garden branch and the remediation path' {
        $script:entrySource | Should -Match 'if \(Test-MainSkipCiscoBrowserKill\)'
        $script:capSource   | Should -Match 'if \(Test-MainSkipCiscoBrowserKill\)'
    }

    It 'resolves from inside the remediation function source itself' {
        # The live failure: the remediation path could not resolve the command.
        $remediation = Get-CprFunctionSource -Path $script:capPath -Names @('Invoke-CaptivePortalRemediation')
        $remediation | Should -Match 'Test-MainSkipCiscoBrowserKill'
        Get-Command Test-MainSkipCiscoBrowserKill -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'preserves semantics: base mode always skips the Cisco browser kill' {
        $global:CapPortalRunnerMode = 'base'
        $global:CapPortalSkipBrowserKill = $false   # even an explicit false
        Test-MainSkipCiscoBrowserKill | Should -BeTrue
    }

    It 'preserves semantics: full mode skips when true or undefined, kills only on explicit $false' {
        $global:CapPortalRunnerMode = 'full'
        Remove-Variable -Name CapPortalSkipBrowserKill -Scope Global -ErrorAction SilentlyContinue
        Test-MainSkipCiscoBrowserKill | Should -BeTrue          # undefined => skip
        $global:CapPortalSkipBrowserKill = $true
        Test-MainSkipCiscoBrowserKill | Should -BeTrue
        $global:CapPortalSkipBrowserKill = $false
        Test-MainSkipCiscoBrowserKill | Should -BeFalse         # legacy kill-then-Edge
    }

    AfterAll {
        Remove-Variable -Name CapPortalRunnerMode -Scope Global -ErrorAction SilentlyContinue
        Remove-Variable -Name CapPortalSkipBrowserKill -Scope Global -ErrorAction SilentlyContinue
    }
}

Describe 'Required A - audit: no other function is called from a path that cannot load it' {
    It 'declares every main/ function at file scope except deliberately private local helpers' {
        $allowedNested = @('Get-SelfUpdateNetworkState')  # only ever called inside its own parent
        foreach ($file in (Get-ChildItem -Path (Join-Path $script:root 'main') -Filter '*.ps1')) {
            $errors = $null; $tokens = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            $errors | Should -BeNullOrEmpty
            foreach ($fn in $ast.FindAll({
                    param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
                }, $true)) {
                $parent = $fn.Parent
                $nested = $false
                $owner = $null
                while ($parent) {
                    if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $nested = $true; $owner = $parent; break }
                    $parent = $parent.Parent
                }
                if (-not $nested) { continue }

                $allowedNested | Should -Contain $fn.Name
                # And a deliberately private helper must only be called from
                # within the function that defines it.
                $callers = Select-String -Path (Join-Path $script:root 'main/*.ps1') -Pattern ("\b{0}\b" -f $fn.Name)
                foreach ($hit in $callers) {
                    if ($hit.Line -match ('function\s+{0}\b' -f $fn.Name)) { continue }
                    $hit.Filename | Should -Be (Split-Path $file.FullName -Leaf)
                    $hit.LineNumber | Should -BeGreaterThan $owner.Extent.StartLineNumber
                    $hit.LineNumber | Should -BeLessThan $owner.Extent.EndLineNumber
                }
            }
        }
    }
}

# =============================================================================
# Required B - OrderedDictionary-safe key access
# =============================================================================
Describe 'Required B - safe map key access' {
    BeforeAll { . $script:commonPath }

    It 'handles a plain hashtable' {
        $map = @{ url = 'https://portal.example/welcome'; port = '443' }
        Test-CprMapKey -Map $map -Key 'url'     | Should -BeTrue
        Test-CprMapKey -Map $map -Key 'missing' | Should -BeFalse
        Get-CprMapValue -Map $map -Key 'port'   | Should -Be '443'
        Get-CprMapValue -Map $map -Key 'nope' -Default '' | Should -Be ''
    }

    It 'handles an ordered dictionary - which has Contains() but NOT ContainsKey()' {
        $map = [ordered]@{ url = 'https://cp-app.wifi.connected.xfinity.com/welcome'; port = '443' }
        $map.GetType().FullName | Should -Be 'System.Collections.Specialized.OrderedDictionary'
        { $map.ContainsKey('url') } | Should -Throw      # the live crash, reproduced
        Test-CprMapKey -Map $map -Key 'url'     | Should -BeTrue
        Test-CprMapKey -Map $map -Key 'missing' | Should -BeFalse
        Get-CprMapValue -Map $map -Key 'url'    | Should -Be 'https://cp-app.wifi.connected.xfinity.com/welcome'
    }

    It 'handles a PSCustomObject (ConvertFrom-Json artifact shape) and $null' {
        $obj = [pscustomobject]@{ url = 'https://portal/x'; port = 80 }
        Test-CprMapKey -Map $obj -Key 'port'  | Should -BeTrue
        Test-CprMapKey -Map $obj -Key 'other' | Should -BeFalse
        Get-CprMapValue -Map $obj -Key 'port' | Should -Be 80
        Test-CprMapKey -Map $null -Key 'url'  | Should -BeFalse
        Get-CprMapValue -Map $null -Key 'url' -Default 'fallback' | Should -Be 'fallback'
    }

    It 'treats a present-but-null value as absent for Get-CprMapValue' {
        Get-CprMapValue -Map ([ordered]@{ url = $null }) -Key 'url' -Default '' | Should -Be ''
    }

    It 'no active RC2 code probes an ordered dictionary with .ContainsKey()' {
        $offenders = @()
        foreach ($file in (Get-ChildItem -Path (Join-Path $script:root 'main') -Filter '*.ps1')) {
            $text = Get-Content $file.FullName -Raw
            if ($text -match '\$RedirectTelemetry\.ContainsKey|\$State\.ContainsKey|\$dispatch\w*\.ContainsKey|timing_contract\w*\.ContainsKey') {
                $offenders += $file.Name
            }
        }
        $offenders | Should -BeNullOrEmpty
    }

    It 'the outcome telemetry writer reads redirect fields through the safe accessor' {
        $writer = Get-CprFunctionSource -Path $script:capPath -Names @('Write-CaptivePortalOutcomeTelemetry')
        $writer | Should -Match 'Get-CprMapValue -Map \$RedirectTelemetry -Key ''url'''
        $writer | Should -Match 'Get-CprMapValue -Map \$RedirectTelemetry -Key ''port'''
        $writer | Should -Not -Match '\$RedirectTelemetry\.ContainsKey'
    }

    It 'the artifact writer tests its state map through the safe accessor' {
        $writer = Get-CprFunctionSource -Path $script:capPath -Names @('Write-CapPortalRemediationState')
        $writer | Should -Match 'Test-CprMapKey -Map \$State -Key ''timestamp'''
    }
}

# =============================================================================
# Required C - detection must reach dispatch (Event 778) and end cleanly
# =============================================================================
Describe 'Required C - redirect-detected base run reaches Event 778' {
    BeforeAll {
        . $script:commonPath

        # The REAL captive-portal functions under test.
        Invoke-Expression (Get-CprFunctionSource -Path $script:capPath -Names @(
            'Invoke-CaptivePortalRemediation'
            'Write-CaptivePortalOutcomeTelemetry'
            'Test-MainSkipCiscoBrowserKill'
            'Get-CaptivePortalRedirectTelemetry'
            'Get-CaptivePortalNetworkContext'
            'ConvertTo-TelemetryValue'
            'Test-CprAccepted301RemediationEvidence'
            'Get-CprPortalUrlFields'
            'Get-CprCiscoWebHelperQueryParameter'
            'Get-CprCiscoWebHelperQueryParameterAny'
            'Get-CapPortalDispatchContext'
            'Get-CapPortalBaseEscalationPolicy'
            'Get-CapPortalFlareEventId'
            'Write-CapPortalRemediationState'
            'Test-CaptivePortalCompatibility'
            'Get-CaptiveEventCount'
            'Add-CaptiveEvent'
            'Clear-CaptiveEventHistory'
            'Clear-CaptivePortalFlag'
        ))

        # Out-of-scope collaborators only.
        function global:Write-Log { param($Message, $Level = 'INFO') $global:CprLogLines += ,("[$Level] $Message") }
        function global:Write-TeeLog { param($Tag, $Data) $global:CprTeeTags += ,$Tag }
        function global:Send-FlareEvent { param($Tag) $global:CprFlares += ,$Tag }
        function global:In-Cooldown { param($Tag, $Minutes) return $false }
        function global:Start-CiscoBrowserKiller { }
        function global:Save-State { }
        function global:Show-CaptivePortalAlert { param($EventCount) }
        function global:Get-VpnState { return 'Disconnected' }
        function global:Test-VPNBlockingNetwork { param($VPNState, $RedirectDetected) return $false }
        function global:Test-CaptivePortalCleared { return $global:CprPortalCleared }
        function global:Get-FlareConfig { return [pscustomobject]@{ flare_events = [pscustomobject]@{
            captive_portal_browser_base = [pscustomobject]@{ event_id = 778 } } } }
        function global:Get-CaptivePortalResult {
            param([int]$TimeoutSeconds)
            $global:CprPortalCleared = $true
            return @{ status = 'SUCCESS'; details = 'runner reported success'; captive_browser_pid = 0 }
        }
    }

    BeforeEach {
        $global:CprLogLines = @()
        $global:CprTeeTags  = @()
        $global:CprFlares   = @()
        $global:CprPortalCleared = $false

        $script:workDir = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $script:workDir -Force | Out-Null

        # Run state mirroring the live xfinitywifi evidence.
        $global:CapPortalRunnerMode   = 'base'
        $global:CapPortalSkipBrowserKill = $true
        $global:CapPortalBaseAllowFullEscalation = $false
        $global:CapPortalBaseTimeoutSeconds   = 120
        $global:CapPortalBaseCheckIntervalSec = 10
        $global:CaptiveEventCooldown = 1
        $global:CaptiveEventLimit    = 3
        $global:CaptivePortalTimeout = 120
        $global:CapPortalWebHelper301MaxAgeSec = 180
        $global:LastWebHelper301Evidence = $null
        $global:RunId      = '20261015232812971-62488'
        $global:WhatIf     = $false
        $global:StateFile  = Join-Path $script:workDir 'state.json'
        $global:FlagFile   = Join-Path $script:workDir 'portal_complete.flag'
        $global:InterruptFile = Join-Path $script:workDir 'network_interrupt.flag'
        $global:CaptiveFailureFlag = Join-Path $script:workDir 'captive_failure.flag'
        $global:_state = [pscustomobject]@{ captiveEvents = @() }
        $global:RemediationStateFile = Join-Path $script:workDir 'cap_portal_remediation_active.flag'
        $global:networkInfo = [pscustomobject]@{
            SSID = 'xfinitywifi'; IPAddress = '172.20.20.20'; DefaultGateway = '172.20.20.1'
            DNSServers = @('75.75.75.75'); ConnectionType = 'WiFi'
        }
        $global:LastCapPreflightResult = [pscustomobject]@{
            ProbeUrl = 'https://gateway.optum.com'; Status = 'unreachable'
            Classification = 'INCONCLUSIVE'; RedirectUrl = ''; RedirectType = ''
            Protocol = ''; Fqdn = ''; Port = ''; HttpStatus = ''; ObservationTime = ''
            Reason = 'timeout'
        }
    }

    AfterEach {
        Remove-Item -LiteralPath $script:workDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'completes without throwing - no unresolved command, no OrderedDictionary failure' {
        { Invoke-CaptivePortalRemediation -PortalType 'NON_ISE' `
            -RedirectUrl 'https://cp-app.wifi.connected.xfinity.com/welcome?h=abc' } | Should -Not -Throw
    }

    It 'fires Event 778 (captive_portal_browser_base) in base mode' {
        Invoke-CaptivePortalRemediation -PortalType 'NON_ISE' `
            -RedirectUrl 'https://cp-app.wifi.connected.xfinity.com/welcome?h=abc' | Out-Null
        $global:CprFlares | Should -Contain 'captive_portal_browser_base'
        $global:CprFlares | Should -Contain 'captive_portal_non_ise'
        $global:CprFlares | Should -Not -Contain 'captive_portal_browser'
    }

    It 'logs no unresolved-command or OrderedDictionary error on the way to dispatch' {
        Invoke-CaptivePortalRemediation -PortalType 'NON_ISE' `
            -RedirectUrl 'https://cp-app.wifi.connected.xfinity.com/welcome?h=abc' | Out-Null
        ($global:CprLogLines -join "`n") | Should -Not -Match 'is not recognized'
        ($global:CprLogLines -join "`n") | Should -Not -Match 'ContainsKey'
        ($global:CprLogLines -join "`n") | Should -Not -Match '\[ERROR\]'
    }

    It 'writes the dispatch artifact BEFORE firing the flare' {
        Invoke-CaptivePortalRemediation -PortalType 'NON_ISE' `
            -RedirectUrl 'https://cp-app.wifi.connected.xfinity.com/welcome?h=abc' | Out-Null
        Test-Path $global:RemediationStateFile | Should -BeTrue
        $artifact = Get-Content $global:RemediationStateFile -Raw | ConvertFrom-Json
        $artifact.url | Should -Be 'https://cp-app.wifi.connected.xfinity.com/welcome?h=abc'
        $artifact.ssid | Should -Be 'xfinitywifi'
        $artifact.dispatch_context.event_id | Should -Be '778'
    }

    It 'emits the normalized redirect and outcome telemetry for the run' {
        Invoke-CaptivePortalRemediation -PortalType 'NON_ISE' `
            -RedirectUrl 'https://cp-app.wifi.connected.xfinity.com/welcome?h=abc' | Out-Null
        $global:CprTeeTags | Should -Contain 'cap_portal_redirect'
        $global:CprTeeTags | Should -Contain 'cap_portal_remediation_passed'
    }

    It 'returns success so the run ends normally instead of exit_reason="error_exception"' {
        $result = Invoke-CaptivePortalRemediation -PortalType 'NON_ISE' `
            -RedirectUrl 'https://cp-app.wifi.connected.xfinity.com/welcome?h=abc'
        $result | Should -BeTrue
        # error_exception is set ONLY by the orchestration catch block, which is
        # precisely what the two fatal errors used to trigger.
        $script:entrySource | Should -Match '\$script:exitReason = "error_exception"'
    }

    AfterAll {
        foreach ($name in @('CapPortalRunnerMode','CapPortalSkipBrowserKill','CapPortalBaseAllowFullEscalation',
                'networkInfo','LastCapPreflightResult','RunId','WhatIf')) {
            Remove-Variable -Name $name -Scope Global -ErrorAction SilentlyContinue
        }
    }
}
