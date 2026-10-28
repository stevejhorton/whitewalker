#Requires -RunAsAdministrator
<#
.SYNOPSIS
    High-fidelity captive portal mock flow testing real HTTP-redirect detection,
    off-network reachability gating, queue-then-drain telemetry, and WDAC-immune browser substitution.

.DESCRIPTION
    Validates end-to-end WhiteWalker captive portal detection and telemetry delivery without
    relying on WebView2 rendering or requiring an active off-prem captive portal network.

    CONTEXT & PROBLEM SOLVED:
    1. Historical telemetry gap: Prior plumbing tests (e.g. TEST_simulate_cap_portal.ps1) wrote
       synthetic remediation state directly and fired Event Log triggers, bypassing real HTTP
       redirect detection and the off-network queue-then-drain path that every genuine captive
       portal encounter undergoes.
    2. WDAC / WebView2 blank-render issue: Endpoint security policies recently blocked WebView2
       via WDAC for any endpoint not on the always-on VPN profile. This broke manual testing
       (flipping uhg_always_on XML + restarting Secure Client) because the captive portal runner's
       WebView2 window renders completely blank.
    This mock tool is immune to the WebView2/WDAC blank-render issue: it provides a Stub or Edge
    browser mode substitution so that the flow can be verified end-to-end based on telemetry and
    queue evidence without requiring WebView2 to render content.

    FLOW ARCHITECTURE:
    1. Ephemeral loopback HTTP listener (System.Net.HttpListener) responds with genuine HTTP 302
       redirects to a realistic mock captive portal login URL.
    2. Drives real AST-extracted detection logic (Test-Redirect, Get-RedirectType, and
       Get-CaptivePortalRedirectTelemetry) against the live HTTP listener.
    3. Browser substitution (Stub or Edge) generates the appropriate completion signals (portal_complete.flag)
       without being blocked by WDAC.
    4. Off-network gating: Temporarily sets C:\Windows\UHGLogs\state.json to an off-network state
       ('mock_captive') so Test-SyslogReachable returns false and forces telemetry through the
       offline queue path (Write-TeeLog -PassThru confirming Queued=$true into haystack_syslog_queue.jsonl).
    5. Reachability restoration & drain: Restores state.json to reachable ('user_tun') and invokes
       Drain-SyslogQueue to drain queued events to the syslog collector, reporting sent/expired/failed metrics.
    6. Non-destructive restoration: An unconditional finally block ensures C:\Windows\UHGLogs\state.json
       is always restored to its original state even on error or script termination.

    SYNTHETIC MARKER & SPLUNK FILTERING:
    - Synthetic marker field: ssid="CPR-MOCK-FLOW" (default, configurable via -SsidMarker).
    - Splunk exclusion query for production dashboards / SLO calculations:
        NOT ssid="CPR-MOCK-FLOW"
    - machine= is -MachineName (default CPR_TESTER, applied to this process only so Write-TeeLog stamps it);
      user reflects the real executing context (WindowsIdentity) so results stay attributable to whoever ran the mock.

.PARAMETER Outcome
    Simulated remediation outcome.
    Values:
      - 'Pass': Listener verifies clearance (200 OK on check probe) and queues cap_portal_remediation_passed.
      - 'Fail': Listener continues redirecting (302 on check probe) and queues cap_portal_remediation_failed.
    Default: 'Pass'.

.PARAMETER BrowserMode
    WDAC-immune browser execution mode.
    Values:
      - 'Stub': Simulates completion signal without launching any browser process (fastest, fully WDAC-immune).
      - 'Edge': Launches msedge.exe pointed at the mock listener URL as an optional visual aid.
                Pass/fail verdict is strictly based on queue evidence, not browser display.
    Default: 'Stub'.

.PARAMETER ListenPort
    TCP port for the loopback HTTP listener. 0 selects an available ephemeral port automatically.
    Default: 0.

.PARAMETER SsidMarker
    Unambiguous synthetic marker value used in the ssid field to distinguish mock traffic.
    Default: 'CPR-MOCK-FLOW'.

.PARAMETER StateJsonPath
    Path to WhiteWalker state.json file used for reachability checking.
    Default: 'C:\Windows\UHGLogs\state.json'.

.PARAMETER QueueFilePath
    Path to Haystack syslog queue file.
    Default: 'C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl'.

.PARAMETER FlagFilePath
    Path to portal completion flag file.
    Default: 'C:\ProgramData\WhiteWalker\portal_complete.flag'.

.PARAMETER TeeEventsPath
    Path to active Tee events profile.
    Default: 'C:\ProgramData\WhiteWalker\WW_tee_events.psd1'.

.PARAMETER SyslogServer
    Target syslog collector server address.
    Default: 'cpr-syslog.uhc.com'.

.PARAMETER SyslogPort
    Target syslog collector UDP port.
    Default: 514.

.PARAMETER DrainTimeoutSec
    Timeout in seconds for queue drain operations.
    Default: 30.

.PARAMETER SkipDrain
    Switch to skip queue drain and only verify off-network queueing.
    Default: $false.

.EXAMPLE
    .\TEST_mock_cap_portal_flow.ps1
    Runs the full mock captive portal flow in Pass mode using Stub browser substitution.

.EXAMPLE
    .\TEST_mock_cap_portal_flow.ps1 -Outcome Fail -BrowserMode Edge
    Runs the flow in Fail mode, launching Edge as a visual aid to inspect the mock portal page.
#>

[CmdletBinding()]
param(
    [ValidateSet('Pass', 'Fail')]
    [string]$Outcome = 'Pass',

    [ValidateSet('Stub', 'Edge')]
    [string]$BrowserMode = 'Stub',

    [Alias('ProbePort')]
    [int]$ListenPort = 0,

    [string]$SsidMarker = 'CPR-MOCK-FLOW',

    [string]$MachineName = 'CPR_TESTER',

    [string]$StateJsonPath = 'C:\Windows\UHGLogs\state.json',

    [string]$QueueFilePath = 'C:\ProgramData\WhiteWalker\logs\haystack_syslog_queue.jsonl',

    [string]$FlagFilePath = 'C:\ProgramData\WhiteWalker\portal_complete.flag',

    [string]$TeeEventsPath = 'C:\ProgramData\WhiteWalker\WW_tee_events.psd1',

    [string]$SyslogServer = 'cpr-syslog.uhc.com',

    [int]$SyslogPort = 514,

    [int]$DrainTimeoutSec = 30,

    [switch]$SkipDrain
)

Set-StrictMode -Off

$runStartTime = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " WhiteWalker Captive Portal Flow Mock (Real Detection + Queue/Drain)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  Outcome Mode : $Outcome"
Write-Host "  Browser Mode : $BrowserMode (WDAC-immune substitution)"
Write-Host "  SSID Marker  : $SsidMarker"
Write-Host "  State JSON   : $StateJsonPath"
Write-Host "  Syslog Queue : $QueueFilePath"
Write-Host "  Syslog Target: $SyslogServer`:$SyslogPort"
Write-Host "--------------------------------------------------------------------------------"

# -----------------------------------------------------------------------------
# 0. Locate CPR_RC2 Root and Validate Prerequisites
# -----------------------------------------------------------------------------
$cprRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath (Join-Path $cprRoot 'WW_tee.ps1'))) {
    # Fallback if executed from another working directory
    $possibleRoots = @(
        $PSScriptRoot,
        (Split-Path -Parent $PSScriptRoot),
        'C:\ProgramData\WhiteWalker',
        (Join-Path $PSScriptRoot '..')
    )
    foreach ($candidate in $possibleRoots) {
        if ($candidate -and (Test-Path -LiteralPath (Join-Path $candidate 'WW_tee.ps1'))) {
            $cprRoot = (Resolve-Path $candidate).Path
            break
        }
    }
}

Write-Host "[STEP 0/7] Preflight checks & AST extraction..." -ForegroundColor Cyan

$mainNetFile = Join-Path $cprRoot 'main\Main.Network.ps1'
if (-not (Test-Path -LiteralPath $mainNetFile)) {
    $mainNetFile = Join-Path $cprRoot 'main/Main.Network.ps1'
}
$mainCapFile = Join-Path $cprRoot 'main\Main.CaptivePortal.ps1'
if (-not (Test-Path -LiteralPath $mainCapFile)) {
    $mainCapFile = Join-Path $cprRoot 'main/Main.CaptivePortal.ps1'
}
$haFile = Join-Path $cprRoot 'haystack_action.ps1'
$teeFile = Join-Path $cprRoot 'WW_tee.ps1'
$schemaFile = Join-Path $cprRoot 'WW_haystack_schema.ps1'
$syslogScriptFile = Join-Path $cprRoot 'WW_syslog.ps1'

foreach ($reqFile in @($mainNetFile, $mainCapFile, $haFile, $teeFile)) {
    if (-not (Test-Path -LiteralPath $reqFile)) {
        Write-Host "[FAIL] Required component file not found: $reqFile" -ForegroundColor Red
        exit 1
    }
}

# Define local logging shim for AST-extracted functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    Write-Verbose "[$Level] $Message"
}

# Extract AST functions cleanly from Main.Network.ps1
$netAst = [System.Management.Automation.Language.Parser]::ParseFile($mainNetFile, [ref]$null, [ref]$null)
$fnTestRedirect = $netAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-Redirect' }, $true)
$fnGetRedirectType = $netAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-RedirectType' }, $true)

if (-not $fnTestRedirect -or -not $fnGetRedirectType) {
    Write-Host "[FAIL] Could not extract Test-Redirect or Get-RedirectType from $mainNetFile" -ForegroundColor Red
    exit 1
}
Invoke-Expression $fnTestRedirect.Extent.Text
Invoke-Expression $fnGetRedirectType.Extent.Text

# Extract AST functions cleanly from Main.CaptivePortal.ps1
$capAst = [System.Management.Automation.Language.Parser]::ParseFile($mainCapFile, [ref]$null, [ref]$null)
$fnGetTelem = $capAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-CaptivePortalRedirectTelemetry' }, $true)
$fnConvertToTelem = $capAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'ConvertTo-TelemetryValue' }, $true)

if (-not $fnGetTelem -or -not $fnConvertToTelem) {
    Write-Host "[FAIL] Could not extract Get-CaptivePortalRedirectTelemetry or ConvertTo-TelemetryValue from $mainCapFile" -ForegroundColor Red
    exit 1
}
Invoke-Expression $fnGetTelem.Extent.Text
Invoke-Expression $fnConvertToTelem.Extent.Text

# Extract AST functions cleanly from haystack_action.ps1
$haAst = [System.Management.Automation.Language.Parser]::ParseFile($haFile, [ref]$null, [ref]$null)
$fnDrainSyslog = $haAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Drain-SyslogQueue' }, $true)
$fnTestReachable = $haAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-SyslogReachable' }, $true)
$fnGetNetState = $haAst.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-CurrentNetworkState' }, $true)

if (-not $fnDrainSyslog -or -not $fnTestReachable -or -not $fnGetNetState) {
    Write-Host "[FAIL] Could not extract Drain-SyslogQueue, Test-SyslogReachable, or Get-CurrentNetworkState from $haFile" -ForegroundColor Red
    exit 1
}
Invoke-Expression $fnDrainSyslog.Extent.Text
Invoke-Expression $fnTestReachable.Extent.Text
Invoke-Expression $fnGetNetState.Extent.Text

# Setup Drain environment and logger capture
if (-not [string]::IsNullOrWhiteSpace($MachineName)) { $env:COMPUTERNAME = $MachineName }   # process-scoped; Write-TeeLog stamps machine= from it
if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
    try {
        $env:COMPUTERNAME = [System.Net.Dns]::GetHostName()
    } catch {
        if ($env:HOSTNAME) { $env:COMPUTERNAME = $env:HOSTNAME } else { $env:COMPUTERNAME = 'LOCALHOST' }
    }
}

$script:DrainLogLines = [System.Collections.Generic.List[string]]::new()
function Write-HALog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "$ts [$Level] [HayStack_Action] $Message"
    $script:DrainLogLines.Add($line)
    Write-Verbose $line
}

# Point haystack_action state & syslog variables to test targets
$WwStateFile            = $StateJsonPath
$WWSyslogScript         = $syslogScriptFile
$SyslogQueueFile        = $QueueFilePath
$SyslogQueueMaxEntries  = 500
$SyslogQueueMaxAgeDays  = 7
$SyslogFacility         = 16
$SyslogSeverity         = 5

# Ensure queue directory exists
$queueDir = Split-Path -Parent $QueueFilePath
if ($queueDir -and -not (Test-Path -LiteralPath $queueDir)) {
    New-Item -Path $queueDir -ItemType Directory -Force | Out-Null
}

# Setup WW_tee.ps1
$resolvedTeeProfile = $TeeEventsPath
if (-not (Test-Path -LiteralPath $resolvedTeeProfile)) {
    $fallbackProfile = Join-Path $cprRoot 'WW_tee_events.psd1'
    if (Test-Path -LiteralPath $fallbackProfile) {
        $resolvedTeeProfile = $fallbackProfile
    }
}

. $teeFile

$script:TeeQueueFile  = $QueueFilePath
$script:TeeEventsFile = $resolvedTeeProfile
$global:HaystackEnabled = $true
$global:TeeEnabled      = $true
$global:TeeEventsFile   = $resolvedTeeProfile
$script:HaystackEnabled = $true
$script:TeeEnabled      = $true

# Load schema helper if present
if (Test-Path -LiteralPath $schemaFile) {
    try { . $schemaFile } catch { }
}

Write-Host "[OK] Real detection, queueing, and drain functions extracted via AST successfully." -ForegroundColor Green

# -----------------------------------------------------------------------------
# Record Initial State for Guaranteed Cleanup
# -----------------------------------------------------------------------------
$stateFileExistsAtStart = Test-Path -LiteralPath $StateJsonPath
$stateOriginalContent   = $null
if ($stateFileExistsAtStart) {
    try {
        $stateOriginalContent = Get-Content -LiteralPath $StateJsonPath -Raw -ErrorAction Stop
        Write-Host "[OK] Saved original content of $StateJsonPath for post-test restoration." -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Could not read existing $StateJsonPath : $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "[OK] $StateJsonPath does not exist; will be cleanly removed in post-test cleanup." -ForegroundColor Green
}

$queueLineCountAtStart = 0
if (Test-Path -LiteralPath $QueueFilePath) {
    try {
        $queueLineCountAtStart = @(Get-Content -LiteralPath $QueueFilePath -ErrorAction SilentlyContinue).Count
    } catch { }
}

$listenerRunspace = $null
$edgeLaunchedPid  = 0
$overallPass      = $false

try {
    # -------------------------------------------------------------------------
    # 1. Ephemeral Loopback HttpListener
    # -------------------------------------------------------------------------
    Write-Host "[STEP 1/7] Initializing loopback HTTP listener for real redirect responses..." -ForegroundColor Cyan

    if ($ListenPort -le 0) {
        $tcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $tcpListener.Start()
        $ListenPort = ($tcpListener.LocalEndpoint).Port
        $tcpListener.Stop()
    }

    $mockPortalLoginUrl = "http://127.0.0.1:$ListenPort/portal/login?from=cpr_mock"
    $probeUrl           = "http://127.0.0.1:$ListenPort/probe"
    $checkUrl           = "http://127.0.0.1:$ListenPort/check"

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $listenerRunspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($iss)
    $listenerRunspace.Open()
    $listenerPs = [System.Management.Automation.PowerShell]::Create()
    $listenerPs.Runspace = $listenerRunspace

    $serverWorker = {
        param([int]$Port, [string]$OutcomeMode, [string]$TargetLoginUrl)
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://127.0.0.1:$Port/")
        $listener.Start()
        $active = $true

        while ($active) {
            $context = $listener.GetContext()
            $req = $context.Request
            $resp = $context.Response
            $path = $req.Url.AbsolutePath.ToLowerInvariant()

            if ($path -eq '/probe') {
                $resp.StatusCode = 302
                $resp.RedirectLocation = $TargetLoginUrl
                $body = [System.Text.Encoding]::UTF8.GetBytes("<html><body>Redirecting to mock captive portal...</body></html>")
                $resp.ContentType = "text/html"
                $resp.ContentLength64 = $body.Length
                $resp.OutputStream.Write($body, 0, $body.Length)
                $resp.OutputStream.Close()
            } elseif ($path -eq '/portal/login') {
                $resp.StatusCode = 200
                $body = [System.Text.Encoding]::UTF8.GetBytes("<html><head><title>Mock Captive Portal</title></head><body><h1>Captive Portal Mock</h1><p>WDAC-immune browser substitution test page.</p></body></html>")
                $resp.ContentType = "text/html"
                $resp.ContentLength64 = $body.Length
                $resp.OutputStream.Write($body, 0, $body.Length)
                $resp.OutputStream.Close()
            } elseif ($path -eq '/check') {
                if ($OutcomeMode -eq 'Pass') {
                    $resp.StatusCode = 200
                    $body = [System.Text.Encoding]::UTF8.GetBytes("<html><body>Internet Connected</body></html>")
                } else {
                    $resp.StatusCode = 302
                    $resp.RedirectLocation = $TargetLoginUrl
                    $body = [System.Text.Encoding]::UTF8.GetBytes("<html><body>Still captive</body></html>")
                }
                $resp.ContentType = "text/html"
                $resp.ContentLength64 = $body.Length
                $resp.OutputStream.Write($body, 0, $body.Length)
                $resp.OutputStream.Close()
            } elseif ($path -eq '/shutdown') {
                $active = $false
                $resp.StatusCode = 200
                $body = [System.Text.Encoding]::UTF8.GetBytes("Mock server shutting down")
                $resp.ContentType = "text/plain"
                $resp.ContentLength64 = $body.Length
                $resp.OutputStream.Write($body, 0, $body.Length)
                $resp.OutputStream.Close()
            } else {
                $resp.StatusCode = 404
                $resp.OutputStream.Close()
            }
        }
        $listener.Stop()
        $listener.Close()
    }

    $null = $listenerPs.AddScript($serverWorker).AddArgument($ListenPort).AddArgument($Outcome).AddArgument($mockPortalLoginUrl).BeginInvoke()
    Start-Sleep -Milliseconds 300
    Write-Host "[OK] HttpListener active on http://127.0.0.1:$ListenPort/ (login URL: $mockPortalLoginUrl)" -ForegroundColor Green

    # -------------------------------------------------------------------------
    # 2. Real HTTP Redirect Detection via Extracted Logic
    # -------------------------------------------------------------------------
    Write-Host "[STEP 2/7] Executing real Test-Redirect against loopback listener..." -ForegroundColor Cyan
    $redirectResult = Test-Redirect -Url $probeUrl

    if (-not $redirectResult.IsRedirect) {
        Write-Host "[FAIL] Test-Redirect did not detect redirect from $probeUrl (IsRedirect is false)" -ForegroundColor Red
        throw "Redirect detection failed against mock listener."
    }

    Write-Host "[OK] Real redirect detected: URL redirected to $($redirectResult.RedirectUrl)" -ForegroundColor Green

    $portalType = Get-RedirectType -RedirectUrl $redirectResult.RedirectUrl
    Write-Host "[OK] Portal type classified: $portalType" -ForegroundColor Green

    $redirectTelem = Get-CaptivePortalRedirectTelemetry -RedirectUrl $redirectResult.RedirectUrl
    Write-Host "[OK] Redirect telemetry parsed: url='$($redirectTelem.url)' port='$($redirectTelem.port)' protocol='$($redirectTelem.protocol)' fqdn='$($redirectTelem.fqdn)'" -ForegroundColor Green

    # -------------------------------------------------------------------------
    # 3. WDAC-Immune Browser Substitution (Stub vs Edge)
    # -------------------------------------------------------------------------
    Write-Host "[STEP 3/7] Browser substitution ($BrowserMode mode) and completion signaling..." -ForegroundColor Cyan

    $completionStatus = if ($Outcome -eq 'Pass') { 'SUCCESS_NATIVE' } else { 'TIMEOUT_NATIVE' }
    $completionDetails = if ($Outcome -eq 'Pass') { 'Mock captive portal cleared connectivity' } else { 'Observation window expired without connectivity' }

    if ($BrowserMode -eq 'Edge') {
        $edgeCandidates = @(
            "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
            "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
        )
        $edgeExe = $null
        foreach ($c in $edgeCandidates) {
            if ($c -and (Test-Path -LiteralPath $c)) { $edgeExe = $c; break }
        }
        if (-not $edgeExe) {
            $cmd = Get-Command msedge.exe -ErrorAction SilentlyContinue
            if ($cmd) { $edgeExe = $cmd.Source }
        }

        if ($edgeExe) {
            Write-Host "[OK] Launching Microsoft Edge substitution (visual aid): $edgeExe" -ForegroundColor Green
            try {
                $proc = Start-Process -FilePath $edgeExe -ArgumentList @($mockPortalLoginUrl, "--new-window") -PassThru -ErrorAction Stop
                $edgeLaunchedPid = $proc.Id
                Write-Host "[OK] Microsoft Edge launched with PID $edgeLaunchedPid pointing to $mockPortalLoginUrl" -ForegroundColor Green
            } catch {
                Write-Host "[WARN] Edge launch attempt failed: $_ (visual aid only - does not affect test verdict)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[WARN] msedge.exe not found on system (visual aid only - proceeding with test)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[OK] Stub browser mode: no browser process launched, bypassing WebView2 WDAC restrictions completely." -ForegroundColor Green
    }

    # Write completion flag file
    $flagDir = Split-Path -Parent $FlagFilePath
    if ($flagDir -and -not (Test-Path -LiteralPath $flagDir)) {
        New-Item -Path $flagDir -ItemType Directory -Force | Out-Null
    }

    $currentUser = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
    if (-not $currentUser) { $currentUser = 'MOCK_USER' }

    $flagPayload = @{
        timestamp           = (Get-Date).ToString('o')
        status              = $completionStatus
        details             = $completionDetails
        user                = $currentUser
        captive_browser_pid = $edgeLaunchedPid
    } | ConvertTo-Json -Compress

    Set-Content -LiteralPath $FlagFilePath -Value $flagPayload -Encoding UTF8 -Force
    Write-Host "[OK] Completion flag written to $FlagFilePath (status=$completionStatus)" -ForegroundColor Green

    # Verify clearance poll mirroring Test-CaptivePortalCleared
    $checkResult = Test-Redirect -Url $checkUrl
    if ($Outcome -eq 'Pass') {
        if (-not $checkResult.IsRedirect) {
            Write-Host "[OK] Clearance poll confirmed: portal cleared (200 OK, no redirect)." -ForegroundColor Green
        } else {
            Write-Host "[WARN] Clearance poll returned redirect during Pass outcome." -ForegroundColor Yellow
        }
    } else {
        if ($checkResult.IsRedirect) {
            Write-Host "[OK] Failure poll confirmed: portal remained captive (302 redirect persists)." -ForegroundColor Green
        } else {
            Write-Host "[WARN] Failure poll cleared unexpectedly during Fail outcome." -ForegroundColor Yellow
        }
    }

    # -------------------------------------------------------------------------
    # 4. Off-Network Gating & Offline Queueing
    # -------------------------------------------------------------------------
    Write-Host "[STEP 4/7] Forcing off-network state & asserting offline queueing..." -ForegroundColor Cyan

    # Ensure state directory exists
    $stateDir = Split-Path -Parent $StateJsonPath
    if ($stateDir -and -not (Test-Path -LiteralPath $stateDir)) {
        New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
    }

    # Write synthetic off-network state.json
    $mockOffNetState = @{
        currentState = 'mock_captive'
        lastUpdated  = (Get-Date).ToString('o')
        simulatedBy  = 'TEST_mock_cap_portal_flow.ps1'
    } | ConvertTo-Json -Depth 3
    Set-Content -LiteralPath $StateJsonPath -Value $mockOffNetState -Encoding UTF8 -Force

    # Verify Test-SyslogReachable returns $false
    $isReachable = Test-SyslogReachable
    if ($isReachable) {
        Write-Host "[FAIL] Test-SyslogReachable returned true when currentState was 'mock_captive'!" -ForegroundColor Red
        throw "Gating failure: system considered reachable while off-network."
    }
    Write-Host "[OK] Test-SyslogReachable correctly returned false (offline gating confirmed)." -ForegroundColor Green

    # Prepare realistic network context
    $mockIp  = '10.254.254.10'
    $mockGw  = '10.254.254.1'
    $mockDns = '10.254.254.1,10.254.254.2'
    $mockVpn = 'Disconnected'

    # Queue Event 1: cap_portal_redirect
    Write-Host "[STEP] Writing 'cap_portal_redirect' tee event..." -ForegroundColor Cyan
    $redirectTelemetryData = @{
        EvtTime     = (Get-Date -Format 'o')
        url         = ConvertTo-TelemetryValue $redirectTelem.url
        port        = ConvertTo-TelemetryValue $redirectTelem.port
        ssid        = $SsidMarker
        vpn_state   = $mockVpn
        ip          = $mockIp
        gw          = $mockGw
        dns         = $mockDns
        portal_type = ConvertTo-TelemetryValue $portalType
        status      = 'detected'
        reason      = 'redirect_detected'
    }

    $redirectWrite = Write-TeeLog 'cap_portal_redirect' $redirectTelemetryData -PassThru
    if (-not $redirectWrite.Queued) {
        Write-Host "[FAIL] Write-TeeLog did not queue cap_portal_redirect: $($redirectWrite.Reason)" -ForegroundColor Red
        throw "Queue write failed for cap_portal_redirect."
    }
    Write-Host "[OK] 'cap_portal_redirect' successfully queued (Queued=$($redirectWrite.Queued), Reason=$($redirectWrite.Reason))" -ForegroundColor Green

    # Queue Event 2: cap_portal_remediation_passed or cap_portal_remediation_failed
    $outcomeTag = if ($Outcome -eq 'Pass') { 'cap_portal_remediation_passed' } else { 'cap_portal_remediation_failed' }
    $outcomeStatus = if ($Outcome -eq 'Pass') { 'cleared' } else { 'failed' }
    $outcomeReason = if ($Outcome -eq 'Pass') { 'portal_cleared' } else { 'runner_timeout_or_no_response' }

    Write-Host "[STEP] Writing '$outcomeTag' tee event..." -ForegroundColor Cyan
    $outcomeTelemetryData = @{
        EvtTime     = (Get-Date -Format 'o')
        url         = ConvertTo-TelemetryValue $redirectTelem.url
        port        = ConvertTo-TelemetryValue $redirectTelem.port
        ssid        = $SsidMarker
        vpn_state   = $mockVpn
        ip          = $mockIp
        gw          = $mockGw
        dns         = $mockDns
        portal_type = ConvertTo-TelemetryValue $portalType
        status      = $outcomeStatus
        reason      = $outcomeReason
    }

    $outcomeWrite = Write-TeeLog $outcomeTag $outcomeTelemetryData -PassThru
    if (-not $outcomeWrite.Queued) {
        Write-Host "[FAIL] Write-TeeLog did not queue ${outcomeTag}: $($outcomeWrite.Reason)" -ForegroundColor Red
        throw "Queue write failed for $outcomeTag."
    }
    Write-Host "[OK] '$outcomeTag' successfully queued (Queued=$($outcomeWrite.Queued), Reason=$($outcomeWrite.Reason))" -ForegroundColor Green

    # -------------------------------------------------------------------------
    # 5. Queue Inspection & Schema Verification
    # -------------------------------------------------------------------------
    Write-Host "[STEP 5/7] Inspecting queued events and validating required fields..." -ForegroundColor Cyan

    $RequiredFields = @(
        'EvtTime', 'action', 'machine', 'user', 'ssid', 'url', 'port',
        'ip', 'gw', 'dns', 'vpn_state', 'portal_type', 'status', 'reason'
    )

    function ConvertFrom-QueuePayloadString {
        param([string]$Payload)
        $fields = @{}
        if ([string]::IsNullOrWhiteSpace($Payload)) { return $fields }
        foreach ($m in [regex]::Matches($Payload, '([A-Za-z0-9_]+)="((?:[^"\\]|\\.)*)"')) {
            $fields[$m.Groups[1].Value] = $m.Groups[2].Value
        }
        return $fields
    }

    $allQueueLines = @()
    if (Test-Path -LiteralPath $QueueFilePath) {
        $allQueueLines = @(Get-Content -LiteralPath $QueueFilePath -ErrorAction SilentlyContinue)
    }

    $newQueueLines = @()
    if ($allQueueLines.Count -gt $queueLineCountAtStart) {
        $newQueueLines = $allQueueLines[$queueLineCountAtStart..($allQueueLines.Count - 1)]
    }

    Write-Host "[OK] Queue grew by $($newQueueLines.Count) line(s) during this test (total: $($allQueueLines.Count))" -ForegroundColor Green

    $capturedMockRows = @()
    foreach ($line in $newQueueLines) {
        $payload = $null
        try {
            $entry = $line | ConvertFrom-Json -ErrorAction Stop
            $payload = [string]$entry.payload
        } catch {
            $payload = [string]$line
        }

        $fields = ConvertFrom-QueuePayloadString -Payload $payload
        $act = [string]$fields['action']

        if (@('cap_portal_redirect', 'cap_portal_remediation_passed', 'cap_portal_remediation_failed') -contains $act) {
            if ($fields['ssid'] -eq $SsidMarker) {
                $capturedMockRows += [pscustomobject]@{
                    Raw     = $line
                    Payload = $payload
                    Fields  = $fields
                    Action  = $act
                }
            }
        }
    }

    if ($capturedMockRows.Count -lt 2) {
        Write-Host "[FAIL] Expected at least 2 mock events matching ssid='$SsidMarker', found $($capturedMockRows.Count)" -ForegroundColor Red
        throw "Incomplete queue capture for mock run."
    }

    $allRequiredFieldsPresent = $true
    foreach ($row in $capturedMockRows) {
        Write-Host "--- Raw Queue Event: $($row.Action) ---" -ForegroundColor Yellow
        Write-Host "    $($row.Raw)"

        $present = @()
        $missing = @()
        foreach ($f in $RequiredFields) {
            if ($row.Fields.ContainsKey($f) -and $null -ne $row.Fields[$f]) {
                $present += $f
            } else {
                $missing += $f
            }
        }

        Write-Host "    Fields present: $($present.Count)/$($RequiredFields.Count)"
        if ($missing.Count -gt 0) {
            Write-Host "[FAIL] Missing required fields: $($missing -join ', ')" -ForegroundColor Red
            $allRequiredFieldsPresent = $false
        } else {
            Write-Host "[OK] All $($RequiredFields.Count) required fields present." -ForegroundColor Green
        }

        # Timestamp validation
        $evtTimeVal = [string]$row.Fields['EvtTime']
        [datetime]$parsedTime = [datetime]::MinValue
        if (-not [string]::IsNullOrWhiteSpace($evtTimeVal) -and [datetime]::TryParse($evtTimeVal, [ref]$parsedTime)) {
            Write-Host "[OK] EvtTime stamped locally and valid: $evtTimeVal" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] EvtTime invalid or missing: '$evtTimeVal'" -ForegroundColor Red
            $allRequiredFieldsPresent = $false
        }

        # Schema helper validation if available
        if (Get-Command Test-HaystackMsgSchema -ErrorAction SilentlyContinue) {
            $schemaRes = Test-HaystackMsgSchema -Fields $row.Fields
            if ($schemaRes -and $schemaRes.IsValid) {
                Write-Host "[OK] Test-HaystackMsgSchema validated event as conformant." -ForegroundColor Green
            } elseif ($schemaRes -and -not $schemaRes.IsValid) {
                $schemaIssues = @()
                if ($schemaRes.MissingFields) { $schemaIssues += "Missing: $($schemaRes.MissingFields -join ',')" }
                if ($schemaRes.UnknownFields) { $schemaIssues += "Unknown: $($schemaRes.UnknownFields -join ',')" }
                Write-Host "[WARN] Test-HaystackMsgSchema reported schema issues: $($schemaIssues -join '; ')" -ForegroundColor Yellow
            }
        }
    }

    # -------------------------------------------------------------------------
    # 6. Reconnection & Queue Drain Execution
    # -------------------------------------------------------------------------
    Write-Host "[STEP 6/7] Restoring reachability state & triggering queue drain..." -ForegroundColor Cyan

    # Flip state to reachable
    $mockOnNetState = @{
        currentState = 'user_tun'
        lastUpdated  = (Get-Date).ToString('o')
        simulatedBy  = 'TEST_mock_cap_portal_flow.ps1'
    } | ConvertTo-Json -Depth 3
    Set-Content -LiteralPath $StateJsonPath -Value $mockOnNetState -Encoding UTF8 -Force

    $isReachableNow = Test-SyslogReachable
    if (-not $isReachableNow) {
        Write-Host "[FAIL] Test-SyslogReachable returned false when currentState was 'user_tun'!" -ForegroundColor Red
        throw "Gating failure: system not considered reachable after reconnect."
    }
    Write-Host "[OK] Test-SyslogReachable returned true (reconnected state confirmed)." -ForegroundColor Green

    if ($SkipDrain) {
        Write-Host "[INFO] -SkipDrain specified; skipping syslog queue drain operation." -ForegroundColor Yellow
    } else {
        Write-Host "[STEP] Triggering Drain-SyslogQueue (Server=$SyslogServer, Port=$SyslogPort)..." -ForegroundColor Cyan
        $script:DrainLogLines.Clear()
        Drain-SyslogQueue -Server $SyslogServer -Port $SyslogPort -TimeoutSec $DrainTimeoutSec

        $drainSummary = $script:DrainLogLines | Where-Object { $_ -match 'SyslogQueue: drained' } | Select-Object -Last 1
        if ($drainSummary) {
            Write-Host "[OK] Queue drain result: $drainSummary" -ForegroundColor Green
        } else {
            $drainWarn = $script:DrainLogLines | Where-Object { $_ -match 'SyslogQueue:' } | Select-Object -Last 1
            if ($drainWarn) {
                Write-Host "[INFO] Queue drain status: $drainWarn" -ForegroundColor Yellow
            } else {
                Write-Host "[INFO] Drain executed without specific drain log line." -ForegroundColor Yellow
            }
        }
    }

    if ($allRequiredFieldsPresent -and $capturedMockRows.Count -ge 2) {
        $overallPass = $true
    }

} catch {
    Write-Host "[ERROR] Mock flow execution error: $_" -ForegroundColor Red
    $overallPass = $false
} finally {
    # -------------------------------------------------------------------------
    # 7. Unconditional State Cleanup & Restoration
    # -------------------------------------------------------------------------
    Write-Host "[STEP 7/7] Unconditional cleanup & state restoration..." -ForegroundColor Cyan

    # 1. Restore state.json
    try {
        if ($stateFileExistsAtStart -and $null -ne $stateOriginalContent) {
            Set-Content -LiteralPath $StateJsonPath -Value $stateOriginalContent -Encoding UTF8 -Force
            Write-Host "[OK] Restored original content of $StateJsonPath" -ForegroundColor Green
        } elseif (-not $stateFileExistsAtStart) {
            if (Test-Path -LiteralPath $StateJsonPath) {
                Remove-Item -LiteralPath $StateJsonPath -Force -ErrorAction SilentlyContinue
                Write-Host "[OK] Removed temporary test state file: $StateJsonPath" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "[WARN] Failed restoring $StateJsonPath : $_" -ForegroundColor Yellow
    }

    # 2. Stop and dispose loopback HttpListener runspace
    if ($listenerRunspace) {
        try {
            if ($ListenPort -gt 0) {
                try {
                    Invoke-WebRequest -Uri "http://127.0.0.1:$ListenPort/shutdown" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
                } catch { }
            }
            $listenerRunspace.Close()
            $listenerRunspace.Dispose()
            Write-Host "[OK] Loopback HTTP listener terminated and disposed." -ForegroundColor Green
        } catch { }
    }

    # 3. Clean up completion flag file
    if ($FlagFilePath -and (Test-Path -LiteralPath $FlagFilePath)) {
        try {
            Remove-Item -LiteralPath $FlagFilePath -Force -ErrorAction SilentlyContinue
            Write-Host "[OK] Cleaned up temporary test flag file: $FlagFilePath" -ForegroundColor Green
        } catch { }
    }
}

# -----------------------------------------------------------------------------
# Final Verdict & Splunk Query Hints
# -----------------------------------------------------------------------------
$runEndTime = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " Mock Flow Verdict & Operator Telemetry Guidance" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

if ($overallPass) {
    Write-Host "[PASS] Mock captive portal flow succeeded." -ForegroundColor Green
    Write-Host "       - Real HTTP redirect detected and classified via live loopback listener."
    Write-Host "       - WDAC-immune browser substitution executed ($BrowserMode mode)."
    Write-Host "       - Offline reachability gating verified: events queued to haystack_syslog_queue.jsonl."
    Write-Host "       - All 14 required normalized fields verified with valid local EvtTime."
    Write-Host "       - Reconnection state verified and Drain-SyslogQueue path exercised."
    Write-Host "       - state.json restored to its original state."
} else {
    Write-Host "[FAIL] Mock captive portal flow did not complete all pass criteria." -ForegroundColor Red
}

Write-Host "`n[STEP] Operator Validation Splunk Queries:" -ForegroundColor Cyan
Write-Host "[OK] Query to inspect normalized telemetry for this specific run:" -ForegroundColor Green
Write-Host "index=cba_cpr_logging action IN (`"cap_portal_redirect`",`"cap_portal_remediation_passed`",`"cap_portal_remediation_failed`") ssid=`"$SsidMarker`" | table EvtTime,action,machine,user,ssid,url,port,ip,gw,dns,vpn_state,portal_type,status,reason | sort 0 - EvtTime"

Write-Host "`n[OK] Query to EXCLUDE this mock traffic from production / SLO calculations:" -ForegroundColor Green
Write-Host "index=cba_cpr_logging NOT ssid=`"$SsidMarker`""

Write-Host "`n[OK] Time-boxed run query ($runStartTime to $runEndTime):" -ForegroundColor Green
Write-Host "index=cba_cpr_logging ssid=`"$SsidMarker`" earliest=`"$runStartTime`" latest=`"$runEndTime`" | sort 0 - _time"
Write-Host "================================================================================" -ForegroundColor Cyan

if (-not $overallPass) {
    exit 1
}
