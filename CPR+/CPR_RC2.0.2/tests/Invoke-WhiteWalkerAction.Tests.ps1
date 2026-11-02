# Focused tests for admin\Invoke-WhiteWalkerAction.ps1.
#
# Loading mirrors the existing CPR_RC2 test convention (see
# CPR_RC2.HeaderNeedle.Tests.ps1 / WW_xml_vault.Tests.ps1): function bodies
# are extracted as text and Invoke-Expression'd so neither script's
# interactive menu / entry point ever executes, and so neither script's
# top-of-file Windows-drive-literal path assignments (e.g. "C:\ProgramData\...")
# run on a non-Windows test host. Script-scope path variables are instead
# pointed at $TestDrive before each relevant function is exercised.
#
# Covers (per task scope): New Needle Wizard input validation (valid/invalid
# per directive type, reusing haystack.ps1's real Read-NeedleFile), the
# needles-diff comparison logic (mocked file/version scenarios), tee-level-
# picker file listing/selection logic, and flag-touch logic for the restore/
# self-update actions (mocked filesystem + mocked Read-Host confirmation).

BeforeAll {
    $script:ReleaseRoot = Split-Path -Parent $PSScriptRoot

    # --- haystack.ps1 parser/compare functions (Write-HSLog, Get-HsFileVersion,
    #     Get-HsFileHash, Sync-NeedlesFile, Invoke-NeedleSync, Read-NeedleFile,
    #     $HaystackHeaderFields) - same extraction boundary as
    #     CPR_RC2.HeaderNeedle.Tests.ps1, which skips the top-of-file
    #     hardcoded C:\ProgramData\WhiteWalker config block. ---
    $hsContent = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'haystack.ps1') -Raw
    $hsPre     = ($hsContent -split '(?ms)^# =+\r?\n# Entry Point')[0]
    Invoke-Expression $hsPre.Substring($hsPre.IndexOf('function Write-HSLog'))

    # --- admin\Invoke-WhiteWalkerAction.ps1 functions - extracted the same
    #     way, starting at Write-WWAdminLog (skips the top-of-file hardcoded
    #     C:\ProgramData\WhiteWalker path block) and stopping before the
    #     final "if (-not ($MyInvocation..." entry-point guard. ---
    # Script-scope path variables the extracted admin-script bootstrap block
    # references immediately (before any function is called) - point them at
    # harmless, nonexistent TestDrive paths so the bootstrap's Test-Path
    # checks simply evaluate to $false (no real haystack.ps1/WW_tee.ps1 to
    # dot-source) instead of erroring on a null/undefined variable.
    $script:WWRoot         = $TestDrive
    $script:WWLogDir       = Join-Path $TestDrive 'logs'
    $script:AdminActionLog = Join-Path $script:WWLogDir 'white_walker.admin_actions.log'
    $script:HaystackScript = Join-Path $TestDrive 'haystack.ps1'
    $script:ActiveTeeProfile = Join-Path $TestDrive 'WW_tee_events.psd1'
    # Pre-set so the admin script's own fallback block (its own
    # Join-Path against a literal UNC share path) is skipped entirely -
    # that literal UNC Join-Path call is Windows-only and errors on a
    # non-Windows test host with no registered PSDrive for it.
    $script:RemoteNeedlesFile = Join-Path $TestDrive 'remote_needles.cfg'
    $script:LocalNeedlesFile  = Join-Path $TestDrive 'local_needles.cfg'

    $actionContent = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'admin/Invoke-WhiteWalkerAction.ps1') -Raw
    $actionPre     = ($actionContent -split "(?ms)^if \(-not \(\`$MyInvocation")[0]
    Invoke-Expression $actionPre.Substring($actionPre.IndexOf('function Write-WWAdminLog'))
}

Describe 'Invoke-WhiteWalkerAction - needle wizard validation (Test-WWLabelSafe)' {
    It 'accepts a simple safe label' {
        Test-WWLabelSafe -Label 'VPN_Reconnect' | Should -Be $true
    }
    It 'rejects an empty label' {
        Test-WWLabelSafe -Label '' | Should -Be $false
    }
    It 'rejects a label containing a space' {
        Test-WWLabelSafe -Label 'VPN Reconnect' | Should -Be $false
    }
    It 'rejects a label containing a reserved character' {
        Test-WWLabelSafe -Label 'VPN:Reconnect' | Should -Be $false
    }
}

Describe 'Invoke-WhiteWalkerAction - needle wizard validation (Test-WWNeedleCandidateLine, via real Read-NeedleFile)' {
    BeforeEach {
        $script:HaystackLogFile     = Join-Path $TestDrive 'haystack.log'
        $script:HaystackLogMaxBytes = 1MB
        $script:HaystackLogKeep     = 5
    }

    It 'accepts a valid NEEDLE line' {
        Test-WWNeedleCandidateLine -Line 'NEEDLE|Application|1000||Test_Needle' | Should -Be $true
    }
    It 'rejects a NEEDLE line with a non-numeric EventID' {
        Test-WWNeedleCandidateLine -Line 'NEEDLE|Application|abc||Test_Needle' | Should -Be $false
    }
    It 'rejects a NEEDLE line with an unsafe label' {
        Test-WWNeedleCandidateLine -Line 'NEEDLE|Application|1000||Bad Label' | Should -Be $false
    }
    It 'accepts a valid SESSION line' {
        Test-WWNeedleCandidateLine -Line 'SESSION|SessionUnlock|Unlock_Trigger' | Should -Be $true
    }
    It 'rejects a SESSION line with an invalid StateChange' {
        Test-WWNeedleCandidateLine -Line 'SESSION|NotARealState|Unlock_Trigger' | Should -Be $false
    }
    It 'accepts a valid DEFENDER line' {
        Test-WWNeedleCandidateLine -Line 'DEFENDER|WebView2|6|Defender_Check' | Should -Be $true
    }
    It 'accepts a valid HEADER line with a known field' {
        Test-WWNeedleCandidateLine -Line 'HEADER|csc_version|CSC_Version|RefreshHours=6|SendHours=24' | Should -Be $true
    }
    It 'accepts a valid HEADER line using the * wildcard field' {
        Test-WWNeedleCandidateLine -Line 'HEADER|*|Run_Header_All|SendHours=12' | Should -Be $true
    }
    It 'rejects a HEADER line with an unknown FieldName' {
        Test-WWNeedleCandidateLine -Line 'HEADER|not_a_real_field|Bad_Field' | Should -Be $false
    }
}

Describe 'Invoke-WhiteWalkerAction - New-WWNeedleCandidateLine wizard prompts' {
    It 'builds a valid NEEDLE line from prompted answers' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('Application','1000','','Wizard_Needle',''))
        Mock Read-Host { $answers.Dequeue() }

        $line = New-WWNeedleCandidateLine -Type 'NEEDLE'

        $line | Should -Be 'NEEDLE|Application|1000||Wizard_Needle'
    }
    It 'returns $null when EventID is not numeric' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('Application','notanumber'))
        Mock Read-Host { $answers.Dequeue() }

        New-WWNeedleCandidateLine -Type 'NEEDLE' | Should -BeNullOrEmpty
    }
    It 'builds a valid SESSION line from prompted answers' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('SessionUnlock','Wizard_Session'))
        Mock Read-Host { $answers.Dequeue() }

        $line = New-WWNeedleCandidateLine -Type 'SESSION'

        $line | Should -Be 'SESSION|SessionUnlock|Wizard_Session'
    }
    It 'returns $null when SESSION StateChange is invalid' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('NotARealState'))
        Mock Read-Host { $answers.Dequeue() }

        New-WWNeedleCandidateLine -Type 'SESSION' | Should -BeNullOrEmpty
    }
    It 'returns $null when DEFENDER ExtendedLogging is invalid (rejected at wizard level before writing)' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('WebView2','6','Wizard_Defender','bogus'))
        Mock Read-Host { $answers.Dequeue() }

        New-WWNeedleCandidateLine -Type 'DEFENDER' | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-WhiteWalkerAction - needles sync diff (Get-WWNeedlesSyncStatus)' {
    BeforeEach {
        $script:RemoteNeedlesFile = Join-Path $TestDrive 'remote_needles.cfg'
        $script:LocalNeedlesFile  = Join-Path $TestDrive 'local_needles.cfg'
        Remove-Item -Path $script:RemoteNeedlesFile, $script:LocalNeedlesFile -Force -ErrorAction SilentlyContinue
    }

    It 'reports in_sync when version lines match' {
        'version:5' | Set-Content -Path $script:RemoteNeedlesFile -Encoding UTF8
        'version:5' | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

        $result = Get-WWNeedlesSyncStatus

        $result.Status | Should -Be 'in_sync'
    }
    It 'reports out_of_sync when version lines differ and content differs' {
        'version:7' | Set-Content -Path $script:RemoteNeedlesFile -Encoding UTF8
        'version:5' | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

        $result = Get-WWNeedlesSyncStatus

        $result.Status        | Should -Be 'out_of_sync'
        $result.RemoteVersion | Should -Be '7'
        $result.LocalVersion  | Should -Be '5'
    }
    It 'reports in_sync when version tag drifted but file hash matches (hash fallback)' {
        # Same body, but remote has a trailing blank line so the *first* line
        # (version tag) differs while overall content is otherwise identical -
        # exercises the hash-fallback path rather than the version fast path.
        @('version:5', 'NEEDLE|Application|1000||Foo') | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8
        @('version:5', 'NEEDLE|Application|1000||Foo') | Set-Content -Path $script:RemoteNeedlesFile -Encoding UTF8

        $result = Get-WWNeedlesSyncStatus

        $result.Status | Should -Be 'in_sync'
    }
    It 'reports share_unreachable when the remote file does not exist' {
        'version:5' | Set-Content -Path $script:LocalNeedlesFile -Encoding UTF8

        $result = Get-WWNeedlesSyncStatus

        $result.Status | Should -Be 'share_unreachable'
    }
}

Describe 'Invoke-WhiteWalkerAction - tee level picker (Get-WWTeeLevelFiles / Get-WWActiveTeeProfileName)' {
    BeforeEach {
        $script:TeeMasterFile = Join-Path $TestDrive 'WW_tee_master.psd1'
        $script:TeeSetScript  = Join-Path (Split-Path -Parent $PSScriptRoot) 'WW_set_tee_level.ps1'
        @'
@{
    MasterVersion = 'T1'
    LevelDescriptions = @{ L0 = 'SILENT'; L1 = 'CORE'; L2 = 'CORE + NETWORK CONTEXT'; L3 = 'L3'; L4 = 'L4'; L5 = 'L5' }
    Levels = @{
        L1 = @{ Events = @{ a_tag = @{ action = 'a_tag'; fields = @('x') } } }
        L2 = @{ Events = @{ tech_checkin = @{ action = 'tech_checkin'; fields = @('note') } } }
    }
}
'@ | Set-Content -Path $script:TeeMasterFile -Encoding UTF8
        $script:ActiveTeeProfile = Join-Path $TestDrive 'WW_tee_events.psd1'
        Remove-Item $script:ActiveTeeProfile -Force -ErrorAction SilentlyContinue
    }

    It 'lists levels 0-5 from the master with descriptions' {
        $levels = @(Get-WWTeeLevelFiles)
        $levels.Count | Should -Be 6
        ($levels | Select-Object -ExpandProperty Name) | Should -Contain 'tee_level_0'
        ($levels | Where-Object Name -eq 'tee_level_2').Description | Should -Match 'CORE \+ NETWORK CONTEXT'
    }

    It 'returns $null for the active profile name when no active file exists yet' {
        Get-WWActiveTeeProfileName | Should -BeNullOrEmpty
    }

    It 'identifies the active profile by its Level marker after activation' {
        . $script:TeeSetScript
        (Set-CprTeeLevel -Level 2 -MasterPath $script:TeeMasterFile -ActivePath $script:ActiveTeeProfile).Success | Should -BeTrue
        Get-WWActiveTeeProfileName | Should -Be 'tee_level_2'
    }

    It 'reports a freshly generated profile as current and one missing a tag as stale' {
        . $script:TeeSetScript
        $null = Set-CprTeeLevel -Level 2 -MasterPath $script:TeeMasterFile -ActivePath $script:ActiveTeeProfile
        (Test-WWTeeProfileStale).Stale | Should -BeFalse
        "@{ Level = 2; ProfileVersion = 'T1'; Events = @{ a_tag = @{ action = 'a_tag'; fields = @('x') } } }" |
            Set-Content -Path $script:ActiveTeeProfile -Encoding UTF8
        $st = Test-WWTeeProfileStale
        $st.Stale | Should -BeTrue
        $st.MissingTags | Should -Contain 'tech_checkin'
    }
}

Describe 'Invoke-WhiteWalkerAction - flag-touch logic (VPN restore / self-update), mocked filesystem' {
    BeforeEach {
        $script:XmlRestoreFlag       = Join-Path $TestDrive 'xml_restore.flag'
        $script:XmlVaultLog          = Join-Path $TestDrive 'white_walker.xml_vault.log'
        $script:SelfUpdateDevFlag    = Join-Path $TestDrive 'cpr_update_dev.flag'
        $script:SelfUpdateProdFlag   = Join-Path $TestDrive 'cpr_update_prod.flag'
        $script:SelfUpdateInstallLog = Join-Path $TestDrive 'white_walker_install.log'
        $script:AdminActionLog       = Join-Path $TestDrive 'white_walker.admin_actions.log'
        $script:WWLogDir             = $TestDrive
        $script:AdminActionLogMaxBytes = 1MB
        $script:AdminActionLogKeep     = 5
        Remove-Item -Path $script:XmlRestoreFlag, $script:SelfUpdateDevFlag, $script:SelfUpdateProdFlag -Force -ErrorAction SilentlyContinue
    }

    It 'touches the restore flag when the tech confirms' {
        Mock Read-Host { 'y' }

        Invoke-WWVpnProfileRestore

        Test-Path -LiteralPath $script:XmlRestoreFlag | Should -Be $true
    }

    It 'does not touch the restore flag when the tech declines' {
        Mock Read-Host { 'n' }

        Invoke-WWVpnProfileRestore

        Test-Path -LiteralPath $script:XmlRestoreFlag | Should -Be $false
    }

    It 'touches the DEV self-update flag when channel 1 is chosen and confirmed' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('1','','y'))
        Mock Read-Host { $answers.Dequeue() }

        Invoke-WWSelfUpdateTrigger

        Test-Path -LiteralPath $script:SelfUpdateDevFlag  | Should -Be $true
        Test-Path -LiteralPath $script:SelfUpdateProdFlag | Should -Be $false
    }

    It 'touches the PROD self-update flag when channel 2 is chosen and confirmed' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('2','','y'))
        Mock Read-Host { $answers.Dequeue() }

        Invoke-WWSelfUpdateTrigger

        Test-Path -LiteralPath $script:SelfUpdateProdFlag | Should -Be $true
        Test-Path -LiteralPath $script:SelfUpdateDevFlag  | Should -Be $false
    }

    It 'creates a combined update+tee flag (keep) when a tee level and keep are chosen' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('1','5','y','y'))
        Mock Read-Host { $answers.Dequeue() }

        Invoke-WWSelfUpdateTrigger

        Test-Path -LiteralPath (Join-Path $TestDrive 'cpr_update_dev_tee_5_keep.flag') | Should -Be $true
        Test-Path -LiteralPath $script:SelfUpdateDevFlag | Should -Be $false
    }

    It 'creates a combined flag without _keep when keep is declined' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('2','3','n','y'))
        Mock Read-Host { $answers.Dequeue() }

        Invoke-WWSelfUpdateTrigger

        Test-Path -LiteralPath (Join-Path $TestDrive 'cpr_update_prod_tee_3.flag') | Should -Be $true
    }

    It 'rejects a bad tee level and creates nothing' {
        # TestDrive is shared by the Its in this block: clear flags the earlier Its created.
        Get-ChildItem -LiteralPath $TestDrive -Filter 'cpr_update_*.flag' | Remove-Item -Force
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('1','9'))
        Mock Read-Host { $answers.Dequeue() }

        Invoke-WWSelfUpdateTrigger

        @(Get-ChildItem -LiteralPath $TestDrive -Filter 'cpr_update_*.flag').Count | Should -Be 0
    }
}

# --- Tech Check-In telemetry (bootstrap + "queue changed = queued success,
#     unchanged = failure" contract). These exercise the console's own logic
#     with a stand-in Write-TeeLog and TestDrive paths. The real end-to-end
#     path (queue -> haystack_action.ps1 drain -> WW_syslog -> Splunk) needs a
#     deployed Windows box with Task Scheduler and is NOT covered here. ---

Describe 'Invoke-WhiteWalkerAction - tech check-in telemetry bootstrap (AST / source contract)' {
    BeforeAll {
        $script:AdminSource = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'admin/Invoke-WhiteWalkerAction.ps1') -Raw
        $script:AdminAst    = [System.Management.Automation.Language.Parser]::ParseInput($script:AdminSource, [ref]$null, [ref]$null)
    }

    It 'parses without syntax errors' {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseInput($script:AdminSource, [ref]$null, [ref]$errors) | Out-Null
        $errors.Count | Should -Be 0
    }

    It 'establishes <Name> in Global scope at top level, matching what Write-TeeLog resolves first' -TestCases @(
        @{ Name = 'HaystackEnabled' }
        @{ Name = 'TeeEnabled' }
        @{ Name = 'TeeEventsFile' }
    ) {
        param($Name)

        $assignments = $script:AdminAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq "`$global:$Name"
        }, $true)

        $assignments.Count | Should -BeGreaterThan 0 -Because "Write-TeeLog checks Global scope before Script scope"
        # Must be top-level (not nested in a function), so it is in effect for
        # every action the console runs.
        $inFunction = $assignments[0].Parent
        while ($inFunction -and -not ($inFunction -is [System.Management.Automation.Language.FunctionDefinitionAst])) {
            $inFunction = $inFunction.Parent
        }
        $inFunction | Should -BeNullOrEmpty
    }

    It 'still keeps the Script-scope copies for its own reads' {
        $script:AdminSource | Should -Match '\$script:TeeEventsFile\s*=' 
    }

    It 'routes check-in telemetry only through Send-WWTelemetry/Write-TeeLog (no second telemetry path)' {
        $script:AdminSource | Should -Not -Match 'UdpClient'
        $script:AdminSource | Should -Match "Send-WWTelemetry -Tag 'tech_checkin'"
    }

    It 'no longer claims an unverified "Check-in sent"' {
        $script:AdminSource | Should -Not -Match 'Done\. Check-in sent\.'
    }
}

Describe 'Invoke-WhiteWalkerAction - Send-WWTelemetry queue verification' {
    BeforeEach {
        $script:WWLogDir        = Join-Path $TestDrive 'logs_telemetry'
        $script:AdminActionLog  = Join-Path $script:WWLogDir 'white_walker.admin_actions.log'
        $script:TeeQueueFile    = Join-Path $script:WWLogDir 'haystack_syslog_queue.jsonl'
        $script:ActiveTeeProfile = Join-Path $TestDrive 'WW_tee_events.psd1'
        Remove-Item -LiteralPath $script:WWLogDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'creates the queue parent directory before invoking telemetry' {
        function Write-TeeLog { param($Tag, $Data, [switch]$PassThru) }

        Test-Path -LiteralPath $script:WWLogDir | Should -BeFalse
        Send-WWTelemetry -Tag 'tech_checkin' -Data @{ note = 'x' } -PassThru | Out-Null
        Test-Path -LiteralPath $script:WWLogDir | Should -BeTrue
    }

    It 'reports Queued when the queue file is created by the call' {
        function Write-TeeLog {
            param($Tag, $Data, [switch]$PassThru)
            Add-Content -Path $script:TeeQueueFile -Value '{"payload":"action=\"tech_checkin\""}'
            if ($PassThru) { [pscustomobject]@{ Tag = $Tag; Queued = $true; Reason = 'queued'; Error = $null; QueueFile = $script:TeeQueueFile } }
        }

        $result = Send-WWTelemetry -Tag 'tech_checkin' -Data @{ note = 'x' } -PassThru
        $result.Queued | Should -BeTrue
        $result.Reason | Should -Be 'queued'
    }

    It 'reports Queued when an existing queue file gains a line' {
        New-Item -Path $script:WWLogDir -ItemType Directory -Force | Out-Null
        Set-Content -Path $script:TeeQueueFile -Value '{"payload":"old"}'

        function Write-TeeLog {
            param($Tag, $Data, [switch]$PassThru)
            Add-Content -Path $script:TeeQueueFile -Value '{"payload":"new"}'
            if ($PassThru) { [pscustomobject]@{ Tag = $Tag; Queued = $true; Reason = 'queued'; Error = $null; QueueFile = $script:TeeQueueFile } }
        }

        $result = Send-WWTelemetry -Tag 'tech_checkin' -Data @{ note = 'x' } -PassThru
        $result.Queued | Should -BeTrue
        @(Get-Content -LiteralPath $script:TeeQueueFile).Count | Should -Be 2
    }

    It 'reports NOT queued when the tag is gated by the active tee profile' {
        function Write-TeeLog {
            param($Tag, $Data, [switch]$PassThru)
            if ($PassThru) { [pscustomobject]@{ Tag = $Tag; Queued = $false; Reason = 'tag_not_in_profile'; Error = $null; QueueFile = $script:TeeQueueFile } }
        }

        $result = Send-WWTelemetry -Tag 'tech_checkin' -Data @{ note = 'x' } -PassThru
        $result.Queued | Should -BeFalse
        $result.Reason | Should -Be 'tag_not_in_profile'
    }

    It 'reports queue_unchanged when Write-TeeLog claims success but nothing was written' {
        function Write-TeeLog {
            param($Tag, $Data, [switch]$PassThru)
            if ($PassThru) { [pscustomobject]@{ Tag = $Tag; Queued = $true; Reason = 'queued'; Error = $null; QueueFile = $script:TeeQueueFile } }
        }

        $result = Send-WWTelemetry -Tag 'tech_checkin' -Data @{ note = 'x' } -PassThru
        $result.Queued | Should -BeFalse
        $result.Reason | Should -Be 'queue_unchanged'
    }

    It 'falls back to queue-change proof on an older Write-TeeLog with no -PassThru' {
        function Write-TeeLog {
            param($Tag, $Data)
            Add-Content -Path $script:TeeQueueFile -Value '{"payload":"legacy"}'
        }

        $result = Send-WWTelemetry -Tag 'tech_checkin' -Data @{ note = 'x' } -PassThru
        $result.Queued | Should -BeTrue
        $result.Reason | Should -Be 'queued'
    }
}

Describe 'Invoke-WhiteWalkerAction - Invoke-WWTechCheckIn honest reporting' {
    BeforeEach {
        $script:WWLogDir        = Join-Path $TestDrive 'logs_checkin'
        $script:AdminActionLog  = Join-Path $script:WWLogDir 'white_walker.admin_actions.log'
        $script:TeeQueueFile    = Join-Path $script:WWLogDir 'haystack_syslog_queue.jsonl'
        $script:ActiveTeeProfile = Join-Path $TestDrive 'WW_tee_events.psd1'
        Remove-Item -LiteralPath $script:WWLogDir -Recurse -Force -ErrorAction SilentlyContinue

        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('ticket 123','y'))
        Mock Read-Host { $answers.Dequeue() }
        $script:CheckInOutput = New-Object System.Collections.Generic.List[string]
        Mock Write-Host { $script:CheckInOutput.Add([string]$Object) } -ParameterFilter { $true }
    }

    It 'reports QUEUED (not "sent to Splunk") and logs it when the queue changed' {
        function Write-TeeLog {
            param($Tag, $Data, [switch]$PassThru)
            Add-Content -Path $script:TeeQueueFile -Value '{"payload":"action=\"tech_checkin\""}'
            if ($PassThru) { [pscustomobject]@{ Tag = $Tag; Queued = $true; Reason = 'queued'; Error = $null; QueueFile = $script:TeeQueueFile } }
        }

        Invoke-WWTechCheckIn

        $text = $script:CheckInOutput -join "`n"
        $text | Should -Match 'QUEUED'
        $text | Should -Match 'next HayStack wake'
        $text | Should -Not -Match 'Check-in sent'
        (Get-Content -LiteralPath $script:AdminActionLog -Raw) | Should -Match 'Tech check-in queued'
    }

    It 'reports an actionable failure and logs ERROR when the event was gated' {
        function Write-TeeLog {
            param($Tag, $Data, [switch]$PassThru)
            if ($PassThru) { [pscustomobject]@{ Tag = $Tag; Queued = $false; Reason = 'tag_not_in_profile'; Error = $null; QueueFile = $script:TeeQueueFile } }
        }

        Invoke-WWTechCheckIn

        $text = $script:CheckInOutput -join "`n"
        $text | Should -Match 'NOT sent'
        $text | Should -Match 'tag_not_in_profile'
        $text | Should -Match 'Tee Log Level Picker'
        $log = Get-Content -LiteralPath $script:AdminActionLog -Raw
        $log | Should -Match '\[ERROR\]'
        $log | Should -Match 'Tech check-in NOT queued'
    }

    It 'reports an actionable failure when Write-TeeLog itself failed' {
        function Write-TeeLog {
            param($Tag, $Data, [switch]$PassThru)
            if ($PassThru) { [pscustomobject]@{ Tag = $Tag; Queued = $false; Reason = 'error'; Error = 'access denied'; QueueFile = $script:TeeQueueFile } }
        }

        Invoke-WWTechCheckIn

        $text = $script:CheckInOutput -join "`n"
        $text | Should -Match 'NOT sent'
        $text | Should -Match 'access denied'
    }
}

Describe 'Invoke-WhiteWalkerAction - Get-WWFileNewline' {
    BeforeEach {
        $script:NewlineTestFile = Join-Path $TestDrive 'newline_test.cfg'
        Remove-Item -LiteralPath $script:NewlineTestFile -Force -ErrorAction SilentlyContinue
    }

    It 'detects LF when the file only uses LF line endings' {
        [System.IO.File]::WriteAllText($script:NewlineTestFile, "line1`nline2`n")
        Get-WWFileNewline -Path $script:NewlineTestFile | Should -Be 'LF'
    }
    It 'detects CRLF when the file uses CRLF line endings' {
        [System.IO.File]::WriteAllText($script:NewlineTestFile, "line1`r`nline2`r`n")
        Get-WWFileNewline -Path $script:NewlineTestFile | Should -Be 'CRLF'
    }
    It 'defaults to CRLF when the file does not exist' {
        Get-WWFileNewline -Path $script:NewlineTestFile | Should -Be 'CRLF'
    }
    It 'defaults to CRLF when the file is empty' {
        [System.IO.File]::WriteAllText($script:NewlineTestFile, '')
        Get-WWFileNewline -Path $script:NewlineTestFile | Should -Be 'CRLF'
    }
    It 'defaults to CRLF when the file has content but no newline at all' {
        [System.IO.File]::WriteAllText($script:NewlineTestFile, 'single line, no newline')
        Get-WWFileNewline -Path $script:NewlineTestFile | Should -Be 'CRLF'
    }
}

Describe 'Invoke-WhiteWalkerAction - Add-WWNeedleLine (newline preservation + provenance)' {
    BeforeEach {
        $script:AppendTestFile = Join-Path $TestDrive 'append_test.cfg'
        Remove-Item -LiteralPath $script:AppendTestFile -Force -ErrorAction SilentlyContinue
    }

    It 'preserves LF endings and does not introduce any CR bytes' {
        [System.IO.File]::WriteAllText($script:AppendTestFile, "# header`nNEEDLE|Application|1000||Existing`n")

        Add-WWNeedleLine -Path $script:AppendTestFile -Line 'NEEDLE|Application|2000||New_One'

        $raw = [System.IO.File]::ReadAllText($script:AppendTestFile)
        $raw | Should -Not -Match "`r"
        $raw | Should -Match "NEEDLE\|Application\|2000\|\|New_One`n"
    }
    It 'preserves CRLF endings when the file already uses CRLF' {
        [System.IO.File]::WriteAllText($script:AppendTestFile, "# header`r`nNEEDLE|Application|1000||Existing`r`n")

        Add-WWNeedleLine -Path $script:AppendTestFile -Line 'NEEDLE|Application|2000||New_One'

        $raw = [System.IO.File]::ReadAllText($script:AppendTestFile)
        ($raw -split "`r`n").Count | Should -BeGreaterThan 3
        # Every newline in the resulting file should be part of a CRLF pair -
        # i.e. no bare LF exists once every CRLF has been stripped out.
        $raw.Replace("`r`n", '') | Should -Not -Match "`n"
    }
    It 'adds exactly one separator before the provenance comment when the existing file lacks a terminal newline' {
        [System.IO.File]::WriteAllText($script:AppendTestFile, "NEEDLE|Application|1000||First`nNEEDLE|Application|1500||Existing")

        Add-WWNeedleLine -Path $script:AppendTestFile -Line 'NEEDLE|Application|2000||New_One'

        $raw = [System.IO.File]::ReadAllText($script:AppendTestFile)
        $raw | Should -Not -Match "`r"
        $raw | Should -Match "Existing`n# Added via Invoke-WhiteWalkerAction\.ps1 on [\s\S]*`nNEEDLE\|Application\|2000\|\|New_One"
        # No accidental blank-line explosion: exactly one newline separates
        # the old last line from the new provenance comment.
        $raw | Should -Not -Match "Existing`n`n"
    }
    It 'falls back to Windows CRLF default and creates the file when it is missing' {
        Add-WWNeedleLine -Path $script:AppendTestFile -Line 'NEEDLE|Application|2000||New_One'

        Test-Path -LiteralPath $script:AppendTestFile | Should -Be $true
        $raw = [System.IO.File]::ReadAllText($script:AppendTestFile)
        $raw | Should -Match "`r`n"
    }
    It 'falls back to Windows CRLF default when the file exists but is empty' {
        [System.IO.File]::WriteAllText($script:AppendTestFile, '')

        Add-WWNeedleLine -Path $script:AppendTestFile -Line 'NEEDLE|Application|2000||New_One'

        $raw = [System.IO.File]::ReadAllText($script:AppendTestFile)
        $raw | Should -Match "`r`n"
    }
    It 'writes a provenance comment immediately before the needle line, with exactly one newline between them' {
        [System.IO.File]::WriteAllText($script:AppendTestFile, "NEEDLE|Application|1000||Existing`n")

        Add-WWNeedleLine -Path $script:AppendTestFile -Line 'NEEDLE|Application|2000||New_One'

        $raw   = [System.IO.File]::ReadAllText($script:AppendTestFile)
        $lines = $raw -split "`n" | Where-Object { $_ -ne '' }
        $lines[-2] | Should -Match '^# Added via Invoke-WhiteWalkerAction\.ps1 on \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
        $lines[-1] | Should -Be 'NEEDLE|Application|2000||New_One'
    }
    It 'produces a provenance-commented needle that Read-NeedleFile still parses correctly' {
        [System.IO.File]::WriteAllText($script:AppendTestFile, "NEEDLE|Application|1000||Existing`n")

        Add-WWNeedleLine -Path $script:AppendTestFile -Line 'NEEDLE|Application|2000||New_One'

        $parsed = @(Read-NeedleFile -Path $script:AppendTestFile -SourceTag 'test')
        $parsed.Count | Should -Be 2
        @($parsed | Where-Object { $_.Label -eq 'New_One' }).Count | Should -Be 1
    }
}

Describe 'Invoke-WhiteWalkerAction - Invoke-WWNewNeedleWizard write behavior' {
    BeforeEach {
        $script:WizardNeedlesFile = Join-Path $TestDrive 'wizard_needles_local.cfg'
        $script:NeedlesLocalFile  = $script:WizardNeedlesFile
        Remove-Item -LiteralPath $script:WizardNeedlesFile -Force -ErrorAction SilentlyContinue

        $script:WWLogDir       = Join-Path $TestDrive 'logs_wizard'
        $script:AdminActionLog = Join-Path $script:WWLogDir 'white_walker.admin_actions.log'
        Remove-Item -LiteralPath $script:WWLogDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'does not write anything when the candidate is cancelled (no type selected)' {
        Mock Read-Host { '9' }

        Invoke-WWNewNeedleWizard

        Test-Path -LiteralPath $script:WizardNeedlesFile | Should -Be $false
    }
    It 'does not write anything when validation fails' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('1','Application','notanumber'))
        Mock Read-Host { $answers.Dequeue() }

        Invoke-WWNewNeedleWizard

        Test-Path -LiteralPath $script:WizardNeedlesFile | Should -Be $false
    }
    It 'does not write anything when the operator declines the final confirmation' {
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('1','Application','1000','','Wizard_Needle','','n'))
        Mock Read-Host { $answers.Dequeue() }

        Invoke-WWNewNeedleWizard

        Test-Path -LiteralPath $script:WizardNeedlesFile | Should -Be $false
    }
    It 'appends the provenance comment and needle line, preserving an existing LF file' {
        [System.IO.File]::WriteAllText($script:WizardNeedlesFile, "NEEDLE|Application|1000||Existing`n")
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('1','Application','2000','','Wizard_Needle','','y'))
        Mock Read-Host { $answers.Dequeue() }

        Invoke-WWNewNeedleWizard

        $raw = [System.IO.File]::ReadAllText($script:WizardNeedlesFile)
        $raw | Should -Not -Match "`r"
        $raw | Should -Match '# Added via Invoke-WhiteWalkerAction\.ps1 on'
        $raw | Should -Match "NEEDLE\|Application\|2000\|\|Wizard_Needle`n"
        (Get-Content -LiteralPath $script:AdminActionLog -Raw) | Should -Match 'Appended needle to needles_local\.cfg'
    }
    It 'logs and reports failure instead of claiming success when the write throws' {
        [System.IO.File]::WriteAllText($script:WizardNeedlesFile, "NEEDLE|Application|1000||Existing`n")
        $answers = [System.Collections.Generic.Queue[string]]::new([string[]]@('1','Application','2000','','Wizard_Needle','','y'))
        Mock Read-Host { $answers.Dequeue() }
        Mock Add-WWNeedleLine { throw 'simulated disk failure' }
        $script:WizardOutput = New-Object System.Collections.Generic.List[string]
        Mock Write-Host { $script:WizardOutput.Add([string]$Object) } -ParameterFilter { $true }

        Invoke-WWNewNeedleWizard

        $text = $script:WizardOutput -join "`n"
        $text | Should -Match 'Failed to write to needles_local\.cfg'
        $log = Get-Content -LiteralPath $script:AdminActionLog -Raw
        $log | Should -Match '\[ERROR\]'
        $log | Should -Match 'failed to append line'
    }
}
