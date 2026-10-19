# Focused tests for the CPR RC2 HEADER needle directive:
#   - haystack.ps1      : parsing/validation + trigger-XML exclusion
#   - Main.Logging.ps1  : RefreshHours-gated header_cache.json refresh
#   - haystack_action.ps1 : SendHours-gated telemetry shipping (incl. * bundling)
#
# Loading mirrors WW_Tests_Haystack.ps1 / WW_Tests_Haystack_Action.ps1: the
# function bodies are extracted and Invoke-Expression'd so the scripts' entry
# points never execute.

BeforeAll {
    $script:ReleaseRoot = Split-Path -Parent $PSScriptRoot

    # --- haystack_action.ps1 functions (loaded first; haystack.ps1's shared
    #     parser/merge copies intentionally win below so parser tests can mock
    #     Write-HSLog) ---
    $haContent = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'haystack_action.ps1') -Raw
    $haPre     = ($haContent -split '(?ms)^# =+\r?\n# Main')[0]
    Invoke-Expression $haPre.Substring($haPre.IndexOf('function Write-HALog'))

    # --- haystack.ps1 parser functions ---
    $hsContent = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'haystack.ps1') -Raw
    $hsPre     = ($hsContent -split '(?ms)^# =+\r?\n# Entry Point')[0]
    Invoke-Expression $hsPre.Substring($hsPre.IndexOf('function Write-HSLog'))

    # --- Main.Logging.ps1 header cache functions ---
    if (-not (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
        function Write-Log { param([string]$Message, [string]$Level = 'INFO') }
    }
    $mlContent = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'main/Main.Logging.ps1') -Raw
    $mlStart   = $mlContent.IndexOf('$HeaderCacheFieldNames = @(')
    $mlEnd     = $mlContent.IndexOf('function Write-RunHeader {')
    Invoke-Expression $mlContent.Substring($mlStart, $mlEnd - $mlStart)

    if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
        function Register-ScheduledTask { param([string]$Xml, [string]$TaskName, [string]$TaskPath, [switch]$Force) }
    }
    if (-not (Get-Command Write-TeeLog -ErrorAction SilentlyContinue)) {
        function Write-TeeLog { param([string]$Tag, [hashtable]$Data) }
    }

    $script:HaystackVersion           = '1.0.2'
    $script:HeartbeatIntervalMinutes  = 30
    $script:HeartbeatRandomDelayMinutes = 0
    $script:ActionScriptPath          = Join-Path $TestDrive 'haystack_action.ps1'
    $script:LocalCacheDir             = $TestDrive
    $script:TsTaskName                = 'HayStack_Monitor'
    $script:TsTaskPath                = '\HayStack\'
    $script:HaystackLogFile           = Join-Path $TestDrive 'haystack.log'
    $script:HaystackLogMaxBytes       = 1MB
    $script:HaystackLogKeep           = 5
    $script:HeaderSendIntervalHours   = 24
}

Describe 'Read-NeedleFile - HEADER directives' {
    BeforeEach {
        $script:NeedleFile = Join-Path $TestDrive 'needles_header.cfg'
        $script:LogBuffer  = [System.Collections.Generic.List[object]]::new()
        Mock Write-HSLog {
            param($Message, $Level)
            $script:LogBuffer.Add([pscustomobject]@{ Message = $Message; Level = $Level })
        }
    }

    It 'parses a specific field with both interval tokens' {
        'HEADER|csc_version|CSC_Version|RefreshHours=6|SendHours=24' |
            Set-Content -Path $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local')

        $result.Count          | Should -Be 1
        $result[0].Type        | Should -Be 'HEADER'
        $result[0].FieldName   | Should -Be 'csc_version'
        $result[0].Label       | Should -Be 'CSC_Version'
        $result[0].RefreshHours| Should -Be 6
        $result[0].SendHours   | Should -Be 24
        $result[0].Source      | Should -Be 'local'
    }

    It 'parses the * wildcard field' {
        'HEADER|*|Run_Header_All|SendHours=12' | Set-Content -Path $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'share')

        $result.Count        | Should -Be 1
        $result[0].FieldName | Should -Be '*'
        $result[0].SendHours | Should -Be 12
        $result[0].RefreshHours | Should -BeNullOrEmpty
    }

    It 'accepts the interval tokens in either order' {
        'HEADER|os|OS_Version|SendHours=48|RefreshHours=2' | Set-Content -Path $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local')

        $result[0].RefreshHours | Should -Be 2
        $result[0].SendHours    | Should -Be 48
    }

    It 'skips an unknown FieldName with a WARN' {
        'HEADER|csc_verzion|Typo_Label' | Set-Content -Path $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local')

        $result.Count | Should -Be 0
        ($script:LogBuffer | Where-Object { $_.Level -eq 'WARN' -and $_.Message -match "not a known run-header field" }).Count |
            Should -BeGreaterThan 0
    }

    It 'falls back to defaults and WARNs on malformed interval values' {
        'HEADER|serial|Device_Serial|RefreshHours=abc|SendHours=-4' |
            Set-Content -Path $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local')

        $result.Count           | Should -Be 1
        $result[0].RefreshHours | Should -BeNullOrEmpty
        $result[0].SendHours    | Should -BeNullOrEmpty
        ($script:LogBuffer | Where-Object { $_.Level -eq 'WARN' -and $_.Message -match 'is invalid - using global default' }).Count |
            Should -Be 2
    }

    It 'WARNs on an unrecognized trailing token but keeps the needle' {
        'HEADER|model|Device_Model|Daily' | Set-Content -Path $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local')

        $result.Count | Should -Be 1
        ($script:LogBuffer | Where-Object { $_.Level -eq 'WARN' -and $_.Message -match 'is not recognized' }).Count |
            Should -BeGreaterThan 0
    }

    It 'skips a HEADER line with an unsafe label' {
        'HEADER|os|Bad Label' | Set-Content -Path $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local')

        $result.Count | Should -Be 0
        ($script:LogBuffer | Where-Object { $_.Level -eq 'WARN' -and $_.Message -match 'invalid characters' }).Count |
            Should -BeGreaterThan 0
    }

    It 'skips a HEADER line with too few fields' {
        'HEADER|os' | Set-Content -Path $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local')

        $result.Count | Should -Be 0
        ($script:LogBuffer | Where-Object { $_.Level -eq 'WARN' -and $_.Message -match 'expected at least 3' }).Count |
            Should -BeGreaterThan 0
    }

    It 'does not disturb existing directive types on the same file' {
        @(
            'NEEDLE|System|6005||BootHit'
            'SESSION|SessionUnlock|Unlock'
            'DEFENDER|Some Rule|6|Fw_Rule'
            'HEADER|csc_version|CSC_Version'
        ) | Set-Content -Path $script:NeedleFile -Encoding UTF8

        $result = @(Read-NeedleFile -Path $script:NeedleFile -SourceTag 'local')

        ($result | Where-Object Type -eq 'NEEDLE').Count   | Should -Be 1
        ($result | Where-Object Type -eq 'SESSION').Count  | Should -Be 1
        ($result | Where-Object Type -eq 'DEFENDER').Count | Should -Be 1
        ($result | Where-Object Type -eq 'HEADER').Count   | Should -Be 1
    }
}

Describe 'HEADER needles in merge and task XML' {
    BeforeEach {
        Mock Write-HSLog {}
    }

    It 'lets a local HEADER needle win a label collision with the share' {
        $local = @([pscustomobject]@{ Type = 'HEADER'; FieldName = 'os';          Label = 'Dup'; RefreshHours = 1; SendHours = 1; Source = 'local' })
        $share = @([pscustomobject]@{ Type = 'HEADER'; FieldName = 'csc_version'; Label = 'Dup'; RefreshHours = 9; SendHours = 9; Source = 'share' })

        $merged = @(Merge-Needles -ShareNeedles $share -LocalNeedles $local)

        $merged.Count        | Should -Be 1
        $merged[0].Source    | Should -Be 'local'
        $merged[0].FieldName | Should -Be 'os'
    }

    It 'never emits trigger XML for a HEADER needle' {
        $needles = @(
            [pscustomobject]@{ Type = 'NEEDLE'; LogName = 'System'; EventID = '6005'; XPathFilter = ''; Label = 'BootHit'; ExtendedLogging = '0'; Source = 'share' }
            [pscustomobject]@{ Type = 'HEADER'; FieldName = 'csc_version'; Label = 'CSC_Version'; RefreshHours = 6; SendHours = 24; Source = 'local' }
        )

        $xml = Build-HaystackTaskXml -Needles $needles

        $xml | Should -Not -BeNullOrEmpty
        $xml | Should -Not -Match 'HayStack_CSC_Version'
        $xml | Should -Match 'HayStack_BootHit'
        # One event trigger + the heartbeat; the HEADER needle contributes none.
        ([regex]::Matches($xml, '<EventTrigger').Count) | Should -Be 1
    }
}

Describe 'Update-HeaderCacheFields - refresh interval gating' {
    BeforeEach {
        $script:HeaderCacheFile = Join-Path $TestDrive 'header_cache.json'
        if (Test-Path $script:HeaderCacheFile) { Remove-Item $script:HeaderCacheFile -Force }
        $script:HeaderCacheDefaultRefreshHours = 6
        $script:HeaderNeedleFiles = @()
        $script:Fields = @{
            ww_version  = '3.14.0_RC2.0'
            os          = 'Windows 11'
            model       = 'Dell Latitude'
            serial      = 'ABC123'
            last_boot   = '2026-10-10 06:00:00'
            csc_version = '5.1.17.3394'
            csc_source  = 'manifest'
            vpn_profile = 'uhg_always_on'
        }
    }

    It 'creates the consolidated cache with every known field in one write' {
        (Update-HeaderCacheFields -Fields $script:Fields) | Should -BeTrue

        $cache = Get-Content -LiteralPath $script:HeaderCacheFile -Raw | ConvertFrom-Json
        foreach ($field in $HeaderCacheFieldNames) {
            $cache.Fields.$field.value | Should -Not -BeNullOrEmpty
            $cache.Fields.$field.collected_at | Should -Not -BeNullOrEmpty
        }
        $cache.Fields.csc_version.value | Should -Be '5.1.17.3394'
    }

    It 'does not rewrite a field before its RefreshHours elapses' {
        Update-HeaderCacheFields -Fields $script:Fields | Out-Null
        $before = Get-Content -LiteralPath $script:HeaderCacheFile -Raw | ConvertFrom-Json

        $script:Fields.csc_version = '9.9.9.9'
        (Update-HeaderCacheFields -Fields $script:Fields) | Should -BeFalse

        $after = Get-Content -LiteralPath $script:HeaderCacheFile -Raw | ConvertFrom-Json
        $after.Fields.csc_version.value        | Should -Be '5.1.17.3394'
        $after.Fields.csc_version.collected_at | Should -Be $before.Fields.csc_version.collected_at
    }

    It 'rewrites a field once its RefreshHours has elapsed' {
        Update-HeaderCacheFields -Fields $script:Fields | Out-Null

        $cache = Get-Content -LiteralPath $script:HeaderCacheFile -Raw | ConvertFrom-Json
        $stale = ([datetimeoffset]::Now.AddHours(-7)).ToString('o')
        $cache.Fields.csc_version.collected_at = $stale
        $cache | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:HeaderCacheFile -Encoding UTF8

        $script:Fields.csc_version = '9.9.9.9'
        (Update-HeaderCacheFields -Fields $script:Fields) | Should -BeTrue

        $after = Get-Content -LiteralPath $script:HeaderCacheFile -Raw | ConvertFrom-Json
        $after.Fields.csc_version.value | Should -Be '9.9.9.9'
    }

    It 'preserves last_sent_at across a refresh' {
        Update-HeaderCacheFields -Fields $script:Fields | Out-Null

        $cache = Get-Content -LiteralPath $script:HeaderCacheFile -Raw | ConvertFrom-Json
        $sentAt = ([datetimeoffset]::Now.AddHours(-1)).ToString('o')
        $cache.Fields.os.last_sent_at = $sentAt
        $cache.Fields.os.collected_at = ([datetimeoffset]::Now.AddHours(-7)).ToString('o')
        $cache | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:HeaderCacheFile -Encoding UTF8

        $script:Fields.os = 'Windows 11 Updated'
        Update-HeaderCacheFields -Fields $script:Fields | Out-Null

        $after = Get-Content -LiteralPath $script:HeaderCacheFile -Raw | ConvertFrom-Json
        $after.Fields.os.value | Should -Be 'Windows 11 Updated'
        ([datetimeoffset]$after.Fields.os.last_sent_at) | Should -Be ([datetimeoffset]$sentAt)
    }
}

Describe 'Get-HeaderFieldRefreshHours' {
    BeforeEach {
        $script:HeaderCacheDefaultRefreshHours = 6
        $script:NeedleCfg = Join-Path $TestDrive 'refresh_needles.cfg'
        $script:HeaderNeedleFiles = @($script:NeedleCfg)
    }

    It 'defaults every known field when no HEADER needle exists' {
        '' | Set-Content -Path $script:NeedleCfg -Encoding UTF8
        $hours = Get-HeaderFieldRefreshHours
        foreach ($field in $HeaderCacheFieldNames) { $hours[$field] | Should -Be 6 }
    }

    It 'uses the shortest interval when needles disagree on the same field' {
        @(
            'HEADER|csc_version|A|RefreshHours=4'
            'HEADER|csc_version|B|RefreshHours=2'
        ) | Set-Content -Path $script:NeedleCfg -Encoding UTF8

        (Get-HeaderFieldRefreshHours)['csc_version'] | Should -Be 2
    }

    It 'applies a * needle interval to every field' {
        'HEADER|*|All|RefreshHours=1' | Set-Content -Path $script:NeedleCfg -Encoding UTF8

        $hours = Get-HeaderFieldRefreshHours
        foreach ($field in $HeaderCacheFieldNames) { $hours[$field] | Should -Be 1 }
    }

    It 'ignores an unknown field name' {
        'HEADER|not_a_field|X|RefreshHours=1' | Set-Content -Path $script:NeedleCfg -Encoding UTF8

        $hours = Get-HeaderFieldRefreshHours
        foreach ($field in $HeaderCacheFieldNames) { $hours[$field] | Should -Be 6 }
    }
}

Describe 'Invoke-HeaderNeedleCheck - send interval gating' {
    BeforeEach {
        $script:HeaderCacheFile         = Join-Path $TestDrive 'header_cache_send.json'
        $script:HeaderSendIntervalHours = 24
        $script:HaystackLogFile         = Join-Path $TestDrive 'haystack.log'
        $script:Sent                    = [System.Collections.Generic.List[object]]::new()

        Mock Write-HALog {}
        Mock Write-HaystackTelemetry {
            param($Tag, $Data)
            $script:Sent.Add([pscustomobject]@{ Tag = $Tag; Data = $Data })
        }

        $collected = ([datetimeoffset]::Now.AddMinutes(-5)).ToString('o')
        $cache = [ordered]@{
            SchemaVersion = 1
            UpdatedAt     = $collected
            Fields        = [ordered]@{
                csc_version = [ordered]@{ value = '5.1.17.3394'; collected_at = $collected; last_sent_at = $null }
                os          = [ordered]@{ value = 'Windows 11';  collected_at = $collected; last_sent_at = $null }
            }
            Bundles       = [ordered]@{}
        }
        $cache | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:HeaderCacheFile -Encoding UTF8
    }

    It 'sends a never-sent field and stamps last_sent_at' {
        $needle = [pscustomobject]@{ Type = 'HEADER'; FieldName = 'csc_version'; Label = 'CSC_Version'; RefreshHours = 6; SendHours = 24; Source = 'local' }

        (Invoke-HeaderNeedleCheck -Needles @($needle)) | Should -Be 1

        $script:Sent.Count            | Should -Be 1
        $script:Sent[0].Tag           | Should -Be 'haystack_header_fields'
        $script:Sent[0].Data.Label    | Should -Be 'CSC_Version'
        $script:Sent[0].Data.header_field | Should -Be 'csc_version'
        $script:Sent[0].Data.csc_version  | Should -Be '5.1.17.3394'

        $cache = Get-Content -LiteralPath $script:HeaderCacheFile -Raw | ConvertFrom-Json
        $cache.Fields.csc_version.last_sent_at | Should -Not -BeNullOrEmpty
        $cache.Fields.os.last_sent_at          | Should -BeNullOrEmpty
    }

    It 'does not resend before SendHours elapses' {
        $needle = [pscustomobject]@{ Type = 'HEADER'; FieldName = 'csc_version'; Label = 'CSC_Version'; RefreshHours = 6; SendHours = 24; Source = 'local' }
        Invoke-HeaderNeedleCheck -Needles @($needle) | Out-Null
        $script:Sent.Clear()

        (Invoke-HeaderNeedleCheck -Needles @($needle)) | Should -Be 0
        $script:Sent.Count | Should -Be 0
    }

    It 'resends once SendHours has elapsed' {
        $cache = Get-Content -LiteralPath $script:HeaderCacheFile -Raw | ConvertFrom-Json
        $cache.Fields.csc_version.last_sent_at = ([datetimeoffset]::Now.AddHours(-25)).ToString('o')
        $cache | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:HeaderCacheFile -Encoding UTF8

        $needle = [pscustomobject]@{ Type = 'HEADER'; FieldName = 'csc_version'; Label = 'CSC_Version'; RefreshHours = 6; SendHours = 24; Source = 'local' }

        (Invoke-HeaderNeedleCheck -Needles @($needle)) | Should -Be 1
    }

    It 'honors the global default SendHours when the needle omits it' {
        $cache = Get-Content -LiteralPath $script:HeaderCacheFile -Raw | ConvertFrom-Json
        $cache.Fields.os.last_sent_at = ([datetimeoffset]::Now.AddHours(-2)).ToString('o')
        $cache | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:HeaderCacheFile -Encoding UTF8

        $needle = [pscustomobject]@{ Type = 'HEADER'; FieldName = 'os'; Label = 'OS_Version'; RefreshHours = $null; SendHours = $null; Source = 'local' }

        (Invoke-HeaderNeedleCheck -Needles @($needle)) | Should -Be 0

        $script:HeaderSendIntervalHours = 1
        (Invoke-HeaderNeedleCheck -Needles @($needle)) | Should -Be 1
    }

    It 'sends * as ONE combined payload rather than one call per field' {
        $needle = [pscustomobject]@{ Type = 'HEADER'; FieldName = '*'; Label = 'Run_Header_All'; RefreshHours = $null; SendHours = 24; Source = 'local' }

        (Invoke-HeaderNeedleCheck -Needles @($needle)) | Should -Be 1

        $script:Sent.Count                 | Should -Be 1
        $script:Sent[0].Data.header_field  | Should -Be '*'
        $script:Sent[0].Data.csc_version   | Should -Be '5.1.17.3394'
        $script:Sent[0].Data.os            | Should -Be 'Windows 11'

        $cache = Get-Content -LiteralPath $script:HeaderCacheFile -Raw | ConvertFrom-Json
        $cache.Bundles.Run_Header_All.last_sent_at | Should -Not -BeNullOrEmpty
    }

    It 'gates the * bundle on its own per-label stamp' {
        $needle = [pscustomobject]@{ Type = 'HEADER'; FieldName = '*'; Label = 'Run_Header_All'; RefreshHours = $null; SendHours = 24; Source = 'local' }
        Invoke-HeaderNeedleCheck -Needles @($needle) | Out-Null
        $script:Sent.Clear()

        (Invoke-HeaderNeedleCheck -Needles @($needle)) | Should -Be 0
    }

    It 'is a safe no-op when the cache file does not exist yet' {
        Remove-Item -LiteralPath $script:HeaderCacheFile -Force
        $needle = [pscustomobject]@{ Type = 'HEADER'; FieldName = 'os'; Label = 'OS_Version'; RefreshHours = $null; SendHours = 24; Source = 'local' }

        (Invoke-HeaderNeedleCheck -Needles @($needle)) | Should -Be 0
        $script:Sent.Count | Should -Be 0
    }

    It 'returns zero when no HEADER needles are configured' {
        (Invoke-HeaderNeedleCheck -Needles @()) | Should -Be 0
    }
}

Describe 'HEADER telemetry registration' {
    It 'registers haystack_header_fields in tee profiles level 2 and above' {
        foreach ($level in 2..5) {
            $profilePath = Join-Path $script:ReleaseRoot "tee_profiles/tee_level_$level.psd1"
            $data = Import-PowerShellDataFile -Path $profilePath
            $data.Events.ContainsKey('haystack_header_fields') | Should -BeTrue
        }
    }

    It 'documents every HEADER payload field in haystack_msg_schema.psd1' {
        $schema = Import-PowerShellDataFile -Path (Join-Path $script:ReleaseRoot 'support_files/haystack_msg_schema.psd1')
        foreach ($field in @('header_field','collected_at','ww_version','os','model','serial','last_boot','csc_version','csc_source','vpn_profile')) {
            $schema.Optional.ContainsKey($field) | Should -BeTrue
            $schema.CanonicalCasing              | Should -Contain $field
        }
    }

    It 'documents the HEADER directive in needles.cfg' {
        $cfg = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'needles.cfg') -Raw
        $cfg | Should -Match 'FORMAT: HEADER\|FieldName\|Label'
        $cfg | Should -Match 'HEADER\|csc_version\|CSC_Version\|RefreshHours=6\|SendHours=24'
    }
}
