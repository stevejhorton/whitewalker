# WW_tee.Tests.ps1
# RC1.25 - normalized cap_portal_* payload contract and local EvtTime stamping

BeforeAll {
    . (Join-Path $PSScriptRoot 'WW_tee.ps1')
    . (Join-Path $PSScriptRoot 'WW_haystack_schema.ps1')

    function ConvertFrom-TestPayload {
        param([string]$Payload)
        $fields = @{}
        foreach ($m in [regex]::Matches($Payload, '([A-Za-z0-9_]+)="((?:[^"\\]|\\.)*)"')) {
            $fields[$m.Groups[1].Value] = $m.Groups[2].Value
        }
        return $fields
    }

    function Get-LastQueuedPayload {
        param([string]$QueueFile)
        $line = (Get-Content -LiteralPath $QueueFile | Select-Object -Last 1)
        return ($line | ConvertFrom-Json).payload
    }
}

Describe 'ConvertTo-NormalizedCapPortalData' {
    It 'fills every required normalized field for <Tag>' -TestCases @(
        @{ Tag = 'cap_portal_redirect' }
        @{ Tag = 'cap_portal_remediation_passed' }
        @{ Tag = 'cap_portal_remediation_failed' }
    ) {
        param($Tag)

        $result = ConvertTo-NormalizedCapPortalData -Tag $Tag -Data @{ url = 'http://portal' }

        foreach ($field in @('ssid','url','port','ip','gw','dns','vpn_state','portal_type','status','reason')) {
            $result.ContainsKey($field) | Should -BeTrue -Because "$field is part of the normalized contract"
        }
        $result.url | Should -Be 'http://portal'
        $result.ip  | Should -Be ''
    }

    It 'does not invent values for a caller-supplied field' {
        $result = ConvertTo-NormalizedCapPortalData -Tag 'cap_portal_redirect' -Data @{ ip = '10.1.2.3' }
        $result.ip | Should -Be '10.1.2.3'
    }

    It 'leaves non-captive-portal tags untouched' {
        $result = ConvertTo-NormalizedCapPortalData -Tag 'network_state' -Data @{ ip = '10.1.2.3' }
        $result.Keys.Count | Should -Be 1
    }
}

Describe 'Write-TeeLog payload' {
    BeforeEach {
        $script:HaystackEnabled = $true
        $script:TeeEnabled      = $true
        $script:TeeEventsFile   = Join-Path $PSScriptRoot 'WW_tee_events.psd1'
        $script:TeeQueueFile    = Join-Path $TestDrive 'haystack_syslog_queue.jsonl'
        $script:TeeProfileCache = $null
        Remove-Item -LiteralPath $script:TeeQueueFile -Force -ErrorAction SilentlyContinue

        Mock Get-HaystackUserContext { 'CORP\jdoe' }
    }

    It 'stamps action, machine, user and a local EvtTime on a normalized event' {
        Write-TeeLog 'cap_portal_redirect' @{ url = 'http://portal.example.com'; port = '80' }

        $fields = ConvertFrom-TestPayload (Get-LastQueuedPayload -QueueFile $script:TeeQueueFile)

        $fields['action']  | Should -Be 'cap_portal_redirect'
        $fields['user']    | Should -Be 'CORP\jdoe'
        $fields.ContainsKey('machine') | Should -BeTrue
        $fields['EvtTime'] | Should -Not -BeNullOrEmpty
        { [datetime]::Parse($fields['EvtTime']) } | Should -Not -Throw
    }

    It 'emits every required normalized field, empty when unavailable' {
        Write-TeeLog 'cap_portal_remediation_failed' @{ status = 'timeout'; reason = 'native_timeout_escalated' }

        $fields = ConvertFrom-TestPayload (Get-LastQueuedPayload -QueueFile $script:TeeQueueFile)

        foreach ($field in @('EvtTime','action','machine','user','ssid','url','port','ip','gw','dns','vpn_state','portal_type','status','reason')) {
            $fields.ContainsKey($field) | Should -BeTrue -Because "$field is part of the normalized contract"
        }
        $fields['ip']     | Should -Be ''
        $fields['status'] | Should -Be 'timeout'
    }

    It 'honors a producer-supplied EvtTime instead of re-stamping it' {
        $stamped = '2026-10-10T01:02:03.0000000+00:00'
        Write-TeeLog 'cap_portal_redirect' @{ EvtTime = $stamped; url = 'http://portal' }

        $payload = Get-LastQueuedPayload -QueueFile $script:TeeQueueFile
        (ConvertFrom-TestPayload $payload)['EvtTime'] | Should -Be $stamped
        ([regex]::Matches($payload, 'EvtTime="')).Count | Should -Be 1
    }

    It 'never emits duplicate action/machine/user fields when a caller passes them' {
        Write-TeeLog 'cap_portal_redirect' @{ action = 'spoofed'; machine = 'spoofed'; user = 'spoofed' }

        $payload = Get-LastQueuedPayload -QueueFile $script:TeeQueueFile
        ([regex]::Matches($payload, 'action="')).Count  | Should -Be 1
        ([regex]::Matches($payload, 'user="')).Count    | Should -Be 1
        $payload | Should -Not -Match 'spoofed'
    }

    It 'is a no-op when the tag is not in the active profile' {
        Write-TeeLog 'not_a_real_tag' @{ url = 'http://portal' }
        Test-Path -LiteralPath $script:TeeQueueFile | Should -BeFalse
    }

    It 'is a no-op when tee is disabled (fleet toggle respected)' {
        $script:TeeEnabled = $false
        Write-TeeLog 'cap_portal_redirect' @{ url = 'http://portal' }
        Test-Path -LiteralPath $script:TeeQueueFile | Should -BeFalse
    }
}

Describe 'Get-TeeUserContextFallback' {
    It 'returns a value honoring the user-context contract' {
        $value = Get-TeeUserContextFallback
        $value | Should -Not -BeNullOrEmpty
    }
}

Describe 'Write-TeeLog -PassThru result contract (opt-in failure surfacing)' {
    BeforeEach {
        $script:HaystackEnabled = $true
        $script:TeeEnabled      = $true
        $script:TeeEventsFile   = Join-Path $PSScriptRoot 'WW_tee_events.psd1'
        $script:TeeQueueFile    = Join-Path $TestDrive 'passthru_queue.jsonl'
        $script:TeeProfileCache = $null
        Remove-Item -LiteralPath $script:TeeQueueFile -Force -ErrorAction SilentlyContinue

        Mock Get-HaystackUserContext { 'CORP\jdoe' }
    }

    It 'emits nothing to the pipeline when -PassThru is not used (production behavior unchanged)' {
        $out = Write-TeeLog 'cap_portal_redirect' @{ url = 'http://portal' }
        $out | Should -BeNullOrEmpty
        Test-Path -LiteralPath $script:TeeQueueFile | Should -BeTrue
    }

    It 'reports Queued/queued when the entry is written' {
        $result = Write-TeeLog -Tag 'cap_portal_redirect' -Data @{ url = 'http://portal' } -PassThru
        $result.Queued    | Should -BeTrue
        $result.Reason    | Should -Be 'queued'
        $result.Error     | Should -BeNullOrEmpty
        $result.QueueFile | Should -Be $script:TeeQueueFile
    }

    It 'reports tag_not_in_profile when the volume knob gates the tag' {
        $result = Write-TeeLog -Tag 'not_a_real_tag' -Data @{} -PassThru
        $result.Queued | Should -BeFalse
        $result.Reason | Should -Be 'tag_not_in_profile'
    }

    It 'reports haystack_disabled when the master switch is off' {
        $script:HaystackEnabled = $false
        $result = Write-TeeLog -Tag 'cap_portal_redirect' -Data @{} -PassThru
        $result.Queued | Should -BeFalse
        $result.Reason | Should -Be 'haystack_disabled'
    }

    It 'reports tee_disabled when the tee switch is off' {
        $script:TeeEnabled = $false
        $result = Write-TeeLog -Tag 'cap_portal_redirect' -Data @{} -PassThru
        $result.Queued | Should -BeFalse
        $result.Reason | Should -Be 'tee_disabled'
    }

    It 'reports error (and still never throws) when the queue write fails' {
        Mock Add-Content { throw 'access denied' }
        $result = Write-TeeLog -Tag 'cap_portal_redirect' -Data @{} -PassThru
        $result.Queued | Should -BeFalse
        $result.Reason | Should -Be 'error'
        $result.Error  | Should -Match 'access denied'
    }
}
