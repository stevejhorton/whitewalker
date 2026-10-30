# WW_haystack_schema.Tests.ps1
# RC1.25 - user-context resolution contract (the USER_UNKNOWN fix)

BeforeAll {
    . (Join-Path $PSScriptRoot 'WW_haystack_schema.ps1')

    # Platform-neutral stubs for the CIM/WMI probes so the probe-ordering
    # contract can be exercised anywhere Pester runs. The real functions are
    # only present on Windows; these are replaced per-test with Mock.
    if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
        function Get-CimInstance { param($ClassName, $Filter) }
    }
    if (-not (Get-Command Invoke-CimMethod -ErrorAction SilentlyContinue)) {
        function Invoke-CimMethod { param($InputObject, $MethodName) }
    }
    # Windows PowerShell 5.1 has the real Get-WmiObject: unmocked, probe 3 answers with the
    # human running the tests. Shim it where absent so every test can mock it.
    if (-not (Get-Command Get-WmiObject -ErrorAction SilentlyContinue)) {
        function Get-WmiObject { param($Class) }
    }
}

Describe 'Test-HaystackMachineAccount' {
    It 'treats <Name> as a machine/service account' -TestCases @(
        @{ Name = 'NT AUTHORITY\SYSTEM' }
        @{ Name = 'NT AUTHORITY\LOCAL SERVICE' }
        @{ Name = 'NT AUTHORITY\NETWORK SERVICE' }
        @{ Name = 'CORP\WORKSTATION1$' }
        @{ Name = '' }
    ) {
        param($Name)
        Test-HaystackMachineAccount -Name $Name | Should -BeTrue
    }

    It 'treats a real domain user as an interactive account' {
        Test-HaystackMachineAccount -Name 'CORP\jdoe' | Should -BeFalse
    }
}

Describe 'Resolve-HaystackUserContext probe contract' {
    It 'returns the current identity when it is a real (non-service) user' {
        Mock Get-HaystackCurrentIdentityName { 'CORP\jdoe' }

        $result = Resolve-HaystackUserContext

        $result.User   | Should -Be 'CORP\jdoe'
        $result.Source | Should -Be 'current_identity'
    }

    It 'falls through to Win32_ComputerSystem when running as SYSTEM' {
        Mock Get-HaystackCurrentIdentityName { 'NT AUTHORITY\SYSTEM' }
        Mock Get-CimInstance { [pscustomobject]@{ UserName = 'CORP\jdoe' } }

        $result = Resolve-HaystackUserContext

        $result.User   | Should -Be 'CORP\jdoe'
        $result.Source | Should -Be 'cim_computersystem'
    }

    It 'rejects a machine identity returned by a SYSTEM-context probe' {
        Mock Get-HaystackCurrentIdentityName { 'NT AUTHORITY\SYSTEM' }
        Mock Get-CimInstance {
            if ($ClassName -eq 'Win32_ComputerSystem') {
                [pscustomobject]@{ UserName = 'NT AUTHORITY\SYSTEM' }
            } else {
                throw 'no explorer process'
            }
        }
        Mock Invoke-CimMethod { $null }
        Mock Get-WmiObject { [pscustomobject]@{ UserName = 'NT AUTHORITY\SYSTEM' } }

        $result = Resolve-HaystackUserContext

        $result.User | Should -Be 'NO_INTERACTIVE_USER'
        $result.User | Should -Not -Match 'SYSTEM'
    }

    It 'emits NO_INTERACTIVE_USER when probes succeed but nobody is logged on' {
        Mock Get-HaystackCurrentIdentityName { 'NT AUTHORITY\SYSTEM' }
        Mock Get-CimInstance { [pscustomobject]@{ UserName = '' } }
        Mock Invoke-CimMethod { $null }
        Mock Get-WmiObject { [pscustomobject]@{ UserName = '' } }

        $result = Resolve-HaystackUserContext

        $result.User   | Should -Be 'NO_INTERACTIVE_USER'
        $result.Source | Should -Be 'no_interactive_session'
    }

    It 'reserves USER_UNKNOWN for a true lookup failure (every probe errors)' {
        Mock Get-HaystackCurrentIdentityName { throw 'identity unavailable' }
        Mock Get-CimInstance { throw 'cim unavailable' }
        Mock Get-WmiObject { throw 'wmi unavailable' }

        $result = Resolve-HaystackUserContext

        $result.User        | Should -Be 'USER_UNKNOWN'
        $result.Source      | Should -Be 'lookup_failed'
        $result.ProbeErrors | Should -Contain 'cim_computersystem'
    }

    It 'never throws' {
        Mock Get-HaystackCurrentIdentityName { throw 'boom' }
        Mock Get-CimInstance { throw 'boom' }

        { Get-HaystackUserContext } | Should -Not -Throw
    }

    It 'Get-HaystackUserContext returns the resolved string, or the object with -AsObject' {
        Mock Get-HaystackCurrentIdentityName { 'CORP\jdoe' }

        Get-HaystackUserContext | Should -Be 'CORP\jdoe'
        (Get-HaystackUserContext -AsObject).Source | Should -Be 'current_identity'
    }
}

Describe 'Get-HaystackMsgSchema path resolution' {
    It 'loads the repo support_files schema by default' {
        $schema = Get-HaystackMsgSchema
        $schema.Mandatory.Keys | Should -Contain 'EvtTime'
        $schema.Mandatory.Keys | Should -Contain 'user'
    }

    It 'documents the captive portal event_class discriminator' {
        $schema = Get-HaystackMsgSchema -Path (Join-Path $PSScriptRoot 'support_files/haystack_msg_schema.psd1')
        $schema.Optional.Keys | Should -Contain 'event_class'
    }
}
