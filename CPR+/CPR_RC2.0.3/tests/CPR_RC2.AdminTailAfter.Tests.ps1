# Run-then-tail helpers in the tech console (RC2.0.3): Invoke-WWTailAfter / Invoke-WWOfferFollow.
# Fail-soft contract: a missing log, watcher or stream never throws and never blocks the menu.

BeforeAll {
    $script:ReleaseRoot = Split-Path -Parent $PSScriptRoot
    $hsContent = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'haystack.ps1') -Raw
    $hsPre     = ($hsContent -split '(?ms)^# =+\r?\n# Entry Point')[0]
    Invoke-Expression $hsPre.Substring($hsPre.IndexOf('function Write-HSLog'))

    $script:WWRoot = $TestDrive
    $script:WWLogDir = Join-Path $TestDrive 'logs'
    $script:AdminActionLog = Join-Path $script:WWLogDir 'white_walker.admin_actions.log'
    $script:HaystackScript = Join-Path $TestDrive 'haystack.ps1'
    $script:ActiveTeeProfile = Join-Path $TestDrive 'WW_tee_events.psd1'
    $script:RemoteNeedlesFile = Join-Path $TestDrive 'remote_needles.cfg'
    $script:LocalNeedlesFile  = Join-Path $TestDrive 'local_needles.cfg'

    $actionContent = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'admin/Invoke-WhiteWalkerAction.ps1') -Raw
    $actionPre     = ($actionContent -split "(?ms)^if \(-not \(\`$MyInvocation")[0]
    Invoke-Expression $actionPre.Substring($actionPre.IndexOf('function Write-WWAdminLog'))
}

Describe 'Invoke-WWTailAfter' {
    BeforeEach { Mock Write-Host { } }

    It 'never throws when the watcher or stream is unavailable' {
        { Invoke-WWTailAfter -Stream 'Main' } | Should -Not -Throw
        { Invoke-WWTailAfter -Stream 'NoSuchStream' -FollowSeconds 5 } | Should -Not -Throw
    }
    It 'prints the last lines without following when FollowSeconds is 0' {
        function Get-WWLogInventory { @([pscustomobject]@{ Name = 'Main'; File = 'x.log'; Json = $false }) }
        function Get-WWLogPath { param($Definition) Join-Path $TestDrive 'x.log' }
        Set-Content -Path (Join-Path $TestDrive 'x.log') -Value 'line'
        $script:Seen = $null
        function Show-WWLogStream { param($Definition, [int]$Count, $Match, [switch]$Follow, [switch]$AllowExitKey, [int]$MaxIterations)
            $script:Seen = @{ Count = $Count; Follow = [bool]$Follow; Max = $MaxIterations } }
        Invoke-WWTailAfter -Stream 'Main' -Lines 7
        $script:Seen.Count | Should -Be 7
        $script:Seen.Follow | Should -BeFalse
    }
    It 'follows for FollowSeconds (two 500 ms iterations per second) with the exit key enabled' {
        function Get-WWLogInventory { @([pscustomobject]@{ Name = 'Main'; File = 'x.log'; Json = $false }) }
        function Get-WWLogPath { param($Definition) Join-Path $TestDrive 'x.log' }
        Set-Content -Path (Join-Path $TestDrive 'x.log') -Value 'line'
        $script:Seen = $null
        function Show-WWLogStream { param($Definition, [int]$Count, $Match, [switch]$Follow, [switch]$AllowExitKey, [int]$MaxIterations)
            $script:Seen = @{ Follow = [bool]$Follow; Key = [bool]$AllowExitKey; Max = $MaxIterations } }
        Invoke-WWTailAfter -Stream 'Main' -FollowSeconds 30
        $script:Seen.Follow | Should -BeTrue
        $script:Seen.Key | Should -BeTrue
        $script:Seen.Max | Should -Be 60
    }
    It 'says the log is not there yet instead of failing' {
        function Get-WWLogInventory { @([pscustomobject]@{ Name = 'Main'; File = 'missing.log'; Json = $false }) }
        function Get-WWLogPath { param($Definition) Join-Path $TestDrive 'missing.log' }
        function Show-WWLogStream { throw 'must not be called' }
        { Invoke-WWTailAfter -Stream 'Main' } | Should -Not -Throw
    }
}

Describe 'Invoke-WWOfferFollow' {
    BeforeEach { Mock Write-Host { }; Mock Invoke-WWTailAfter { } }
    It 'does nothing by default (Enter) or on n' -ForEach @(@{ A = '' }, @{ A = 'n' }) {
        Mock Read-Host { $A }
        Invoke-WWOfferFollow -Stream 'Installer'
        Should -Invoke Invoke-WWTailAfter -Times 0 -Exactly
    }
    It 'follows the named stream on y' {
        Mock Read-Host { 'y' }
        Invoke-WWOfferFollow -Stream 'Installer' -Seconds 90
        Should -Invoke Invoke-WWTailAfter -Times 1 -Exactly -ParameterFilter { $Stream -eq 'Installer' -and $FollowSeconds -eq 90 }
    }
}

Describe 'which actions show a log afterwards (source contract)' {
    BeforeAll { $script:Src = Get-Content -LiteralPath (Join-Path $script:ReleaseRoot 'admin/Invoke-WhiteWalkerAction.ps1') -Raw }
    It 'synchronous actions tail their result log' {
        $script:Src | Should -Match "(?s)function Invoke-WWForceXmlVaultSync.*?Invoke-WWTailAfter -Stream 'XmlVault'"
        $script:Src | Should -Match "(?s)function Invoke-WWQuickForceMainRun.*?Invoke-WWTailAfter -Stream 'Main'"
    }
    It 'flag-touch actions (work happens at the next run) offer to follow' {
        $script:Src | Should -Match "(?s)function Invoke-WWVpnProfileRestore.*?Invoke-WWOfferFollow -Stream 'XmlVault'"
        $script:Src | Should -Match "(?s)function Invoke-WWSelfUpdateTrigger.*?Invoke-WWOfferFollow -Stream 'Installer'"
    }
}
