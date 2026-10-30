# TEST-ONLY log timing (RC2.0.3): -WWTiming switch or cpr_logtiming.flag appends [+Nms | S.SSs] to Write-Log lines.
# Off by default: the line text must be exactly what it was before.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Src  = Get-Content -LiteralPath (Join-Path $script:Root 'main\Main.Logging.ps1') -Raw
    $start = $script:Src.IndexOf('$script:WWTimingFlagPath')
    $end   = $script:Src.IndexOf('function Write-DebugBlock')
    $script:Block = $script:Src.Substring($start, $end - $start)
    function script:Get-Block([string]$FlagPath) {
        $script:Block.Replace("'C:\Windows\Temp\cpr_logtiming.flag'", "'$FlagPath'")
    }
    $script:Lines = New-Object System.Collections.Generic.List[string]
    function Add-LogLine { param($line) $script:Lines.Add($line) }
}

Describe 'Write-Log timing suffix' {
    BeforeEach { $script:Lines.Clear(); Remove-Variable WWTiming -Scope Global -ErrorAction SilentlyContinue }

    It 'adds nothing when neither the switch nor the flag is present' {
        Invoke-Expression (Get-Block (Join-Path $TestDrive 'none.flag'))
        Write-Log 'hello' 'INFO'
        $script:Lines[0] | Should -Match '\[WW\] \[INFO\] hello$'
    }
    It 'adds [+Nms | S.SSs] when the flag file exists' {
        $f = Join-Path $TestDrive 'on.flag'; Set-Content $f 'x'
        Invoke-Expression (Get-Block $f)
        Write-Log 'one'; Start-Sleep -Milliseconds 60; Write-Log 'two'
        $script:Lines[0] | Should -Match 'one \[\+\d+ms \| \d+(\.\d+)?s\]$'
        $script:Lines[1] | Should -Match 'two \[\+\d+ms \| \d+(\.\d+)?s\]$'
        [int]([regex]::Match($script:Lines[1], '\[\+(\d+)ms').Groups[1].Value) | Should -BeGreaterOrEqual 50
    }
    It 'turns on from the -WWTiming switch variable' {
        $global:WWTiming = $true
        Invoke-Expression (Get-Block (Join-Path $TestDrive 'none.flag'))
        Write-Log 'x'
        $script:Lines[0] | Should -Match 'x \[\+\d+ms \| '
    }
    It 'is wired into WW_main.ps1 as a switch and the console offers the toggle' {
        (Get-Content (Join-Path $script:Root 'WW_main.ps1') -Raw) | Should -Match '\[switch\]\$WWTiming'
        (Get-Content (Join-Path $script:Root 'admin\Invoke-WhiteWalkerAction.ps1') -Raw) | Should -Match "'6' \{ Invoke-WWAction -Name 'QuickAction:LogTiming'"
    }
}
