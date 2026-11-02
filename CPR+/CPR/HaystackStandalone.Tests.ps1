Describe "HayStack standalone wiring" {
    BeforeAll {
        # Targets the CURRENT release, not an old CPR_3.14_RC1.x copy.
        # Works from the release root (shipped copy) and from tests\.
        $repoRoot = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'haystack.ps1')) { $PSScriptRoot } else { Split-Path $PSScriptRoot -Parent }
        $script:haystackPath = Join-Path $repoRoot "haystack.ps1"
        $script:haystackText = Get-Content -LiteralPath $haystackPath -Raw
        # RC2 split WW_main: HayStack config lives in Main.Configuration.ps1, the reroll launch in Main.Entry.ps1.
        $script:wwMainText   = (Get-Content -LiteralPath (Join-Path $repoRoot "main\Main.Configuration.ps1") -Raw) + "`n" +
                               (Get-Content -LiteralPath (Join-Path $repoRoot "main\Main.Entry.ps1") -Raw)
    }

    It "makes haystack.ps1 standalone with the expected flags" {
        $haystackText | Should -Match '\[CmdletBinding\(\)\]\s*param\(\s*\[switch\]\$reroll,\s*\[switch\]\$remove,\s*\[switch\]\$Force,[^\r\n]*\r?\n\s*\[int\]\$RerollCooldownMinutes = 0\s*\)'
    }

    It "uses the new internal cooldown default and removes the old dot-source guard" {
        $haystackText | Should -Match '\$HaystackRerollCooldownMinutes = if \(\$RerollCooldownMinutes -gt 0\) \{ \$RerollCooldownMinutes \} else \{ 60 \}'
        $haystackText | Should -Not -Match 'if \(-not \$HaystackRerollCooldownMinutes\)'
        $haystackText | Should -Not -Match '\$MyInvocation\.InvocationName -ne ''\.'''
    }

    It "has a flag-driven entry point for reroll and remove" {
        $haystackText | Should -Match 'Specify exactly one flag: -reroll OR -remove'
        $haystackText | Should -Match 'Write-HSLog "HayStack -remove: unregistering TS task" "INFO"'
        $haystackText | Should -Match 'Unregister-HaystackTask'
        $haystackText | Should -Match 'Invoke-HaystackReroll'
    }

    It "keeps WW_main haystack integration limited to config and Start-Process orchestration" {
        $wwMainText | Should -Match '\$HaystackEnabled\s*=\s*\$(true|false)'
        $wwMainText | Should -Match '\$HaystackScriptPath\s*=\s*"C:\\ProgramData\\WhiteWalker\\haystack\.ps1"'
        $wwMainText | Should -Match '\$HaystackRerollCooldownMinutes\s*=\s*60'
        $wwMainText | Should -Match 'Start-Process "powershell\.exe"'
        $wwMainText | Should -Match '-File `"\$HaystackScriptPath`" -reroll"'
        $wwMainText | Should -Match 'Would invoke haystack\.ps1 -reroll'
        $wwMainText | Should -Not -Match 'Invoke-HaystackReroll'
        $wwMainText | Should -Not -Match '\.\s+\$HaystackScriptPath'
    }
}
