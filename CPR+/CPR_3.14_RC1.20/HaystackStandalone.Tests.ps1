Describe "HayStack standalone wiring" {
    BeforeAll {
        $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $script:haystackPath = Join-Path $repoRoot "CPR_3.14_RC1.14/haystack.ps1"
        $script:wwMainPath   = Join-Path $repoRoot "CPR_3.14_RC1.13/WW_main.ps1"
        $script:haystackText = Get-Content -LiteralPath $haystackPath -Raw
        $script:wwMainText   = Get-Content -LiteralPath $wwMainPath -Raw
    }

    It "makes haystack.ps1 standalone with the expected flags" {
        $haystackText | Should -Match '\[CmdletBinding\(\)\]\s*param\(\s*\[switch\]\$reroll,\s*\[switch\]\$remove,\s*\[int\]\$RerollCooldownMinutes = 0\s*\)'
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
        $wwMainText | Should -Match '\$HaystackEnabled\s*=\s*\$false'
        $wwMainText | Should -Match '\$HaystackScriptPath\s*=\s*"C:\\ProgramData\\WhiteWalker\\haystack\.ps1"'
        $wwMainText | Should -Match '\$HaystackRerollCooldownMinutes\s*=\s*60'
        $wwMainText | Should -Match 'Start-Process "powershell\.exe"'
        $wwMainText | Should -Match '-reroll -RerollCooldownMinutes \$HaystackRerollCooldownMinutes'
        $wwMainText | Should -Match 'Would invoke haystack\.ps1 -reroll -RerollCooldownMinutes \$HaystackRerollCooldownMinutes'
        $wwMainText | Should -Not -Match 'Invoke-HaystackReroll'
        $wwMainText | Should -Not -Match '\.\s+\$HaystackScriptPath'
    }
}
