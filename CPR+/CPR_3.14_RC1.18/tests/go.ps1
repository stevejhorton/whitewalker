$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile('C:\ProgramData\WhiteWalker\WW_main.ps1', [ref]$null, [ref]$errors)
$errors
