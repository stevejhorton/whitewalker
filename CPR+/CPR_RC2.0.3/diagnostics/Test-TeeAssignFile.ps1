<#
.SYNOPSIS
Read-only formatting check for tee_assign.cfg (run it before copying the file to the NETLOGON share).
.DESCRIPTION
Applies the same parse rules CPR uses and reports what CPR would ignore or misread:
  ERROR  a [teeN] section outside 1-5 (its hosts are ignored), a pattern that matches every host
  WARN   host line above any section, unknown [section], odd characters in a host name, duplicate host
  INFO   host listed in more than one section (highest level wins)
Then prints how many hosts each level has. With -ComputerName it also prints the level that name would get.
Exit code 1 if any ERROR.
.EXAMPLE
.\Test-TeeAssignFile.ps1 -Path .\tee_assign.cfg -ComputerName LAB-07
#>
param(
    [string]$Path = 'C:\ProgramData\WhiteWalker\tee_assign.cfg',
    [string]$ComputerName = ''
)
if (-not (Test-Path -LiteralPath $Path)) { Write-Host "ERROR file not found: $Path"; exit 1 }
$lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
$errors = 0; $warns = 0
$section = $null; $sectionName = ''; $seen = @{}; $count = @{ 1=0; 2=0; 3=0; 4=0; 5=0 }
$n = 0
foreach ($raw in $lines) {
    $n++
    $l = ("$raw" -replace '\s+#.*$', '').Trim()
    if (-not $l -or $l.StartsWith('#') -or $l -match '^version\s*:') { continue }
    if ($raw -match '[^\x20-\x7E\t]') { Write-Host "WARN  line ${n}: non-ASCII or control character: '$l'"; $warns++ }
    if ($l -match '^\[tee([1-5])\]$') { $section = [int]$Matches[1]; $sectionName = $l; continue }
    if ($l -match '^\[tee\d+\]$' -or $l -match '^\[tee\s*\d+\s*\]$') { Write-Host "ERROR line ${n}: '$l' is not a valid section (use [tee1]..[tee5]); its hosts are ignored"; $errors++; $section = $null; continue }
    if ($l.StartsWith('[')) { Write-Host "WARN  line ${n}: unknown section '$l' - its hosts are ignored"; $warns++; $section = $null; continue }
    if ($null -eq $section) { Write-Host "WARN  line ${n}: '$l' is not under a valid [teeN] section - ignored"; $warns++; continue }
    if ($l -notmatch '[A-Za-z0-9]') { Write-Host "ERROR line ${n}: '$l' would match EVERY host"; $errors++; continue }
    if ($l -notmatch '^[A-Za-z0-9_\-\*\?\.]+$') { Write-Host "WARN  line ${n}: '$l' has characters that are not normally in a computer name"; $warns++ }
    $key = $l.ToLowerInvariant()
    if ($seen.ContainsKey($key)) {
        if ($seen[$key] -eq $section) { Write-Host "WARN  line ${n}: '$l' is listed twice in $sectionName"; $warns++ }
        else { Write-Host "INFO  line ${n}: '$l' is also in [tee$($seen[$key])] - the higher level wins" }
    } else { $seen[$key] = $section }
    $count[$section]++
}
Write-Host ("Entries per level: tee1={0} tee2={1} tee3={2} tee4={3} tee5={4}" -f $count[1],$count[2],$count[3],$count[4],$count[5])
if ($ComputerName) {
    $src = Join-Path $PSScriptRoot '..\main\Main.TeeFlag.ps1'
    if (-not (Test-Path -LiteralPath $src)) { $src = 'C:\ProgramData\WhiteWalker\main\Main.TeeFlag.ps1' }
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$null, [ref]$null)
    $fn = $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Get-TeeAssignLevelFromLines' }, $true) | Select-Object -First 1
    if ($fn) {
        . ([scriptblock]::Create($fn.Extent.Text))
        $lvl = Get-TeeAssignLevelFromLines -Lines $lines -ComputerName $ComputerName
        Write-Host $(if ($null -ne $lvl) { "$ComputerName would be assigned tee level $lvl" } else { "$ComputerName is not listed (no assignment)" })
    } else { Write-Host "WARN  could not load the CPR parser from $src" }
}
Write-Host "Result: $errors error(s), $warns warning(s)"
if ($errors -gt 0) { exit 1 }
