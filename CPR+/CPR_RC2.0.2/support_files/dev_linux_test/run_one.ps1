# Runs ONE Pester file and prints machine-readable lines:  FAIL|<path>|<message>   and   SUMMARY|passed|failed|skipped|notrun|<container errors>
param([Parameter(Mandatory)][string]$Path)
Import-Module Pester -ErrorAction Stop
$c = New-PesterConfiguration
$c.Run.Path = $Path; $c.Run.PassThru = $true; $c.Output.Verbosity = 'None'
$r = Invoke-Pester -Configuration $c
foreach ($t in ($r.Tests | Where-Object Result -eq 'Failed')) {
  $m = ($t.ErrorRecord.Exception.Message -replace '\s+', ' ')
  'FAIL|' + $t.ExpandedPath + '|' + $m.Substring(0, [Math]::Min(300, $m.Length))
}
'SUMMARY|' + $r.PassedCount + '|' + $r.FailedCount + '|' + $r.SkippedCount + '|' + $r.NotRunCount + '|' +
  (($r.Containers | Where-Object Result -eq 'Failed' | ForEach-Object { 'CONTAINERFAIL:' + $_.ErrorRecord }) -join ' ')
