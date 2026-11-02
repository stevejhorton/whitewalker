<#
.SYNOPSIS
  READ-ONLY: is it safe and worthwhile to run 'vpncli stats', 'state' and 'status' at the same time?
.DESCRIPTION
  Runs the three read-only vpncli commands one after another, then all three concurrently, several times,
  and reports wall-clock time and whether the connection-state lines agree. Never connects or disconnects.
  Run from an elevated Windows PowerShell:  .\Test-VpncliParallel.ps1  [-Rounds 3]
#>
param(
    [int]$Rounds = 3,
    [string]$VpnCli = 'C:\Program Files (x86)\Cisco\Cisco Secure Client\vpncli.exe',
    [int]$TimeoutSec = 20
)
if (-not (Test-Path -LiteralPath $VpnCli)) { Write-Host "vpncli not found: $VpnCli" -ForegroundColor Red; return }
$cmds = @('stats','state','status')

function Start-Vpn([string]$Arguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $VpnCli; $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    [pscustomobject]@{ Proc = $p; Out = $p.StandardOutput.ReadToEndAsync(); Err = $p.StandardError.ReadToEndAsync(); Cmd = $Arguments }
}
function Wait-Vpn($h) {
    if (-not $h.Proc.WaitForExit($TimeoutSec * 1000)) { try { $h.Proc.Kill() } catch { }; return '<<TIMEOUT>>' }
    $h.Proc.WaitForExit(); return [string]$h.Out.Result
}
function Get-Key([string]$Text) {
    # Only the lines that say what the tunnel is doing (counters in stats change between calls)
    (($Text -split "`r?`n") | Where-Object { $_ -match '(?i)management\s+connection\s+state|>>\s*state:|^\s*state\s*:' } |
        ForEach-Object { $_.Trim() }) -join ' | '
}

$rows = @()
for ($i = 1; $i -le $Rounds; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew(); $seq = @{}
    foreach ($c in $cmds) { $seq[$c] = Wait-Vpn (Start-Vpn $c) }
    $seqMs = $sw.ElapsedMilliseconds

    $sw.Restart(); $hs = foreach ($c in $cmds) { Start-Vpn $c }
    $par = @{}; foreach ($h in $hs) { $par[$h.Cmd] = Wait-Vpn $h }
    $parMs = $sw.ElapsedMilliseconds

    $same = $true; $notes = @()
    foreach ($c in $cmds) {
        if ($par[$c] -eq '<<TIMEOUT>>') { $same = $false; $notes += "$c timed out in parallel" }
        elseif ([string]::IsNullOrWhiteSpace($par[$c]) -and -not [string]::IsNullOrWhiteSpace($seq[$c])) { $same = $false; $notes += "$c empty in parallel" }
        elseif ((Get-Key $par[$c]) -ne (Get-Key $seq[$c])) { $same = $false; $notes += "$c state lines differ" }
    }
    $rows += [pscustomobject]@{ Round = $i; SequentialMs = $seqMs; ParallelMs = $parMs; StateLinesAgree = $same; Notes = ($notes -join '; ') }
}
$rows | Format-Table -AutoSize
$avgS = [int](($rows | Measure-Object SequentialMs -Average).Average); $avgP = [int](($rows | Measure-Object ParallelMs -Average).Average)
Write-Host ("Average: sequential {0} ms, parallel {1} ms (saves about {2} ms per run)" -f $avgS, $avgP, ($avgS - $avgP)) -ForegroundColor Cyan
if ($rows.StateLinesAgree -contains $false) { Write-Host "Parallel results did NOT always match: do not run vpncli concurrently." -ForegroundColor Yellow }
else { Write-Host "Parallel results matched in every round." -ForegroundColor Green }
