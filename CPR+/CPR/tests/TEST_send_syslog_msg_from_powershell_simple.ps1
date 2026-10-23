# Simple raw UDP syslog test (PowerShell equivalent of bash netcat test)

$SyslogServer = "cpr-syslog.uhc.com"
$SyslogPort   = 514

$hostname = $env:COMPUTERNAME                      # real host: syslog header only
$machine  = "CPR_TESTER"                        # machine= value, same as every test tool
$user     = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$ts       = Get-Date -Format "MMM d HH:mm:ss"   # RFC3164-ish timestamp
$evtTime  = (Get-Date).ToString("o")            # EvtTime, same format as production
$pri      = "<133>"                             # local0.notice (same as your bash test)

$msg = "$pri$ts $hostname CPR-test: action=""test_shot"" machine=""$machine"" user=""$user"" EvtTime=""$evtTime"" msg=""hello from powershell"" note=""src_host=$hostname"""

Write-Host "SENT: $msg"

try {
    $udp = New-Object System.Net.Sockets.UdpClient
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($msg)
    [void]$udp.Send($bytes, $bytes.Length, $SyslogServer, $SyslogPort)
    $udp.Close()
    Write-Host "UDP send complete to $SyslogServer`:$SyslogPort" -ForegroundColor Green
} catch {
    Write-Host "UDP send failed: $_" -ForegroundColor Red
    exit 1
}
