# Simple raw UDP syslog test (PowerShell equivalent of bash netcat test)

$SyslogServer = "cpr-syslog.uhc.com"
$SyslogPort   = 514

$hostname = $env:COMPUTERNAME
$user     = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$ts       = Get-Date -Format "MMM d HH:mm:ss"   # RFC3164-ish timestamp
$pri      = "<133>"                             # local0.notice (same as your bash test)

$msg = "$pri$ts testhost CPR-test: action=test_shot machine=""$hostname"" user=""$user"" msg=""hello from powershell"""

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
