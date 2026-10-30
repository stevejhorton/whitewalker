$Version = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}').pv

$WebViewExe = "C:\Program Files (x86)\Microsoft\EdgeWebView\Application\$Version\msedgewebview2.exe"

Test-Path $WebViewExe

$Version = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}').pv

$Version
