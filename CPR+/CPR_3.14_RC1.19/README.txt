-dl the zip that is pinned (i'll update it and the room name when we switch versions.

-Open an elevated powershell (ASAM Developer etc)

-unzip the file via file explorer

-(inside powershell) cd to the dir created CPR_3.14_RC1.13/CPR_3.14_RC1.13 is normally how it is written out
-./install.ps1
-Let it complete the install
-from the same powershell cd c:\ProgramData\WhiteWalker\ #This is the main dir

#TO SEE LOGS (Note:Logs are generated as needed, so if you see no data (red powershell error) on a fresh install, this is expected.
tail_ww_log.ps1           #MAIN LOG 
tail_ww_blackhole.ps1     #VPN BLACKHOLE LOG
tail_ww_cap_log.ps1       #CAP PORTAL LOG
tail_ww_haystack_log.ps1  #HAYSTACK LOG


WW_main.ps1 vars of Interest
# VPN Blackhole (on_prem hairpin prevention)
$BlackholeEnabled       = $false  # set to $true to enable VPN blackhole on on_prem flare

# HayStack Event Monitor (event log needle watcher)
$HaystackEnabled            = $false  # set to $true to enable HayStack event monitoring


