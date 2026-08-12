#Write-EventLog -LogName Application -Source Application -EventId 7777 -EntryType Information -Message "WhiteWalker: Captive portal authentication required"

eventcreate /T INFORMATION /ID 777 /L APPLICATION /SO "WhiteWalkerTrigger" /D "Captive portal authentication required, starting user browser now!!"
