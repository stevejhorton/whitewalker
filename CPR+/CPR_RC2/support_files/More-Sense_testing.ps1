# Appsense Replacement (PoC)
# Steve Horton
# steve.horton@optum.com
# 8Aug25
# NOTES: Updated to move dev_ xmls into place with prod filenams
# NOTES: Flipped result 11 and 19 (to place the correct xml in place for exceptions and elevated AO users)
# TO DO:	
#
#files and dirs
#------------------------------------------------------------------------------------------------------------
$reg_val = $((Get-itemproperty -Path "HKLM:\SYSTEM\UHG\DSM").VPN)
$reg_path = "HKLM:\SYSTEM\UHG\DSM"
$trigger_file = "C:\Windows\UHGLogs\dev_vpn.txt" #if exitst, run in DEV mode
$timestamp = $(((get-date).ToUniversalTime()).ToString("ddMMMyy_HHmmssZ"))
$tmp_dir = "C:\temp"
$clone_dir = "$tmp_dir\clones"
$log_dir = "$tmp_dir\logs"
$logfile = "$log_dir\aovpn_moresense_log_"+ $timestamp +".txt"
$user_gp = "user_gp.info"
$machine_gp = "machine_gp.info"
$all_gp = "$tmp_dir\all_gp.info" #contains USER and MACHINE GP info
$total = "$tmp_dir\total"
$anyconnect_vpn_xml_folder = "C:\ProgramData\Cisco\Cisco AnyConnect Secure Mobility Client\Profile\"
$secureconnect_vpn_xml_folder = "C:\ProgramData\Cisco\Cisco Secure Client\VPN\Profile\"
$global:client_dir = ""
$root_share = "\\ms.ds.uhc.com\netlogon\UHG\Scripts\AOVPN"
#$check = $(whoami.exe /GROUPS)
$loggedOnUser = (Get-CIMInstance -ClassName Win32_ComputerSystem | select username).username.split('\')[1]
$MachineName = &hostname
#------------------------------------------------------------------------------------------------------------
#
function set_env_val(){
	$trigger = $(Test-Path -Path $trigger_file)
	
	if (!$trigger){
	$env = "AOVPN-PROD"
	}
	else{
	$env = "AOVPN-DEV"
	}
	return $env
}
$global:env = set_env_val
$env = $global:env
#
$line = "++++++++++++++++++++++++++++++++++"
#ALL Groups
#
#Machine
$m1 = "GP_C_EnforceSmartCardLogon"
$m2 = "EmpVPN_Workstations"
$m3 = "Some_New_Machine_Group"
$machine_groups = @( $m1, $m2 ,$m3 )
#
#Users
$u1 = "EmpVPN_Elevated_Access"
$u2 = "AOVPN_User_Exceptions"
$u3 = "SomeNewUserGroup"
$user_groups = @( $u1, $u2 ,$u3 )
#
$privs_hash = @{
	$m1 = 1
	$m2 = 2
	$m3 = 4
	$u1 = 8
	$u2 = 16
	$u3 = 32
}
#
#XMLS      #TODO: Just loop on the contents of the share and populate maybe??
$x1 = "uhg_always_on.xml"
$x2 = "uhg_always_on_elevated.xml"
$x3 = "uhg_always_on_exception.xml"
$x4 = "uhg_always_on_exception_elevated.xml"
$x5 = "uhg_smartcard_exception.xml"
$x6 = "uhg_smartcard_exception_elevated.xml"
$x7 = "uhgprofile.xml"
$x8 = "SomeNewXML"
$xml_files = @( $x1, $x2, $x3, $x4, $x5, $x6, $x7, $x8  )
#
#
function pick_client(){

$sc_path = Test-Path $secureconnect_vpn_xml_folder
$ac_path = Test-Path $anyconnect_vpn_xml_folder

if ($sc_path){
	Write-Output $line `n
	Write-Output "Configuring for SecureClient."
	$global:client_dir = $secureconnect_vpn_xml_folder
	$client = "sc"
	return $global:client_dir
	}
elseif ($ac_path){
	Write-Output $line `n
	Write-Output "Configuring for AnyConnect."
	$global:client_dir = $anyconnect_vpn_xml_folder
	$client = "ac"
	return $global:client_dir
	}
else{
	Write-Output $line `n
	Write-Output "AnyConnect OR SecureClient not found! Exiting..(exit 3)"
	exit 3
	} 
	#return $global:client_dir
}
#
function find_string($str,$file){
	$result = $(cat $file | Select-String "$str" -Quiet)
		if ($result){
			return $true
}
		else{
			return $false
}
}
#
function start_logging() {
	Start-Transcript -Append $logfile

	Write-Output $line `n
	Write-Output "**************** AOVPN MoreSense Log ****************"
	$today = Get-Date -f MM-dd-yyyy-HHmm
	Write-Host "`nTimestamp: $today"
	Write-Output "GOT ENV AS: $(set_env_val)"
	Write-Host "Current Reg Value: $reg_val"
	Write-Output "Start Logging to $logfile"
	Write-Output $line `n
}
#
function stop_logging() {
	Write-Output $line `n
	Write-Output "Stop Logging to $logfile"
	Stop-Transcript
	Write-Output $line `n
}
#
function get_user_global() {
	Write-Output "Checking User Memberships.. "
	Write-Output $line `n


	foreach ($gp in $user_groups) {
	$stat = (New-Object System.Security.Principal.WindowsPrincipal($loggedOnUser)).IsInRole("$gp")
	if ($stat) 
	{
	Write-Output "$gp = $stat"
	Write-Output "Adding: $privs_hash.$gp"
	$privs_hash.$gp >> $total
	$priv_total += $val
	}
	elseif (!$stat)
	{
	Write-Output "$gp = NOT_A_MEMBER"
	}
 }
	Write-Output $line `n
 }
#
function get_computer_global() {
	Write-Output "Checking Machine Memberships.. "
	Write-Output $line `n

	foreach ($gp in $machine_groups) {
	$stat = (New-Object System.Security.Principal.WindowsPrincipal($MachineName)).IsInRole("$gp")
	if ($stat) 
	{
	Write-Output "$gp = $stat"
	Write-Output "Adding: $privs_hash.$gp"
	$privs_hash.$gp >> $total
	$priv_total += $val
	}
	elseif (!$stat)
	{
	Write-Output "$gp = NOT_A_MEMBER"
	}
 }
	Write-Output $line `n
}
#
function calculate_privs(){
	Get-Content $total | Where-Object{$_ -match "\d+(,\d+)?"} | 
    	ForEach-Object{[double]($matches[0] -replace ",",".")} | 
    	Measure-Object -Sum | Select-Object -ExpandProperty sum
}
#
function setup_env(){
	Write-Output "Inspecting local env now."
	Write-Output $line `n
	Write-Output "-Current Permissions HashTable-" `n
	$privs_hash
	Write-Output $line
}

function pick_xml(){

	$num = calculate_privs
	$env_dir = set_env_val

	Write-Output "Calculated Total: $num"
	Write-Output $line `n
if ( $num -eq 19 ){
	$xml = "uhg_always_on_exception.xml"
	$global:prod_xml = "uhg_always_on_exception.xml"
	if ($env -eq "AOVPN-DEV"){
	$pre = "dev_"
	$xml = $pre+$xml
	}	
	Write-Output "Using: $xml"
	Write-Output $line `n
	}
elseif ( $num -eq 11 ){
	$xml = "uhg_always_on_elevated.xml"
	$global:prod_xml = "uhg_always_on_elevated.xml"
	if ($env -eq "AOVPN-DEV"){
	$pre = "dev_"
	$xml = $pre+$xml
	}	
	Write-Output "Using: $xml"
	Write-Output $line `n
	}
elseif ( $num -eq 27 ){
	$xml = "uhg_always_on_exception_elevated.xml"
	$global:prod_xml = "uhg_always_on_exception_elevated.xml"
	if ($env -eq "AOVPN-DEV"){
	$pre = "dev_"
	$xml = $pre+$xml
	}	
	Write-Output "Using: $xml"
	Write-Output $line `n
	}
else{
	Write-Output "Using default/fallback xml for this user/machine"
	$xml = "uhg_always_on.xml"
	$global:prod_xml = "uhg_always_on.xml"
	Write-Output "Using: $xml"
	Write-Output $line `n
	}
	$new_file = $(Join-Path -Path $root_share -ChildPath $env_dir | Join-Path -ChildPath $xml)
	$current_file = $(Join-Path -Path $global:client_dir -ChildPath $xml)
	Write-Output ""
	Write-Output "Building file paths"
	Write-Output "====================================="
	Write-Output "NEW_FILE: $new_file"
	Write-Output "CURRENT_FILE: $current_file"
	Write-Output "====================================="
	
	hash_xml ($new_file, $current_file)

}
#
function check_reg($new_xml){
	Write-Output ""
	Write-Output "====================================="
	Write-Host "Seeing if existing reg value needs to be updated.."
	$base_xml = [System.Io.Path]::GetFileNameWithoutExtension($new_xml)
	$result = [bool]($reg_val -Contains $base_xml)
	
		if ($result){
		Write-Host "Reg Value: $reg_path set to $base_xml.."
		return $result
		}	
		elseif (!$result){
		Write-Host "Current Val: $reg_val"
		Write-Host "Reg Value: Needs updating.."
		Write-Host "Attempting to set Reg Value: $reg_path to $base_xml.."
		Set-Itemproperty -path $reg_path -Name "VPN" -value "$base_xml"
		Write-Host "Validating Reg Value: $reg_path now set to $base_xml.."
		$reg_val = $((Get-itemproperty -Path "HKLM:\SYSTEM\UHG\DSM").VPN) #re-pull reg val after change
		$result = [bool]($reg_val -Contains $base_xml)
		Write-Output "Reg Updated?"
		return $result
		}
		else {
		Write-Host "Reg Value: $reg_path not found! Exiting now..(exit 6)"
		exit 6
	}
	
}
#
function clean_old_xmls(){
		Write-Output "====================================="
		Write-Output "Cleaning out any old profile XMLs $dst"
		$dst = $global:client_dir
		$env = $global:env
		
			Write-Output "Client Dir is: $dst"
			Write-Output "SKIPPING Final XML: $xml if found.."
			Write-Output `n 	
		foreach ($file in $xml_files) {
			$item = Join-Path -Path $dst -ChildPath $file
				if (($env -eq "AOVPN-DEV") -And (Test-Path -Path $item)){
				Write-Output "In DEV_MODE $file.. being deleted now.. "
				Remove-Item $item
				}
				if (($file -ne $xml) -And (Test-Path -Path $item)){
				Write-Output "$file found.. deleting now.. "
				Remove-Item $item
				if (Test-Path -Path $item){
				Write-Output "Unable to remove old XML $item!!.. Privs?? Exiting now..(exit 7)"
				exit 7
				}
				else{
				Write-Output "$item removed.."
				}
			}
			else{
			Write-Output "$file not found.. moving on.. "
			}
 	}
	Write-Output $line `n
}


function write_xml($new_xml){
		Write-Output "====================================="
		$prod_xml = $global:prod_xml
		$dst = $global:client_dir
		$final_src_file = $new_xml

		
		$final_result = $dst+$xml
		Write-Output "xml = $xml"
		Write-Output "final_result = $final_result"
		Write-Output "dst = $dst"
		Write-Output "final_src_file = $final_src_file"
		Write-Output "Writing $final_src_file >> $dst"
		Copy-Item -Path $final_src_file -Destination $dst -Force #!!!!!!!!! ONLY ENABLE WHEN READY TO GO LIVE !!!!!!!!!!!	
		if (-not (Test-Path -Path $final_result)){
		Write-Output "====================================="
		Write-Output "Error writing $final_result into place!!! Exiting now..(exit 4)"
		exit 4 
		}
		else{
		
		if ($env -eq "AOVPN-DEV"){
		Write-Output "====================================="
				Write-Output "Checking $dst+$prod_xml"
		Write-Output "Running in DEV Mode, stripping dev_ prefix; turning $xml into $prod_xml (SO IT WILL REMAIN WHEN SWITCHING TO PROD MODE)"
		Write-Output "NOTE: All other refs, Logs and Reg Key will reflect the dev_ prepended name even though we've renamed it."
		Write-Output "Checking $dst$prod_xml NOW!"
		Rename-Item $final_result -NewName $prod_xml -Force
			if (-not (Test-Path -Path $dst$prod_xml)){
			Write-Output "====================================="
			Write-Output "Error renaming $xml to $prod_xml!!! Exiting now..(exit 10)"
			exit 10
			}
			else{
			Write-Output "Renaming of $xml to $prod_xml successful!"
			}	
		Write-Output "====================================="
		Write-Output "XML: $final_result write successful."
		Write-Output "Checking/Updating reg_val now.."
		check_reg ($xml)
		}	
}
}

function hash_xml($array){
	$n_hash = $array[0]
	$c_hash = $array[1]

	Write-Output "====================================="

	if (-not (Test-Path -Path $n_hash)){
	Write-Output "$n_hash NOT Found!"
	Write-Output ""
	Write-Output "New xml $n_hash not found! Exiting..(exit 5)"
	exit 5
}	

	if (-not (Test-Path -Path $c_hash)){
	Write-Output "$c_hash NOT Found!"
	Write-Output ""
	Write-Output "NOTE: Assuming this is a new XML for this Computer."
	Write-Output "Writing NEW file out now.."
	clean_old_xmls
	write_xml($n_hash)
}	
	
	if ( (Test-Path $c_hash) -and (Test-Path $n_hash)){
	Write-Output "BOTH: $c_hash -AND- $n_hash Found!"
	
	$current_hash = (Get-FileHash $c_hash -a sha256).Hash
	$new_hash = (Get-FileHash $n_hash -a sha256).Hash
	Write-Output ""
	Write-Output "Comparing sha256 bit hash values"
	Write-Output "====================================="
	Write-Output "NEW_HASH is: $n_hash : $new_hash"
	Write-Output "CURRENT_HASH is: $c_hash : $current_hash"
	Write-Output "====================================="
	$new = Split-Path $n_hash -leaf
	$current = Split-Path $c_hash -leaf
	if ($env -eq "AOVPN-DEV"){
		Write-Output "DEV_MODE = TRUE"	
		clean_old_xmls
		Write-Output "Writing w/ FORCE $n_hash into $global:client_dir"
		Write-Output "====================================="
		write_xml($n_hash)
	}
	elseif ( ($new_hash -eq $current_hash) -or ($new -eq $current)){
		Write-Output "FILEMATCH = TRUE -OR- FILENAME_EXISTS = TRUE"	
		clean_old_xmls
		Write-Output "Validating registry entry up to date.."
		check_reg ($xml)
	}

	else
	{
		
		Write-Output "FILEMATCH = FALSE"	
		clean_old_xmls
		Write-Output "Writing $n_hash into $global:client_dir"
		Write-Output "====================================="
		write_xml($n_hash)
	}
	}
}	
#
function cleanup(){
	Write-Output $line `n
	Write-Output "Doing some cleanup.."
	Write-Output ""
	if (Test-Path -Path $all_gp){
	Remove-Item $all_gp
	}
}
#
function check_network(){
	Write-Output "Checking for domain connectivity now.."
        if (!(Test-ComputerSecureChannel -Verbose)) {
                Write-Output "Connection to domain failed! Exiting Now..(exit 1)"
		exit 1
        }
        else {
                Write-Output "Connection to domain successful!"
		Write-Output $line `n
        }
}
#
###############################
#	     MAIN             #
###############################
#
Write-Output "" > $total #clear out $total
cleanup
start_logging
check_network
setup_env
pick_client
get_user_global
get_computer_global
pick_xml
stop_logging
cleanup
