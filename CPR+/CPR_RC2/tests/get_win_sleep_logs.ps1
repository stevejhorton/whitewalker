$event = Get-WinEvent -FilterHashTable @{
	LogName = 'System'
	ProviderName = 'Microsoft-Windows-Kernel-Power'
} -MaxEvents 10

$event | Format-List TimeCreated, Id, ProviderName, LogName, Message
	#ProviderName = 'Microsoft-Windows-Kernel-Power'
	#ProviderName = 'Kernel-Power'
	#Id = 566

