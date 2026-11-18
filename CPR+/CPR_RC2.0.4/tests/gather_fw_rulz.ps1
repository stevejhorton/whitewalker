$rules = Get-NetFirewallRule -PolicyStore ActiveStore |
    Where-Object { $_.PolicyStoreSourceType -eq 'MDM' }

$result = foreach ($rule in $rules) {

    $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    $service = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    $addr = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        Name        = $rule.DisplayName
        Enabled     = $rule.Enabled
        Direction   = $rule.Direction
        Action      = $rule.Action
        Profile     = $rule.Profile
        Program     = $app.Program
        Service     = $service.Service
        Protocol    = $port.Protocol
        LocalPort   = $port.LocalPort
        RemotePort  = $port.RemotePort
        SourceType  = $rule.PolicyStoreSourceType
        Source      = $rule.PolicyStoreSource
        LocalAddress = ($addr.LocalAddress -join '; ')
        RemoteAddress = ($addr.RemoteAddress -join '; ')

    }
}

$result | Export-Csv "C:\Temp\IntuneFirewallRulesDetailed.csv" -NoTypeInformation
