
Add-Type -AssemblyName System.Device

$geo = New-Object System.Device.Location.GeoCoordinateWatcher
$geo.Start()

try {
    $timeout = [Diagnostics.Stopwatch]::StartNew()

    while ($geo.Status -ne 'Ready' -and
           $geo.Permission -ne 'Denied' -and
           $timeout.Elapsed.TotalSeconds -lt 15) {
        Start-Sleep -Milliseconds 100
    }

    if ($geo.Permission -eq 'Denied') {
        throw "Windows location permission denied."
    }

    if ($geo.Status -ne 'Ready' -or
        $geo.Position.Location.IsUnknown) {
        throw "Unable to obtain location."
    }

    $p = $geo.Position.Location

    # Use invariant formatting for URL coordinates
    $lat = $p.Latitude.ToString(
        [Globalization.CultureInfo]::InvariantCulture)
    $lon = $p.Longitude.ToString(
        [Globalization.CultureInfo]::InvariantCulture)

    $url = "https://nominatim.openstreetmap.org/reverse?lat=$lat&lon=$lon&format=json&addressdetails=1"

    $headers = @{
        "User-Agent" = "HortonGeoTool/1.0 (personal PowerShell utility)"
    }

    $result = Invoke-RestMethod -Uri $url -Headers $headers

    [PSCustomObject]@{
        Latitude  = $p.Latitude
        Longitude = $p.Longitude
        Accuracy  = $p.HorizontalAccuracy
        Address   = $result.display_name
        Street    = $result.address.road
        City      = if ($result.address.city) {
                        $result.address.city
                    } elseif ($result.address.town) {
                        $result.address.town
                    } else {
                        $result.address.village
                    }
        State     = $result.address.state
        Zip       = $result.address.postcode
        MapsURL   = "https://www.google.com/maps?q=$lat,$lon"
    } | Format-List
}
finally {
    $geo.Stop()
}
