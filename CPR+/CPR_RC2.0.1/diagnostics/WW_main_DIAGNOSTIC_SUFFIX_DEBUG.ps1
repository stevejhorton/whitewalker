# DIAGNOSTIC VERSION - Enhanced Test-DC function with detailed suffix logging
# This is the REPLACEMENT Test-DC function for CPR_3.14_RC1.17/WW_main.ps1
# Copy this function and replace the existing Test-DC function (around line 1230)

function Test-DC { 
    param([string]$hostname = $DC_FQDN)
    
    # Ping the DC, then confirm via DNS suffix.
    # Stale VPN routes can make DC pingable from any network - suffixes don't lie.
    # If ANY non-corporate suffix is found, we're off-prem.
    try {
        Write-Log "=== TEST-DC START (Diagnostic Mode) ===" "INFO"
        Write-Log "Testing DC hostname: $hostname" "DEBUG"
        
        $pingResult = Test-Connection -ComputerName $hostname -Count 1 -Quiet -ErrorAction Stop
        Write-Log "DC Ping result: $pingResult" "DEBUG"
        
        if (-not $pingResult) { 
            Write-Log "DC not reachable - returning off-prem" "DEBUG"
            Write-Log "=== TEST-DC END (result=FALSE) ===" "INFO"
            return $false 
        }
        
        try {
            $corpSuffixes = @('ms.ds.uhc.com', 'ds.uhc.com', 'uhc.com')
            $foundSuffixes = @()

            # Method 1: Get DNS suffix search list (the clean way - no regex!)
            Write-Log "[SUFFIX-COLLECTION] Starting Method 1: Get-DnsClientGlobalSetting" "DEBUG"
            try {
                $dnsGlobal = Get-DnsClientGlobalSetting -ErrorAction Stop
                if ($dnsGlobal.SuffixSearchList) {
                    Write-Log "[SUFFIX-COLLECTION] Method 1 returned list:" "DEBUG"
                    foreach ($suffix in $dnsGlobal.SuffixSearchList) {
                        $cleanSuffix = $suffix.ToLower().Trim()
                        Write-Log "  [SUFFIX-METHOD1] Found: '$cleanSuffix'" "DEBUG"
                        $foundSuffixes += $cleanSuffix
                    }
                } else {
                    Write-Log "[SUFFIX-COLLECTION] Method 1: SuffixSearchList is empty/null" "DEBUG"
                }
            } catch {
                Write-Log "[SUFFIX-COLLECTION] Method 1 FAILED: $_" "DEBUG"
            }

            # Method 2: Get primary DNS suffix (computer's domain membership)
            Write-Log "[SUFFIX-COLLECTION] Starting Method 2: IPGlobalProperties.DomainName" "DEBUG"
            try {
                $primary = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
                if (-not [string]::IsNullOrWhiteSpace($primary)) { 
                    $cleanPrimary = $primary.ToLower().Trim()
                    Write-Log "  [SUFFIX-METHOD2] Found: '$cleanPrimary'" "DEBUG"
                    $foundSuffixes += $cleanPrimary 
                } else {
                    Write-Log "[SUFFIX-COLLECTION] Method 2: DomainName is empty/null" "DEBUG"
                }
            } catch {
                Write-Log "[SUFFIX-COLLECTION] Method 2 FAILED: $_" "DEBUG"
            }

            # Remove duplicates and blanks
            $foundSuffixes = $foundSuffixes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
            
            # ========== DIAGNOSTIC OUTPUT ==========
            Write-Log "" "INFO"
            Write-Log "+==========================================================+" "INFO"
            Write-Log "|         DNS SUFFIX DIAGNOSTIC REPORT (Test-DC)          |" "INFO"
            Write-Log "+==========================================================+" "INFO"
            Write-Log "DC Hostname Tested: $hostname" "INFO"
            Write-Log "DC Reachable: $pingResult" "INFO"
            Write-Log "Total Suffixes Found: $($foundSuffixes.Count)" "INFO"
            Write-Log "Suffixes (comma-separated): $($foundSuffixes -join ',')" "INFO"
            if ($foundSuffixes.Count -gt 0) {
                Write-Log "Suffixes (detailed list):" "INFO"
                for ($i = 0; $i -lt $foundSuffixes.Count; $i++) {
                    Write-Log "  [$($i+1)] '$($foundSuffixes[$i])'" "INFO"
                }
            }
            Write-Log "Corporate Suffixes List: $($corpSuffixes -join ',')" "INFO"
            Write-Log "" "INFO"
            
            if (-not $foundSuffixes) {
                Write-Log "[WARN] DC ping succeeded but NO DNS suffixes found - cannot confirm on-prem" "WARN"
                Write-Log "+==========================================================+" "INFO"
                Write-Log "|              RETURNING: FALSE (off-prem assumed)         |" "INFO"
                Write-Log "+==========================================================+" "INFO"
                Write-Log "=== TEST-DC END (result=FALSE, no suffixes) ===" "INFO"
                return $false
            }

            # Check if we have ONLY corporate suffixes (no ISP/public WiFi suffixes)
            # On-prem: only corp suffixes present
            # VPN from home: corp suffixes + ISP suffix (comcast.net, att.net, etc.)
            $corpSuffixCount = 0
            $nonCorpSuffixes = @()
            
            Write-Log "" "INFO"
            Write-Log "SUFFIX CLASSIFICATION ANALYSIS:" "INFO"
            Write-Log "-----------------------------------------------------------" "INFO"
            
            foreach ($found in $foundSuffixes) {
                $isCorp = $false
                foreach ($corp in $corpSuffixes) {
                    # Exact match or subdomain (e.g., "foo.uhc.com" matches "uhc.com")
                    if ($found -eq $corp -or $found -like "*.$corp") {
                        $isCorp = $true
                        $corpSuffixCount++
                        Write-Log "  [OK] CORPORATE: '$found' matches pattern '$corp'" "INFO"
                        break
                    }
                }
                if (-not $isCorp) {
                    $nonCorpSuffixes += $found
                    Write-Log "  [!!] NON-CORPORATE: '$found' (does NOT match any trusted pattern)" "INFO"
                }
            }
            
            Write-Log "-----------------------------------------------------------" "INFO"
            Write-Log "Corporate suffixes found: $corpSuffixCount" "INFO"
            Write-Log "Non-corporate suffixes found: $($nonCorpSuffixes.Count)" "INFO"
            if ($nonCorpSuffixes.Count -gt 0) {
                Write-Log "Non-corporate list: $($nonCorpSuffixes -join ',')" "INFO"
            }
            Write-Log "" "INFO"

            # Must have at least one corporate suffix
            if ($corpSuffixCount -eq 0) {
                Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
                Write-Log "[!!] UNTRUSTED SUFFIX DETECTED - DC REACHABLE BUT ON-PREM DENIED" "ERROR"
                Write-Log "[!!] No corporate DNS suffixes found. Found: $($foundSuffixes -join ', ')" "ERROR"
                Write-Log "[!!] Check NIC DNS suffix config on this machine." "ERROR"
                Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
                Write-Log "+==========================================================+" "INFO"
                Write-Log "|         RETURNING: FALSE (no corporate suffixes)         |" "INFO"
                Write-Log "+==========================================================+" "INFO"
                Write-Log "=== TEST-DC END (result=FALSE, no corp suffixes) ===" "INFO"
                return $false
            }

            # Must have ONLY corporate suffixes (no ISP/public suffixes)
            if ($nonCorpSuffixes.Count -gt 0) {
                Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
                Write-Log "[!!] UNTRUSTED SUFFIX DETECTED - DC REACHABLE BUT ON-PREM DENIED" "ERROR"
                Write-Log "[!!] Non-corporate suffix(es) present: $($nonCorpSuffixes -join ', ')" "ERROR"
                Write-Log "[!!] Corporate suffixes also found - likely VPN from off-prem, or hardcoded suffix on NIC." "ERROR"
                Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
                Write-Log "+==========================================================+" "INFO"
                Write-Log "| RETURNING: FALSE (non-corporate suffixes + corporate)    |" "INFO"
                Write-Log "| DIAGNOSIS: Likely VPN from off-prem home network         |" "INFO"
                Write-Log "+==========================================================+" "INFO"
                Write-Log "=== TEST-DC END (result=FALSE, mixed suffixes) ===" "INFO"
                return $false
            }

            Write-Log "[OK] SUCCESS: DC reachable with ONLY corporate DNS suffixes ($($foundSuffixes -join ', ')) - on-prem confirmed" "DEBUG"
            Write-Log "+==========================================================+" "INFO"
            Write-Log "|         RETURNING: TRUE (on-prem confirmed)              |" "INFO"
            Write-Log "|         Suffixes: $($foundSuffixes -join ',')   |" "INFO"
            Write-Log "+==========================================================+" "INFO"
            Write-Log "=== TEST-DC END (result=TRUE, on-prem) ===" "INFO"
            return $true
            
        } catch {
            # Suffix check failed - fall through and trust the ping
            Write-Log "[WARN] Could not validate DNS suffixes: $_" "DEBUG"
            Write-Log "Falling back to trusting DC ping result: TRUE" "DEBUG"
            Write-Log "+==========================================================+" "INFO"
            Write-Log "|    RETURNING: TRUE (fallback to ping, suffix check failed)|" "INFO"
            Write-Log "+==========================================================+" "INFO"
            Write-Log "=== TEST-DC END (result=TRUE, fallback) ===" "INFO"
            return $true
        }
        
    } catch { 
        Write-Log "Test-DC outer exception: $_" "ERROR"
        Write-Log "+==========================================================+" "INFO"
        Write-Log "|    RETURNING: FALSE (outer exception)                    |" "INFO"
        Write-Log "+==========================================================+" "INFO"
        Write-Log "=== TEST-DC END (result=FALSE, exception) ===" "INFO"
        return $false 
    }
}

# HOW TO DEPLOY:
# 1. Copy this entire function
# 2. Find the existing Test-DC function in CPR_3.14_RC1.17/WW_main.ps1 (starts around line 1230)
# 3. Replace the old Test-DC with this new one
# 4. Run the script with -WWDebug flag on an affected system
# 5. Look in white_walker.main.log for the diagnostic output showing:
#    - "+=========================================================="
#    - "|         DNS SUFFIX DIAGNOSTIC REPORT (Test-DC)          |"
#    - Full list of detected suffixes
#    - Classification of each suffix (CORPORATE vs NON-CORPORATE)
#
# EXAMPLE EXPECTED LOG OUTPUT (on-prem):
#   [INFO] Suffixes (comma-separated): ms.ds.uhc.com,ds.uhc.com,uhc.com
#   [INFO]   [OK] CORPORATE: 'ms.ds.uhc.com' matches pattern 'ms.ds.uhc.com'
#   [INFO] Corporate suffixes found: 3
#   [INFO] Non-corporate suffixes found: 0
#   [INFO] [OK] SUCCESS: DC reachable with ONLY corporate DNS suffixes
#
# EXAMPLE EXPECTED LOG OUTPUT (off-prem with home router):
#   [INFO] Suffixes (comma-separated): ms.ds.uhc.com,home,router,comcast.net
#   [INFO]   [OK] CORPORATE: 'ms.ds.uhc.com' matches pattern 'ms.ds.uhc.com'
#   [INFO]   [!!] NON-CORPORATE: 'home' (does NOT match any trusted pattern)
#   [INFO]   [!!] NON-CORPORATE: 'router' (does NOT match any trusted pattern)
#   [INFO]   [!!] NON-CORPORATE: 'comcast.net' (does NOT match any trusted pattern)
#   [INFO] Corporate suffixes found: 1
#   [INFO] Non-corporate suffixes found: 3
#   [ERROR] [!!] Non-corporate suffix(es) present: home,router,comcast.net
#
# This will show you EXACTLY what the script is seeing!
