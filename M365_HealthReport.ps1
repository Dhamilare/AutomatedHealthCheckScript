#=====================================================================
#  M365HC_v2.ps1 - ULTIMATE M365 / ENTRA ID HEALTH CHECK v2.4
#
#  RE-STRUCTURED SECTIONS (as requested):
#  1. Domain & Email Security
#  2. Licenses
#  3. Identity & Access (includes Devices summary + App Registrations + Password Policy + Security Defaults + PIM + Roles + Guests + Inactive)
#  4. Hybrid & Directory Sync
#  5. Messaging & Collaboration (Mailboxes + Email Forwarding + Impersonation)
#  6. Security & Compliance (includes MFA & Authentication + all risk/CA/audit/secure score)
#  7. Service Health
#=====================================================================

param(
    [string]$ReportFile,
    [string]$CompanyDisplayName = "iAmHtosin Enterprise",
    [string]$LogoPath           = "C:\Users\iAmHtosin\Desktop\Entra.webp",
    [int]$InactiveDays          = 30,
    [int]$StaleDeviceDays       = 90
)

#region CREDENTIALS
$TenantId   = [System.Environment]::GetEnvironmentVariable("GRAPH_TENANT_ID",        "Machine")
$ClientId   = [System.Environment]::GetEnvironmentVariable("GRAPH_CLIENT_ID",        "Machine")
$Thumbprint = [System.Environment]::GetEnvironmentVariable("M365HC_CERT_THUMBPRINT", "Machine")
$Sender     = [System.Environment]::GetEnvironmentVariable("GRAPH_SENDER_EMAIL",     "Machine")
$RecipRaw   = [System.Environment]::GetEnvironmentVariable("GRAPH_RECIPIENTS",       "Machine")
$Recipients = if ($RecipRaw) { $RecipRaw -split "," } else { @() }

$missingVars = @()
if (-not $TenantId)   { $missingVars += "GRAPH_TENANT_ID" }
if (-not $ClientId)   { $missingVars += "GRAPH_CLIENT_ID" }
if (-not $Thumbprint) { $missingVars += "M365HC_CERT_THUMBPRINT" }
if (-not $Sender)     { $missingVars += "GRAPH_SENDER_EMAIL" }
if (-not $Recipients) { $missingVars += "GRAPH_RECIPIENTS" }
if ($missingVars.Count -gt 0) {
    Write-Error "FATAL: Missing environment variables:`n  $($missingVars -join "`n  ")"
    exit 1
}
#endregion

#region MODULE CHECK & AUTO-INSTALL
Write-Host "Checking required PowerShell modules..." -ForegroundColor Cyan

$modulesToCheck = @(
    @{ Name = "ExchangeOnlineManagement"; Version = "3.5.1" },
    @{ Name = "Microsoft.Graph"; Version = "2.35.1" }
)

foreach ($mod in $modulesToCheck) {
    $installed = Get-Module -ListAvailable -Name $mod.Name | Where-Object { $_.Version -ge $mod.Version }
    if (-not $installed) {
        Write-Host "Installing $($mod.Name) v$($mod.Version)..." -ForegroundColor Yellow
        try {
            Install-Module -Name $mod.Name -RequiredVersion $mod.Version -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
            Write-Host "$($mod.Name) installed successfully." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to install $($mod.Name): $($_.Exception.Message)"
        }
    } else {
        Write-Host "$($mod.Name) v$($mod.Version) already installed." -ForegroundColor Green
    }
}
#endregion

#region INITIALISATION
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Timestamp  = Get-Date -Format 'yyyyMMdd_HHmm'
$LogFile    = "C:\M365_HealthCheck_$Timestamp.log"
if (-not $ReportFile) { $ReportFile = "C:\M365_HealthReport_$Timestamp.html" }

Get-ChildItem -Path "C:\" -Include "M365_HealthCheck_*.log","M365_HealthReport_*.html" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Force -ErrorAction SilentlyContinue

Start-Transcript -Path $LogFile -Append
$GlobalStart = Get-Date
Write-Host "Starting M365 / Entra ID Health Check for $CompanyDisplayName`n" -ForegroundColor Cyan

$LogoHtml = ""
if ($LogoPath) {
    if ($LogoPath -match "^https?://") {
        $LogoHtml = "<img src='$LogoPath' alt='$CompanyDisplayName' class='company-logo' />"
        Write-Host "Logo: using hosted URL." -ForegroundColor Cyan
    } elseif (Test-Path $LogoPath -ErrorAction SilentlyContinue) {
        try {
            $ext      = [System.IO.Path]::GetExtension($LogoPath).TrimStart(".").ToLower()
            $mimeMap  = @{ png="image/png"; jpg="image/jpeg"; jpeg="image/jpeg"; gif="image/gif"; svg="image/svg+xml"; webp="image/webp" }
            $mime     = if ($mimeMap[$ext]) { $mimeMap[$ext] } else { "image/png" }
            $b64Logo  = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($LogoPath))
            $LogoHtml = "<img src='data:$mime;base64,$b64Logo' alt='$CompanyDisplayName' class='company-logo' />"
            Write-Host "Logo: embedded from $LogoPath" -ForegroundColor Cyan
        } catch { Write-Warning "Could not read logo at $LogoPath - omitting." }
    } else { Write-Warning "Logo path not found: $LogoPath - omitting." }
}
#endregion

#region RESULTS COLLECTION
$Script:Results = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Result {
    param($Section, $Category, $Check, $Status, $Value, $Remediation = "", $Item = "")
    $rem = if ($Status -eq "Pass") { "" } else { $Remediation }
    $Script:Results.Add([pscustomobject]@{
        Section=$Section; Category=$Category; Check=$Check
        Status=$Status; Value=$Value; Remediation=$rem; Item=$Item
    })
}
#endregion

#region AUTHENTICATION - Certificate-Based (CBA)
function Get-GraphTokenWithCert {
    param($TenantId, $ClientId, $Thumbprint)
    $clean = $Thumbprint.Replace(" ","").ToUpper()
    $cert  = Get-Item "Cert:\LocalMachine\My\$clean" -ErrorAction SilentlyContinue
    if (-not $cert) { $cert = Get-Item "Cert:\CurrentUser\My\$clean" -ErrorAction Stop }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    function To-B64Url { param([byte[]]$b) return [Convert]::ToBase64String($b).Split('=')[0].Replace('+','-').Replace('/','_') }
    $now     = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header  = @{ alg="RS256"; typ="JWT"; x5t=(To-B64Url $cert.GetCertHash()) }
    $payload = @{ aud="https://login.microsoftonline.com/$TenantId/v2.0"; exp=($now+3600); iss=$ClientId; jti=[Guid]::NewGuid().ToString(); nbf=($now-300); sub=$ClientId }
    $hBytes  = [System.Text.Encoding]::UTF8.GetBytes(($header  | ConvertTo-Json -Compress))
    $pBytes  = [System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
    $toSign  = "$(To-B64Url $hBytes).$(To-B64Url $pBytes)"
    $sig     = $rsa.SignData([System.Text.Encoding]::UTF8.GetBytes($toSign),[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $assert  = "$toSign.$(To-B64Url $sig)"
    $resp = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body @{ client_id=$ClientId; client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"; client_assertion=$assert; scope="https://graph.microsoft.com/.default"; grant_type="client_credentials" }
    return $resp.access_token
}
try {
    $accessToken = Get-GraphTokenWithCert -TenantId $TenantId -ClientId $ClientId -Thumbprint $Thumbprint
    $headers = @{ Authorization = "Bearer $accessToken"; "Content-Type" = "application/json" }
    Write-Host "Graph authentication successful." -ForegroundColor Green
} catch {
    Write-Error "AUTH FAILED: $($_.Exception.Message)"; Stop-Transcript; exit 1
}
#endregion

#region GRAPH HELPER
function Invoke-GraphGet {
    param([string]$Uri, [int]$MaxRetries = 3, [hashtable]$ExtraHeaders = @{})
    $results = @()
    try {
        do {
            $attempt = 0; $resp = $null
            while ($attempt -lt $MaxRetries) {
                try {
                    $requestHeaders = $headers + $ExtraHeaders
                    $resp = Invoke-RestMethod -Uri $Uri -Headers $requestHeaders -Method Get -ErrorAction Stop
                    break
                } catch {
                    $attempt++
                    if ($_.Exception.Message -match "connection was closed|connection reset|timed out" -and $attempt -lt $MaxRetries) {
                        Write-Warning "Transient connection error (attempt $attempt) - retrying in 3s..."
                        Start-Sleep -Seconds 3
                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    } else { throw }
                }
            }
            if ($resp) {
                if ($resp.PSObject.Properties.Name -contains 'value') { $results += $resp.value } else { $results += $resp }
                $Uri = $resp.'@odata.nextLink'
            } else { $Uri = $null }
        } while ($Uri)
    } catch { Write-Warning "Graph GET failed for $Uri - $($_.Exception.Message)" }
    return $results
}
#endregion

#region EXO HELPER WITH RETRY
function Invoke-EXOWithRetry {
    param([scriptblock]$ScriptBlock, [int]$MaxRetries = 8)

    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $result = & $ScriptBlock
            Write-Host "EXO command succeeded on attempt $i" -ForegroundColor Green
            return $result
        } catch {
            $errMsg = $_.Exception.Message
            if ($errMsg -match "underlying connection was closed|timed out|connection reset|receive|DataServiceTransportException" -and $i -lt $MaxRetries) {
                $delay = 3 * $i
                Write-Warning "EXO transient error (attempt $i of $MaxRetries) - retrying in $delay seconds... ($errMsg)"

                if ($i -ge 3) {
                    Write-Warning "Full reconnect + module reload (attempt $i)..."
                    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                    Start-Sleep -Seconds 3

                    Remove-Module ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue
                    Import-Module ExchangeOnlineManagement -RequiredVersion 3.5.1 -Force -ErrorAction Stop

                    $org = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/organization"
                    $initialDomain = ($org.verifiedDomains | Where-Object { $_.isInitial -eq $true } | Select-Object -First 1).name

                    Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $Thumbprint `
                        -Organization $initialDomain -ShowBanner:$false -EnableErrorReporting:$false -UseRPSSession:$false -ErrorAction Stop
                    Start-Sleep -Seconds 15
                }
                Start-Sleep -Seconds $delay
            } else {
                Write-Warning "EXO command failed after $MaxRetries attempts: $errMsg"
                return @()   # Return empty array instead of throwing - prevents red error
            }
        }
    }
    return @()
}
#endregion

#region EXCHANGE ONLINE CONNECTION
$ExoConnected = $false
try {
    $org = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/organization"
    $initialDomain = ($org.verifiedDomains | Where-Object { $_.isInitial -eq $true } | Select-Object -First 1).name
    
    Import-Module ExchangeOnlineManagement -RequiredVersion 3.5.1 -Force -ErrorAction Stop
    
    Connect-ExchangeOnline -AppId $ClientId -CertificateThumbprint $Thumbprint `
        -Organization $initialDomain -ShowBanner:$false -EnableErrorReporting:$false -UseRPSSession:$false -ErrorAction Stop
    
    $ExoConnected = $true
    Write-Host "Exchange Online connected successfully (REST session)." -ForegroundColor Green
    Start-Sleep -Seconds 15
} catch {
    Write-Warning "Exchange Online connection failed - EXO-dependent checks will be skipped."
    Write-Warning $_.Exception.Message
}
#endregion

#region 1. DOMAIN & EMAIL SECURITY
Write-Host "[ 1/7] Domain & Email Security..." -ForegroundColor Cyan
try {
    $domains = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/domains"
    foreach ($domain in $domains) {
        $dn = $domain.id
        $st = if ($domain.isVerified) { "Pass" } else { "Fail" }
        Add-Result "Domain & Email Security" "Domain Verification" $dn $st "Verified: $($domain.isVerified)" `
            $(if (-not $domain.isVerified) { "Domain is not verified in Entra ID. Complete verification in M365 Admin Centre." } else { "" }) $dn

        if ($dn -match "\.onmicrosoft\.com$") { continue }

        try {
            $spfRec  = Resolve-DnsName -Name $dn -Type TXT -ErrorAction SilentlyContinue | Where-Object { $_.Strings -match "v=spf1" } | Select-Object -First 1
            if ($spfRec) {
                $spfVal  = ($spfRec.Strings -join " ")
                $spfHard = $spfVal -match "~all|-all"
                $st      = if ($spfHard) { "Pass" } else { "Warning" }
                Add-Result "Domain & Email Security" "SPF" "SPF: $dn" $st $spfVal.Substring(0, [Math]::Min(80, $spfVal.Length)) `
                    $(if (-not $spfHard) { "SPF record exists but does not use -all or ~all. Update to prevent spoofing." } else { "" }) $dn
            } else {
                Add-Result "Domain & Email Security" "SPF" "SPF: $dn" "Fail" "No SPF record found" "Create a TXT record: v=spf1 include:spf.protection.outlook.com -all" $dn
            }
        } catch { Add-Result "Domain & Email Security" "SPF" "SPF: $dn" "Warning" "DNS query failed" "Verify DNS connectivity." $dn }

        try {
            $dkim1 = Resolve-DnsName -Name "selector1._domainkey.$dn" -Type CNAME -ErrorAction SilentlyContinue
            $dkim2 = Resolve-DnsName -Name "selector2._domainkey.$dn" -Type CNAME -ErrorAction SilentlyContinue
            if ($dkim1 -or $dkim2) {
                Add-Result "Domain & Email Security" "DKIM" "DKIM: $dn" "Pass" "DKIM selectors present" "" $dn
            } else {
                Add-Result "Domain & Email Security" "DKIM" "DKIM: $dn" "Fail" "No DKIM selectors found" "Enable DKIM signing in Exchange Admin Centre > Email Authentication, then publish the CNAME records in DNS." $dn
            }
        } catch { Add-Result "Domain & Email Security" "DKIM" "DKIM: $dn" "Warning" "DNS query failed" "Verify DNS connectivity." $dn }

        try {
            $dmarcRec = Resolve-DnsName -Name "_dmarc.$dn" -Type TXT -ErrorAction SilentlyContinue | Where-Object { $_.Strings -match "v=DMARC1" } | Select-Object -First 1
            if ($dmarcRec) {
                $dmarcVal    = ($dmarcRec.Strings -join " ")
                $dmarcPolicy = if ($dmarcVal -match "p=reject") { "reject" } elseif ($dmarcVal -match "p=quarantine") { "quarantine" } else { "none" }
                $st          = if ($dmarcPolicy -eq "reject") { "Pass" } elseif ($dmarcPolicy -eq "quarantine") { "Warning" } else { "Fail" }
                Add-Result "Domain & Email Security" "DMARC" "DMARC: $dn" $st "Policy: $dmarcPolicy" `
                    $(if ($dmarcPolicy -ne "reject") { "Upgrade to p=reject once SPF and DKIM are confirmed working to fully block spoofed emails." } else { "" }) $dn
            } else {
                Add-Result "Domain & Email Security" "DMARC" "DMARC: $dn" "Fail" "No DMARC record found" "Create a TXT record at _dmarc.${dn}: v=DMARC1; p=quarantine; rua=mailto:dmarc@${dn}" $dn
            }
        } catch { Add-Result "Domain & Email Security" "DMARC" "DMARC: $dn" "Warning" "DNS query failed" "Verify DNS connectivity." $dn }
    }
} catch { Add-Result "Domain & Email Security" "Domain Scan" "Domain Check" "Fail" "Error" $_.Exception.Message "N/A" }
#endregion

#region 2. LICENSES
Write-Host "[ 2/7] Licenses..." -ForegroundColor Cyan
try {
    $subs = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/subscribedSkus?`$select=skuPartNumber,capabilityStatus,prepaidUnits,consumedUnits"

    foreach ($sub in $subs) {
        $sku       = $sub.skuPartNumber
        $status    = $sub.capabilityStatus
        $enabled   = $sub.prepaidUnits.enabled
        $consumed  = $sub.consumedUnits
        $pctUsed   = if ($enabled -gt 0) { [math]::Round(($consumed / $enabled) * 100, 1) } else { 0 }

        if ($status -eq "Enabled") {
            $st = if ($pctUsed -lt 90) { "Pass" } elseif ($pctUsed -lt 100) { "Warning" } else { "Fail" }
            $rem = if ($pctUsed -ge 90) { "Approaching licence capacity. Consider purchasing additional seats." } else { "" }
            $val = "$consumed / $enabled used ($pctUsed%)"
        }
        else {
            $st  = "Fail"
            $val = "$status - $consumed / $enabled used"
            $rem = "Subscription is in $status state. Check billing / renewal in Microsoft 365 Admin Center > Billing > Your products."
        }

        Add-Result "Licenses" "Subscriptions" $sku $st $val $rem $sku
    }
} catch { 
    Add-Result "Licenses" "Subscriptions" "Licence Check" "Fail" "Error" $_.Exception.Message "N/A" 
}

try {
    $disabledLicensed = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/users?`$filter=accountEnabled eq false&`$select=displayName,userPrincipalName,assignedLicenses"
    $wasting          = @($disabledLicensed) | Where-Object { $_.assignedLicenses -and @($_.assignedLicenses).Count -gt 0 }
    $wasteCount       = @($wasting).Count
    $st               = if ($wasteCount -eq 0) { "Pass" } elseif ($wasteCount -le 5) { "Warning" } else { "Fail" }
    Add-Result "Licenses" "Licence Waste" "Disabled Users with Licences" $st "Count: $wasteCount" `
        $(if ($wasteCount -gt 0) { "Remove licence assignments from disabled accounts to recover seats and reduce cost." } else { "" }) "Disabled Accounts"
    if ($wasteCount -gt 0 -and $wasteCount -le 20) {
        foreach ($u in $wasting) {
            Add-Result "Licenses" "Licence Waste" "Licensed + Disabled: $($u.displayName)" "Warning" "$(@($u.assignedLicenses).Count) licence(s) assigned" `
                "Remove licence assignments from this disabled account." $u.userPrincipalName
        }
    }
} catch { 
    Add-Result "Licenses" "Licence Waste" "Disabled User Scan" "Warning" "Skipped" "Could not query disabled users." "N/A" 
}
#endregion

#region 3. IDENTITY & ACCESS
Write-Host "[ 3/7] Identity & Access..." -ForegroundColor Cyan

# Global Administrator + Expanded privileged roles (MEMBERS HIDDEN for security)
try {
    $allRoles = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/directoryRoles"
    $rolesToCheck = @(
        "Global Administrator","Exchange Administrator","SharePoint Administrator","User Administrator",
        "Helpdesk Administrator","Security Administrator","Billing Administrator","Privileged Role Administrator",
        "Compliance Administrator","Application Administrator","Cloud Application Administrator",
        "Authentication Administrator","Password Administrator","Teams Administrator","Intune Administrator",
        "License Administrator","Directory Writers","Azure AD Joined Device Local Administrator"
    )

    foreach ($roleName in $rolesToCheck) {
        $role = $allRoles | Where-Object { $_.displayName -eq $roleName } | Select-Object -First 1
        if ($role) {
            $members = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members"
            $count   = @($members).Count

            # MEMBERS ARE NOW HIDDEN (security requirement)
            $memberList = "Members hidden for security reasons"

            # Status logic (unchanged)
            $st = if ($roleName -eq "Global Administrator") {
                if ($count -ge 2 -and $count -le 4) { "Pass" } else { "Warning" }
            } else {
                if ($count -eq 0) { "Info" } elseif ($count -le 3) { "Pass" } else { "Warning" }
            }

            # Remediation / Notes column (kept exactly as before)
            $note = if ($roleName -eq "Global Administrator" -and $count -lt 2) { 
                "Too few Global Admins - minimum 2 recommended for redundancy." 
            } elseif ($roleName -eq "Global Administrator" -and $count -gt 4) { 
                "Too many Global Admins ($count) - reduce to 2-4." 
            } elseif ($count -eq 0) { 
                "No members assigned" 
            } else { "" }

            Add-Result "Identity & Access" "Privileged Roles" $memberList $st "Count: $count" $note $roleName
        }
    }
} catch { 
    Add-Result "Identity & Access" "Privileged Roles" "Privileged Role Scan" "Fail" "Error" $_.Exception.Message "N/A" 
}

# Guest users
try {
    $guests     = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=displayName,userPrincipalName,accountEnabled,createdDateTime"
    $guestCount = @($guests).Count
    $st         = if ($guestCount -eq 0) { "Info" } elseif ($guestCount -le 20) { "Pass" } else { "Warning" }
    Add-Result "Identity & Access" "Guest Users" "Guest User Count" $st "Total: $guestCount" $(if ($guestCount -gt 20) { "Review guest accounts - ensure all are still required and scoped appropriately." } else { "" }) "Guest Accounts"
} catch { Add-Result "Identity & Access" "Guest Users" "Guest User Count" "Fail" "Error" $_.Exception.Message "N/A" }

# Inactive users
try {
    $inactiveUsers = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/users?`$filter=accountEnabled eq true&`$select=displayName,userPrincipalName,signInActivity&`$top=999"
    $inactive      = @($inactiveUsers) | Where-Object { $_.signInActivity -and $_.signInActivity.lastSignInDateTime -and ([datetime]$_.signInActivity.lastSignInDateTime -lt (Get-Date).AddDays(-$InactiveDays)) }
    $inactiveCount = @($inactive).Count
    $st            = if ($inactiveCount -eq 0) { "Pass" } elseif ($inactiveCount -le 10) { "Warning" } else { "Fail" }
    Add-Result "Identity & Access" "Inactive Users" "No Sign-in ($InactiveDays+ days)" $st "Count: $inactiveCount" $(if ($inactiveCount -gt 0) { "Review these accounts - disable or delete if no longer needed to reduce attack surface." } else { "" }) "Inactive Users"
    if ($inactiveCount -gt 0 -and $inactiveCount -le 25) {
        foreach ($u in $inactive) {
            $lastSign = if ($u.signInActivity.lastSignInDateTime) { $u.signInActivity.lastSignInDateTime } else { "Never" }
            Add-Result "Identity & Access" "Inactive Users" "Inactive: $($u.displayName)" "Warning" "Last sign-in: $lastSign" "Consider disabling this account if no longer in use." $u.userPrincipalName
        }
    }
} catch {
    Add-Result "Identity & Access" "Inactive Users" "Inactive User Scan" "Warning" "Skipped" "Requires AuditLog.Read.All permission to read signInActivity." "N/A"
}

# PIM
try {
    $pimSchedules = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$top=10"
    $pimCount     = @($pimSchedules).Count
    if ($pimCount -gt 0) {
        Add-Result "Identity & Access" "PIM" "Privileged Identity Management" "Pass" "Active - $pimCount eligible (just-in-time) role assignment(s) detected" "" "Tenant"
    } else {
        Add-Result "Identity & Access" "PIM" "Privileged Identity Management" "Warning" "No PIM eligible assignments detected" "No Privileged Identity Management (PIM) eligible assignments found. All admin roles appear to be permanently active, which increases standing access risk. Enable PIM so admins request elevation only when needed, with approval and time-limits." "Tenant"
    }
} catch {
    Add-Result "Identity & Access" "PIM" "Privileged Identity Management" "Warning" "Skipped" "Requires RoleManagement.Read.Directory or RoleEligibilitySchedule.Read.Directory permission." "N/A"
}

# Security Defaults
try {
    $sdPolicy  = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" `
                     -Headers $headers -Method Get -ErrorAction Stop
    $sdEnabled = $sdPolicy.isEnabled -eq $true

    $caPolicies = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    $caEnabled  = @($caPolicies | Where-Object { $_.state -eq "enabled" }).Count -gt 0

    if ($sdEnabled) {
        $st  = "Pass"
        $val = "Enabled"
        $rem = if ($caEnabled) { "Security Defaults are enabled alongside active Conditional Access policies." } else { "" }
    } else {
        $st  = if ($caEnabled) { "Info" } else { "Warning" }
        $val = "Disabled"
        $rem = if ($caEnabled) { "Conditional Access policies are managing security controls — Security Defaults are intentionally disabled." } `
               else { "No Conditional Access policies are enabled and Security Defaults are disabled. This is a security gap — enable Security Defaults or create Conditional Access policies." }
    }
    Add-Result "Identity & Access" "Security Defaults" "Security Defaults Status" $st $val $rem "Tenant"
} catch {
    Add-Result "Identity & Access" "Security Defaults" "Security Defaults" "Warning" "Skipped" `
        "Requires Policy.Read.All permission. Error: $($_.Exception.Message)" "N/A"
}

# Password Policy
try {
    $neverExpireUsers = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/users?`$filter=passwordPolicies eq 'DisablePasswordExpiration'&`$select=displayName,userPrincipalName&`$top=25&`$count=true" -ExtraHeaders @{ ConsistencyLevel = "eventual" }
    $neverCount = @($neverExpireUsers).Count
    $st = if ($neverCount -eq 0) { "Pass" } else { "Warning" }
    Add-Result "Identity & Access" "Password Policy" "Users with Password Never Expires" $st "Count: $neverCount" $(if ($neverCount -gt 0) { "Microsoft recommends password expiration. Review and remove 'never expires' setting." } else { "" }) "Users"
    if ($neverCount -gt 0 -and $neverCount -le 10) {
        foreach ($u in $neverExpireUsers) {
            Add-Result "Identity & Access" "Password Policy" "Never Expires: $($u.displayName)" "Warning" $u.userPrincipalName "Change this account to enforce password expiration." $u.userPrincipalName
        }
    }
} catch {
    Add-Result "Identity & Access" "Password Policy" "Password Policy Check" "Warning" "Skipped" "Could not query password policy: $($_.Exception.Message)" "N/A"
}

# App & Enterprise App Status
try {
    $allSpns = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=displayName,appId,accountEnabled,keyCredentials,passwordCredentials,createdDateTime,appOwnerOrganizationId&`$top=999"
    $spns = @($allSpns | Where-Object { $_.appOwnerOrganizationId -eq $TenantId })

    $totalApps   = @($spns).Count
    $deactivated = @($spns | Where-Object { $_.accountEnabled -eq $false }).Count

    $expiredCerts   = @()
    $expiringCerts  = @()
    $expiredSecrets = @()
    $expiringSecrets = @()
    $now = Get-Date

    foreach ($sp in $spns) {
        if ($sp.keyCredentials) {
            foreach ($cert in $sp.keyCredentials) {
                $expiry = [datetime]$cert.endDateTime
                if ($expiry -lt $now) {
                    $expiredCerts += [pscustomobject]@{ Name = $sp.displayName; AppId = $sp.appId; Expires = $expiry.ToString('yyyy-MM-dd') }
                } elseif ($expiry -lt $now.AddDays(30)) {
                    $expiringCerts += [pscustomobject]@{ Name = $sp.displayName; AppId = $sp.appId; Expires = $expiry.ToString('yyyy-MM-dd') }
                }
            }
        }
        if ($sp.passwordCredentials) {
            foreach ($secret in $sp.passwordCredentials) {
                $expiry = [datetime]$secret.endDateTime
                if ($expiry -lt $now) {
                    $expiredSecrets += [pscustomobject]@{ Name = $sp.displayName; AppId = $sp.appId; Expires = $expiry.ToString('yyyy-MM-dd') }
                } elseif ($expiry -lt $now.AddDays(30)) {
                    $expiringSecrets += [pscustomobject]@{ Name = $sp.displayName; AppId = $sp.appId; Expires = $expiry.ToString('yyyy-MM-dd') }
                }
            }
        }
    }

    $expiringCount = @($expiringCerts).Count + @($expiringSecrets).Count
    $expiredCount  = @($expiredCerts).Count + @($expiredSecrets).Count

    $st = if ($deactivated -eq 0 -and $expiredCount -eq 0) { "Pass" } elseif ($deactivated -gt 0 -or $expiredCount -gt 0) { "Fail" } else { "Warning" }
    Add-Result "Identity & Access" "App Registrations" "App & Enterprise App Status" $st `
        "Total: $totalApps | Deactivated: $deactivated | Expired: $expiredCount | Expiring <30d: $expiringCount" `
        $(if ($deactivated -gt 0 -or $expiredCount -gt 0) { "Review deactivated apps and expired certificates/secrets immediately." } else { "" }) "Apps"

    # Detailed rows - ONE row per problematic app (no duplicates)
    $problemApps = @{}
    foreach ($item in $expiredCerts)   { $problemApps[$item.Name] = "Expired Cert (Expires: $($item.Expires))" }
    foreach ($item in $expiredSecrets) { $problemApps[$item.Name] = "Expired Secret (Expires: $($item.Expires))" }
    foreach ($item in $expiringCerts)  { $problemApps[$item.Name] = "Expiring Soon (Cert) (Expires: $($item.Expires))" }
    foreach ($item in $expiringSecrets){ $problemApps[$item.Name] = "Expiring Soon (Secret) (Expires: $($item.Expires))" }

    foreach ($appName in $problemApps.Keys) {
        $issue = $problemApps[$appName]
        $stDetail = if ($issue -like "*Expired*") { "Fail" } else { "Warning" }
        $rem = if ($issue -like "*Cert*") { 
            "Certificate expires soon/expired. Renew it before authentication breaks." 
        } else { 
            "Client secret expires soon/expired. Create a new secret and update any scripts/apps." 
        }
        Add-Result "Identity & Access" "App Registrations" $issue $stDetail $appName $rem $appName
    }
} catch {
    Add-Result "Identity & Access" "App Registrations" "App Status Check" "Warning" "Skipped" `
        "Could not query app status: $($_.Exception.Message) (requires Application.Read.All)" "N/A"
}
#endregion

#region 4. HYBRID & DIRECTORY SYNC
Write-Host "[ 4/7] Hybrid & Directory Sync..." -ForegroundColor Cyan
try {
    $orgResp = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/organization?`$select=id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesProvisioningErrors" -Headers $headers -Method Get -ErrorAction Stop
    $orgObj  = if ($orgResp.PSObject.Properties.Name -contains 'value') { $orgResp.value | Select-Object -First 1 } else { $orgResp }
    $isHybrid = $orgObj.onPremisesSyncEnabled -eq $true
    if ($isHybrid) {
        $syncType = if ($orgObj.onPremisesSyncEnabled -eq $true) { "Azure AD Connect" } else { "Cloud Sync" }
        Add-Result "Hybrid & Directory Sync" "Sync Configuration" "Tenant Type" "Info" "$syncType is enabled" "" "Tenant"

        if ($orgObj.onPremisesLastSyncDateTime) {
            $lastSyncDt = [datetime]$orgObj.onPremisesLastSyncDateTime
            $syncAgeMin = [math]::Round(((Get-Date) - $lastSyncDt).TotalMinutes, 0)
            $syncAgeHrs = [math]::Round($syncAgeMin / 60, 1)

            $st = if ($syncAgeMin -le 30) { 
                "Pass" 
            } elseif ($syncAgeHrs -lt 24) { 
                "Warning" 
            } else { 
                "Fail" 
            }

            Add-Result "Hybrid & Directory Sync" "Sync Status" "Last Directory Sync" $st `
                "$($lastSyncDt.ToString('yyyy-MM-dd HH:mm')) UTC ($syncAgeMin minutes ago)" `
                $(if ($syncAgeMin -le 30) { "Sync is current." } 
                  elseif ($syncAgeHrs -lt 24) { "Sync is delayed (>30 minutes). Normal sync interval is every 30 minutes." } 
                  else { "Sync has not run in over 24 hours. Check Azure AD Connect service and server." }) "Azure AD Connect"
        } else {
            Add-Result "Hybrid & Directory Sync" "Sync Status" "Last Directory Sync" "Warning" "Timestamp not available" "Could not determine last sync time. Verify Azure AD Connect is running." "Azure AD Connect"
        }
        $orgErrCount = if ($orgObj.onPremisesProvisioningErrors) { @($orgObj.onPremisesProvisioningErrors).Count } else { 0 }
        $st = if ($orgErrCount -eq 0) { "Pass" } else { "Fail" }
        Add-Result "Hybrid & Directory Sync" "Sync Errors" "Org-Level Provisioning Errors" $st "Count: $orgErrCount" $(if ($orgErrCount -gt 0) { "Organisation-level provisioning errors detected..." } else { "" }) "Organisation"
        try {
            $usersWithSyncErrors = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/users?`$filter=onPremisesProvisioningErrors/any(o:o/category eq 'PropertyConflict')&`$select=displayName,userPrincipalName,onPremisesProvisioningErrors&`$top=25&`$count=true" -ExtraHeaders @{ ConsistencyLevel = "eventual" }
            $userErrCount = @($usersWithSyncErrors).Count
            $st = if ($userErrCount -eq 0) { "Pass" } else { "Fail" }
            Add-Result "Hybrid & Directory Sync" "Sync Errors" "Users with Sync Errors" $st "Count: $userErrCount" $(if ($userErrCount -gt 0) { "Users have on-premises provisioning errors..." } else { "" }) "Users"
            if ($userErrCount -gt 0 -and $userErrCount -le 15) {
                foreach ($u in $usersWithSyncErrors) {
                    $errCat = if ($u.onPremisesProvisioningErrors -and @($u.onPremisesProvisioningErrors).Count -gt 0) { $u.onPremisesProvisioningErrors[0].category } else { "Unknown" }
                    Add-Result "Hybrid & Directory Sync" "Sync Errors" "Sync Error: $($u.displayName)" "Fail" "Category: $errCat" "Common causes: duplicate attributes..." $u.userPrincipalName
                }
            }
        } catch {
            Add-Result "Hybrid & Directory Sync" "Sync Errors" "User Sync Error Scan" "Warning" "Skipped" "Could not query user provisioning errors: $($_.Exception.Message)" "N/A"
        }
    } else {
        Add-Result "Hybrid & Directory Sync" "Sync Configuration" "Tenant Type" "Info" "Cloud-only - no on-premises directory synchronisation configured" "" "Tenant"
    }
} catch {
    Add-Result "Hybrid & Directory Sync" "Sync Configuration" "Hybrid Check" "Warning" "Skipped" "Could not query organisation sync status: $($_.Exception.Message)" "N/A"
}
#endregion

#region 5. MESSAGING & COLLABORATION
Write-Host "[ 5/7] Messaging & Collaboration..." -ForegroundColor Cyan

try {
    if ($ExoConnected) {
        $allMailboxes = Invoke-EXOWithRetry { Get-EXOMailbox -ResultSize Unlimited }
        $totalMb = @($allMailboxes).Count
    } else {
        $totalMb = 0
    }

    $mbReport = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/reports/getMailboxUsageDetail(period='D7')" -Headers $headers -Method Get -ErrorAction Stop
    $mbCsv    = [System.Text.Encoding]::UTF8.GetString([byte[]][char[]]$mbReport) | ConvertFrom-Csv

    $over80 = 0; $over95 = 0
    foreach ($mb in $mbCsv) {
        if ($mb.'Storage Used (Byte)' -and $mb.'Prohibit Send Quota (Byte)') {
            $usedPct = [math]::Round(([long]$mb.'Storage Used (Byte)' / [long]$mb.'Prohibit Send Quota (Byte)') * 100, 1)
            if ($usedPct -ge 95) {
                $over95++
                Add-Result "Messaging & Collaboration" "Mailbox Usage" "Over Quota (95%+)" "Fail" "$usedPct% used" "Mailbox critically full..." $mb.'User Principal Name'
            } elseif ($usedPct -ge 80) {
                $over80++
                Add-Result "Messaging & Collaboration" "Mailbox Usage" "Approaching Quota (80-95%)" "Warning" "$usedPct% used" "Mailbox approaching send quota..." $mb.'User Principal Name'
            }
        }
    }
    $st = if ($over95 -eq 0 -and $over80 -eq 0) { "Pass" } elseif ($over95 -gt 0) { "Fail" } else { "Warning" }
    Add-Result "Messaging & Collaboration" "Mailbox Usage" "Usage Summary" $st "$totalMb mailboxes | $over80 at 80%+ | $over95 at 95%+" "" "All Mailboxes"
} catch { 
    Add-Result "Messaging & Collaboration" "Mailbox Usage" "Usage Report" "Fail" "Error" $_.Exception.Message "N/A" 
}

if ($ExoConnected) {
    # Shared mailboxes, Impersonation, Forwarding (unchanged)
    # Shared mailboxes
    try {
        $sharedMBs    = Invoke-EXOWithRetry { Get-EXOMailbox -RecipientTypeDetails SharedMailbox -PropertySets All -ResultSize Unlimited }
        $loginEnabled = @($sharedMBs) | Where-Object { $_.AccountDisabled -eq $false }
        $loginCount   = @($loginEnabled).Count
        $st           = if ($loginCount -eq 0) { "Pass" } else { "Warning" }
        Add-Result "Messaging & Collaboration" "Shared Mailboxes" "Direct Login Enabled" $st "$loginCount shared mailbox(es) with sign-in enabled" $(if ($loginCount -gt 0) { "Shared mailboxes should have direct sign-in disabled..." } else { "" }) "Shared Mailboxes"
        if ($loginCount -gt 0 -and $loginCount -le 20) {
            foreach ($mb in $loginEnabled) {
                Add-Result "Messaging & Collaboration" "Shared Mailboxes" "Sign-in enabled: $($mb.DisplayName)" "Warning" $mb.PrimarySmtpAddress "Disable direct sign-in on this shared mailbox." $mb.UserPrincipalName
            }
        }
    } catch { Add-Result "Messaging & Collaboration" "Shared Mailboxes" "Shared Mailbox Check" "Warning" "Skipped" $_.Exception.Message "N/A" }

    # Mailbox Impersonation / Delegation
    try {
        $mailboxes = Invoke-EXOWithRetry { Get-EXOMailbox -ResultSize Unlimited }
        $impersonations = @()
        foreach ($mb in $mailboxes) {
            $perms = Invoke-EXOWithRetry { Get-EXOMailboxPermission -Identity $mb.UserPrincipalName } | 
                Where-Object { $_.User -notlike "NT AUTHORITY\*" -and $_.IsInherited -eq $false -and $_.AccessRights -match "FullAccess|SendAs" }
            foreach ($p in $perms) { $impersonations += [pscustomobject]@{ Mailbox = $mb.DisplayName; Delegate = $p.User; Rights = ($p.AccessRights -join ", ") } }
            if ($mb.GrantSendOnBehalfTo) {
                foreach ($d in $mb.GrantSendOnBehalfTo) { $impersonations += [pscustomobject]@{ Mailbox = $mb.DisplayName; Delegate = $d; Rights = "SendOnBehalf" } }
            }
        }
        $impCount = @($impersonations).Count
        $st = if ($impCount -eq 0) { "Pass" } else { "Info" }
        Add-Result "Messaging & Collaboration" "Impersonation & Delegation" "Mailbox Impersonation / Delegation" $st "Found $impCount delegation(s)" "Review delegations - ensure they are still required and not over-privileged." "Mailboxes"
        if ($impCount -gt 0 -and $impCount -le 15) {
            foreach ($imp in $impersonations) {
                Add-Result "Messaging & Collaboration" "Impersonation & Delegation" "Delegate: $($imp.Delegate) on $($imp.Mailbox)" "Info" $imp.Rights "Verify this delegation is authorised." $imp.Mailbox
            }
        }
    } catch { Add-Result "Messaging & Collaboration" "Impersonation & Delegation" "Impersonation Check" "Warning" "Skipped" $_.Exception.Message "N/A" }

    # Email Forwarding
    try {
        $fwdMailboxes = Invoke-EXOWithRetry { Get-EXOMailbox -Filter "ForwardingSmtpAddress -ne `$null" -PropertySets Delivery -ResultSize Unlimited }
        $externalFwd = @(); $internalFwd = @()
        foreach ($mb in $fwdMailboxes) {
            $fwd = $mb.ForwardingSmtpAddress
            if ($fwd) {
                if ($fwd -notmatch "@ha-shem\.com$") { $externalFwd += $mb } else { $internalFwd += $mb }
            }
        }
        $extCount = @($externalFwd).Count
        if ($extCount -gt 0) {
            foreach ($mb in $externalFwd) {
                Add-Result "Messaging & Collaboration" "Forwarding Rules" "External Fwd: $($mb.DisplayName)" "Warning" "To: $($mb.ForwardingSmtpAddress)" "Verify authorised - external forwarding is a data exfiltration risk." $mb.UserPrincipalName
            }
        }
        $stExt = if ($extCount -eq 0) { "Pass" } else { "Warning" }
        Add-Result "Messaging & Collaboration" "Forwarding Rules" "External Forwarding Summary" $stExt "$extCount external rule(s)" $(if ($extCount -gt 0) { "Review external forwarding immediately." } else { "" }) "All Mailboxes"

        $intCount = @($internalFwd).Count
        $stInt = if ($intCount -eq 0) { "Pass" } else { "Info" }
        Add-Result "Messaging & Collaboration" "Forwarding Rules" "Internal Forwarding Summary" $stInt "$intCount internal rule(s)" $(if ($intCount -gt 0) { "Internal forwarding is usually benign but verify business need." } else { "" }) "All Mailboxes"
        if ($intCount -gt 0 -and $intCount -le 10) {
            foreach ($mb in $internalFwd) {
                Add-Result "Messaging & Collaboration" "Forwarding Rules" "Internal Fwd: $($mb.DisplayName)" "Info" "To: $($mb.ForwardingSmtpAddress)" "" $mb.UserPrincipalName
            }
        }
    } catch { Add-Result "Messaging & Collaboration" "Forwarding Rules" "Forwarding Check" "Fail" "EXO query failed" $_.Exception.Message "N/A" }
} else {
    Add-Result "Messaging & Collaboration" "Forwarding Rules" "Forwarding Check" "Warning" "Skipped" "Exchange Online not connected." "N/A"
}
#endregion

#region 6. SECURITY & COMPLIANCE
Write-Host "[ 6/7] Security & Compliance..." -ForegroundColor Cyan

# MFA & Authentication - summary first, then list (exclude #EXT#)
try {
    $mfaDetails = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"
    $mfaFail = 0; $mfaPass = 0
    $nonMFAUsers = @()
    foreach ($mfa in $mfaDetails) {
        if ($mfa.userPrincipalName -like "*#EXT#*") { continue }   # exclude external/guest accounts
        if ($mfa.isMfaRegistered) { $mfaPass++ } else {
            $mfaFail++
            $nonMFAUsers += $mfa
        }
    }
    $total  = $mfaPass + $mfaFail
    $pctReg = if ($total -gt 0) { [math]::Round(($mfaPass / $total) * 100, 1) } else { 0 }
    $st     = if ($mfaFail -eq 0) { "Pass" } elseif ($mfaFail -le 5) { "Warning" } else { "Fail" }
    Add-Result "Security & Compliance" "MFA Registration" "MFA Summary" $st "$mfaPass / $total registered ($pctReg%)" $(if ($mfaFail -gt 0) { "$mfaFail user(s) do not have MFA registered." } else { "" }) "All Users"

    # List non-MFA users after summary
    foreach ($mfa in $nonMFAUsers) {
        Add-Result "Security & Compliance" "MFA Registration" "MFA Not Registered" "Fail" "Not registered" "Enable MFA for this account immediately - accounts without MFA are at high risk of compromise." $mfa.userPrincipalName
    }
} catch { Add-Result "Security & Compliance" "MFA Registration" "MFA Check" "Fail" "Error" $_.Exception.Message "N/A" }

# Legacy Authentication, CA Policy, Secure Score, Risky Users, Confirmed Compromised, Risk Detections, Audit Log (unchanged)
try {
    $caPolicies    = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
    $blockLegacyCA = $caPolicies | Where-Object { $_.state -eq "enabled" -and ($_.displayName -match "legacy|basic auth|block.*auth" -or ($_.conditions.clientAppTypes -contains "exchangeActiveSync" -or $_.conditions.clientAppTypes -contains "other")) }
    if ($blockLegacyCA) {
        Add-Result "Security & Compliance" "Legacy Authentication" "Legacy Auth Block Policy" "Pass" "Policy found: $($blockLegacyCA[0].displayName)" "" "Conditional Access"
    } else {
        Add-Result "Security & Compliance" "Legacy Authentication" "Legacy Auth Block Policy" "Warning" "No dedicated block policy found" "Create a Conditional Access policy to block legacy authentication protocols (Basic Auth, ActiveSync). These bypass MFA and are a common attack vector." "Conditional Access"
    }
} catch { Add-Result "Security & Compliance" "Legacy Authentication" "CA Policy Check" "Warning" "Skipped" "Requires Policy.Read.All permission." "N/A" }

try {
    $sspr = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy" -Headers $headers -Method Get -ErrorAction Stop
    Add-Result "Security & Compliance" "SSPR" "Auth Methods Policy" $(if ($sspr) { "Pass" } else { "Warning" }) "Policy configured" "" "Tenant"
} catch { Add-Result "Security & Compliance" "SSPR" "SSPR Policy Check" "Warning" "Skipped" "Requires Policy.Read.All permission." "N/A" }

# Secure Score, Risky Users, Confirmed Compromised, Risk Detections, Conditional Access, Audit Log
# Secure Score
try {
    $scores = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1"
    $score  = $scores | Select-Object -First 1
    if ($score) {
        $current = [math]::Round($score.currentScore, 1)
        $max     = [math]::Round($score.maxScore, 1)
        $pct     = if ($max -gt 0) { [math]::Round(($current / $max) * 100, 1) } else { 0 }
        $st      = if ($pct -ge 70) { "Pass" } elseif ($pct -ge 40) { "Warning" } else { "Fail" }
        Add-Result "Security & Compliance" "Secure Score" "Microsoft Secure Score" $st "$current / $max ($pct%)" $(if ($pct -lt 70) { "Review Secure Score recommendations in the M365 Defender portal." } else { "" }) "Tenant"
    }
} catch { Add-Result "Security & Compliance" "Secure Score" "Secure Score" "Warning" "Skipped" "Requires SecurityEvents.Read.All permission." "N/A" }

# === Adoption Score (Total + all sub-scores)
try {
    # Fresh token specifically for the Reports API
    $freshToken = Get-GraphTokenWithCert -TenantId $TenantId -ClientId $ClientId -Thumbprint $Thumbprint
    $reportHeaders = @{ Authorization = "Bearer $freshToken" }

    $adoptionReport = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/reports/getAdoptionScore(period='D30')" `
                                        -Headers $reportHeaders -Method Get -ErrorAction Stop

    $latest = $adoptionReport | Sort-Object reportDate -Descending | Select-Object -First 1

    if ($latest) {
        $totalScore = $latest.score
        $maxScore   = 400
        $pct        = if ($maxScore -gt 0) { [math]::Round(($totalScore / $maxScore) * 100, 1) } else { 0 }
        $st         = if ($pct -ge 50) { "Pass" } elseif ($pct -ge 30) { "Warning" } else { "Fail" }

        Add-Result "Security & Compliance" "Adoption Score" "Microsoft 365 Adoption Score" $st `
            "$totalScore / $maxScore points ($pct%)" `
            "Overall Adoption Score measures how effectively the organization uses Microsoft 365 for digital transformation." "Tenant"

        # Individual sub-scores
        $subScores = @(
            @{ Name = "Communication"; Column = "communication" },
            @{ Name = "Meetings";      Column = "meetings" },
            @{ Name = "Collaboration"; Column = "collaboration" },
            @{ Name = "AI";            Column = "ai" },
            @{ Name = "Mobility";      Column = "mobility" },
            @{ Name = "Teamwork";      Column = "teamwork" }
        )

        foreach ($sub in $subScores) {
            if ($latest.PSObject.Properties.Name -contains $sub.Column) {
                $scoreValue = $latest.$($sub.Column)
                $subPct = [math]::Round(($scoreValue / 100) * 100, 1)
                $subSt  = if ($subPct -ge 70) { "Pass" } elseif ($subPct -ge 40) { "Warning" } else { "Fail" }
                Add-Result "Security & Compliance" "Adoption Score" "$($sub.Name) Adoption Score" $subSt `
                    "$scoreValue / 100 ($subPct%)" "" "Tenant"
            }
        }
    }
} catch {
    $err = $_.Exception.Message
    if ($err -match "400") {
        Add-Result "Security & Compliance" "Adoption Score" "Microsoft 365 Adoption Score" "Info" "Not yet available" `
            "Adoption Score report has not been generated yet in this tenant (Microsoft needs several days of usage data). Check manually in Microsoft 365 Admin Center > Reports > Adoption Score." "Tenant"
    } else {
        Add-Result "Security & Compliance" "Adoption Score" "Microsoft 365 Adoption Score" "Warning" "Skipped" `
            "Could not retrieve Adoption Score: $err" "N/A"
    }
}

# Risky users, Confirmed compromised, Risk detections, Conditional Access, Audit Log
$risky     = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
$atRisk    = @($risky) | Where-Object { $_.riskLevel -ne "none" -and $_.riskState -notin @("remediated","dismissed","confirmedSafe") }
$riskCount = @($atRisk).Count
$st        = if ($riskCount -eq 0) { "Pass" } elseif ($riskCount -le 3) { "Warning" } else { "Fail" }
Add-Result "Security & Compliance" "Risky Users" "Identity Risk Summary" $st "$riskCount at-risk user(s) detected" $(if ($riskCount -gt 0) { "Investigate and remediate flagged accounts via Entra ID Protection." } else { "" }) "All Users"
if ($riskCount -gt 0 -and $riskCount -le 15) {
    foreach ($u in $atRisk) {
        Add-Result "Security & Compliance" "Risky Users" "Risk Level: $($u.riskLevel)" "Warning" "State: $($u.riskState)" "Investigate this account..." $u.userPrincipalName
    }
}

# Confirmed compromised accounts
$compromised = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'confirmedCompromised'"
$compCount   = @($compromised).Count
$st          = if ($compCount -eq 0) { "Pass" } else { "Fail" }
Add-Result "Security & Compliance" "Account Compromise" "Confirmed Compromised Accounts" $st "$compCount account(s) confirmed compromised" $(if ($compCount -gt 0) { "URGENT: Confirmed compromised accounts detected..." } else { "" }) "All Users"
if ($compCount -gt 0) {
    foreach ($u in $compromised) {
        $detectedOn = if ($u.riskLastUpdatedDateTime) { $u.riskLastUpdatedDateTime } else { "Unknown" }
        Add-Result "Security & Compliance" "Account Compromise" "COMPROMISED: $($u.userDisplayName)" "Fail" "Risk level: $($u.riskLevel) | Last updated: $detectedOn" "IMMEDIATE ACTION required..." $u.userPrincipalName
    }
}

# Risk detections (last 7 days)
$cutoffISO   = (Get-Date).AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$riskDetect  = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $cutoffISO&`$top=25&`$orderby=detectedDateTime desc"
$detectCount = @($riskDetect).Count
$highRisk    = @($riskDetect) | Where-Object { $_.riskLevel -eq "high" }
$highCount   = @($highRisk).Count
$st          = if ($detectCount -eq 0) { "Pass" } elseif ($highCount -gt 0) { "Fail" } else { "Warning" }
Add-Result "Security & Compliance" "Account Compromise" "Risk Detections (Last 7 Days)" $st "$detectCount total | $highCount high-risk" $(if ($detectCount -gt 0) { "Review risk detections..." } else { "" }) "All Users"
if ($highCount -gt 0 -and $highCount -le 10) {
    foreach ($d in $highRisk) {
        Add-Result "Security & Compliance" "Account Compromise" "High Risk: $($d.userDisplayName)" "Fail" "Type: $($d.riskEventType) | Detected: $($d.detectedDateTime)" "Investigate this high-risk sign-in detection..." $d.userPrincipalName
    }
}

# Conditional Access
$caPolicies   = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
$caEnabled    = @($caPolicies | Where-Object { $_.state -eq "enabled" }).Count
$caDisabled   = @($caPolicies | Where-Object { $_.state -eq "disabled" }).Count
$caReportOnly = @($caPolicies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" }).Count
$st           = if ($caEnabled -gt 0) { "Pass" } else { "Fail" }
Add-Result "Security & Compliance" "Conditional Access" "CA Policy Summary" $st "$caEnabled enabled | $caReportOnly report-only | $caDisabled disabled" $(if ($caEnabled -eq 0) { "No Conditional Access policies enabled..." } elseif ($caReportOnly -gt 0) { "$caReportOnly policies in report-only mode..." } else { "" }) "Tenant"

# Unified Audit Log
if ($ExoConnected) {
    try {
        $auditCfg     = Get-AdminAuditLogConfig -ErrorAction Stop
        $auditEnabled = $auditCfg.UnifiedAuditLogIngestionEnabled
        $st           = if ($auditEnabled -eq $true) { "Pass" } else { "Fail" }
        Add-Result "Security & Compliance" "Audit Log" "Unified Audit Log" $st $(if ($auditEnabled) { "Enabled (confirmed via Exchange Online)" } else { "DISABLED" }) $(if (-not $auditEnabled) { "Enable audit logging..." } else { "" }) "Tenant"
    } catch {
        try {
            $null = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/auditLog/queries?`$top=1" -Headers $headers -Method Get -ErrorAction Stop
            Add-Result "Security & Compliance" "Audit Log" "Unified Audit Log" "Pass" "Accessible (API responds)" "" "Tenant"
        } catch {
            Add-Result "Security & Compliance" "Audit Log" "Unified Audit Log" "Warning" "Cannot verify remotely" "Could not confirm audit log status..." "Tenant"
        }
    }
} else {
    try {
        $null = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/auditLog/queries?`$top=1" -Headers $headers -Method Get -ErrorAction Stop
        Add-Result "Security & Compliance" "Audit Log" "Unified Audit Log" "Pass" "API accessible" "" "Tenant"
    } catch {
        $errMsg = $_.Exception.Message
        Add-Result "Security & Compliance" "Audit Log" "Unified Audit Log" "Warning" "Cannot verify (EXO not connected)" $(if ($errMsg -match "403|Forbidden") { "Graph API returned 403..." } else { "Could not determine audit log status..." }) "Tenant"
    }
}
#endregion

#region 7. SERVICE HEALTH
Write-Host "[ 7/7] Service Health..." -ForegroundColor Cyan
try {
    $healthOverviews = Invoke-GraphGet -Uri "https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/healthOverviews"
    $issuesFound = $false
    if ($healthOverviews -and @($healthOverviews).Count -gt 0) {
        foreach ($svc in $healthOverviews) {
            if ($svc.status -ne "serviceOperational") {
                $issuesFound = $true
                $st  = if ($svc.status -match "Degraded|Restored") { "Warning" } else { "Fail" }
                $val = ($svc.status -replace "([A-Z])"," `$1").Trim()
                Add-Result "Service Health" "Live Status" $svc.service $st $val "Check Microsoft 365 Admin Centre > Service Health for latest updates." $svc.service
            }
        }
    }
    if (-not $issuesFound) {
        Add-Result "Service Health" "Live Status" "All Services" "Pass" "All services are operational" "" "N/A"
    }
} catch {
    Add-Result "Service Health" "Live Status" "Query" "Fail" "Error" $_.Exception.Message "N/A"
}
#endregion

#region SECTION RAG STATUS
$SectionOrder = @(
    "Domain & Email Security",
    "Licenses",
    "Identity & Access",
    "Hybrid & Directory Sync",
    "Messaging & Collaboration",
    "Security & Compliance",
    "Service Health"
)

$SectionRAG = @{}
foreach ($sec in ($Script:Results | Select-Object -ExpandProperty Section | Sort-Object -Unique)) {
    $secRows = $Script:Results | Where-Object { $_.Section -eq $sec }
    if     ($secRows | Where-Object { $_.Status -eq "Fail"    }) { $SectionRAG[$sec] = "Fail"    }
    elseif ($secRows | Where-Object { $_.Status -eq "Warning" }) { $SectionRAG[$sec] = "Warning" }
    else                                                          { $SectionRAG[$sec] = "Pass"    }
}
#endregion

#region HTML REPORT (with wider Remediation column)
$CountPass  = @($Script:Results | Where-Object { $_.Status -eq "Pass"    }).Count
$CountWarn  = @($Script:Results | Where-Object { $_.Status -eq "Warning" }).Count
$CountFail  = @($Script:Results | Where-Object { $_.Status -eq "Fail"    }).Count
$ReportDate = Get-Date -Format "dd MMM yyyy HH:mm"
$TotalMins  = [math]::Round(((Get-Date) - $GlobalStart).TotalMinutes, 1)

$tocLinks = @()
foreach ($sec in $SectionOrder) {
    $ragVal = $SectionRAG[$sec]; if (-not $ragVal) { continue }
    $rag    = $ragVal.ToLower()
    $anchor = $sec -replace '[^a-zA-Z0-9]', '_'
    $tocLinks += "<a href='#$anchor' class='toc-link toc-$rag'>$sec</a>"
}
$tocHtml = $tocLinks -join "&nbsp;&nbsp;"

$css = @"
<style>
  @import url('https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700;800&display=swap');
  :root{--brand:#000366;--brand-lt:#1a1f8a;--pass:#1a7a3c;--warn:#b8730a;--fail:#b52b27;--bg:#eef0f7;--surface:#ffffff;--border:#d0d4ec;--row-alt:#f4f5fb;}
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:'Century Gothic','CenturyGothic','Nunito','AppleGothic',sans-serif;background:var(--bg);padding:30px;font-size:14px;color:#1a1a2e;}
  .wrap{max-width:1400px;margin:auto;background:var(--surface);padding:36px 44px;border-radius:14px;box-shadow:0 4px 28px rgba(0,3,102,.12);position:relative;overflow:hidden;}
  .wrap::before{content:"CONFIDENTIAL - $CompanyDisplayName";position:fixed;top:50%;left:50%;transform:translate(-50%,-50%) rotate(-35deg);font-size:64px;font-weight:900;color:rgba(0,3,102,0.042);white-space:nowrap;pointer-events:none;z-index:0;letter-spacing:8px;text-transform:uppercase;user-select:none;font-family:'Century Gothic','CenturyGothic',sans-serif;}
  body::before{content:"";position:fixed;top:0;left:0;right:0;bottom:0;background-image:repeating-linear-gradient(-35deg,transparent,transparent 180px,rgba(0,3,102,0.010) 180px,rgba(0,3,102,0.010) 181px);pointer-events:none;z-index:0;}
  .wrap>*{position:relative;z-index:1;}
  .conf-ribbon{display:block;text-align:center;background:var(--brand);color:#fff;font-size:0.74em;font-weight:700;letter-spacing:3px;padding:6px 0;margin-bottom:16px;border-radius:5px;text-transform:uppercase;}
  .header-band{background:linear-gradient(135deg,var(--brand) 0%,var(--brand-lt) 100%);border-radius:10px;padding:20px 28px;margin-bottom:20px;display:flex;align-items:center;position:relative;overflow:hidden;}
  .header-band::after{content:"";position:absolute;top:-40px;right:-40px;width:160px;height:160px;background:rgba(255,255,255,0.06);border-radius:50%;}
  .company-logo{max-height:68px;max-width:190px;object-fit:contain;z-index:2;}
  .header-text{position:absolute;left:50%;transform:translateX(-50%);text-align:center;pointer-events:none;}
  .company-name{font-size:24px;font-weight:800;color:#fff;text-transform:uppercase;letter-spacing:3px;font-family:'Century Gothic','CenturyGothic',sans-serif;}
  .report-title{font-size:0.9em;color:rgba(255,255,255,.75);margin-top:5px;}
  .summary{background:#f0f2fb;border-left:5px solid var(--brand);padding:16px 24px;border-radius:8px;margin:18px 0;text-align:center;font-size:1.08em;font-weight:700;}
  .s-pass{color:var(--pass);}.s-warn{color:var(--warn);}.s-fail{color:var(--fail);}
  .toc{background:#f4f5fb;border:1px solid var(--border);border-radius:8px;padding:14px 20px;margin:18px 0;line-height:2.6;}
  .toc-title{font-weight:800;color:var(--brand);margin-bottom:6px;font-size:0.9em;}
  .toc-link{text-decoration:none;padding:4px 12px;border-radius:5px;font-size:0.82em;font-weight:700;margin:2px;display:inline-block;}
  .toc-pass{color:var(--pass);background:#edfaf3;border:1px solid #a3d9b6;}
  .toc-warning{color:var(--warn);background:#fef8ec;border:1px solid #f5d78e;}
  .toc-fail{color:var(--fail);background:#fdf0ef;border:1px solid #f0b0ad;}
  h2{color:var(--brand);border-left:5px solid var(--brand);padding:8px 16px;display:flex;align-items:center;gap:10px;margin-top:38px;font-size:1.08em;background:#f0f2fb;border-radius:0 7px 7px 0;font-family:'Century Gothic','CenturyGothic',sans-serif;}
  .rag-badge{display:inline-block;padding:3px 14px;border-radius:12px;font-size:0.72em;font-weight:800;color:#fff;letter-spacing:1px;}
  .rag-pass{background:var(--pass);}.rag-warning{background:var(--warn);}.rag-fail{background:var(--fail);}
  .top-link{font-size:0.73em;color:var(--brand);text-decoration:none;margin-left:auto;}
  .cat-header td{background:var(--brand) !important;color:#fff !important;font-weight:700;font-size:0.78em;letter-spacing:1.5px;text-transform:uppercase;padding:7px 12px !important;}
  table{width:100%;border-collapse:collapse;margin:8px 0 22px;font-size:0.9em;}
  th{background:var(--brand);color:#fff;padding:10px 13px;text-align:left;font-family:'Century Gothic','CenturyGothic',sans-serif;}
  td{padding:9px 12px;border-bottom:1px solid #e5e8f0;vertical-align:top;}
  tr:hover td{background:var(--row-alt);}
  /* Wider Remediation column */
  th:nth-child(5), td:nth-child(5) { width: 38%; }
  .pass{color:var(--pass);font-weight:700;}.warning{color:var(--warn);font-weight:700;}.fail{color:var(--fail);font-weight:700;}.info{color:var(--brand);}
  .note{font-size:0.82em;color:#2c2c2c;background:#f4f5fb;padding:7px 10px;border-left:4px solid var(--brand);line-height:1.5;}
  hr{border:0;border-top:1px solid var(--border);margin:4px 0;}
  .footer{text-align:center;color:#999;font-size:0.8em;margin-top:28px;border-top:2px solid var(--brand);padding-top:14px;}
</style>
"@

$htmlTop = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>$CompanyDisplayName - M365 Health Check</title>
  $css
</head>
<body id="top">
<div class="wrap">
  <span class="conf-ribbon">&#128274; Confidential - Internal Use Only - $CompanyDisplayName</span>
  <div class="header-band">
    $LogoHtml
    <div class="header-text">
      <div class="company-name">$CompanyDisplayName</div>
      <div class="report-title">&#9729;&#65039; Microsoft 365 &amp; Entra ID - Health Check Report</div>
    </div>
  </div>
  <div class="summary">
    &#128197; $ReportDate &nbsp;&nbsp;|&nbsp;&nbsp;
    <span class="s-pass">&#10003; $CountPass Passed</span> &nbsp;|&nbsp;
    <span class="s-warn">&#9888; $CountWarn Warnings</span> &nbsp;|&nbsp;
    <span class="s-fail">&#10007; $CountFail Failed</span>
  </div>
  <div class="toc">
    <div class="toc-title">&#128269; Jump to Section:</div>
    $tocHtml
  </div>
"@
$htmlBody = ""
foreach ($sec in $SectionOrder) {
    $secRows = $Script:Results | Where-Object { $_.Section -eq $sec }
    if (-not $secRows) { continue }
    $anchor   = $sec -replace '[^a-zA-Z0-9]', '_'
    $ragVal   = $SectionRAG[$sec]; if (-not $ragVal) { $ragVal = "Pass" }
    $ragClass = "rag-$($ragVal.ToLower())"
    $ragLabel = $ragVal.ToUpper()
    $htmlBody += "`n<h2 id='$anchor'>$sec <span class='rag-badge $ragClass'>$ragLabel</span><a href='#top' class='top-link'>&#11014; Back to Top</a></h2>`n"
    $htmlBody += "<table>`n<tr><th style='width:22%'>Item</th><th style='width:24%'>Check</th><th style='width:7%'>Status</th><th style='width:18%'>Value</th><th style='width:38%'>Remediation / Notes</th></tr>`n"
    $cats = $secRows | Select-Object -ExpandProperty Category | Sort-Object -Unique
    foreach ($cat in $cats) {
        $htmlBody += "<tr class='cat-header'><td colspan='5'>&#9656;&nbsp; $cat</td></tr>`n"
        $catRows = $secRows | Where-Object { $_.Category -eq $cat }
        foreach ($row in $catRows) {
            $cls = $row.Status.ToLower()
            $rem = if ($row.Remediation) { "<div class='note'>$($row.Remediation)</div>" } else { "" }
            $htmlBody += "<tr><td>$($row.Item)</td><td>$($row.Check)</td><td class='$cls'>$($row.Status)</td><td>$($row.Value)</td><td>$rem</td></tr>`n"
        }
    }
    $htmlBody += "</table>`n"
}
$htmlBottom = @"
  <div class="footer">
    &#128274; This report is confidential and intended for authorised <strong>$CompanyDisplayName</strong> IT personnel only.<br/>
    Generated by M365HC_v2.ps1 &nbsp;|&nbsp; Completed in $TotalMins minutes &nbsp;|&nbsp; $ReportDate
  </div>
</div>
</body>
</html>
"@
($htmlTop + $htmlBody + $htmlBottom) | Out-File -FilePath $ReportFile -Encoding UTF8 -Force
Write-Host "`nReport saved: $ReportFile" -ForegroundColor Green
#endregion

#region PDF Conversion 
# === PDF CONVERSION
$PdfFile = $ReportFile -replace '\.html$', '.pdf'

try {
    $wkhtmlPath = "C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"

    if (Test-Path $wkhtmlPath) {
        Write-Host "Converting HTML to PDF using wkhtmltopdf..." -ForegroundColor Cyan

        $wkArgs = @(
            "--enable-local-file-access",
            "--margin-top", "0",
            "--margin-right", "0",
            "--margin-bottom", "0",
            "--margin-left", "0",
            "--dpi", "300",
            "--image-quality", "95",
            "--disable-smart-shrinking",
            "`"$ReportFile`"",
            "`"$PdfFile`""
        )

        Start-Process -FilePath $wkhtmlPath -ArgumentList $wkArgs -Wait -WindowStyle Hidden -ErrorAction Stop

        if (Test-Path $PdfFile) {
            Write-Host "PDF report successfully saved: $PdfFile" -ForegroundColor Green
        } else {
            Write-Warning "wkhtmltopdf completed but PDF file was not created."
        }
    } 
    else {
        Write-Warning "wkhtmltopdf not found. Please install it manually from:"
        Write-Warning "https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox-0.12.6.1-2.msvc2015-win64.exe"
        Write-Warning "HTML report is still fully functional."
    }
} 
catch {
    Write-Warning "PDF conversion failed: $($_.Exception.Message)"
    Write-Warning "HTML report is still available and fully functional."
}
#endregion

#region EMAIL
if     ($CountFail -gt 0) { $overallStatus = "requires your attention";  $statusEmoji = "??" }
elseif ($CountWarn -gt 0) { $overallStatus = "has some items to review"; $statusEmoji = "??" }
else                       { $overallStatus = "is looking healthy";       $statusEmoji = "??" }

$topIssues   = $Script:Results | Where-Object { $_.Status -in @("Fail","Warning") } | Select-Object -First 6
$bulletLines = ""
foreach ($issue in $topIssues) {
    $icon = if ($issue.Status -eq "Fail") { "&#10060;" } else { "&#9888;&#65039;" }
    $bulletLines += "<li>$icon &nbsp;<b>[$($issue.Section)]</b> $($issue.Check) - $($issue.Value)</li>`n"
}
if (-not $bulletLines) { $bulletLines = "<li>&#9989; &nbsp;No failures or warnings detected across any check.</li>`n" }

$emailBody = @"
<div style="font-family:'Century Gothic','CenturyGothic','Segoe UI',Arial,sans-serif; font-size:15px; color:#1a1a2e; max-width:680px;">
  <p>Hi Team,</p>
  <p>Hope you're all doing well. The automated <strong style="color:#000366;">Microsoft 365 &amp; Entra ID</strong> health check for <strong style="color:#000366;">$CompanyDisplayName</strong> has completed and the environment <strong>$overallStatus $statusEmoji</strong>.</p>
  <p>Here's a quick snapshot from this run:</p>
  <table style="border-collapse:collapse; margin:12px 0 22px; width:340px; border-radius:8px; overflow:hidden;">
    <tr><td style="padding:10px 16px; background:#edfaf3; font-weight:600; color:#1a7a3c;">&#10003;&nbsp; Passed</td><td style="padding:10px 16px; background:#edfaf3; font-weight:700; color:#1a7a3c; text-align:right;">$CountPass</td></tr>
    <tr><td style="padding:10px 16px; background:#fef8ec; font-weight:600; color:#7d4e06;">&#9888;&nbsp; Warnings</td><td style="padding:10px 16px; background:#fef8ec; font-weight:700; color:#7d4e06; text-align:right;">$CountWarn</td></tr>
    <tr><td style="padding:10px 16px; background:#fdf0ef; font-weight:600; color:#8b1a17;">&#10007;&nbsp; Failed</td><td style="padding:10px 16px; background:#fdf0ef; font-weight:700; color:#8b1a17; text-align:right;">$CountFail</td></tr>
  </table>
  <p><strong>Notable items from this run:</strong></p>
  <ul style="line-height:2.1; padding-left:20px;">$bulletLines</ul>
  <p>The full report is attached as an HTML file - open it in any browser for a complete breakdown across all 7 check categories.</p>
  <p>If anything needs immediate attention or you'd like to discuss any of the findings, please raise it with the IT team.</p>
  <p>Thanks for keeping an eye on things.<br/><br/><strong style="color:#000366;">$CompanyDisplayName - Automated M365 Monitoring</strong><br/><span style="color:#aaa; font-size:0.85em;">Automated message generated on $ReportDate. Please do not reply to this mailbox.</span></p>
  <hr style="border:0; border-top:2px solid #000366; margin:22px 0;" />
  <p style="font-size:0.8em; color:#999;">&#128274; This email and its attachment are confidential and intended solely for authorised <strong>$CompanyDisplayName</strong> IT personnel. If received in error, please delete it and notify the IT team immediately.</p>
</div>
"@
try {
    $freshToken = Get-GraphTokenWithCert -TenantId $TenantId -ClientId $ClientId -Thumbprint $Thumbprint
    $b64        = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($ReportFile))
    $attachments = @(
        @{ "@odata.type" = "#microsoft.graph.fileAttachment"; name = (Split-Path $ReportFile -Leaf); contentType = "text/html"; contentBytes = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($ReportFile)) }
    )

    if (Test-Path $PdfFile) {
        $attachments += @{ "@odata.type" = "#microsoft.graph.fileAttachment"; name = (Split-Path $PdfFile -Leaf); contentType = "application/pdf"; contentBytes = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($PdfFile)) }
    }

    $mail = @{
        message = @{
            subject      = "$CompanyDisplayName - M365 Health Check | $(Get-Date -Format 'dd MMM yyyy')"
            body         = @{ contentType = "HTML"; content = $emailBody }
            toRecipients = @( foreach ($r in $Recipients) { @{ emailAddress = @{ address = $r.Trim() } } } )
            attachments  = $attachments
        }
    }
    $sendAttempt = 0; $sendSuccess = $false
    while ($sendAttempt -lt 3 -and -not $sendSuccess) {
        try {
            $sendAttempt++
            Invoke-RestMethod -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$Sender/sendMail" -Headers @{ Authorization = "Bearer $freshToken" } -Body ($mail | ConvertTo-Json -Depth 10) -ContentType "application/json" -ErrorAction Stop
            $sendSuccess = $true
            Write-Host "Mail sent to: $($Recipients -join ', ')" -ForegroundColor Green
        } catch {
            if ($sendAttempt -lt 3) {
                Write-Warning "Mail send attempt $sendAttempt failed - retrying in 5s... ($($_.Exception.Message))"
                Start-Sleep -Seconds 5
            } else { Write-Error "Mail send failed after 3 attempts: $($_.Exception.Message)" }
        }
    }
} catch { Write-Error "Could not obtain fresh token for mail send: $($_.Exception.Message)" }
#endregion

if ($ExoConnected -and (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue)) {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}

Write-Host "`nM365 Health Check complete. Total time: $TotalMins minutes." -ForegroundColor Cyan
Stop-Transcript