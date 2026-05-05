#=====================================================================
#  AHC_v4.ps1 – ULTIMATE HYBRID HEALTH CHECK v4.0
#
#  Changes over v3:
#    - Company display name parameter (defaults to "Ha-Shem Limited")
#    - Logo parameter — accepts hosted URL or local file path
#    - Role-based check scoping (DC / File Server / Exchange / All)
#    - LDAP/LDAPS checks restricted to Domain Controllers only
#    - DA & EA member names listed in Domain Wide section
#    - All Servers: Ping, WinRM, CPU, Memory, Disk, Patch, Uptime, Event Logs
#    - DC only: DNS/NTDS/NetLogon, LDAP/LDAPS, SYSVOL/NETLOGON, DCDIAG, Time Sync, GP
#    - File Server only: LanmanServer, Shares, DFS
#    - Exchange only: Full Exchange health block
#    - Azure AD Connect: any server where ADSync is detected
#    - PS5 compatible throughout
#=====================================================================

param(
    [Parameter(Position = 0)]
    [string]$ReportFile,

    # Display name shown in the report header and email.
    # Defaults to "Ha-Shem Limited". Override if needed.
    [string]$CompanyDisplayName = "iAmHtosin Enterprise",

    # Logo: accepts a hosted image URL  OR  a local file path on the server.
    # Examples:
    #   -LogoPath "https://cdn.company.com/logo.png"
    #   -LogoPath "C:\HealthCheck\logo.png"
    # Leave blank to omit the logo.
    [string]$LogoPath = "C:\Users\iAmHtosin\Desktop\server.webp",

    [switch]$AllDomainControllers,
    [int]$ThrottleLimit = 10
)

#region ---------------------------------------------------------------
# CREDENTIALS — machine-level environment variables
#   [System.Environment]::SetEnvironmentVariable("GRAPH_TENANT_ID",     "...", "Machine")
#   [System.Environment]::SetEnvironmentVariable("GRAPH_CLIENT_ID",     "...", "Machine")
#   [System.Environment]::SetEnvironmentVariable("GRAPH_CLIENT_SECRET", "...", "Machine")
#   [System.Environment]::SetEnvironmentVariable("GRAPH_SENDER_EMAIL",  "...", "Machine")
#   [System.Environment]::SetEnvironmentVariable("GRAPH_RECIPIENTS",    "a@b.com,c@d.com", "Machine")
#----------------------------------------------------------------------
$TenantId      = [System.Environment]::GetEnvironmentVariable("GRAPH_TENANT_ID", "Machine")
$ClientId      = [System.Environment]::GetEnvironmentVariable("GRAPH_CLIENT_ID", "Machine")
$ClientSecret  = [System.Environment]::GetEnvironmentVariable("GRAPH_CLIENT_SECRET", "Machine")
$Sender        = [System.Environment]::GetEnvironmentVariable("GRAPH_SENDER_EMAIL", "Machine")
$RecipientsRaw = [System.Environment]::GetEnvironmentVariable("GRAPH_RECIPIENTS", "Machine")
$Recipients    = if ($RecipientsRaw) { $RecipientsRaw -split "," } else { @() }

$missingVars = @()
if (-not $TenantId)     { $missingVars += "GRAPH_TENANT_ID" }
if (-not $ClientId)     { $missingVars += "GRAPH_CLIENT_ID" }
if (-not $ClientSecret) { $missingVars += "GRAPH_CLIENT_SECRET" }
if (-not $Sender)       { $missingVars += "GRAPH_SENDER_EMAIL" }
if (-not $Recipients)   { $missingVars += "GRAPH_RECIPIENTS" }

if ($missingVars.Count -gt 0) {
    Write-Error "FATAL: Missing environment variables:`n  $($missingVars -join "`n  ")`nSet with [System.Environment]::SetEnvironmentVariable(`"NAME`",`"value`",`"Machine`") then reboot."
    exit 1
}
#endregion

#region ---------------------------------------------------------------
# INITIALISATION
#----------------------------------------------------------------------
# NetBIOS name is detected for internal use (AD queries etc.)
# but $CompanyDisplayName is what appears in the report and email.
try {
    $DomainInfo    = Get-ADDomain
    $NetBIOSName   = $DomainInfo.NetBIOSName
    Write-Host "Detected NetBIOS name: $NetBIOSName" -ForegroundColor Green
} catch {
    $NetBIOSName = $CompanyDisplayName
    Write-Warning "Could not detect NetBIOS name. Using display name as fallback."
}

Write-Host "Report will display company as: $CompanyDisplayName" -ForegroundColor Cyan

$LogFile = "C:\Health_Check_TaskLog_$(Get-Date -Format 'yyyy-MM-dd').txt"
Start-Transcript -Path $LogFile -Append

if (-not $ReportFile) {
    $ReportFile = "C:\Hybrid_HealthReport_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
}

$GlobalStart = Get-Date
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# ------------------------------------------------------------------
# LOGO HANDLING
# If a local file path is provided, convert to base64 data URI so
# the report is fully self-contained and works without network access.
# If a URL is provided, embed it as an <img src="url">.
# ------------------------------------------------------------------
$LogoHtml = ""
if ($LogoPath) {
    if ($LogoPath -match "^https?://") {
        # Hosted URL — use directly
        $LogoHtml = "<img src='$LogoPath' alt='$CompanyDisplayName' class='company-logo' />"
        Write-Host "Logo: using hosted URL." -ForegroundColor Cyan
    } elseif (Test-Path $LogoPath -ErrorAction SilentlyContinue) {
        # Local file — convert to base64 data URI
        try {
            $ext      = [System.IO.Path]::GetExtension($LogoPath).TrimStart(".").ToLower()
            $mimeMap  = @{ png = "image/png"; jpg = "image/jpeg"; jpeg = "image/jpeg";
                           gif = "image/gif"; svg = "image/svg+xml"; webp = "image/webp" }
            $mime     = if ($mimeMap[$ext]) { $mimeMap[$ext] } else { "image/png" }
            $b64Logo  = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($LogoPath))
            $LogoHtml = "<img src='data:$mime;base64,$b64Logo' alt='$CompanyDisplayName' class='company-logo' />"
            Write-Host "Logo: embedded as base64 from $LogoPath" -ForegroundColor Cyan
        } catch {
            Write-Warning "Could not read logo file at $LogoPath — logo will be omitted."
        }
    } else {
        Write-Warning "Logo path not found: $LogoPath — logo will be omitted."
    }
}
#endregion

#region ---------------------------------------------------------------
# SERVER DISCOVERY
#----------------------------------------------------------------------
Write-Host "`nQuerying AD for Domain Controllers..." -ForegroundColor Cyan
$DCs = Get-ADDomainController -Filter * |
    Select-Object -ExpandProperty HostName | Sort-Object

Write-Host "Querying AD for all Windows Server machines..." -ForegroundColor Cyan
$AllSrvs = Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' -Properties DNSHostName |
    Select-Object -ExpandProperty DNSHostName

if (-not $AllSrvs) {
    Write-Warning "No Server OS computers found — falling back to all AD computers."
    $AllSrvs = Get-ADComputer -Filter * -Properties DNSHostName |
        Select-Object -ExpandProperty DNSHostName
}

$Servers = $AllSrvs | Where-Object { $_ } | Sort-Object -Unique

if (-not $Servers -or $Servers.Count -eq 0) {
    Write-Error "CRITICAL: AD query returned zero results."
    Stop-Transcript; exit 1
}

Write-Host "Discovered $($Servers.Count) server(s). Beginning health checks...`n" -ForegroundColor Cyan
#endregion

#region ---------------------------------------------------------------
# SECTION ORDER — controls display order in the HTML report
#----------------------------------------------------------------------
$SectionOrder = @(
    "Connectivity",
    "Performance",
    "Services",
    "Directory & Replication",
    "LDAP Ports",
    "File Services",
    "Azure AD Connect",
    "Exchange Health",
    "Patching & Uptime",
    "Event Logs"
)
#endregion

#region ---------------------------------------------------------------
# PER-SERVER CHECK FUNCTION
# Check matrix (from design spec):
#   ALL SERVERS  : Ping/WinRM, CPU/Memory/Disk, Patching & Uptime, Event Logs
#   DC ONLY      : DNS/NTDS/NetLogon, LDAP/LDAPS, SYSVOL/NETLOGON, DCDIAG/Time Sync/GP
#   FILE SERVER  : LanmanServer, Shares, DFS
#   EXCHANGE     : Full Exchange health block
#   ANY SERVER   : Azure AD Connect (only if ADSync service detected)
#----------------------------------------------------------------------
function Invoke-ServerCheck {
    param(
        [string]   $Server,
        [string[]] $DomainControllers
    )

    $r    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $isDC = $DomainControllers -contains $Server

    function Add-R {
        param($Computer, $Section, $Check, $Status, $Value, $Note = "")
        $r.Add([pscustomobject]@{
            Computer = $Computer
            Section  = $Section
            Check    = $Check
            Status   = $Status
            Value    = $Value
            Note     = $Note
        })
    }

    # ==================================================================
    # ALL SERVERS — CONNECTIVITY
    # ==================================================================

    if (-not (Test-Connection -ComputerName $Server -Count 2 -Quiet -ErrorAction SilentlyContinue)) {
        Add-R $Server "Connectivity" "Ping" "Fail" "Unreachable" `
              "Server did not respond to ICMP ping — offline or ICMP blocked. No further checks performed."
        return $r
    }
    Add-R $Server "Connectivity" "Ping" "Pass" "Reachable"

    $winrmOpen = Test-NetConnection -ComputerName $Server -Port 5985 `
                     -InformationLevel Quiet -WarningAction SilentlyContinue
    Add-R $Server "Connectivity" "WinRM (5985)" `
          $(if ($winrmOpen) { "Pass" } else { "Fail" }) `
          $(if ($winrmOpen) { "Open" } else { "Closed" })

    if (-not $winrmOpen) {
        Add-R $Server "Connectivity" "Remote Checks" "Fail" "All skipped" `
              "WinRM port 5985 is closed. Enable WinRM via GPO or run: winrm quickconfig"
        return $r
    }

    # ==================================================================
    # ALL SERVERS — PERFORMANCE  (CPU / Memory / Disk)
    # ==================================================================

    try {
        $cpu = [math]::Round(
            (Get-CimInstance Win32_Processor -ComputerName $Server -ErrorAction Stop |
             Measure-Object -Property LoadPercentage -Average).Average, 1)
        $st = if ($cpu -lt 80) { "Pass" } elseif ($cpu -lt 90) { "Warning" } else { "Fail" }
        Add-R $Server "Performance" "CPU Utilization" $st "$cpu%"
    } catch {
        Add-R $Server "Performance" "CPU Utilization" "Fail" "N/A" "Query failed: $($_.Exception.Message)"
    }

    try {
        $os  = Get-CimInstance Win32_OperatingSystem -ComputerName $Server -ErrorAction Stop
        $mem = [math]::Round(100 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize * 100), 1)
        $st  = if ($mem -lt 85) { "Pass" } elseif ($mem -lt 95) { "Warning" } else { "Fail" }
        Add-R $Server "Performance" "Memory Utilization" $st "$mem% used"
    } catch {
        Add-R $Server "Performance" "Memory Utilization" "Fail" "N/A" "Query failed: $($_.Exception.Message)"
    }

    try {
        $disks = Get-CimInstance Win32_LogicalDisk -ComputerName $Server -Filter "DriveType=3" -ErrorAction Stop
        if ($disks) {
            foreach ($d in $disks) {
                $totalGB = [math]::Round($d.Size / 1GB, 2)
                $freeGB  = [math]::Round($d.FreeSpace / 1GB, 2)
                $freePct = [math]::Round(($d.FreeSpace / $d.Size) * 100, 1)
                $st      = if ($freePct -gt 20) { "Pass" } elseif ($freePct -gt 10) { "Warning" } else { "Fail" }
                Add-R $Server "Performance" "Disk $($d.DeviceID)" $st "$freeGB GB free of $totalGB GB ($freePct%)"
            }
        } else {
            Add-R $Server "Performance" "Disk Check" "Warning" "No fixed drives found"
        }
    } catch {
        Add-R $Server "Performance" "Disk Check" "Fail" "N/A" "Query failed: $($_.Exception.Message)"
    }

    # ==================================================================
    # DC ONLY — SERVICES  (DNS, NTDS, NetLogon)
    # ==================================================================
    if ($isDC) {
        foreach ($svcName in @("DNS", "NTDS", "NetLogon")) {
            try {
                $svc = Get-Service -Name $svcName -ComputerName $Server -ErrorAction Stop
                $st  = if ($svc.Status -eq "Running") { "Pass" } else { "Fail" }
                Add-R $Server "Services" "$svcName Service" $st $svc.Status
            } catch {
                Add-R $Server "Services" "$svcName Service" "Fail" "Not found" "Service may not be installed on this DC."
            }
        }
    }

    # ==================================================================
    # DC ONLY — DIRECTORY & REPLICATION
    # (SYSVOL/NETLOGON shares, DCDIAG, Time Sync, Last GP Update)
    # ==================================================================
    if ($isDC) {
        # SYSVOL & NETLOGON share access
        foreach ($shareName in @("SYSVOL", "NETLOGON")) {
            $ok = Test-Path "\\$Server\$shareName" -ErrorAction SilentlyContinue
            Add-R $Server "Directory & Replication" "$shareName Share" `
                  $(if ($ok) { "Pass" } else { "Fail" }) `
                  $(if ($ok) { "Accessible" } else { "Missing" })
        }

        # DCDIAG — single run, per-test line parsing
        $dcdiagTests = @("Advertising", "Replications", "KnowsOfRoleHolders", "FSMOCheck", "Services")
        try {
            $out = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock {
                dcdiag /test:Advertising /test:Replications /test:KnowsOfRoleHolders /test:FSMOCheck /test:Services
            }
            foreach ($t in $dcdiagTests) {
                $matchLine = ($out | Select-String -Pattern $t | Select-Object -Last 1)
                $lineText  = if ($matchLine) { $matchLine.ToString() } else { "" }
                if     ($lineText -match "passed") { Add-R $Server "Directory & Replication" "DCDIAG: $t" "Pass"    "OK" }
                elseif ($lineText -match "failed") { Add-R $Server "Directory & Replication" "DCDIAG: $t" "Fail"    "Test failed — run dcdiag /v on the DC for full detail." }
                else                               { Add-R $Server "Directory & Replication" "DCDIAG: $t" "Warning" "Result unclear — output did not match 'passed' or 'failed'." }
            }
        } catch {
            Add-R $Server "Directory & Replication" "DCDIAG Tests" "Fail" "Execution error" $_.Exception.Message
        }

        # Time Synchronisation
        try {
            $w32tm = Invoke-Command -ComputerName $Server -ErrorAction Stop -ScriptBlock { w32tm /query /status }
            if ($w32tm) {
                $srcLine  = ($w32tm | Select-String "^Source:")  | Select-Object -Last 1
                $strtLine = ($w32tm | Select-String "^Stratum:") | Select-Object -Last 1
                $source   = if ($srcLine)  { $srcLine.ToString().Split(":", 2)[1].Trim()  } else { "Unknown" }
                $stratum  = if ($strtLine) { $strtLine.ToString().Split(":", 2)[1].Trim() } else { "Unknown" }
                $ok       = ($source -notmatch "Local CMOS Clock") -and ($stratum -notin @("0", "Unknown"))
                Add-R $Server "Directory & Replication" "Time Sync" `
                      $(if ($ok) { "Pass" } else { "Warning" }) "Source: $source | Stratum: $stratum"
            }
        } catch {
            Add-R $Server "Directory & Replication" "Time Sync" "Fail" "Query failed" $_.Exception.Message
        }

        # Last Group Policy application
        try {
            $gpEvent = Get-WinEvent -ComputerName $Server -MaxEvents 1 -ErrorAction SilentlyContinue `
                           -FilterHashtable @{ LogName = 'Microsoft-Windows-GroupPolicy/Operational'; ID = 8004 }
            if ($gpEvent) {
                $ts  = (Get-Date) - $gpEvent.TimeCreated
                $val = "{0}d {1}h {2}m ago" -f $ts.Days, $ts.Hours, $ts.Minutes
                Add-R $Server "Directory & Replication" "Last GP Update" `
                      $(if ($ts.TotalDays -le 1) { "Pass" } else { "Warning" }) $val
            } else {
                Add-R $Server "Directory & Replication" "Last GP Update" "Warning" "No GP events found" `
                      "Event ID 8004 not present in the GP Operational log."
            }
        } catch {
            Add-R $Server "Directory & Replication" "Last GP Update" "Fail" "Query failed" $_.Exception.Message
        }
    }

    # ==================================================================
    # DC ONLY — LDAP PORTS  (389 & 636)
    # LDAP/LDAPS are DC-specific services. Closed ports on file servers
    # or Exchange servers are expected and are NOT checked here.
    # ==================================================================
    if ($isDC) {
        $ldap389 = Test-NetConnection -ComputerName $Server -Port 389 `
                       -InformationLevel Quiet -WarningAction SilentlyContinue
        Add-R $Server "LDAP Ports" "LDAP (389)" `
              $(if ($ldap389) { "Pass" } else { "Fail" }) `
              $(if ($ldap389) { "Open" } else { "Closed" })

        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $ok  = $tcp.ConnectAsync($Server, 636).Wait(1500)
            $tcp.Close()
            Add-R $Server "LDAP Ports" "LDAPS (636)" `
                  $(if ($ok) { "Pass" } else { "Fail" }) `
                  $(if ($ok) { "Open" } else { "Closed" })
        } catch {
            Add-R $Server "LDAP Ports" "LDAPS (636)" "Fail" "Connection error" $_.Exception.Message
        }
    }

    # ==================================================================
    # FILE SERVER ONLY — FILE SERVICES  (LanmanServer, Shares, DFS)
    # Only runs on non-DC, non-Exchange servers where LanmanServer exists.
    # ==================================================================
    $isExchange = $false
    try {
        $exchDetect = Get-Service -ComputerName $Server -Name MSExchangeServiceHost -ErrorAction SilentlyContinue
        if ($exchDetect) { $isExchange = $true }
    } catch { }

    if (-not $isDC -and -not $isExchange) {
        try {
            $fsSvc = Get-Service -Name "LanmanServer" -ComputerName $Server -ErrorAction Stop
            $st    = if ($fsSvc.Status -eq "Running") { "Pass" } else { "Fail" }
            Add-R $Server "File Services" "LanmanServer Service" $st $fsSvc.Status

            if ($fsSvc.Status -eq "Running") {
                # Shares
                try {
                    $shares = Get-CimInstance Win32_Share -ComputerName $Server -ErrorAction Stop
                    if ($shares) {
                        foreach ($share in $shares) {
                            $path = "\\$Server\$($share.Name)"
                            $ok   = Test-Path $path -ErrorAction SilentlyContinue
                            Add-R $Server "File Services" "Share: $($share.Name)" `
                                  $(if ($ok) { "Pass" } else { "Fail" }) `
                                  $(if ($ok) { "Accessible" } else { "Not Accessible" })
                        }
                    } else {
                        Add-R $Server "File Services" "Shares" "Info" "No shares found"
                    }
                } catch {
                    Add-R $Server "File Services" "Shares" "Fail" "Query failed" $_.Exception.Message
                }

                # DFS Namespace roots
                try {
                    $dfsRoots = Get-DfsnRoot -ComputerName $Server -ErrorAction SilentlyContinue
                    if ($dfsRoots) {
                        foreach ($root in $dfsRoots) {
                            Add-R $Server "File Services" "DFS Root: $($root.Path)" "Info" "Detected"
                        }
                    } else {
                        Add-R $Server "File Services" "DFS" "Info" "No DFS roots found on this server"
                    }
                } catch {
                    Add-R $Server "File Services" "DFS" "Info" "DFS cmdlets not available or unreachable"
                }
            }
        } catch {
            Add-R $Server "File Services" "LanmanServer Service" "Info" "Not detected" `
                  "This server does not appear to be configured as a file server."
        }
    }

    # ==================================================================
    # ANY SERVER — AZURE AD CONNECT  (only if ADSync is detected)
    # ==================================================================
    try {
        $adSync = Get-Service -ComputerName $Server -Name ADSync -ErrorAction SilentlyContinue
        if ($adSync) {
            $st = if ($adSync.Status -eq "Running") { "Pass" } else { "Fail" }
            Add-R $Server "Azure AD Connect" "ADSync Service" $st $adSync.Status `
                  $(if ($adSync.Status -ne "Running") { "ADSync is installed but not running. Check the Azure AD Connect console for sync errors." } else { "" })
        }
        # Not every server runs ADSync — silently skip if absent
    } catch { }

    # ==================================================================
    # EXCHANGE ONLY — EXCHANGE HEALTH
    # ==================================================================
      if ($isExchange) {
        Write-Host "Exchange detected on $Server — connecting via Exchange endpoint..." -ForegroundColor Magenta
        # Key Exchange Windows services (these still use WinRM — no AD query needed)
        $exchServices = @(
            "MSExchangeServiceHost",
            "MSExchangeTransport",
            "MSExchangeFrontEndTransport",
            "MSExchangeIS",
            "MSExchangeADTopology",
            "W3Svc"
        )
        foreach ($svcName in $exchServices) {
            try {
                $svc = Get-Service -Name $svcName -ComputerName $Server -ErrorAction Stop
                $st  = if ($svc.Status -eq "Running") { "Pass" } else { "Fail" }
                Add-R $Server "Exchange Health" "Service: $svcName" $st $svc.Status
            } catch {
                Add-R $Server "Exchange Health" "Service: $svcName" "Warning" "Not found" `
                      "Service may not apply to this Exchange role."
            }
        }

        $exchSession = $null
        try {
            $exchSession = New-PSSession `
                -ConfigurationName Microsoft.Exchange `
                -ConnectionUri "http://$Server/PowerShell/" `
                -Authentication Kerberos `
                -ErrorAction Stop

            # Import only what we need — avoids polluting the session with all cmdlets
            $null = Import-PSSession $exchSession `
                -CommandName Get-ExchangeServer,
                             Get-MailboxDatabase,
                             Get-Queue,
                             Get-DatabaseAvailabilityGroup,
                             Get-MailboxDatabaseCopyStatus,
                             Get-ExchangeCertificate `
                -DisableNameChecking `
                -AllowClobber `
                -ErrorAction Stop

            # Exchange build version
            try {
                $srvObj = Get-ExchangeServer $Server -ErrorAction Stop
                Add-R $Server "Exchange Health" "Exchange Build" "Info" $srvObj.AdminDisplayVersion.ToString()
            } catch {
                Add-R $Server "Exchange Health" "Exchange Build" "Warning" "Unable to retrieve" $_.Exception.Message
            }

            # Mailbox databases
            try {
                $dbs = Get-MailboxDatabase -Status -ErrorAction Stop
                if ($dbs) {
                    foreach ($db in $dbs) {
                        $mounted = $db.Mounted -eq $true
                        $st      = if ($mounted) { "Pass" } else { "Fail" }
                        $size    = if ($db.DatabaseSize) { $db.DatabaseSize.ToString() } else { "Unknown" }
                        Add-R $Server "Exchange Health" "DB: $($db.Name)" $st `
                              $(if ($mounted) { "Mounted | Size: $size | Server: $($db.Server)" } else { "NOT MOUNTED | Size: $size" }) `
                              $(if (-not $mounted) { "Database is not mounted — users cannot access mailboxes. Investigate immediately using Get-MailboxDatabase -Status and check the Application event log." } else { "" })
                    }
                } else {
                    Add-R $Server "Exchange Health" "Mailbox Databases" "Warning" "No databases returned"
                }
            } catch {
                Add-R $Server "Exchange Health" "Mailbox Databases" "Fail" "Query failed" $_.Exception.Message
            }

            # Mail queues
            try {
                $queues = Get-Queue -ErrorAction Stop
                if ($queues) {
                    foreach ($q in $queues) {
                        $qFail = ($q.MessageCount -gt 100) -or ($q.Status -eq "Retry")
                        $st    = if ($qFail) { "Fail" } elseif ($q.MessageCount -gt 20) { "Warning" } else { "Pass" }
                        Add-R $Server "Exchange Health" "Queue: $($q.Identity)" $st `
                              "$($q.MessageCount) messages | Status: $($q.Status) | NextHop: $($q.NextHopDomain)" `
                              $(if ($qFail) { "Queue depth elevated or in Retry state. Run Get-Queue | Get-Message to investigate mail flow." } else { "" })
                    }
                } else {
                    Add-R $Server "Exchange Health" "Mail Queues" "Pass" "No queues with backlog detected"
                }
            } catch {
                Add-R $Server "Exchange Health" "Mail Queues" "Warning" "Query failed" $_.Exception.Message
            }

            # DAG membership and copy health
            try {
                $dag = Get-DatabaseAvailabilityGroup -ErrorAction SilentlyContinue |
                       Where-Object { $_.Servers -match ($Server -split "\.")[0] }
                if ($dag) {
                    $dagMembers = ($dag.Servers | ForEach-Object { $_.Name }) -join ", "
                    Add-R $Server "Exchange Health" "DAG" "Info" $dag.Name "Members: $dagMembers"

                    $copies = Get-MailboxDatabaseCopyStatus -ErrorAction SilentlyContinue
                    if ($copies) {
                        foreach ($copy in $copies) {
                            $healthy = $copy.Status -in @("Healthy", "Mounted")
                            $qWarn   = ($copy.CopyQueueLength -gt 10) -or ($copy.ReplayQueueLength -gt 10)
                            $st      = if ($healthy -and -not $qWarn) { "Pass" } elseif ($healthy -and $qWarn) { "Warning" } else { "Fail" }
                            Add-R $Server "Exchange Health" "DB Copy: $($copy.Name)" $st `
                                  "Status: $($copy.Status) | CopyQueue: $($copy.CopyQueueLength) | ReplayQueue: $($copy.ReplayQueueLength)" `
                                  $(if ($st -ne "Pass") { "High replication queue may indicate network or disk issues on the passive copy node." } else { "" })
                        }
                    }
                } else {
                    Add-R $Server "Exchange Health" "DAG" "Info" "Not a DAG member (standalone)"
                }
            } catch {
                Add-R $Server "Exchange Health" "DAG" "Warning" "Query failed" $_.Exception.Message
            }

            # Exchange certificates
            try {
                $certs = Get-ExchangeCertificate -ErrorAction Stop
                if ($certs) {
                    foreach ($cert in $certs) {
                        $daysLeft  = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays, 0)
                        $st        = if ($daysLeft -gt 60) { "Pass" } elseif ($daysLeft -gt 14) { "Warning" } else { "Fail" }
                        $thumbShort = $cert.Thumbprint.Substring(0, [Math]::Min(12, $cert.Thumbprint.Length)) + "..."
                        Add-R $Server "Exchange Health" "Cert: $thumbShort" $st `
                              "Expires: $($cert.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft days) | Services: $($cert.Services)" `
                              $(if ($st -ne "Pass") { "Certificate expiry approaching. Subject: $($cert.Subject). Renew before expiry to prevent service disruption." } else { "" })
                    }
                }
            } catch {
                Add-R $Server "Exchange Health" "Certificates" "Warning" "Query failed" $_.Exception.Message
            }

        } catch {
            # Connection to Exchange endpoint failed — provide actionable guidance
            Add-R $Server "Exchange Health" "Exchange Connection" "Fail" "Endpoint unreachable" `
                  "Could not connect to http://$Server/PowerShell/. Verify: (1) The account running this script has an Exchange mailbox or is in the Exchange Management group. (2) IIS and Exchange Backend app pool are running on $Server. (3) Error: $($_.Exception.Message)"
        } finally {
            # Always clean up the session — leaked sessions consume Exchange resources
            if ($exchSession) {
                Remove-PSSession $exchSession -ErrorAction SilentlyContinue
            }
        }
    }

    # ==================================================================
    # ALL SERVERS — PATCHING & UPTIME
    # ==================================================================

    try {
        $patch = Get-CimInstance Win32_QuickFixEngineering -ComputerName $Server -ErrorAction Stop |
                 Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($patch -and $patch.InstalledOn) {
            $ageHrs = [math]::Round(((Get-Date) - $patch.InstalledOn).TotalHours, 1)
            $st     = if ($ageHrs -lt 720) { "Pass" } else { "Warning" }
            Add-R $Server "Patching & Uptime" "Last Patch" $st `
                  "$($patch.HotFixID) — installed $($patch.InstalledOn.ToString('yyyy-MM-dd')) ($ageHrs hrs ago)"
        } else {
            Add-R $Server "Patching & Uptime" "Last Patch" "Warning" "Date unavailable" `
                  "Win32_QuickFixEngineering returned no InstalledOn value. Check Windows Update history manually."
        }
    } catch {
        Add-R $Server "Patching & Uptime" "Last Patch" "Fail" "Query failed" $_.Exception.Message
    }

    try {
        $bootTime = (Get-CimInstance Win32_OperatingSystem -ComputerName $Server -ErrorAction Stop).LastBootUpTime
        $upHrs    = [math]::Round(((Get-Date) - $bootTime).TotalHours, 1)
        $upDays   = [math]::Round($upHrs / 24, 1)
        $st       = if ($upHrs -gt 2) { "Pass" } else { "Warning" }
        Add-R $Server "Patching & Uptime" "Uptime" $st "$upDays days ($upHrs hrs since last boot)" `
              $(if ($upHrs -le 2) { "Server was rebooted recently — monitor for stability over the next few hours." } else { "" })
    } catch {
        Add-R $Server "Patching & Uptime" "Uptime" "Fail" "Query failed" $_.Exception.Message
    }

    # ==================================================================
    # ALL SERVERS — EVENT LOGS  (always last section)
    # ==================================================================
    $logNames = @("System", "Application", "Security")
    if ($isDC)       { $logNames += @("Directory Service", "DNS Server", "DFS Replication") }
    if ($isExchange) { $logNames += "MSExchange Management" }
    $logNames = $logNames | Sort-Object -Unique

    foreach ($logName in $logNames) {
        try {
            $events = Get-WinEvent -ComputerName $Server -MaxEvents 5 -ErrorAction SilentlyContinue `
                          -FilterHashtable @{
                              LogName   = $logName
                              Level     = 1, 2
                              StartTime = (Get-Date).AddDays(-1)
                          }
            if ($events) {
                $detail = ""
                foreach ($e in $events) {
                    $msg = ($e.Message -replace "[\r\n\t]+", " ")
                    if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 497) + "..." }
                    $detail += "<b>[ID $($e.Id)] [$($e.TimeCreated.ToString('yyyy-MM-dd HH:mm'))]</b> $msg<br/><hr/>"
                }
                Add-R $Server "Event Logs" "Log: $logName" "Warning" "$($events.Count) critical/error event(s) in last 24h" $detail
            } else {
                Add-R $Server "Event Logs" "Log: $logName" "Pass" "No critical errors in last 24h"
            }
        } catch {
            Add-R $Server "Event Logs" "Log: $logName" "Info" "N/A" "Log unreachable or access denied."
        }
    }

    return $r
}
#endregion

#region ---------------------------------------------------------------
# DOMAIN-WIDE CHECKS  (run once — not per server)
#----------------------------------------------------------------------
$DomainWide = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-DW {
    param($Check, $Status, $Value, $Note = "")
    $DomainWide.Add([pscustomobject]@{
        Computer = "Domain Wide"
        Section  = "Domain Security"
        Check    = $Check
        Status   = $Status
        Value    = $Value
        Note     = $Note
    })
}

# Domain Admins — count AND member names
try {
    $daMembers = try {
        Get-ADGroupMember "Domain Admins" -Recursive -ErrorAction Stop |
            Where-Object { $_.objectClass -eq "user" } |
            ForEach-Object {
                try { (Get-ADUser $_.SamAccountName -Properties DisplayName -EA Stop).DisplayName } catch { $_.SamAccountName }
            }
    } catch { @("Query error — group may exceed 5000 member limit") }

    $daCount = if ($daMembers -is [array]) { $daMembers.Count } else { 1 }
    $daNamesHtml = ($daMembers | ForEach-Object { "&#8226; $_" }) -join "<br/>"

    $st = if ($daCount -le 5) { "Pass" } else { "Warning" }
    Add-DW "Domain Admins ($daCount members)" $st "$daCount account(s)" `
           "Members: <br/>$daNamesHtml$(if ($daCount -gt 5) { '<br/><br/><b>Recommendation:</b> Review and reduce Domain Admin membership. Apply least privilege / tiered access model.' } else { '' })"
} catch {
    Add-DW "Domain Admins" "Fail" "Query failed" $_.Exception.Message
}

# Enterprise Admins — count AND member names
try {
    $eaMembers = try {
        Get-ADGroupMember "Enterprise Admins" -Recursive -ErrorAction Stop |
            Where-Object { $_.objectClass -eq "user" } |
            ForEach-Object {
                try { (Get-ADUser $_.SamAccountName -Properties DisplayName -EA Stop).DisplayName } catch { $_.SamAccountName }
            }
    } catch { @("Query error — group may exceed 5000 member limit") }

    $eaCount = if ($eaMembers -is [array]) { $eaMembers.Count } else { 1 }
    $eaNamesHtml = ($eaMembers | ForEach-Object { "&#8226; $_" }) -join "<br/>"

    $st = if ($eaCount -le 3) { "Pass" } else { "Warning" }
    Add-DW "Enterprise Admins ($eaCount members)" $st "$eaCount account(s)" `
           "Members: <br/>$eaNamesHtml$(if ($eaCount -gt 3) { '<br/><br/><b>Recommendation:</b> Enterprise Admin membership should be kept to an absolute minimum. Review immediately.' } else { '' })"
} catch {
    Add-DW "Enterprise Admins" "Fail" "Query failed" $_.Exception.Message
}

# Password policy
try {
    $policy = Get-ADDefaultDomainPasswordPolicy
    $issues = @()
    if (-not $policy.ComplexityEnabled)    { $issues += "Complexity disabled" }
    if ($policy.MinPasswordLength -lt 12)  { $issues += "Min length $($policy.MinPasswordLength) (recommend 12+)" }
    if ($policy.MaxPasswordAge.Days -eq 0) { $issues += "Passwords never expire" }
    if ($policy.LockoutThreshold -eq 0)    { $issues += "No account lockout policy set" }
    $status = if ($issues.Count -eq 0) { "Pass" } else { "Warning" }
    Add-DW "Password Policy" $status `
           "Min=$($policy.MinPasswordLength) chars | Complexity=$($policy.ComplexityEnabled) | MaxAge=$($policy.MaxPasswordAge.Days)d | Lockout=$($policy.LockoutThreshold)" `
           ($issues -join " | ")
} catch {
    Add-DW "Password Policy" "Fail" "Query failed" $_.Exception.Message
}
#endregion

#region ---------------------------------------------------------------
# PARALLEL (PS7+) / SEQUENTIAL FALLBACK (PS5)
#----------------------------------------------------------------------
$AllResults = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
$psVersion  = $PSVersionTable.PSVersion.Major

if ($psVersion -ge 7) {
    Write-Host "PowerShell $psVersion detected — running parallel checks (ThrottleLimit: $ThrottleLimit)" -ForegroundColor Cyan
    $checkFnBody = ${function:Invoke-ServerCheck}
    $dcsCopy     = $DCs

    $parallelResults = $Servers | ForEach-Object -Parallel {
        $Server      = $_
        $DcsCopy     = $using:dcsCopy
        $checkFnBody = $using:checkFnBody
        $fn          = [scriptblock]::Create($checkFnBody)
        & $fn -Server $Server -DomainControllers $DcsCopy
    } -ThrottleLimit $ThrottleLimit

    foreach ($set in $parallelResults) {
        foreach ($row in $set) { $AllResults.Add($row) }
    }
} else {
    Write-Host "PowerShell $psVersion detected — running sequentially." -ForegroundColor Yellow
    Write-Host "Tip: Upgrade to PowerShell 7+ for parallel execution on large environments.`n" -ForegroundColor DarkYellow

    foreach ($Server in $Servers) {
        $start = Get-Date
        Write-Host "=== $Server ===" -ForegroundColor Yellow
        $serverResults = Invoke-ServerCheck -Server $Server -DomainControllers $DCs
        foreach ($row in $serverResults) { $AllResults.Add($row) }
        $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
        Write-Host "   Completed in $elapsed sec`n" -ForegroundColor Green
    }
}

foreach ($row in $DomainWide) { $AllResults.Add($row) }
#endregion

#region ---------------------------------------------------------------
# PER-SERVER RAG STATUS
#----------------------------------------------------------------------
$ServerRAG = @{}
foreach ($srv in ($AllResults.Computer | Sort-Object -Unique)) {
    $checks = $AllResults | Where-Object { $_.Computer -eq $srv }
    if     ($checks | Where-Object { $_.Status -eq "Fail"    }) { $ServerRAG[$srv] = "Fail"    }
    elseif ($checks | Where-Object { $_.Status -eq "Warning" }) { $ServerRAG[$srv] = "Warning" }
    else                                                          { $ServerRAG[$srv] = "Pass"    }
}
#endregion

#region ---------------------------------------------------------------
# HTML REPORT  — brand colour #000366
#----------------------------------------------------------------------
$CountPass  = ($AllResults | Where-Object { $_.Status -eq "Pass"    }).Count
$CountWarn  = ($AllResults | Where-Object { $_.Status -eq "Warning" }).Count
$CountFail  = ($AllResults | Where-Object { $_.Status -eq "Fail"    }).Count
$ReportDate = Get-Date -Format "dd MMM yyyy HH:mm"
$TotalMins  = [math]::Round(((Get-Date) - $GlobalStart).TotalMinutes, 1)

$allComputers = $AllResults.Computer | Sort-Object -Unique
$tocLinks = @()
foreach ($c in $allComputers) {
    $ragVal = $ServerRAG[$c]
    if (-not $ragVal) { $ragVal = "Pass" }
    $rag    = $ragVal.ToLower()
    $anchor = $c -replace '[^a-zA-Z0-9]', '_'
    $tocLinks += "<a href='#$anchor' class='toc-link toc-$rag'>$c</a>"
}
$tocHtml = $tocLinks -join "&nbsp;&nbsp;"

$css = @"
<style>
@import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700&display=swap');
  *, *::before, *::after { box-sizing: border-box; }
  body  { font-family: 'Century Gothic', 'AppleGothic', 'Montserrat', sans-serif; background: #eef0f7; padding: 30px; margin: 0; }
  .wrap { max-width: 1600px; margin: auto; background: #fff; padding: 35px 40px;
          border-radius: 12px; box-shadow: 0 2px 20px rgba(0,3,102,.14); position: relative; overflow: hidden; }

  /* WATERMARK */
  .wrap::before {
      content: "CONFIDENTIAL — $CompanyDisplayName";
      position: fixed; top: 50%; left: 50%;
      transform: translate(-50%, -50%) rotate(-35deg);
      font-size: 66px; font-weight: 900; color: rgba(0, 3, 102, 0.045);
      white-space: nowrap; pointer-events: none; z-index: 0;
      letter-spacing: 6px; text-transform: uppercase; user-select: none;
  }
  body::before {
      content: ""; position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background-image: repeating-linear-gradient(
          -35deg, transparent, transparent 160px,
          rgba(0,3,102,0.011) 160px, rgba(0,3,102,0.011) 161px);
      pointer-events: none; z-index: 0;
  }
  .wrap > * { position: relative; z-index: 1; }

  /* HEADER */
  .header-band {
      background: #000366; border-radius: 8px;
      padding: 18px 28px; margin-bottom: 18px;
      display: flex; align-items: center; gap: 22px;
  }
  
  .header-band {
    background: #000366;
    position: relative;
    border-radius: 8px;
    padding: 18px 28px;
    margin-bottom: 18px;

    display: flex;
    align-items: center;
    
    }

    .company-logo {
        max-height: 120px;
        max-width: 200px;
        object-fit: contain;
        z-index: 2;
    }

    .header-text {
        position: absolute;
        text-align: center;
        left: 50%;
        width: 100%;
        transform: translateX(-50%);
        pointer-events: none;
        max-width: 70%;

    }

    .company-name {
        font-size: 26px;
        font-weight: 800;
        color: #ffffff;
        text-transform: uppercase;
        letter-spacing: 3px;
    }

    .report-title {
        font-size: 0.95em;
        color: rgba(255,255,255,0.78);
        margin-top: 6px;
    }

  .company-name { font-size: 26px; font-weight: 800; color: #ffffff;
                  text-transform: uppercase; letter-spacing: 3px; }
  .report-title { font-size: 0.95em; color: rgba(255,255,255,0.78); margin-top: 3px; }
  .confidential-ribbon {
      display: block; text-align: center; background: #000366;
      color: #fff; font-size: 0.76em; font-weight: 700;
      letter-spacing: 3px; padding: 5px 0; margin-bottom: 16px;
      border-radius: 4px; text-transform: uppercase;
  }

  /* SUMMARY */
  .summary { background: #f0f2fb; border-left: 5px solid #000366;
             padding: 16px 22px; border-radius: 8px; margin: 18px 0;
             text-align: center; font-size: 1.12em; font-weight: 600; }
  .s-pass  { color: #1a7a3c; }
  .s-warn  { color: #b8730a; }
  .s-fail  { color: #b52b27; }

  /* TOC */
  .toc       { background: #f4f5fb; border: 1px solid #c5c9e8;
               border-radius: 8px; padding: 14px 20px; margin: 18px 0; line-height: 2.4; }
  .toc-title { font-weight: 700; color: #000366; margin-bottom: 6px; font-size: 0.94em; }
  .toc-link  { text-decoration: none; padding: 3px 10px; border-radius: 4px;
               font-size: 0.83em; font-weight: 600; margin: 2px; display: inline-block; }
  .toc-pass    { color: #1a7a3c; background: #edfaf3; border: 1px solid #a3d9b6; }
  .toc-warning { color: #7d4e06; background: #fef8ec; border: 1px solid #f5d78e; }
  .toc-fail    { color: #8b1a17; background: #fdf0ef; border: 1px solid #f0b0ad; }

  /* SERVER HEADING */
  h2 { color: #000366; border-left: 5px solid #000366; padding: 7px 14px;
       display: flex; align-items: center; gap: 10px; margin-top: 40px;
       font-size: 1.12em; background: #f0f2fb; border-radius: 0 6px 6px 0; }
  .rag-badge   { display: inline-block; padding: 3px 13px; border-radius: 12px;
                 font-size: 0.72em; font-weight: 700; color: #fff; letter-spacing: 1px; }
  .rag-pass    { background: #1a7a3c; }
  .rag-warning { background: #b8730a; }
  .rag-fail    { background: #b52b27; }
  .top-link    { font-size: 0.74em; color: #000366; text-decoration: none; margin-left: auto; }

  /* SECTION SUB-HEADER */
  .section-header td {
      background: #000366 !important;
      color: #ffffff !important;
      font-weight: 700; font-size: 0.8em;
      letter-spacing: 1.5px; text-transform: uppercase;
      padding: 7px 12px !important;
  }

  /* OFFLINE BANNER */
  .offline { background: #dde0f0; color: #000366; padding: 10px 16px;
             border-radius: 6px; font-style: italic; margin: 8px 0; font-size: 0.93em;
             border-left: 4px solid #000366; }

  /* TABLE */
  table { width: 100%; border-collapse: collapse; margin: 8px 0 22px; font-size: 0.91em; }
  th    { background: #000366; color: #fff; padding: 10px 12px; text-align: left; }
  td    { padding: 9px 12px; border-bottom: 1px solid #e5e8f0; vertical-align: top; }
  tr:hover td { background: #f4f5fb; }

  .pass    { color: #1a7a3c; font-weight: 700; }
  .warning { color: #b8730a; font-weight: 700; }
  .fail    { color: #b52b27; font-weight: 700; }
  .info    { color: #000366; }

  .note { font-size: 0.83em; color: #2c2c2c; background: #f4f5fb;
          padding: 7px 10px; border-left: 4px solid #000366; line-height: 1.5; }
  hr    { border: 0; border-top: 1px solid #dde0f0; margin: 4px 0; }

  /* FOOTER */
  .footer { text-align: center; color: #999; font-size: 0.81em; margin-top: 28px;
            border-top: 2px solid #000366; padding-top: 14px; }
</style>
"@

# Header block — logo on left if provided, company name + title on right
$headerInner = @"
$LogoHtml
<div class='header-text'>
    <div class='company-name'>$CompanyDisplayName</div>
    <div class='report-title'>&#128203; Microsoft Windows Infrastructure — Health Check Report</div>
</div>
"@


$htmlTop = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>$CompanyDisplayName — Infrastructure Health Check</title>
  $css
</head>
<body id="top">
<div class="wrap">
  <span class="confidential-ribbon">&#128274; Confidential — Internal Use Only — $CompanyDisplayName</span>

  <div class="header-band">
    $headerInner
  </div>

  <div class="summary">
    &#128197; $ReportDate &nbsp;&nbsp;|&nbsp;&nbsp;
    <span class="s-pass">&#10003; $CountPass Passed</span> &nbsp;|&nbsp;
    <span class="s-warn">&#9888; $CountWarn Warnings</span> &nbsp;|&nbsp;
    <span class="s-fail">&#10007; $CountFail Failed</span>
  </div>

  <div class="toc">
    <div class="toc-title">&#128269; Jump to Server:</div>
    $tocHtml
  </div>
"@

$htmlBody = ""

foreach ($comp in $allComputers) {
    $anchor = $comp -replace '[^a-zA-Z0-9]', '_'
    $ragVal = $ServerRAG[$comp]
    if (-not $ragVal) { $ragVal = "Pass" }
    $ragClass = "rag-$($ragVal.ToLower())"
    $ragLabel = $ragVal.ToUpper()

    $htmlBody += "`n<h2 id='$anchor'>&#128268;&nbsp;$comp <span class='rag-badge $ragClass'>$ragLabel</span><a href='#top' class='top-link'>&#11014; Back to Top</a></h2>`n"

    $compChecks = $AllResults | Where-Object { $_.Computer -eq $comp }
    $isOffline  = ($compChecks | Where-Object { $_.Check -eq "Ping" -and $_.Status -eq "Fail" }) -and
                  ($compChecks.Count -le 2)
    $noWinRM    = $compChecks | Where-Object { $_.Check -eq "WinRM (5985)" -and $_.Status -eq "Fail" }

    if ($isOffline) {
        $htmlBody += "<div class='offline'>&#128683;&nbsp; Server did not respond to ping — all checks skipped.</div>`n"
    } elseif ($noWinRM) {
        $htmlBody += "<div class='offline'>&#9888;&nbsp; Server is reachable but WinRM is unavailable — remote checks were skipped.</div>`n"
    }

    $htmlBody += "<table>`n<tr><th style='width:24%'>Check</th><th style='width:8%'>Status</th><th style='width:28%'>Value</th><th>Notes / Log Detail</th></tr>`n"

    # Render sections in defined order
    $compSections = $compChecks | Select-Object -ExpandProperty Section | Sort-Object -Unique
    $orderedSections = @()
    foreach ($so in $SectionOrder) {
        if ($compSections -contains $so) { $orderedSections += $so }
    }
    foreach ($cs in $compSections) {
        if ($orderedSections -notcontains $cs) { $orderedSections += $cs }
    }

    foreach ($section in $orderedSections) {
        $htmlBody += "<tr class='section-header'><td colspan='4'>&#9656;&nbsp; $section</td></tr>`n"
        $sectionRows = $compChecks | Where-Object { $_.Section -eq $section }

        foreach ($row in $sectionRows) {
            $cls  = $row.Status.ToLower()
            $note = if ($row.Note) { "<div class='note'>$($row.Note)</div>" } else { "" }
            $val  = $row.Value

            # Disk: inline colour for free %
            if ($row.Check -match "^Disk" -and $row.Value -match "([\d\.]+) GB free of ([\d\.]+) GB \(([\d\.]+)%\)") {
                $freeGB  = $Matches[1]; $totalGB = $Matches[2]; $pct = $Matches[3]
                $pctCol  = if ([double]$pct -le 10) { "#b52b27" } elseif ([double]$pct -le 20) { "#b8730a" } else { "#1a7a3c" }
                $val     = "$freeGB GB / $totalGB GB &nbsp;<span style='color:$pctCol;font-weight:700;'>($pct% free)</span>"
            }

            $htmlBody += "<tr><td>$($row.Check)</td><td class='$cls'>$($row.Status)</td><td>$val</td><td>$note</td></tr>`n"
        }
    }

    $htmlBody += "</table>`n"
}

$htmlBottom = @"
  <div class="footer">
    &#128274; This report is confidential and intended for authorised <strong>$CompanyDisplayName</strong> IT personnel only.<br/>
    Generated by AHC_v4.ps1 &nbsp;|&nbsp; $($Servers.Count) servers checked &nbsp;|&nbsp;
    Completed in $TotalMins minutes &nbsp;|&nbsp; $ReportDate
  </div>
</div>
</body>
</html>
"@

($htmlTop + $htmlBody + $htmlBottom) | Out-File -FilePath $ReportFile -Encoding UTF8 -Force
Write-Host "`nReport saved: $ReportFile" -ForegroundColor Green
#endregion

#region ---------------------------------------------------------------
# EMAIL — MICROSOFT GRAPH API
#----------------------------------------------------------------------
if     ($CountFail -gt 0) { $overallStatus = "requires your attention";  $statusEmoji = "🔴" }
elseif ($CountWarn -gt 0) { $overallStatus = "has some items to review"; $statusEmoji = "🟡" }
else                       { $overallStatus = "is looking healthy";       $statusEmoji = "🟢" }

$topIssues = $AllResults | Where-Object { $_.Status -in @("Fail", "Warning") } | Select-Object -First 6
$bulletLines = ""
foreach ($issue in $topIssues) {
    $icon = if ($issue.Status -eq "Fail") { "&#10060;" } else { "&#9888;&#65039;" }
    $bulletLines += "<li>$icon &nbsp;<b>$($issue.Computer)</b> — $($issue.Check): $($issue.Value)</li>`n"
}
if (-not $bulletLines) {
    $bulletLines = "<li>&#9989; &nbsp;No failures or warnings detected across any server.</li>`n"
}

$emailBody = @"
<div style="font-family: Segoe UI, Arial, sans-serif; font-size: 15px; color: #1a1a2e; max-width: 680px;">

  <p>Hi Team,</p>

  <p>
    I trust this email finds you well. Just a heads-up that the automated Windows Server infrastructure health
    check for <strong style="color:#000366;">$CompanyDisplayName</strong> has completed
    and the environment <strong>$overallStatus $statusEmoji</strong>.
  </p>

  <p>Here's a quick snapshot of this run:</p>

  <table style="border-collapse:collapse; margin: 12px 0 22px; width: 340px; border-radius:8px; overflow:hidden;">
    <tr>
      <td style="padding:10px 16px; background:#edfaf3; font-weight:600; color:#1a7a3c;">&#10003;&nbsp; Passed</td>
      <td style="padding:10px 16px; background:#edfaf3; font-weight:700; color:#1a7a3c; text-align:right;">$CountPass</td>
    </tr>
    <tr>
      <td style="padding:10px 16px; background:#fef8ec; font-weight:600; color:#7d4e06;">&#9888;&nbsp; Warnings</td>
      <td style="padding:10px 16px; background:#fef8ec; font-weight:700; color:#7d4e06; text-align:right;">$CountWarn</td>
    </tr>
    <tr>
      <td style="padding:10px 16px; background:#fdf0ef; font-weight:600; color:#8b1a17;">&#10007;&nbsp; Failed</td>
      <td style="padding:10px 16px; background:#fdf0ef; font-weight:700; color:#8b1a17; text-align:right;">$CountFail</td>
    </tr>
  </table>

  <p><strong>Notable items from this run:</strong></p>
  <ul style="line-height: 2.1; padding-left: 20px;">
    $bulletLines
  </ul>

  <p>
    I've attached the full report as an HTML file — just open it in any browser and
    you'll get a complete breakdown per server, including performance metrics,
    event log highlights, disk usage, replication health, Exchange status (where applicable),
    and more. Each server has a Green / Amber / Red indicator so you can spot issues at a glance.
  </p>

  <p>
    If anything in the report needs immediate attention or you have questions about
    a specific result, please don't hesitate to raise it with the infrastructure team.
  </p>

  <p>
    Thank You.<br/><br/>
    <strong style="color:#000366;">Automated Infrastructure Monitoring</strong><br/>
    <span style="color:#aaa; font-size:0.85em;">
      Automated message generated on $ReportDate. Please do not reply to this mailbox.
    </span>
  </p>

  <hr style="border:0; border-top:2px solid #000366; margin: 22px 0;" />
  <p style="font-size:0.8em; color:#999;">
    &#128274; This email and its attachment are confidential and intended solely for
    authorised <strong>$CompanyDisplayName</strong> IT personnel. If you received
    this in error, please delete it and notify the IT team immediately.
  </p>

</div>
"@

try {
    $tokenBody = @{
        grant_type    = "client_credentials"
        scope         = "https://graph.microsoft.com/.default"
        client_id     = $ClientId
        client_secret = $ClientSecret
    }
    $token = Invoke-RestMethod -Method POST -ContentType "application/x-www-form-urlencoded" `
                 -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                 -Body $tokenBody

    $b64 = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($ReportFile))

    $mail = @{
        message = @{
            subject      = "$CompanyDisplayName — Windows Infrastructure Health Check | $(Get-Date -Format 'dd MMM yyyy')"
            body         = @{ contentType = "HTML"; content = $emailBody }
            toRecipients = @(
                foreach ($r in $Recipients) {
                    @{ emailAddress = @{ address = $r.Trim() } }
                }
            )
            attachments  = @(
                @{
                    "@odata.type" = "#microsoft.graph.fileAttachment"
                    name          = (Split-Path $ReportFile -Leaf)
                    contentType   = "text/html"
                    contentBytes  = $b64
                }
            )
        }
    }

    Invoke-RestMethod -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/users/$Sender/sendMail" `
        -Headers @{ Authorization = "Bearer $($token.access_token)" } `
        -Body ($mail | ConvertTo-Json -Depth 10) `
        -ContentType "application/json"

    Write-Host "Mail sent to: $($Recipients -join ', ')" -ForegroundColor Green
} catch {
    Write-Error "Mail send failed: $($_.Exception.Message)"
}
#endregion

Stop-Transcript