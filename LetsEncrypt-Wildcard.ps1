# ================================================
# Let's Encrypt Wildcard Certificate - Automated
# DNS Provider: Cloudflare
# Requires: Posh-ACME v4+, PowerShell 5.1+ / 7+
# ================================================

param(
    [string]$Domain             = "*.readyremotejob.com",
    [string]$CloudflareApiToken = [System.Environment]::GetEnvironmentVariable("CLOUDFLARE_API_TOKEN","Machine"),
    [string]$PfxPassword        = [System.Environment]::GetEnvironmentVariable("M365HC_PFX_PASSWORD","Machine"),
    [string]$ExportPath         = "C:\Certs",
    [int]$RenewWithinDays       = 60
)

# ---------------- SECURITY GUARD ----------------
if ([string]::IsNullOrWhiteSpace($CloudflareApiToken)) {
    throw "CloudflareApiToken is required."
}

# ---------------- MODULE SETUP ----------------
if (-not (Get-Module -ListAvailable -Name Posh-ACME)) {
    Install-Module -Name Posh-ACME -Scope AllUsers -Force
}
Import-Module Posh-ACME -Force

Set-PAServer LE_PROD

# ---------------- PREP ----------------
if (!(Test-Path $ExportPath)) {
    New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
}

Write-Host "`n=== Let's Encrypt Wildcard Certificate Manager ===" -ForegroundColor Cyan
Write-Host "Domain: $Domain"
Write-Host "Export: $ExportPath"

# ---------------- CLOUDFLARE ----------------
$cfParams = @{
    CFToken = (ConvertTo-SecureString $CloudflareApiToken -AsPlainText -Force)
}

$secPfxPassword = ConvertTo-SecureString $PfxPassword -AsPlainText -Force

# ---------------- ISSUE / RENEW ----------------
$existingCert = Get-PACertificate -MainDomain $Domain -ErrorAction SilentlyContinue

if ($existingCert -and (($existingCert.NotAfter - (Get-Date)).Days -gt $RenewWithinDays)) {
    Write-Host "Certificate still valid, skipping renewal." -ForegroundColor Green
    $cert = $existingCert
}
elseif ($existingCert) {
    Write-Host "Renewing certificate..." -ForegroundColor Yellow
    $cert = Submit-Renewal -MainDomain $Domain -PluginArgs $cfParams -PfxPass $secPfxPassword -Force
}
else {
    Write-Host "Requesting new certificate..." -ForegroundColor Yellow
    $cert = New-PACertificate $Domain `
        -Contact $Email `
        -DnsPlugin Cloudflare `
        -PluginArgs $cfParams `
        -PfxPass $secPfxPassword `
        -AcceptTOS
}

if (-not $cert) {
    throw "Certificate issuance failed."
}

# ---------------- OPENSSL AUTO INSTALL ----------------
$opensslPath = "C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

function Install-OpenSSL {
    Write-Host "Installing OpenSSL..." -ForegroundColor Yellow

    $url = "https://slproweb.com/download/Win64OpenSSL_Light-3_5_6.exe"
    $installer = "$env:TEMP\openssl.exe"

    Invoke-WebRequest -Uri $url -OutFile $installer
    Start-Process $installer -ArgumentList "/silent /verysilent /norestart" -Wait
    Remove-Item $installer -Force -ErrorAction SilentlyContinue
}

if (!(Test-Path $opensslPath)) {
    Install-OpenSSL
    if (!(Test-Path $opensslPath)) {
        throw "OpenSSL installation failed."
    }
}

$openssl = $opensslPath
Write-Host "OpenSSL ready." -ForegroundColor Green

# ---------------- FILE PATHS ----------------
$pemCert  = Join-Path $ExportPath "cert.pem"
$pemChain = Join-Path $ExportPath "chain.pem"
$pemKey   = Join-Path $ExportPath "key.pem"
$pfxClean = Join-Path $ExportPath "wildcard.pfx"

# ---------------- EXPORT PEM ----------------
Copy-Item $cert.CertFile  $pemCert  -Force
Copy-Item $cert.ChainFile $pemChain -Force
Copy-Item $cert.KeyFile   $pemKey   -Force

Write-Host "PEM exported." -ForegroundColor Green

# ---------------- BUILD CLEAN PFX ----------------
Write-Host "Building clean PFX..." -ForegroundColor Yellow

$args = @(
    "pkcs12",
    "-export",
    "-out", "`"$pfxClean`"",
    "-inkey", "`"$pemKey`"",
    "-in", "`"$pemCert`"",
    "-certfile", "`"$pemChain`"",
    "-passout", "pass:$PfxPassword"
)

$proc = Start-Process -FilePath $openssl -ArgumentList $args -Wait -NoNewWindow -PassThru

if ($proc.ExitCode -ne 0 -or !(Test-Path $pfxClean)) {
    throw "PFX creation failed."
}

Write-Host "Clean PFX created." -ForegroundColor Green

# ---------------- INSTALL CERT ----------------
Write-Host "Installing certificate..." -ForegroundColor Yellow

$securePass = ConvertTo-SecureString $PfxPassword -AsPlainText -Force

$installed = Import-PfxCertificate `
    -FilePath $pfxClean `
    -CertStoreLocation Cert:\LocalMachine\My `
    -Password $securePass `
    -Exportable

if (-not $installed) {
    throw "Certificate installation failed."
}

Write-Host "Installed successfully!" -ForegroundColor Green

# ---------------- FINAL EXPORT (OPTIONAL BACKUP) ----------------
$pfxBackup = Join-Path $ExportPath "wildcard_backup.pfx"

Export-PfxCertificate `
    -Cert $installed `
    -FilePath $pfxBackup `
    -Password $securePass -Force | Out-Null

# ---------------- SUMMARY ----------------
Write-Host "`n=== CERT READY ===" -ForegroundColor Cyan
Write-Host "Subject    : $($installed.Subject)"
Write-Host "Expires    : $($installed.NotAfter)"
Write-Host "Thumbprint : $($installed.Thumbprint)"
Write-Host "PFX        : $pfxClean"

$installed.Thumbprint | Set-Clipboard
Write-Host "`nThumbprint copied to clipboard."
