
---

# Infrastructure Automation & SSL Lifecycle Scripts

This repository contains a suite of PowerShell automation tools designed to manage Microsoft 365 tenants, on-premises Windows Server infrastructure, and automated Wildcard SSL lifecycles.

## 1. M365HC_v2.ps1 (Microsoft 365 & Entra ID Health Check)

### **Overview**
[cite_start]A comprehensive auditing tool that connects to Microsoft 365 and Entra ID to produce a branded, color-coded HTML health report[cite: 80, 87]. [cite_start]It utilizes **Certificate-Based Authentication (CBA)**, ensuring that no plain-text passwords or client secrets are stored on the host server[cite: 134, 135].

### **Key Features**
* [cite_start]**Security Audit:** Checks SPF, DKIM, and DMARC records, MFA registration status, and identifies risky user sign-ins[cite: 91, 297].
* [cite_start]**Identity Governance:** Monitors privileged role assignments, inactive accounts (90 days), and Security Defaults[cite: 91, 291].
* [cite_start]**Optimization:** Flags "license waste" by finding licensed users who are currently disabled[cite: 289].
* [cite_start]**Automated Delivery:** Sends the final report via Microsoft Graph API to configured IT recipients[cite: 81, 276].

---

## 2. AHC.ps1 (Automated Hybrid Health Check)

### **Overview**
[cite_start]A dynamic discovery script that audits all Windows Servers joined to an Active Directory domain[cite: 474, 477]. [cite_start]It is "role-aware," automatically adjusting its check set if a server is identified as a Domain Controller[cite: 543].

### **Key Features**
* [cite_start]**Infrastructure Vitals:** Monitors CPU, Memory, and Disk usage across the server fleet[cite: 545].
* [cite_start]**Active Directory Health:** Performs DCDIAG tests, monitors SYSVOL/NETLOGON shares, and checks replication status[cite: 547].
* [cite_start]**Compliance Tracking:** Audits privileged group memberships (Domain/Enterprise Admins) and validates Domain Password Policies[cite: 549].
* [cite_start]**Event Log Intelligence:** Parses System and Application logs for critical errors from the last 24 hours[cite: 545, 547].

---

## 3. Wildcard SSL Automation (Let’s Encrypt + Cloudflare)

### **Overview**
Automates the issuance and renewal of wildcard SSL certificates (`*.domain.com`) using Let's Encrypt DNS validation via the Cloudflare API. This script ensures that certificates remain valid without manual intervention.

### **Key Features**
* **Cloudflare Integration:** Handles DNS-01 challenges automatically via API tokens.
* **Format Flexibility:** Supports both PEM and PFX export for various web server requirements.
* **Certificate Store Integration:** Automatically installs renewed certificates into the Windows Certificate Store.
* **OpenSSL Fallback:** Includes support for OpenSSL to ensure compatibility during the conversion process.

### **Environment Variables**
Before running, ensure the following machine-level variables are set:
* `CLOUDFLARE_API_TOKEN`: Your Cloudflare API token with DNS edit permissions.
* `M365_PFX_PASSWORD`: The password used to encrypt the exported PFX files.

---

## Deployment & Setup

### **Common Prerequisites**
* [cite_start]**PowerShell 5.1+:** Required for all scripts[cite: 99, 490].
* [cite_start]**Modules:** `ExchangeOnlineManagement` (v3.5.1) [cite: 99][cite_start], `ActiveDirectory` RSAT[cite: 490, 509], and `Posh-ACME` for SSL automation.
* [cite_start]**Azure App Registration:** Required for M365 and Hybrid scripts to deliver reports via Graph API[cite: 101, 494, 572].

### **Automation**
[cite_start]It is recommended to deploy these scripts as **Scheduled Tasks**[cite: 211, 482]:
* [cite_start]**M365HC:** Run daily to monitor tenant security posture[cite: 226].
* [cite_start]**AHC:** Run during off-peak hours to capture infrastructure status[cite: 525].
* **SSL Automation:** Run daily to handle automatic renewals before the 90-day expiration.

> [cite_start]**Security Note:** Sensitive configuration is stored as machine-level environment variables to keep the script files clean of credentials[cite: 173, 175]. [cite_start]Ensure NTFS permissions restrict access to these scripts to only the Service Account and Domain Admins[cite: 347, 611].