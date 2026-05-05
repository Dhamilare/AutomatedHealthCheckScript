
---

# Infrastructure Automation & SSL Lifecycle Scripts

This repository contains a suite of PowerShell automation tools designed to manage Microsoft 365 tenants, on-premises Windows Server infrastructure, and automated Wildcard SSL lifecycles.

## 1. M365HC_v2.ps1 (Microsoft 365 & Entra ID Health Check)

### **Overview**
A comprehensive auditing tool that connects to Microsoft 365 and Entra ID to produce a branded, color-coded HTML health report. It utilizes **Certificate-Based Authentication (CBA)**, ensuring that no plain-text passwords or client secrets are stored on the host server.

### **Key Features**
* **Security Audit:** Checks SPF, DKIM, and DMARC records, MFA registration status, and identifies risky user sign-ins.
* **Identity Governance:** Monitors privileged role assignments, inactive accounts (90 days), and Security Defaults.
* **Optimization:** Flags "license waste" by finding licensed users who are currently disabled.
* **Automated Delivery:** Sends the final report via Microsoft Graph API to configured IT recipients.

---

## 2. AHC.ps1 (Automated Hybrid Health Check)

### **Overview**
A dynamic discovery script that audits all Windows Servers joined to an Active Directory domain. It is "role-aware," automatically adjusting its check set if a server is identified as a Domain Controller.

### **Key Features**
* **Infrastructure Vitals:** Monitors CPU, Memory, and Disk usage across the server fleet.
* **Active Directory Health:** Performs DCDIAG tests, monitors SYSVOL/NETLOGON shares, and checks replication status.
* **Compliance Tracking:** Audits privileged group memberships (Domain/Enterprise Admins) and validates Domain Password Policies.
* **Event Log Intelligence:** Parses System and Application logs for critical errors from the last 24 hours.

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
* **PowerShell 5.1+:** Required for all scripts.
* **Modules:** `ExchangeOnlineManagement` (v3.5.1), `ActiveDirectory` RSAT, and `Posh-ACME` for SSL automation.
* **Azure App Registration:** Required for M365 and Hybrid scripts to deliver reports via Graph API.

### **Automation**
It is recommended to deploy these scripts as **Scheduled Tasks**:
* **M365HC:** Run daily to monitor tenant security posture.
* **AHC:** Run during off-peak hours to capture infrastructure status.
* **SSL Automation:** Run daily to handle automatic renewals before the 90-day expiration.

> [cite_start]**Security Note:** Sensitive configuration is stored as machine-level environment variables to keep the script files clean of credentials. Ensure NTFS permissions restrict access to these scripts to only the Service Account and Domain Admins.