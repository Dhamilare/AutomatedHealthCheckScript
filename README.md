
---

# Infrastructure Automation & SSL Lifecycle Scripts

This repository contains a suite of PowerShell automation tools designed to manage Microsoft 365 tenants, on-premises Windows Server infrastructure, and SSL certificate lifecycles.

## 1. M365_HealthReport.ps1 (Microsoft 365 & Entra ID Health Check)

### **Overview**
A comprehensive auditing tool that connects to Microsoft 365 and Entra ID to produce a branded, color-coded HTML health report. It utilizes **Certificate-Based Authentication (CBA)**, ensuring that no plain-text passwords or client secrets are stored on the host server.

### **Key Features**
* **Security Audit:** Checks SPF, DKIM, and DMARC records, MFA registration status, and identifies risky user sign-ins.
* **Identity Governance:** Monitors privileged role assignments, inactive guest accounts, and Security Defaults.
* **Optimization:** Flags "license waste" by finding licensed users who are currently disabled.
* **Automated Delivery:** Sends the final report via Microsoft Graph API to configured IT recipients.

---

## 2. Health_Check_Report.ps1 (Automated Windows Server Health Check)

### **Overview**
A dynamic discovery script that audits all Windows Servers joined to an Active Directory domain. It is "role-aware," meaning it automatically adjusts its check set if a server is identified as a Domain Controller.

### **Key Features**
* **Infrastructure Vitals:** Monitors CPU, Memory, and Disk usage across the entire fleet.
* **Active Directory Health:** Performs DCDIAG tests, monitors SYSVOL/NETLOGON shares, and checks replication status.
* **Compliance Tracking:** Audits privileged group memberships (Domain/Enterprise Admins) and validates Domain Password Policies.
* **Event Log Intelligence:** Parses System and Application logs for critical errors from the last 24 hours.

---

# Wildcard SSL Automation (Let’s Encrypt + Cloudflare)

## Purpose
Automates wildcard SSL certificate issuance and renewal using Let's Encrypt DNS validation via Cloudflare API.

---

## Features
- Automated wildcard certificate issuance (*.domain.com)
- Cloudflare DNS challenge integration
- Automatic renewal handling
- PEM + PFX export
- Windows Certificate Store installation
- OpenSSL fallback for compatibility
- Email notification support (via M365 script integration)

---

## Requirements
- Windows Server / Windows 10+
- PowerShell 5.1 or 7+
- Internet access for ACME + OpenSSL download
- Posh-ACME module

---

## Environment Variables
Set these before running:

```powershell
CLOUDFLARE_API_TOKEN
M365HC_PFX_PASSWORD

---

## Deployment & Setup

### **Common Prerequisites**
* **PowerShell 5.1+:** Required for all scripts.
* **Modules:** `ExchangeOnlineManagement` (v3.5.1) for M365HC and `ActiveDirectory` RSAT for AHC.
* **Azure App Registration:** All three scripts require an App Registration with `Mail.Send` permissions to deliver reports via Graph API.

### **Automation**
It is recommended to deploy these scripts as **Scheduled Tasks** via **Group Policy (GPO)**. 
* **M365HC:** Run daily to monitor tenant security posture.
* **AHC:** Run during off-peak hours (e.g., 06:00 AM) to capture infrastructure status.
* **SSL Automation:** Run daily to check for upcoming certificate expirations.

> **Security Note:** Ensure all sensitive variables (Tenant IDs, Client IDs) are stored as machine-level environment variables rather than hardcoded within the `.ps1` files.

---