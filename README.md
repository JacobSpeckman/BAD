# Blessing

---
## Scripts 
---

# Active Directory Audit Scripts

## Overview

This repository (or package) contains PowerShell scripts to **automate** a comprehensive **Active Directory (AD) audit**. It includes functions for:

- **Domain & Forest Inventory**: Gathers information about domain controllers, DNS, sites, and replication.  
- **Security & Privileged Access Reviews**: Checks memberships of highly-privileged groups and delegated permissions.  
- **Group Policy**: Retrieves GPO reports, security permissions, and any logon/logoff scripts.  
- **Event Log Collection**: Collects critical Security events from all domain controllers.  
- **Cleanup & Visibility**: Identifies stale user/computer accounts, reviews password policy, etc.

## Contents

1. **ADAuditTools.ps1**  
   - A **helper module** of PowerShell functions for data collection and analysis.  
   - Includes functions like:
     - **Get-ADDomainInfo**, **Get-ADDomainControllersInfo**, **Get-PrivilegedGroupMembers**, etc.
     - **Get-GPOSecurityPermissions**, **Get-GPOLogonLogoffScripts**, **Collect-DCEventLogs**, **Get-DelegatedOUPermissions**, and more.

2. **Run-ADAudit.ps1**  
   - The **main script** that imports (or dot-sources) `ADAuditTools.ps1` and orchestrates the audit.  
   - Provides **parameters** for the output directory, time range for event log collection, and event IDs of interest.  
   - Exports results (CSV, HTML, TXT) to a specified folder.

## Requirements

- **Windows PowerShell 5.1** or **PowerShell 7+** on a machine with:
  - **ActiveDirectory** and **GroupPolicy** modules installed (available via RSAT or on domain controllers).
  - Sufficient privileges to collect the needed data (often requires **Domain Admin** or equivalent delegated rights).
- **DNS / WMI** modules or permissions (if collecting DNS-related info via WMI).
- **Network Connectivity** to all domain controllers (for event log collection).

## Usage

1. **Copy or Clone the Scripts**  
   - Place `ADAuditTools.ps1` and `Run-ADAudit.ps1` into a folder, e.g. `C:\Scripts\`.

2. **Adjust the Scripts** (Optional)  
   - Update paths or naming conventions to suit your environment.  
   - If you store `ADAuditTools.ps1` in a different location, edit the path in `Run-ADAudit.ps1`.

3. **Open PowerShell** as an Administrator  
   - Ensure you have the necessary AD privileges.

4. **Set Execution Policy** (if needed)  
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope Process
   ```

5. **Run the Main Script**  
   ```powershell
   cd C:\Scripts
   .\Run-ADAudit.ps1 -ReportPath "C:\AD_Audit_Reports" -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date) -EventIds 4624,4625,4768
   ```
   - **Parameters**:  
     - **ReportPath**: Where all output files (CSV, HTML, TXT) will be stored.  
     - **StartTime / EndTime**: Time range for **Collect-DCEventLogs**.  
     - **EventIds**: Which event IDs to capture from the DC Security logs.

6. **Review the Output**  
   - Navigate to the `ReportPath` directory (e.g. `C:\AD_Audit_Reports`) to find:  
     - **DomainInfo.csv**, **DomainControllers.csv**, **DNSZones.csv**, etc.  
     - **PrivilegedGroups.csv**, **GPO_LogonLogoffScripts.csv**, **GPO_SecurityPermissions.csv**, etc.  
     - **DC_SecurityEvents.csv** (Security logs from all DCs).  
     - A **GPO report** in HTML or XML.

## Typical Audit Flow

1. **Inventory & Discovery**  
   - Enumerate domain controllers, sites, DNS zones, privileged groups, service accounts.  
   - Identify stale accounts and gather domain policy information.

2. **Security Reviews**  
   - Check who can edit or link GPOs, and which groups have **delegated** permissions on OUs.  
   - Evaluate **Kerberos** settings, domain password policies, and event logs.

3. **Reporting & Remediation**  
   - Use CSV/HTML reports for analysis.  
   - Identify high-risk findings (e.g., unknown accounts in Domain Admins, outdated DC OS).  
   - Develop a remediation plan (disable stale accounts, reduce broad delegations, enforce password complexity, etc.).

4. **Follow-up**  
   - Implement corrections and run subsequent audits (monthly, quarterly, etc.) to ensure continued compliance.

## Known Limitations

- **Performance**: Collecting large event logs from multiple DCs over a long date range can produce huge output. Adjust the **time span** or filter **EventIds** accordingly.  
- **Permissions**: Some functions (DNS or ACL checks) may fail if your account doesn’t have the required rights.  
- **Large Environments**: Very large AD deployments may need additional **filtering** or **segmentation** to avoid timeouts and to optimize the performance of the scripts.

## Security Considerations

- **Protect the Output**: Many CSV/HTML files contain sensitive data (e.g., account names, group memberships, ACLs). Store them securely and restrict access.  
- **Minimal Privileges**: Run the scripts with the **least-privileged** account that can still gather the required data (though Domain Admin privileges are typically easiest).

## Extending the Scripts

- **SIEM Integration**: Forward CSV or events to Splunk, Azure Sentinel, etc., for advanced analysis.  
- **Custom Filters**: Modify or add new functions to target specific OUs, specific groups, or specialized compliance checks.  
- **Cleanup Automation**: Integrate with automation to **disable** or **remove** stale accounts, or **remediate** misconfigured ACLs automatically.

## Contributing

If you have suggestions, improvements, or bug fixes:

1. Fork or copy the scripts.  
2. Make your changes.  
3. Submit a pull request (if on GitHub) or share your code with the team.

## License

GNU GENERAL PUBLIC LICENSE Version 3

---



---

## Overview

**AD_Cleanup.ps1** is a PowerShell script that helps you **identify** and **clean up** stale user and computer accounts in Active Directory. You can:

- Run it in **dry-run mode** (`-DryRun`) to **report only** (no changes).  
- Choose to **disable** or **remove** stale accounts (e.g., those inactive for 90+ days).  

Removing obsolete accounts enhances security by **reducing the attack surface** and simplifying AD maintenance.

---

## Features

1. **Stale Account Detection**  
   - Uses `Search-ADAccount` to find users and computers that have been **inactive** for a specified number of days.  
2. **Selective Cleanup**  
   - **Disable** old accounts or **remove** them entirely—your choice.  
3. **Dry Run Mode**  
   - Outputs CSV lists of stale accounts **without** making changes (`-DryRun`).  
4. **CSV Logging**  
   - Always exports results to CSV before any changes, so you can review the target accounts.  
5. **Safe Defaults**  
   - Defaults to **90 days** inactivity and logs to `C:\AD_Cleanup_Logs`.  

---

## Requirements

- **Windows PowerShell** (5.1 or higher)  
- **ActiveDirectory** module (e.g., via RSAT or installed on a Domain Controller)  
- Permissions to query, disable, and/or remove accounts (e.g., **Domain Admin** or delegated AD privileges).

---

## Script Parameters

```plaintext
- InactiveDays <int>
  Number of days to consider an account "inactive". Default: 90

- DisableAccounts
  If present, disables accounts identified as stale.

- RemoveAccounts
  If present, removes accounts identified as stale (permanent!).

- DryRun
  If present, only exports stale accounts to CSV without making changes.

- LogPath <string>
  Path where CSV logs are saved (default: C:\AD_Cleanup_Logs).
```

> **Important**: If `-DryRun` is used, the script **ignores** `-DisableAccounts` and `-RemoveAccounts`. No changes are made.

---

## Usage Examples

1. **Dry Run Only (No Changes)**  
   ```powershell
   .\AD_Cleanup.ps1 -InactiveDays 60 -DryRun
   ```
   - Lists user/computer accounts inactive for **60 days**.  
   - Exports results to CSV in `C:\AD_Cleanup_Logs`.  
   - **No** accounts are modified or removed.

2. **Disable Stale Accounts**  
   ```powershell
   .\AD_Cleanup.ps1 -InactiveDays 90 -DisableAccounts
   ```
   - Exports stale accounts (inactive for 90 days) to CSV.  
   - **Disables** each stale account.  

3. **Remove Stale Accounts**  
   ```powershell
   .\AD_Cleanup.ps1 -InactiveDays 180 -RemoveAccounts
   ```
   - Exports stale accounts (inactive for 180 days) to CSV.  
   - **Permanently removes** each stale account.

4. **Combined Switches (But `-DryRun` Overrides)**  
   ```powershell
   .\AD_Cleanup.ps1 -InactiveDays 120 -DisableAccounts -RemoveAccounts -DryRun
   ```
   - **Exports** to CSV but makes **no** changes, because `-DryRun` overrides other cleanup switches.

---

## Process Overview

1. **Run Script** with your chosen parameters.  
2. **Script Exports** stale user/computer lists to CSV (`StaleUsers_*.csv`, `StaleComputers_*.csv`) in the specified or default log path.  
3. If **`-DryRun`** is **not** used and you specify either `-DisableAccounts` or `-RemoveAccounts`, the script:  
   - **Disables** accounts if `-DisableAccounts` is present.  
   - **Removes** accounts if `-RemoveAccounts` is present.  
4. **Review** final console output and CSV logs.  

---

## Best Practices & Warnings

1. **Test in a Lab**  
   - Always test in a **non-production environment** first, especially if you plan to remove accounts.

2. **Two-Phase Approach**  
   - **Disable** accounts first; observe for any negative impact.  
   - If safe after a grace period, **remove** them permanently.

3. **Review CSV Output**  
   - **Before** running in destructive mode, open the CSV files to ensure no important or service accounts are being flagged as stale.

4. **Backups & Recycle Bin**  
   - Enable **AD Recycle Bin** or maintain domain **backups** to recover accidentally deleted accounts.  
   - Removing accounts is **permanent** if Recycle Bin is not enabled or if the tombstone lifetime is exceeded.

5. **Secure the Logs**  
   - Stale account logs can still contain sensitive information (e.g., SamAccountName, DistinguishedName).  
   - Restrict permissions on the `LogPath` folder.

6. **Adjust `InactiveDays`**  
   - Different organizations have different policies (e.g., 30, 60, 90, or 180 days).  
   - Select a threshold that balances security with operational continuity.

---

## Example Run

```powershell
PS C:\Scripts> .\AD_Cleanup.ps1 -InactiveDays 90 -DisableAccounts

=== Starting AD Cleanup (InactiveDays: 90) ===
Stale user accounts exported to: C:\AD_Cleanup_Logs\StaleUsers_20250214-120001.csv
Stale computer accounts exported to: C:\AD_Cleanup_Logs\StaleComputers_20250214-120001.csv

Disabling stale accounts...
Disabled user: olduser
Disabled user: testuser
Disabled computer: TESTPC$
=== AD Cleanup Script Complete ===
```

---

## Version History

- **1.0**: Initial script  
- **1.1**: Added `-DryRun` functionality to safely review stale objects.  
- **1.2**: Updated to use **DistinguishedName** with AD cmdlets for reliable identification.

---

---

### Questions?

If you have any questions or issues:

- Check your **PowerShell** version, **ActiveDirectory** module installation, and **user permissions**.  
- Contact your **AD administrators** or open an **issue** in your internal repository if applicable.  

