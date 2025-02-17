# Example Output from `Run-ADAudit.ps1` (with Security Context)

## Folder Structure

If your **`-ReportPath`** was `C:\AD_Audit_Reports`, you might see something like:

```
C:\AD_Audit_Reports
│   AuditPolicy.txt
│   DC_SecurityEvents.csv
│   DNSZones.csv
│   DomainControllers.csv
│   DomainInfo.csv
│   DomainPasswordPolicy.csv
│   gMSA_Accounts.csv
│   GPO_LogonLogoffScripts.csv
│   GPO_SecurityPermissions.csv
│   AllGPOs.HTML
│   KerberosPolicy.csv
│   OU_DelegatedPermissions.csv
│   PrivilegedGroups.csv
│   Sites.csv
│   SiteLinks.csv
│   Connections.csv
│   StaleUsers.csv
│   StaleComputers.csv
│   UserServiceAccounts.csv
│  

...
```
---
**Note:** File names can vary based on your script or naming preferences.

---

## Sample Files & Snippets

Below are **partial** snippets from some of the CSV, HTML, and TXT files. In a real scenario, you might have **hundreds** or **thousands** of rows.

---

### `DomainInfo.csv`

```csv
"DomainName","DomainMode","ForestName","ForestMode","PDCEmulator","RidMaster","InfrastructureMaster","DomainNamingMaster","SchemaMaster"
"example.local","Win2016Domain","example.local","Win2016Forest","DC1.example.local","DC1.example.local","DC2.example.local","DC1.example.local","DC1.example.local"
```

**Explanation**  
- Shows domain/forest functional levels and **FSMO** roles (PDC, RID, etc.).

**Why it matters for security**  
- **Functional levels** determine the **available security features** (e.g., modern cryptography).  
- **FSMO role holders** (PDC, RidMaster, etc.) are **critical** for domain operations; attackers often target these servers first.

---

### `DomainControllers.csv`

```csv
"Hostname","Forest","Domain","Site","IPv4Address","IsGlobalCatalog","IsReadOnly","OperatingSystem","OperatingSystemVersion"
"DC1","example.local","example.local","Default-First-Site-Name","192.168.10.10","True","False","Windows Server 2019 Standard","10.0 (17763)"
"DC2","example.local","example.local","Default-First-Site-Name","192.168.10.11","False","False","Windows Server 2019 Standard","10.0 (17763)"
```

**Explanation**  
- Lists each DC with **IP**, **OS version**, **Global Catalog** status, and **site** info.

**Why it matters for security**  
- Knowing **which servers are DCs** helps you ensure they’re properly **patched** and **hardened**.  
- Identifying **Read-Only DCs** (RODC) is crucial to confirm whether they’re deployed in **less-secure branches**.

---

### `Sites.csv`, `SiteLinks.csv`, `Connections.csv`

- **Sites.csv** snippet:
  ```csv
  "Name","DistinguishedName"
  "Default-First-Site-Name","CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=local"
  ```
- **SiteLinks.csv** snippet:
  ```csv
  "Name","DistinguishedName","Cost","ReplicationFrequencyInSeconds"
  "DEFAULTIPSITELINK","CN=DEFAULTIPSITELINK,CN=Sites,CN=Configuration,DC=example,DC=local","100","180"
  ```
- **Connections.csv** snippet:
  ```csv
  "Name","DistinguishedName","Enabled","TransportType"
  "NTDS Connection for DC2","CN=NTDS Settings,CN=DC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=local","True","RPC"
  ```

**Explanation**  
- Describes **AD Sites**, **Site Links**, and **Replication** connections.

**Why it matters for security**  
- Improper **site/replication** configurations can lead to **delayed security updates** or **stale data** across DCs.  
- Attackers can exploit **weak replication** or misconfigurations to remain **undetected**.

---

### `DNSZones.csv`

```csv
"Name","ZoneType","DsIntegrated","IsReverseZone"
"example.local","1","True","False"
"10.in-addr.arpa","1","True","True"
```

**Explanation**  
- Shows forward and reverse **DNS zones**, plus integration type (DS integrated or not).

**Why it matters for security**  
- **DS-integrated** zones support **secure dynamic updates**, reducing DNS spoofing.  
- Misconfigured or **non-secure** DNS zones can allow attackers to **poison** DNS or redirect traffic.

---

### `PrivilegedGroups.csv`

```csv
"GroupName","Members"
"Domain Admins","Administrator; JohnSmith; JaneDoe"
"Enterprise Admins","Administrator; EAUser"
"Schema Admins","(none)"
"Administrators","Administrator; Domain Admins; Backup Operators"
"Server Operators","(none)"
"Account Operators","(none)"
"Backup Operators","BackupOpUser"
```

**Explanation**  
- Enumerates memberships (including nested expansions) for **high-privilege groups**.

**Why it matters for security**  
- Privileged groups (e.g., **Domain Admins**) are often **primary targets** for lateral movement and escalation.  
- Ensuring **only** authorized users remain in these groups is crucial for **least privilege**.

---

### `gMSA_Accounts.csv`

```csv
"Name","SamAccountName","DNSHostName","ServicePrincipalNames"
"gmsa-WebApp","gmsa-WebApp$","gmsa-WebApp.example.local","{HTTP/webapp.example.local}"
"gmsa-SQL","gmsa-SQL$","gmsa-SQL.example.local","{MSSQLSvc/sqlserver.example.local}"
```

**Explanation**  
- Lists **Group Managed Service Accounts** (gMSA).

**Why it matters for security**  
- gMSAs eliminate the need for **manual password management**; they’re more secure than traditional service accounts if properly used.  
- Incorrect usage or **over-privileging** can still pose risks.

---

### `UserServiceAccounts.csv`

```csv
"Name","SamAccountName","ServicePrincipalName","Enabled"
"svc_Backup","svc_Backup","{HOST/backupserver.example.local}","True"
"svc_AppPool","svc_AppPool","{}","True"
```

**Explanation**  
- Shows **user-based** service accounts (often filtered by a naming convention like `"svc_*"`).

**Why it matters for security**  
- Human-managed service accounts often have **non-expiring passwords**.  
- Attackers target these accounts to gain **persistent** or **privileged** access.

---

### `AllGPOs.HTML`

- This file is an **HTML** report listing all GPOs and their settings.
- Open it in a web browser for a **detailed** breakdown of **GPO configurations**.

**Why it matters for security**  
- GPOs define **password policies**, **audit settings**, **restrictive policies**, etc.  
- Overly broad or **misconfigured** GPOs can undermine an otherwise secure environment.

---

### `StaleUsers.csv` / `StaleComputers.csv`

```csv
"DistinguishedName","Enabled","LastLogonDate"
"CN=SusanInactive,OU=Users,DC=example,DC=local","True","02/14/2022 08:30:00"
"CN=JohnNoLogin,OU=Users,DC=example,DC=local","False",""
```

**Explanation**  
- Displays accounts (users or computers) that haven’t logged in within a certain timeframe (e.g., 90 days).

**Why it matters for security**  
- **Inactive** or **stale** accounts are prime targets for attackers (easy to compromise without detection).  
- Regularly disabling or removing them helps **reduce attack surface**.

---

### `DomainPasswordPolicy.csv`

```csv
"ComplexityEnabled","LockoutDuration","LockoutObservationWindow","LockoutThreshold","MaxPasswordAge","MinPasswordAge","MinPasswordLength","ReversibleEncryptionEnabled"
"True","00:30:00","00:30:00","5","42.00:00:00","1.00:00:00","12","False"
```

**Explanation**  
- Captures your **Default Domain Policy** password settings.

**Why it matters for security**  
- A strong **password policy** (complexity, length, lockouts) is essential to **prevent brute force** and **weak password** attacks.  
- Checking `ReversibleEncryptionEnabled` helps avoid **plaintext** or easily cracked password storage.

---

### `KerberosPolicy.csv`

```csv
"Setting","Value"
"MaxTicketAge","10"
"MaxRenewAge","7"
"MaxServiceAge","600"
"MaxClockSkew","5"
"DefaultEncryptionType","0"
```

**Explanation**  
- Example registry or GPO-based Kerberos settings (time in days, hours, or minutes).

**Why it matters for security**  
- Proper Kerberos settings help **prevent ticket reuse** and reduce **authentication attacks** (e.g., pass-the-ticket, golden ticket).  
- **MaxTicketAge** and **MaxRenewAge** limit how long a ticket remains valid.

---

### `AuditPolicy.txt`

```
System Audit Policy
Category/Subcategory                      Setting
-------------------------------------     -------------------------------------------
Account Logon/Credentials Validation     Success and Failure
Account Management/User Account Control  Success and Failure
Logon/Logoff/Logon                       Success and Failure
...
```

**Explanation**  
- The **raw output** from `auditpol /get /category:*`, detailing logon, account management, and system audit settings.

**Why it matters for security**  
- Proper **audit policy** helps detect **failed logons**, **privilege use**, and **unauthorized access** attempts.  
- Without auditing, suspicious activities or **breach indicators** can go unnoticed.

---

### `GPO_SecurityPermissions.csv`

```csv
"GPOName","GPOId","Trustee","PermissionLevel"
"Default Domain Policy","{31B2F340-016D-11D2-945F-00C04FB984F9}","EXAMPLE\Domain Admins","GpoEdit"
"Default Domain Policy","{31B2F340-016D-11D2-945F-00C04FB984F9}","NT AUTHORITY\Authenticated Users","GpoApply"
"PasswordPolicy GPO","{A2F3C37B-D5AE-4B81-BD88-AC45FC976538}","EXAMPLE\SecurityTeam","GpoEdit"
```

**Explanation**  
- Shows **which accounts/groups** have **Apply**, **Edit**, or other permissions on each GPO.

**Why it matters for security**  
- Anyone who can **edit** a GPO can push **malicious policies** or **scripts** across the domain.  
- **Limit GPO editing** to a small set of trusted admins.

---

### `GPO_LogonLogoffScripts.csv`

```csv
"GPOName","GPOId","ScriptType","ScriptPath","Parameters"
"Logon Script GPO","{12B345CD-12AB-12A3-A12B-12AA12B12345}","Logon","\\example.local\SysVol\example.local\Scripts\logon.ps1",""
"ShutdownPolicy","{ABCDEF12-3456-7890-ABCD-EF1234567890}","Shutdown","\\example.local\SysVol\example.local\Scripts\shutdown.bat","/silent"
```

**Explanation**  
- Lists **logon/logoff** or **startup/shutdown** scripts defined in various GPOs.

**Why it matters for security**  
- Attackers may **inject** malicious code into **logon scripts**.  
- Knowing these scripts exist allows you to **audit** or **secure** the paths and the code.

---

### `DC_SecurityEvents.csv`

> **Note:** This can be **very large** if you collect many events or have multiple domain controllers.

```csv
"DomainController","EventId","TimeCreated","Message"
"DC1.example.local","4624","3/1/2025 8:04:27 AM","An account was successfully logged on..."
"DC2.example.local","4625","3/1/2025 8:05:10 AM","An account failed to log on..."
"DC2.example.local","4768","3/1/2025 8:10:48 AM","A Kerberos authentication ticket (TGT) was requested..."
```

**Explanation**  
- Captures **Windows Security** event logs from each DC, filtered by **Event IDs** and time range.

**Why it matters for security**  
- Reviewing **failed logons**, **lockouts**, and **Kerberos requests** can reveal **brute force** or **suspicious** activity.  
- Security events are **essential** for **incident detection** and **forensic analysis**.

---

### `OU_DelegatedPermissions.csv`

```csv
"OU","OUDN","IdentityReference","AccessControlType","ActiveDirectoryRights","InheritanceType","InheritedObjectType","ObjectType"
"Workstations","OU=Workstations,DC=example,DC=local","EXAMPLE\\HelpDeskGroup","Allow","ReadProperty, WriteProperty","All","00000000-0000-0000-0000-000000000000","00000000-0000-0000-0000-000000000000"
"ServiceAccounts","OU=ServiceAccounts,DC=example,DC=local","EXAMPLE\\SvcTeam","Allow","WriteProperty","All","00000000-0000-0000-0000-000000000000","00000000-0000-0000-0000-000000000000"
```

**Explanation**  
- Shows **OU ACLs**—which groups/users can modify objects or reset passwords in each OU.

**Why it matters for security**  
- **Overly broad** or **misconfigured** OU delegations can let unauthorized staff **escalate privileges** or **expose** sensitive data.  
- Checking these delegations ensures **least privilege** principles are maintained.

---

## Next Steps for Analysis

1. **Open CSV files** in Excel or another CSV-friendly tool for sorting and filtering.  
2. **Review HTML** reports (e.g., `AllGPOs.HTML`) in your web browser for a structured GPO overview.  
3. **Look for anomalies** such as:
   - Unexpected members in **privileged groups**  
   - **Stale accounts** that need disabling or removing  
   - Excessively broad or unknown **delegations** in `OU_DelegatedPermissions.csv`
4. **Remediate** high-risk findings, then re-run the script to confirm changes.  
5. Combine with additional tools (e.g., **Purple Knight** by Semperis, **SIEM** solutions) to **analyze** or **correlate** the raw data.


**Enjoy your automated AD auditing!**
