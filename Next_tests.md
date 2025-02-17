# Active Directory Security Checklist

This checklist provides a structured way to review and harden your **Active Directory** environment. It covers topics such as **forest/domain design**, **privileged accounts**, **GPO hardening**, **logging/monitoring**, and more.

---

## 1. **Forest & Domain Design**

- [ ] **Tiered Administration**  
  - Implement a **tier model** (Tier 0 for domain controllers, Tier 1 for servers, Tier 2 for workstations).  
  - Separate credentials and management tools by tier to limit lateral movement.

- [ ] **Admin Account Separation**  
  - Use **separate** credentials for domain admin tasks, server admin tasks, and everyday workstation logons.  
  - Avoid logging in to untrusted endpoints with domain admin accounts.

- [ ] **Trusts & External Connections**  
  - Audit **external/forest trusts**; remove any not in use.  
  - Where trusts are required, enable **selective authentication** if possible.
     
  - ✅

---

## 2. **Hardening Domain Controllers**

- [ ] **Physical Security**  
  - Keep DCs in **locked**, access-controlled facilities.  
  - Consider full-disk encryption (e.g., **BitLocker**) for domain controller drives.

- [ ] **Minimal Services**  
  - Install **only** required roles (DNS, AD DS) on DCs.  
  - Avoid unnecessary software or services on domain controllers.

- [ ] **Regular Patching**  
  - Maintain a **strict patch schedule** for Windows OS and critical services.  
  - Apply .NET and other updates that can affect DC security.

- [ ] **Network Controls**  
  - Restrict RDP/remote management to a **secure subnet** or **jump server**.  
  - Use Windows Firewall or network ACLs to limit inbound ports to essential AD/DC ports.

---

## 3. **Password & Authentication**

- [ ] **Domain Password Policy**  
  - Ensure **complexity** (e.g., length > 12), **lockout**, and **password history** are enforced.  
  - Consider **fine-grained password policies** for high-privilege accounts.

- [ ] **Managed Service Accounts & LAPS**  
  - Use **gMSAs** where possible to eliminate manual password management.  
  - Deploy **LAPS** (Local Administrator Password Solution) to manage local admin accounts on domain-joined machines.

- [ ] **Kerberos Hardening**  
  - Limit or disable **NTLM** where feasible; ensure at least **NTLMv2** is enforced.  
  - Verify Kerberos ticket lifetime settings align with best practices (e.g., ~10 hours max ticket age).

- [ ] **Privileged Access Workstations (PAW)**  
  - Provide admins with **isolated workstations** for elevated tasks (i.e., no web/email on these devices).  
  - Helps protect admin credentials from malware on standard user endpoints.

---

## 4. **Monitoring & Logging**

- [ ] **SIEM Integration**  
  - Forward critical **Security** logs from DCs to a central SIEM (Splunk, Sentinel, QRadar, etc.).  
  - Correlate events for suspicious patterns (e.g., brute force attempts).

- [ ] **Audit Policies**  
  - Ensure **detailed auditing** for logon events, account management, directory service changes, and object access.  
  - Configure event log sizes to prevent **overwrites** too quickly.

- [ ] **Event Log Review**  
  - Monitor key events: **4624/4625** (logons), **4768/4769** (Kerberos tickets), **4719** (audit policy changes).  
  - Set up alerts for repeated failures or large spikes in events.

- [ ] **Baseline & Anomaly Detection**  
  - Know what “normal” looks like in your environment.  
  - Investigate anomalies, unusual replication traffic, or unknown processes on DCs.

---

## 5. **Hardening Group Policy**

- [ ] **GPO Permissions**  
  - Limit who can **edit** or **link** GPOs (small group of trusted admins).  
  - Check **GPO ACLs** regularly for unexpected trustees.

- [ ] **Security Baselines**  
  - Compare your GPO settings against **Microsoft Security Baselines** or **CIS Benchmarks**.  
  - Enforce **SMB signing**, **LDAP signing**, and disable **SMBv1** if possible.

- [ ] **Script Policies**  
  - Review **logon/logoff**, **startup/shutdown** scripts for suspicious code.  
  - Consider **AppLocker** or **Software Restriction Policies** to control script execution.

- [ ] **GPO Backup & Versioning**  
  - Schedule **regular GPO backups**.  
  - Track changes (version control, or at least store backups offline) to quickly revert if needed.

---

## 6. **DNS Security**

- [ ] **Secure Dynamic Updates**  
  - Configure **DNS zones** to allow only **secure** updates (DS-integrated).  
  - Avoid legacy or unsecured dynamic updates.

- [ ] **DNS Aging & Scavenging**  
  - Enable **DNS scavenging** to remove stale records automatically.  
  - Set appropriate **TTL** values to reduce DNS pollution or outdated entries.

- [ ] **DNSSEC (If Feasible)**  
  - Consider **DNSSEC** for cryptographically securing DNS records.  
  - Requires careful planning and key management.

---

## 7. **PKI & Certificates**

- [ ] **Active Directory Certificate Services (AD CS)**  
  - Harden CA servers similarly to domain controllers (isolation, minimal roles).  
  - Review certificate templates to ensure **least privilege** enrollment rights.

- [ ] **Smart Card / MFA**  
  - Encourage or enforce **multi-factor** authentication for admin accounts.  
  - Explore **Windows Hello for Business** or other certificate-based auth.

---

## 8. **Delegation & RBAC**

- [ ] **Least Privilege Delegation**  
  - Audit **OU delegated permissions** (help desk, junior admins).  
  - Remove “full control” if only “reset password” or “join computers” is needed.

- [ ] **Read-Only Domain Controllers (RODCs)**  
  - Deploy RODCs in remote or high-risk locations.  
  - Limit credential caching on RODCs (only essential accounts).

- [ ] **Just Enough Administration (JEA)**  
  - Use **PowerShell JEA** to provide role-based, minimal cmdlets for certain admin tasks.

---

## 9. **Threat Detection & Attack Surface Analysis**

- [ ] **Attack Path Mapping**  
  - Leverage **BloodHound** to visualize potential lateral movement paths.  
  - Remediate short paths to **Domain Admin** (e.g., via local admin privileges, ACL misconfigurations).

- [ ] **Periodic Security Assessments**  
  - Run **Purple Knight** or similar AD-focused scanners for comprehensive risk checks.  
  - Compare results against your internal security baselines.

- [ ] **Baseline & Vulnerability Scanning**  
  - Use endpoint vulnerability scanners on domain controllers and critical servers.  
  - Look for missing patches or misconfigurations that could lead to escalation.

---

## 10. **Operational Best Practices**

- [ ] **Regular Backups & Recovery Tests**  
  - Perform **system state** backups of all DCs.  
  - Periodically test **authoritative restores** and forest recovery in a lab.

- [ ] **Maintenance of Stale Objects**  
  - Periodically remove or disable **stale user/computer accounts** (use a cleanup script).  
  - Clean out **stale DNS records** to prevent confusion or security holes.

- [ ] **Documentation & Change Control**  
  - Keep **AD design** and **operational docs** updated.  
  - Use a **change management** process for GPO modifications or schema changes.

- [ ] **Plan for Upgrades**  
  - Retire old OS domain controllers (e.g., 2008/2012) that no longer receive security patches.  
  - Increase **domain/forest functional levels** as you decommission older DCs.

---
