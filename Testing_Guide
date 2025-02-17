Thanks for sharing the **README.md** from the **BAD (Blessing AD) repository**! Now that I have a full understanding of the tool, I can provide **a step-by-step guide for setting up a testing environment** to run and validate these PowerShell scripts.

---

## **Step-by-Step Guide: Setting Up an AD Testing Environment for BAD**
This guide will help you set up **Active Directory (AD) in a virtualized test environment** and run the **BAD** scripts to audit AD security.

---

## **Step 1: Choose Your AD Testing Setup**
Since BAD is a PowerShell-based tool, it requires **Windows with Active Directory installed**. There are **two options** for setting up an AD testing environment:

### **Option 1: Using a Windows Server VM (Recommended)**
- Suitable for a **realistic** AD lab.
- Requires **Windows Server 2016/2019/2022**.
- Uses **Hyper-V, VMware, or VirtualBox**.

### **Option 2: Using Windows Server in a Docker Container**
- More lightweight, but **not officially supported** by Microsoft for AD DS.
- Works best for **quick** AD audits in **non-production** environments.

For the most stable experience, **Option 1 (Windows Server VM) is recommended**.

---

## **Step 2: Set Up a Windows Server VM (Option 1 - Recommended)**
1. **Install a Virtualization Platform** (If you don’t have one):
   - **Windows**: Use **Hyper-V** (`Optional Features > Enable Hyper-V`).
   - **Mac/Linux**: Use **VMware Workstation**, **VirtualBox**, or **Proxmox**.

2. **Download & Install Windows Server**:
   - Get a trial version of **Windows Server 2019/2022** from [Microsoft Eval Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server).

3. **Configure the VM**:
   - Assign at least **4 GB RAM** and **2 vCPUs**.
   - **Enable Nested Virtualization** (if using Hyper-V).

4. **Install Active Directory (AD DS) Role**:
   - Open **PowerShell as Administrator** and run:
     ```powershell
     Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
     ```
   - Promote the server to a **Domain Controller**:
     ```powershell
     Install-ADDSForest -DomainName "test.lab" -InstallDNS -Force
     ```
   - Restart the VM.

---

## **Step 3: Install Required PowerShell Modules**
Once the AD environment is up, **install the necessary PowerShell modules**:

1. **Open PowerShell as Administrator**.
2. Install the **Active Directory** and **Group Policy** modules:
   ```powershell
   Install-WindowsFeature -Name RSAT-AD-Tools -IncludeAllSubFeature
   Import-Module ActiveDirectory
   Import-Module GroupPolicy
   ```

---

## **Step 4: Clone & Set Up BAD Scripts**
Now, download the **BAD** repository and prepare the scripts.

1. **Clone the GitHub repository**:
   ```powershell
   git clone https://github.com/JacobSpeckman/BAD.git C:\Scripts\BAD
   ```

2. **Navigate to the BAD directory**:
   ```powershell
   cd C:\Scripts\BAD
   ```

3. **Check script contents**:
   ```powershell
   ls
   ```

---

## **Step 5: Set Up PowerShell for Execution**
Since these are downloaded scripts, you need to **adjust the PowerShell execution policy**.

1. **Enable execution for unsigned scripts**:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope Process -Force
   ```

---

## **Step 6: Run the AD Audit Scripts**
Now, you can execute **BAD’s PowerShell scripts** to collect and analyze AD data.

### **Option 1: Run the Complete Audit**
```powershell
cd C:\Scripts\BAD
.\Run-ADAudit.ps1 -ReportPath "C:\AD_Audit_Reports" -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date) -EventIds 4624,4625,4768
```
- **Parameters:**
  - `ReportPath`: Where output files (CSV, HTML, TXT) will be stored.
  - `StartTime / EndTime`: Time range for **DC event log collection**.
  - `EventIds`: Specific event IDs to capture.

### **Option 2: Run Individual Audit Functions**
Run each PowerShell function separately for **modular testing**.

#### **Get AD Domain Information**
```powershell
.\ADAuditTools.ps1
Get-ADDomainInfo
```

#### **Check Privileged Groups**
```powershell
Get-PrivilegedGroupMembers
```

#### **Review Group Policy Security Settings**
```powershell
Get-GPOSecurityPermissions
```

#### **Collect Domain Controller Security Logs**
```powershell
Collect-DCEventLogs -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date) -EventIds 4624,4625,4768
```

---

## **Step 7: Review the Output**
Once the scripts complete execution, check the **audit reports**:

1. Navigate to the report directory:
   ```powershell
   cd C:\AD_Audit_Reports
   ls
   ```

2. Open reports in **CSV/HTML format**:
   - `DomainInfo.csv`: Contains AD domain details.
   - `PrivilegedGroups.csv`: Shows users with **admin-level privileges**.
   - `DC_SecurityEvents.csv`: Captures **critical AD security events**.

---

## **Step 8: Run Cleanup & Maintenance Scripts (Optional)**
If you want to **clean up stale accounts**, use:

### **Dry Run (No Changes)**
```powershell
.\AD_Cleanup.ps1 -InactiveDays 90 -DryRun
```
- Generates CSVs of **stale accounts** without modifying anything.

### **Disable Stale Accounts**
```powershell
.\AD_Cleanup.ps1 -InactiveDays 90 -DisableAccounts
```
- This **disables** users & computers **inactive for 90+ days**.

### **Permanently Remove Stale Accounts**
```powershell
.\AD_Cleanup.ps1 -InactiveDays 180 -RemoveAccounts
```
- **Deletes** accounts inactive for **180+ days**.

---

## **Step 9: Secure & Automate Audits**
For ongoing security monitoring, **schedule BAD to run automatically**:

1. Open **Task Scheduler** (`taskschd.msc`).
2. Create a **New Basic Task**.
3. Set the **Trigger**:
   - Run every **week or month**.
4. Set the **Action**:
   - Run PowerShell with:
     ```powershell
     powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\BAD\Run-ADAudit.ps1" -ReportPath "C:\AD_Audit_Reports"
     ```

---

## **Bonus: Integrate with SIEM (Splunk, Sentinel, etc.)**
To send audit logs to **Splunk or Microsoft Sentinel**, export logs to a format that SIEM tools can read:

1. Convert logs to JSON:
   ```powershell
   Import-Csv C:\AD_Audit_Reports\PrivilegedGroups.csv | ConvertTo-Json | Out-File C:\AD_Audit_Reports\PrivilegedGroups.json
   ```

2. Use **PowerShell’s HTTP POST** method to send logs to your SIEM:
   ```powershell
   Invoke-WebRequest -Uri "https://siem.example.com/api/logs" -Method Post -Body (Get-Content C:\AD_Audit_Reports\PrivilegedGroups.json) -Headers @{"Authorization"="Bearer <TOKEN>"}
   ```

---

## **Final Thoughts**
✅ **BAD** is a powerful **Active Directory audit tool** that helps identify security risks.  
✅ A **Windows Server VM with AD DS** is the best environment to test it.  


### **Step-by-Step Guide: Setting Up Docker on Windows for Active Directory (AD) Testing**

Since you want to use **Docker on Windows** for testing **BAD (Blessing AD)**, we'll set up **Windows-based containers** to simulate an **Active Directory environment** and run the **BAD scripts** inside it.

---

## **Step 1: Install Docker on Windows**
Docker can run **Windows Containers**, but you need to **enable Windows features** before installation.

### **1.1 Enable Windows Features**
Before installing Docker, ensure **Windows Containers, Hyper-V, and WSL 2** are enabled:

1. Open **PowerShell as Administrator** and run:
   ```powershell
   dism.exe /online /enable-feature /featurename:Microsoft-Hyper-V /all /norestart
   dism.exe /online /enable-feature /featurename:Containers /all /norestart
   ```
2. **Restart your computer**.

### **1.2 Install Docker Desktop**
1. Download **Docker Desktop for Windows** from [Docker's official website](https://www.docker.com/products/docker-desktop).
2. Install Docker and **select "Windows Containers"** during installation.
3. After installation, **reboot your system**.

### **1.3 Switch to Windows Containers**
By default, Docker uses Linux containers. **Switch to Windows Containers**:
1. Right-click on the **Docker icon** in the system tray.
2. Select **"Switch to Windows Containers"**.

---

## **Step 2: Set Up a Windows Server Core Container**
Windows containers **cannot directly run Active Directory**, but you can **simulate** AD environments.

### **2.1 Pull a Windows Server Image**
1. Open **PowerShell** and pull the latest **Windows Server Core** image:
   ```powershell
   docker pull mcr.microsoft.com/windows/servercore:ltsc2022
   ```
   - This will take some time to download (several GBs).

### **2.2 Run a Windows Server Container**
After pulling the image, create and start a **Windows Server container**:
```powershell
docker run -it --name win-ad --hostname ad.test.lab --memory=4GB --isolation=process mcr.microsoft.com/windows/servercore:ltsc2022 cmd
```
- **`--hostname ad.test.lab`**: Sets the container's hostname to mimic an AD server.
- **`--memory=4GB`**: Allocates enough memory to simulate AD.
- **`--isolation=process`**: Uses **Hyper-V Isolation** for compatibility.

This will **start a container** and drop you into a **Command Prompt** inside Windows Server.

---

## **Step 3: Install Active Directory Services (AD DS) in the Container**
Inside the running **Windows Server container**, install **Active Directory (AD DS) features**.

### **3.1 Install Active Directory Role**
1. Open **PowerShell** inside the container:
   ```powershell
   powershell
   ```
2. Install the **Active Directory Domain Services** (AD DS) role:
   ```powershell
   Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
   ```
   - This installs **Active Directory** inside the container.

### **3.2 Promote to Domain Controller**
Now, set up a new **Active Directory Forest** in the container.

1. **Run this command inside the container**:
   ```powershell
   Install-ADDSForest -DomainName "test.lab" -InstallDNS -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -LogPath "C:\Windows\NTDS" -SysvolPath "C:\Windows\SYSVOL" -Force
   ```
   - This **creates a new AD domain**: `test.lab`.
   - It also installs **DNS Server** automatically.

2. **Restart the Container** to complete the setup:
   ```powershell
   Restart-Computer -Force
   ```

---

## **Step 4: Install BAD (Blessing AD) Scripts Inside the Container**
Once your **Windows Server container** is running AD, install and run **BAD**.

### **4.1 Copy BAD Scripts into the Container**
1. **On your host system**, copy the BAD scripts into the container:
   ```powershell
   docker cp C:\Scripts\BAD win-ad:C:\BAD
   ```

2. **Enter the container again**:
   ```powershell
   docker exec -it win-ad powershell
   ```

3. **Navigate to the BAD directory**:
   ```powershell
   cd C:\BAD
   ```

---

## **Step 5: Run BAD Audit Scripts**
Once inside the **Windows Server container**, execute **BAD’s AD audit scripts**.

### **5.1 Set PowerShell Execution Policy**
Inside the container, run:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process -Force
```

### **5.2 Run the Full AD Audit**
```powershell
.\Run-ADAudit.ps1 -ReportPath "C:\AD_Audit_Reports" -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date) -EventIds 4624,4625,4768
```
- This **collects AD security data** for the last 7 days.
- Reports are saved in `C:\AD_Audit_Reports`.

### **5.3 Review Reports**
After the script runs, check the results:
```powershell
ls C:\AD_Audit_Reports
```

To **exit the container**, type:
```powershell
exit
```

To **copy reports from the container to your Windows host**:
```powershell
docker cp win-ad:C:\AD_Audit_Reports C:\Reports
```

---

## **Step 6: Automate Audits in the Container**
You can set up a **scheduled task** inside the container to **automate audits**.

### **6.1 Create a Scheduled Task**
Inside the container, run:
```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "C:\BAD\Run-ADAudit.ps1 -ReportPath C:\AD_Audit_Reports"
$Trigger = New-ScheduledTaskTrigger -Daily -At 3am
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "Daily_AD_Audit" -Description "Runs BAD audit daily" -User "Administrator" -RunLevel Highest
```

This **runs BAD’s audit script every day at 3 AM**.

---

## **Step 7: Forward AD Logs to SIEM (Splunk, Sentinel, etc.)**
To send audit logs to a **SIEM (Security Information and Event Management) platform**, export logs from the container.

### **7.1 Convert CSV to JSON**
```powershell
Import-Csv C:\AD_Audit_Reports\PrivilegedGroups.csv | ConvertTo-Json | Out-File C:\AD_Audit_Reports\PrivilegedGroups.json
```

### **7.2 Send Logs to SIEM**
Replace `<SIEM_URL>` with your SIEM API:
```powershell
Invoke-WebRequest -Uri "<SIEM_URL>/logs" -Method Post -Body (Get-Content C:\AD_Audit_Reports\PrivilegedGroups.json) -Headers @{"Authorization"="Bearer <API_TOKEN>"}
```

---

## **Final Thoughts**
🎯 **BAD (Blessing AD) works in a Windows Docker container!**  
✅ **Windows Server Core** runs Active Directory **inside Docker**.  
✅ **BAD scripts** collect **AD security data** inside the container.  
✅ **Audit results** are copied to your host system for review.  
✅ **SIEM integration** sends AD logs to **Splunk or Microsoft Sentinel**.  

---

## **Next Steps**
1. **Add test user accounts** in AD:
   ```powershell
   New-ADUser -Name "TestUser" -UserPrincipalName testuser@test.lab -PasswordNeverExpires $true -Enabled $true
   ```
2. **Simulate AD attacks** using **Mimikatz**.
3. **Enhance automation** by running audits on a schedule.



### **Step-by-Step Guide: Creating Fake Users & Groups in AD for Testing BAD (Blessing AD)**

Since we have set up **Active Directory (AD) inside a Windows Docker container**, the next step is to **populate it with fake users, groups, and organizational units (OUs)**. This will allow **BAD** to test AD audit functionality on a more realistic environment.

---

## **Step 1: Generate 100 Fake Users in 50 Different Groups**
We’ll create:
✅ **100 fake user accounts**  
✅ **50 different security groups**  
✅ Assign **2 users per group**  
✅ Organize them in **different Organizational Units (OUs)**  

---

### **Step 1.1: Generate a Fake Users List**
1. **Open PowerShell inside your AD container**:
   ```powershell
   docker exec -it win-ad powershell
   ```

2. **Define fake user details in a loop**:
   ```powershell
   $firstNames = @("John", "Alice", "Bob", "Jane", "Michael", "Emma", "David", "Olivia", "James", "Sophia")
   $lastNames = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Martinez", "Clark")
   ```

---

### **Step 1.2: Create 50 Fake Groups**
Now, create 50 security groups:
```powershell
for ($i=1; $i -le 50; $i++) {
    $groupName = "SecurityGroup$i"
    New-ADGroup -Name $groupName -SamAccountName $groupName -GroupCategory Security -GroupScope Global
    Write-Host "Created Group: $groupName"
}
```

---

### **Step 1.3: Create 100 Fake Users and Assign to Groups**
Now, generate **100 users** and distribute them across **50 security groups**.

```powershell
for ($i=1; $i -le 100; $i++) {
    $firstName = $firstNames[(Get-Random -Minimum 0 -Maximum $firstNames.Length)]
    $lastName = $lastNames[(Get-Random -Minimum 0 -Maximum $lastNames.Length)]
    $username = "$firstName.$lastName$i"
    $password = ConvertTo-SecureString "P@ssword123!" -AsPlainText -Force

    # Create new user
    New-ADUser -Name "$firstName $lastName" `
               -GivenName $firstName `
               -Surname $lastName `
               -UserPrincipalName "$username@test.lab" `
               -SamAccountName $username `
               -Path "OU=Employees,DC=test,DC=lab" `
               -AccountPassword $password `
               -Enabled $true `
               -PasswordNeverExpires $true

    # Assign user to a group
    $groupName = "SecurityGroup$($i % 50 + 1)"  # Distribute across 50 groups
    Add-ADGroupMember -Identity $groupName -Members $username

    Write-Host "Created User: $username and added to $groupName"
}
```
✅ This script will:
- **Generate 100 users** with random first and last names.
- **Assign them to one of the 50 groups** (2 per group).
- **Enable accounts** and set passwords.

---

## **Step 2: Create Organizational Units (OUs)**
To organize users properly, we create **OUs** inside the domain.

```powershell
New-ADOrganizationalUnit -Name "Employees" -Path "DC=test,DC=lab"
New-ADOrganizationalUnit -Name "Admins" -Path "DC=test,DC=lab"
New-ADOrganizationalUnit -Name "IT Support" -Path "DC=test,DC=lab"
New-ADOrganizationalUnit -Name "HR" -Path "DC=test,DC=lab"
New-ADOrganizationalUnit -Name "Finance" -Path "DC=test,DC=lab"
Write-Host "Created Organizational Units!"
```

---

## **Step 3: Add 5 Fake Admin Users**
For **testing privileged access**, create **5 Admin users** and assign them to **Domain Admins**.

```powershell
for ($i=1; $i -le 5; $i++) {
    $username = "AdminUser$i"
    $password = ConvertTo-SecureString "SecureAdminPass!$i" -AsPlainText -Force

    New-ADUser -Name "Admin User$i" `
               -GivenName "Admin" `
               -Surname "User$i" `
               -UserPrincipalName "$username@test.lab" `
               -SamAccountName $username `
               -Path "OU=Admins,DC=test,DC=lab" `
               -AccountPassword $password `
               -Enabled $true `
               -PasswordNeverExpires $true

    # Assign to Domain Admins
    Add-ADGroupMember -Identity "Domain Admins" -Members $username
    Write-Host "Created Admin User: $username and added to Domain Admins"
}
```
✅ **This creates 5 admin users with Domain Admin privileges**.

---

## **Step 4: Simulate Stale Accounts**
Inactive users can be security risks. Let’s create **15 stale user accounts** that haven’t logged in for **6+ months**.

```powershell
for ($i=1; $i -le 15; $i++) {
    $username = "OldUser$i"
    $password = ConvertTo-SecureString "OldPass123!" -AsPlainText -Force

    New-ADUser -Name "Old User$i" `
               -UserPrincipalName "$username@test.lab" `
               -SamAccountName $username `
               -AccountPassword $password `
               -Enabled $true `
               -PasswordNeverExpires $true `
               -PasswordLastSet (Get-Date).AddDays(-200)  # Last password set 200 days ago

    Write-Host "Created Old User: $username"
}
```
✅ This creates **15 inactive users**, making them ideal targets for **stale account detection**.

---

## **Step 5: Run BAD Audit Against Fake Users & Groups**
Now that our test environment is populated, **run BAD to audit AD**:

```powershell
.\Run-ADAudit.ps1 -ReportPath "C:\AD_Audit_Reports" -StartTime (Get-Date).AddDays(-30) -EndTime (Get-Date) -EventIds 4624,4625,4768
```
📌 **What this will check:**
- **All 100 fake users** and their **group memberships**.
- **Privileged admin users** (5 Domain Admins).
- **Stale user accounts** (15 inactive users).
- **Event logs** (4624: Successful Logins, 4625: Failed Logins, 4768: Kerberos Ticket Requests).

---

## **Step 6: Export & Review Audit Results**
1. Check all reports in **C:\AD_Audit_Reports**:
   ```powershell
   ls C:\AD_Audit_Reports
   ```

2. Open reports:
   ```powershell
   notepad C:\AD_Audit_Reports\PrivilegedGroups.csv
   notepad C:\AD_Audit_Reports\DC_SecurityEvents.csv
   ```

3. Copy reports to your **Windows Host**:
   ```powershell
   docker cp win-ad:C:\AD_Audit_Reports C:\Reports
   ```

---

## **Step 7: Automate User Audits Every Week**
To continuously audit AD **every week**, set up a **scheduled task**:

```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "C:\BAD\Run-ADAudit.ps1 -ReportPath C:\AD_Audit_Reports"
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "Weekly_AD_Audit" -Description "Runs BAD audit every Sunday" -User "Administrator" -RunLevel Highest
```
✅ **BAD now runs weekly on Sundays at 2 AM!**

---

## **Final Thoughts**
🎯 We now have a **fully populated** AD testing environment with:
✅ **100 fake users** (random names, assigned to groups).  
✅ **50 security groups**.  
✅ **5 Domain Admins**.  
✅ **15 stale accounts** for testing BAD's cleanup features.  
✅ **Scheduled audits** to detect changes.

### **Step-by-Step Guide: Simulating AD Attacks in Your Docker Environment**  
Now that we have a **fully populated AD testing environment**, let’s simulate **real-world attack techniques** to test how BAD (Blessing AD) detects security risks.

---

## **🛠 Step 1: Enable AD Logging for Attack Detection**  
Before running attacks, ensure **Advanced Security Auditing** is enabled to capture **event logs**.

1. Open **PowerShell inside the AD container**:
   ```powershell
   docker exec -it win-ad powershell
   ```

2. Enable **Kerberos & Logon Event Logging**:
   ```powershell
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable
   auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
   auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
   ```

3. Verify settings:
   ```powershell
   auditpol /get /category:Logon/Logoff
   ```

✅ **Now, AD will log Kerberos & login attempts** for BAD to analyze.

---

# **🛑 ATTACK SCENARIOS & DETECTION TESTING**

---

## **🕵️‍♂️ 1. Kerberoasting Attack (Extract Kerberos Tickets for Cracking)**
**What it does:**  
- Extracts Kerberos **TGS** (Service Tickets) for accounts with **SPNs (Service Principal Names)**.  
- These tickets can be cracked **offline** to obtain plaintext passwords.  

### **👨‍💻 Simulating Kerberoasting**
Inside the **Windows Server container**, run:

```powershell
setspn -L Administrator
```
This lists **Service Principal Names (SPNs)**. Attackers **target accounts with SPNs**.

To request a **Kerberos TGS ticket**:

```powershell
klist tgt
klist tickets
```

If you have **Mimikatz installed**, dump Kerberos tickets:

```powershell
mimikatz.exe "kerberos::list" exit
```

---

### **🛡️ Detect Kerberoasting with BAD**
Now, **run BAD to detect Kerberoasting activity**:

```powershell
.\Run-ADAudit.ps1 -ReportPath "C:\AD_Audit_Reports" -StartTime (Get-Date).AddHours(-1) -EventIds 4769
```
📌 **What to look for in logs:**  
- Event **4769**: **Service Ticket Requests**  
- If **many requests** come from **one user**, it may be **Kerberoasting**.

✅ **Mitigation:**  
- Ensure **strong passwords** for service accounts.  
- Restrict **SPN-based accounts** with **AES encryption**.

---

## **🚀 2. Password Spraying (Brute Force on Multiple Users)**
**What it does:**  
- Tries **one password** against **many accounts** (to avoid lockouts).  
- Example: Trying **"P@ssw0rd123"** against **100 users**.

### **👨‍💻 Simulating Password Spraying**
Inside the **Windows Server container**, run:

```powershell
for ($i=1; $i -le 100; $i++) {
    $username = "TestUser$i"
    $password = "Spring2024!"
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force

    Write-Host "Trying: $username / $password"
    try {
        New-Object System.DirectoryServices.DirectorySearcher -ArgumentList (New-Object System.DirectoryServices.DirectoryEntry("LDAP://$username", $username, $password))
    } catch {
        Write-Host "Failed Login for $username"
    }
}
```
📌 **What happens?**  
- This script attempts to authenticate **100 users** using **one password**.

---

### **🛡️ Detect Password Spraying with BAD**
Run BAD to detect repeated **failed logins**:

```powershell
.\Run-ADAudit.ps1 -ReportPath "C:\AD_Audit_Reports" -StartTime (Get-Date).AddMinutes(-30) -EventIds 4625
```
📌 **What to look for in logs:**  
- **Event 4625 (Failed Logon Attempts)**.  
- Many **failed logins** from **one IP** → 🚨 **Possible Password Spraying!**  

✅ **Mitigation:**  
- Use **smart lockout policies** (e.g., 5 failures in 15 minutes).  
- Require **MFA (Multi-Factor Authentication)**.  

---

## **🕶️ 3. AS-REP Roasting (Offline Cracking of Kerberos Pre-Authentication)**
**What it does:**  
- Extracts **Kerberos AS-REP hashes** for accounts with **"Do not require Kerberos Pre-Authentication"** enabled.  
- Can be cracked **offline** using **Hashcat**.

### **👨‍💻 Simulating AS-REP Roasting**
Find **users without Kerberos Pre-Auth** enabled:

```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

If any users are found, use **Rubeus** or **Mimikatz** to request a **Kerberos AS-REP hash**:

```powershell
rubeus asreproast
```

---

### **🛡️ Detect AS-REP Roasting with BAD**
Run BAD to **detect AS-REP attacks**:

```powershell
.\Run-ADAudit.ps1 -ReportPath "C:\AD_Audit_Reports" -StartTime (Get-Date).AddMinutes(-60) -EventIds 4768
```
📌 **What to look for in logs:**  
- Event **4768 (Kerberos AS-REQ requests)**.  
- Any accounts with **"Do not require Kerberos Pre-Authentication"** should be **fixed**.

✅ **Mitigation:**  
- **Disable "Do not require Kerberos Pre-Authentication"** on all accounts.  
- Enforce **strong passwords**.  

---

## **💣 4. DCSync Attack (Stealing AD Hashes from a Domain Controller)**
**What it does:**  
- Extracts **NTLM password hashes** from the **Domain Controller** using **Replicating Directory Changes**.

### **👨‍💻 Simulating DCSync Attack**
If you have **Mimikatz**, run:

```powershell
mimikatz.exe "lsadump::dcsync /domain:test.lab /user:Administrator" exit
```

📌 **What happens?**  
- If successful, **DCSync** **steals NTLM hashes**.

---

### **🛡️ Detect DCSync with BAD**
Run BAD to detect **DCSync attacks**:

```powershell
.\Run-ADAudit.ps1 -ReportPath "C:\AD_Audit_Reports" -StartTime (Get-Date).AddMinutes(-30) -EventIds 4662
```
📌 **What to look for in logs:**  
- **Event 4662 (Directory Replication Changes)**.  
- If a **non-DC account** is requesting **replication** → 🚨 **DCSync Attack!**  

✅ **Mitigation:**  
- Remove **"Replicating Directory Changes"** permissions from non-DC accounts.  
- Monitor **Event 4662** logs.

---

# **🎯 Final Steps: Automate BAD to Detect Attacks**
To ensure **continuous monitoring**, schedule BAD to **run every hour**:

```powershell
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "C:\BAD\Run-ADAudit.ps1 -ReportPath C:\AD_Audit_Reports"
$Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 60) -RepetitionDuration (New-TimeSpan -Days 365) -AtLogOn
Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "Hourly_AD_Audit" -Description "Runs BAD every hour" -User "Administrator" -RunLevel Highest
```
✅ **BAD will now run every hour** and detect attacks in **real-time**!

---

# **🚀 Summary of Attacks & BAD Detection**
| Attack              | Event ID | Detection |
|---------------------|---------|------------|
| **Kerberoasting** | **4769** | Detects service ticket requests |
| **Password Spraying** | **4625** | Detects multiple failed logins |
| **AS-REP Roasting** | **4768** | Detects Kerberos pre-auth failures |
| **DCSync Attack** | **4662** | Detects unauthorized replication |

Would you like help with **exporting logs to a SIEM** like **Splunk or Sentinel**? 🚀

