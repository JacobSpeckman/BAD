### **Step-by-Step Guide: Exporting BAD Audit Logs to LogRhythm SIEM**

Now that we have **BAD detecting Active Directory (AD) attacks**, we need to **export logs** to **LogRhythm SIEM** for centralized monitoring, alerting, and forensic analysis.

---

## **🛠 Step 1: Prepare LogRhythm for Ingesting AD Logs**
LogRhythm supports multiple ingestion methods:
1. **Syslog (UDP/TCP)**
2. **Windows Event Forwarding (WEF)**
3. **LogRhythm API**
4. **File-Based Log Collection**

For BAD logs, we will **export reports as JSON & CSV** and forward them using **Syslog** or **File Collection**.

---

## **📂 Step 2: Configure BAD to Output Logs for LogRhythm**
BAD generates reports in **CSV and HTML**. We need to **convert them to JSON** for LogRhythm ingestion.

1. **Modify BAD script to output logs in JSON format**
   ```powershell
   Import-Csv C:\AD_Audit_Reports\DC_SecurityEvents.csv | ConvertTo-Json | Out-File C:\AD_Audit_Reports\DC_SecurityEvents.json
   Import-Csv C:\AD_Audit_Reports\PrivilegedGroups.csv | ConvertTo-Json | Out-File C:\AD_Audit_Reports\PrivilegedGroups.json
   ```

2. **Verify JSON files exist**
   ```powershell
   ls C:\AD_Audit_Reports\*.json
   ```

---

## **📡 Step 3: Send Logs to LogRhythm Using Syslog (Preferred)**
LogRhythm **Syslog Receiver** can be configured to collect logs from BAD.

### **Option 1: Send JSON Logs via Syslog**
1. Open **PowerShell** inside the AD server:
   ```powershell
   $LogRhythmSyslogServer = "192.168.1.100"  # Replace with LogRhythm Syslog Server IP
   $SyslogPort = 514                         # Default UDP Syslog Port

   Get-Content C:\AD_Audit_Reports\DC_SecurityEvents.json | ForEach-Object {
       $Message = "<14> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') BAD_LOG: $_"
       $UdpClient = New-Object System.Net.Sockets.UdpClient
       $UdpClient.Connect($LogRhythmSyslogServer, $SyslogPort)
       $Bytes = [System.Text.Encoding]::ASCII.GetBytes($Message)
       $UdpClient.Send($Bytes, $Bytes.Length)
       $UdpClient.Close()
   }
   ```

📌 **What this does:**
- Reads the **BAD JSON logs**.
- Sends them to **LogRhythm's Syslog Server** over **UDP (port 514)**.
- LogRhythm parses the logs into its SIEM.

---

### **Option 2: Send Logs Using LogRhythm File Collection**
If you don’t want to use Syslog, LogRhythm can collect logs from a **shared folder**.

#### **1️⃣ Create a Shared Log Directory**
On the AD server:
```powershell
New-Item -Path "C:\BAD_Logs" -ItemType Directory
icacls "C:\BAD_Logs" /grant Everyone:(OI)(CI)F
```

#### **2️⃣ Modify BAD to Export Logs Here**
Modify the **BAD script** to store JSON logs in the shared directory:
```powershell
Import-Csv C:\AD_Audit_Reports\DC_SecurityEvents.csv | ConvertTo-Json | Out-File C:\BAD_Logs\DC_SecurityEvents.json
Import-Csv C:\AD_Audit_Reports\PrivilegedGroups.csv | ConvertTo-Json | Out-File C:\BAD_Logs\PrivilegedGroups.json
```

#### **3️⃣ Configure LogRhythm to Collect Logs**
- **Log Source Type:** **Flat File**  
- **Path:** `\\<AD_Server_IP>\BAD_Logs\`  
- **File Pattern:** `*.json`  
- **Parser:** **JSON Custom Parser**  

---

## **🔄 Step 4: Automate BAD & Log Export to LogRhythm**
To **run BAD & export logs every hour**, schedule a **PowerShell Task**.

1. **Create a Scheduled Task**
   ```powershell
   $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "C:\BAD\Run-ADAudit.ps1 -ReportPath C:\BAD_Logs"
   $Trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 60) -RepetitionDuration (New-TimeSpan -Days 365) -AtLogOn
   Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "BAD_LogRhythm_Export" -Description "Runs BAD every hour and exports logs to LogRhythm" -User "Administrator" -RunLevel Highest
   ```

✅ **BAD now runs every hour & logs are automatically forwarded to LogRhythm.**

---

## **🎯 Summary: Exporting BAD Logs to LogRhythm**
| Export Method | Setup Steps | Pros | Cons |
|--------------|------------|------|------|
| **Syslog (UDP/TCP)** | Send JSON logs via Syslog | Fast, real-time | Requires Syslog receiver |
| **File-Based Collection** | Save logs to a shared folder | Easy setup | Slight delay in ingestion |

### **Step-by-Step Guide: Configuring LogRhythm Parsing for BAD Logs**  

Now that BAD is exporting **JSON logs** into LogRhythm, we need to configure **LogRhythm's parsing rules** so the logs can be properly indexed, categorized, and used in dashboards, alerts, and forensic investigations.

---

## **🛠 Step 1: Verify Logs are Reaching LogRhythm**
Before configuring parsing, ensure logs are being received.

1️⃣ **If using Syslog**:  
- Go to **LogRhythm Web Console** → **Log Manager** → **Syslog Sources**.  
- Look for incoming logs from your AD server’s IP.  
- Run the following query in **LogRhythm Investigator**:
  ```
  SELECT * FROM Log WHERE OriginHost = '<AD_SERVER_IP>' ORDER BY DateTime DESC
  ```

2️⃣ **If using File Collection**:  
- Navigate to **Log Source Virtualization (LSV) Service** in LogRhythm Admin.  
- Check if LogRhythm has detected new logs in `\\<AD_SERVER_IP>\BAD_Logs\`.  
- Manually open the log file in LogRhythm to confirm ingestion.

✅ **Once logs are confirmed as received, move to parsing setup.**

---

## **📝 Step 2: Create a Custom Log Source Type for BAD**
LogRhythm needs a **custom log source type** to recognize BAD logs.

1. **Open LogRhythm Client Console**.
2. Go to **Deployment Manager** → **Log Source Type Manager**.
3. Click **Add New Log Source Type**.
4. Enter:
   - **Name**: `BAD_AD_Audit`
   - **Log Format**: `JSON`
   - **Collection Method**: Choose `Syslog` or `Flat File`
   - **Log Message Pattern**: Select `Structured`
5. Click **Save**.

---

## **🛠 Step 3: Define Log Parsing Rules**
BAD logs contain **structured JSON data**. We need to **map JSON fields** to LogRhythm fields.

1️⃣ **Open LogRhythm Web Console → Data Processor**.  
2️⃣ Go to **Log Processing Policy** → **Create New Policy** for BAD logs.  
3️⃣ Click **"Add Rule"** and set up mappings:

### **JSON Field Mapping for BAD Logs**
| JSON Field | LogRhythm Field | Description |
|------------|---------------|-------------|
| `Timestamp` | `DateTime` | Timestamp of the log |
| `EventID` | `Event ID` | Windows event ID (4625, 4768, etc.) |
| `UserName` | `User` | The AD user account |
| `SourceIP` | `OriginHost` | IP address of the source system |
| `TargetDomain` | `Domain` | Domain name being audited |
| `EventType` | `Event Name` | Event type (Logon, Group Change, Kerberos Request, etc.) |
| `Result` | `Event Outcome` | Success / Failure |

4️⃣ **Save the parsing rules.**  
5️⃣ Apply the policy to **BAD_AD_Audit** log source type.

---

## **🚀 Step 4: Create LogRhythm AIE Rules (Alerting)**
To detect **AD attacks**, we’ll create **Advanced Intelligence Engine (AIE) rules**.

1️⃣ **Open LogRhythm AIE Console**.  
2️⃣ Go to **AIE Rules Manager** → **Create New Rule**.  
3️⃣ Configure the rule as follows:

### **Rule 1: Detect Kerberoasting Attempts**
- **Event ID**: `4769` (Kerberos TGS Request)
- **Condition**:  
  ```plaintext
  IF "Event ID" = 4769 AND "User" NOT LIKE 'krbtgt' AND "SourceIP" IS UNKNOWN
  ```
- **Action**:  
  - Generate **High Alert**  
  - Notify **SOC Team**  
  - Log **Incident Ticket** in LogRhythm  

---

### **Rule 2: Detect Password Spraying**
- **Event ID**: `4625` (Failed Login)
- **Condition**:  
  ```plaintext
  IF "Event ID" = 4625 AND COUNT("User") > 10 WITHIN 5 minutes
  ```
- **Action**:  
  - **Generate Critical Alert**  
  - Block IP via **SOAR integration**  

---

### **Rule 3: Detect DCSync Attacks**
- **Event ID**: `4662` (Directory Replication)
- **Condition**:  
  ```plaintext
  IF "Event ID" = 4662 AND "User" NOT IN ('Administrator', 'krbtgt')
  ```
- **Action**:  
  - Send **High Alert to SOC**
  - Log incident for **Active Directory team**  

---

## **📊 Step 5: Create LogRhythm Dashboard for BAD Logs**
To **visualize AD security events**, we will create a **dashboard**.

1️⃣ Open **LogRhythm Web Console**.  
2️⃣ Navigate to **Dashboards** → **Create New Dashboard**.  
3️⃣ Add **Widgets** for:
   - **Top Failed Logins** (Event ID `4625`)
   - **Top Kerberos Requests** (Event ID `4769`)
   - **Suspicious Logon Activity** (Event ID `4624`, `4625`)
   - **DCSync Alerts** (Event ID `4662`)
4️⃣ **Save & Share** the dashboard with **SOC & AD Security Teams**.

✅ **Now, your team can monitor BAD logs in real-time via LogRhythm dashboards.**

---

## **🛠 Step 6: Test LogRhythm Parsing & Alerts**
To verify everything works:

1️⃣ **Run BAD Audit Script:**
   ```powershell
   .\Run-ADAudit.ps1 -ReportPath "C:\BAD_Logs"
   ```

2️⃣ **Simulate an Attack:**
   - **Kerberoasting:**  
     ```powershell
     rubeus.exe asreproast
     ```
   - **Password Spraying:**  
     ```powershell
     for ($i=1; $i -le 100; $i++) { Invoke-Command -ScriptBlock { net use \\dc\admin$ /user:TestUser$i P@ssword123 } }
     ```

3️⃣ **Verify LogRhythm Alerts:**
   - Go to **LogRhythm Console** → **Investigate Logs**.
   - Look for **Event IDs 4769, 4625, 4662**.
   - Ensure alerts **trigger correctly**.

✅ **If alerts fire correctly, BAD logs are fully integrated into LogRhythm!** 🚀

---

## **🎯 Final Summary**
| Task | Status |
|------|--------|
| **Export BAD logs as JSON** | ✅ Done |
| **Send logs via Syslog or File Collection** | ✅ Done |
| **Create LogRhythm Parsing Rules** | ✅ Done |
| **Set up AIE Alerts (Kerberoasting, Password Spraying, DCSync)** | ✅ Done |
| **Build LogRhythm Dashboard for AD Threats** | ✅ Done |
| **Simulate Attacks & Validate Logs** | ✅ Done |

