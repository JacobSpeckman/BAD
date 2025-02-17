<#
.SYNOPSIS
    Extended AD Audit script including:
    - GPO Security Permissions
    - Logon/Logoff Scripts
    - Event Log Collection
    - OU Delegated Permissions

.DESCRIPTION
    This script pulls together the “core” AD audit tasks and
    additional extended tasks for a more comprehensive audit.

.NOTES
    Author: Jacob Speckman
    Date:   2025-02-14
#>

Param(
    [string]$ReportPath = "C:\AD_Audit_Reports",
    [datetime]$StartTime = (Get-Date).AddDays(-7),
    [datetime]$EndTime   = (Get-Date),
    [int[]]$EventIds     = @(4624,4625,4768,4769,4776,1102)
)

# 1. Import or dot-source the extended helper module
. "C:\Scripts\ADAuditTools.ps1"  # <-- Adjust path if needed

# 2. Ensure report folder exists
if (!(Test-Path $ReportPath)) {
    New-Item -ItemType Directory -Path $ReportPath | Out-Null
}

Write-Host "`n=== Starting Extended AD Audit ===`n"

# ----------------------
# --- Core Tasks ---
# ----------------------

Write-Host "[1] Collecting domain information..."
$domainInfo = Get-ADDomainInfo
$domainInfo | Export-Csv (Join-Path $ReportPath "DomainInfo.csv") -NoTypeInformation

Write-Host "[2] Collecting domain controller inventory..."
$dcs = Get-ADDomainControllersInfo
$dcs | Export-Csv (Join-Path $ReportPath "DomainControllers.csv") -NoTypeInformation

Write-Host "[3] Collecting AD sites and replication info..."
$repInfo = Get-ADSiteReplicationInfo
$repInfo.Sites        | Export-Csv (Join-Path $ReportPath "Sites.csv") -NoTypeInformation
$repInfo.SiteLinks    | Export-Csv (Join-Path $ReportPath "SiteLinks.csv") -NoTypeInformation
$repInfo.Connections  | Export-Csv (Join-Path $ReportPath "Connections.csv") -NoTypeInformation

Write-Host "[4] Collecting DNS info..."
$dnsInfo = Get-ADDNSInfo
$dnsInfo | Export-Csv (Join-Path $ReportPath "DNSZones.csv") -NoTypeInformation

Write-Host "[5] Collecting privileged group memberships..."
$privGroups = Get-PrivilegedGroupMembers
$privGroups | Export-Csv (Join-Path $ReportPath "PrivilegedGroups.csv") -NoTypeInformation

Write-Host "[6] Collecting service accounts..."
$svcAccounts = Get-ADServiceAccounts
$svcAccounts.gMSAs             | Export-Csv (Join-Path $ReportPath "gMSA_Accounts.csv") -NoTypeInformation
$svcAccounts.UserBasedSvcAccts | Export-Csv (Join-Path $ReportPath "UserServiceAccounts.csv") -NoTypeInformation

Write-Host "[7] Collecting Group Policy (basic report)..."
$domainFQDN     = (Get-ADDomain).DNSRoot
$gpoReportFile  = Get-AllGPOReport -DomainFQDN $domainFQDN -ReportPath $ReportPath -ReportType "HTML"
Write-Host "    > GPO (HTML) report at: $gpoReportFile"

Write-Host "[8] Collecting stale accounts info..."
$staleInfo = Get-StaleAccounts -DaysInactive 90
$staleInfo.InactiveUsers     | Export-Csv (Join-Path $ReportPath "StaleUsers.csv") -NoTypeInformation
$staleInfo.InactiveComputers | Export-Csv (Join-Path $ReportPath "StaleComputers.csv") -NoTypeInformation

Write-Host "[9] Collecting domain password policy..."
$domainDN  = (Get-ADDomain).DistinguishedName
$pwdPolicy = Get-PasswordPolicy -DomainDN $domainDN
$pwdPolicy | Select-Object * | Export-Csv (Join-Path $ReportPath "DomainPasswordPolicy.csv") -NoTypeInformation

Write-Host "[10] Collecting Kerberos settings..."
$kerbSettings = Get-KerbPolicy
$kerbSettings | Export-Csv (Join-Path $ReportPath "KerberosPolicy.csv") -NoTypeInformation

Write-Host "[11] Collecting Audit policy..."
$auditSettings = Get-AuditPolicy
$auditSettings | Out-File (Join-Path $ReportPath "AuditPolicy.txt")

# -----------------------------
# --- Extended Tasks ---
# -----------------------------

Write-Host "`n[12] GPO Security Permissions..."
$gpoPerms = Get-GPOSecurityPermissions -DomainFQDN $domainFQDN
$gpoPerms | Export-Csv (Join-Path $ReportPath "GPO_SecurityPermissions.csv") -NoTypeInformation

Write-Host "[13] GPO Logon/Logoff Scripts..."
$scriptInfo = Get-GPOLogonLogoffScripts -DomainFQDN $domainFQDN
$scriptInfo | Export-Csv (Join-Path $ReportPath "GPO_LogonLogoffScripts.csv") -NoTypeInformation

Write-Host "[14] Collecting DC Event Logs (Security) from $($StartTime) to $($EndTime)..."
$dcEvents = Collect-DCEventLogs -StartTime $StartTime -EndTime $EndTime -EventIds $EventIds
$dcEvents | Export-Csv (Join-Path $ReportPath "DC_SecurityEvents.csv") -NoTypeInformation

Write-Host "[15] Enumerating Delegated OU Permissions..."
$ouDelegations = Get-DelegatedOUPermissions
$ouDelegations | Export-Csv (Join-Path $ReportPath "OU_DelegatedPermissions.csv") -NoTypeInformation

Write-Host "`n=== Extended AD Audit Complete ==="
Write-Host "All reports have been saved to $ReportPath"
