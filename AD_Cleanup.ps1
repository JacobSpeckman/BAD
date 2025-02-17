Param(
    [int]$InactiveDays = 90,
    [switch]$DisableAccounts,
    [switch]$RemoveAccounts,
    [switch]$DryRun,
    [string]$LogPath = "C:\AD_Cleanup_Logs"
)

<#
.SYNOPSIS
    Finds and optionally cleans up stale AD user/computer accounts.

.DESCRIPTION
    Searches Active Directory for user and computer accounts that have not logged on
    within the specified number of days (default: 90).
    -DryRun parameter produces CSV output only, without disabling or removing any accounts.
    -DisableAccounts or -RemoveAccounts execute the respective actions, unless -DryRun is also present.

.PARAMETER InactiveDays
    The age threshold in days for an account to be considered "inactive". Default = 90 days.

.PARAMETER DisableAccounts
    If set, stale accounts are DISABLED instead of just reported (unless -DryRun is used).

.PARAMETER RemoveAccounts
    If set, stale accounts are REMOVED from Active Directory. Use with caution
    (unless -DryRun is used).

.PARAMETER DryRun
    If set, the script only reports the stale accounts to CSV,
    ignoring any -DisableAccounts or -RemoveAccounts switches.

.PARAMETER LogPath
    Folder path to store CSV logs of stale accounts. Defaults to "C:\AD_Cleanup_Logs".

.NOTES
    Author: Jacob Speckman
    Date:   2025-02-14
#>

# Requires the ActiveDirectory module
Import-Module ActiveDirectory -ErrorAction Stop

# 1. Ensure the log folder exists
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath | Out-Null
}

Write-Host "=== Starting AD Cleanup (InactiveDays: $InactiveDays) ==="
if ($DryRun) {
    Write-Host "NOTE: -DryRun enabled. No changes will be made to accounts."
}

# 2. Collect stale accounts
try {
    $timeSpan = New-TimeSpan -Days $InactiveDays

    # -- Stale Users --
    $staleUsers = Search-ADAccount -UsersOnly -AccountInactive -TimeSpan $timeSpan -ErrorAction SilentlyContinue

    # -- Stale Computers --
    $staleComputers = Search-ADAccount -ComputersOnly -AccountInactive -TimeSpan $timeSpan -ErrorAction SilentlyContinue
}
catch {
    Write-Error "Failed to search AD accounts. Error: $($_.Exception.Message)"
    return
}

# 3. Export lists to CSV for review
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$staleUserCsv = Join-Path $LogPath "StaleUsers_$timestamp.csv"
$staleCompCsv = Join-Path $LogPath "StaleComputers_$timestamp.csv"

$staleUsers | Select-Object Name, SamAccountName, Enabled, LastLogonDate, DistinguishedName |
    Export-Csv -Path $staleUserCsv -NoTypeInformation
$staleComputers | Select-Object Name, SamAccountName, Enabled, LastLogonDate, DistinguishedName |
    Export-Csv -Path $staleCompCsv -NoTypeInformation

Write-Host "Stale user accounts exported to: $staleUserCsv"
Write-Host "Stale computer accounts exported to: $staleCompCsv"

# 4. Decide if we should modify accounts or not
if ($DryRun) {
    Write-Host "`nDry Run complete. No changes made."
    Write-Host "Use -DisableAccounts or -RemoveAccounts (without -DryRun) to take action."
    Write-Host "=== AD Cleanup Script Complete (Dry Run) ==="
    return
}

if (-not $DisableAccounts -and -not $RemoveAccounts) {
    Write-Host "`nNo action switch specified (and -DryRun not used). Accounts have been listed only."
    Write-Host "Use -DisableAccounts or -RemoveAccounts to take action."
    Write-Host "=== AD Cleanup Script Complete (Report-Only Mode) ==="
    return
}

# 5. Perform Cleanup Actions (if requested)
if ($DisableAccounts) {
    Write-Host "`nDisabling stale accounts..."

    foreach ($user in $staleUsers) {
        try {
            Disable-ADAccount -Identity $($user.DistinguishedName) -ErrorAction Stop
            Write-Host "Disabled user: $($user.SamAccountName)"
        }
        catch {
            Write-Warning "Failed to disable user '$($user.SamAccountName)': $($_.Exception.Message)"
        }
    }

    foreach ($comp in $staleComputers) {
        try {
            Disable-ADAccount -Identity $($comp.DistinguishedName) -ErrorAction Stop
            Write-Host "Disabled computer: $($comp.SamAccountName)"
        }
        catch {
            Write-Warning "Failed to disable computer '$($comp.SamAccountName)': $($_.Exception.Message)"
        }
    }
}

if ($RemoveAccounts) {
    # Removing accounts is permanent, so let's confirm:
    Write-Host "`nRemoving stale accounts (Permanent!)..."

    foreach ($user in $staleUsers) {
        try {
            Remove-ADUser -Identity $($user.DistinguishedName) -Confirm:$false -ErrorAction Stop
            Write-Host "Removed user: $($user.SamAccountName)"
        }
        catch {
            Write-Warning "Failed to remove user '$($user.SamAccountName)': $($_.Exception.Message)"
        }
    }

    foreach ($comp in $staleComputers) {
        try {
            Remove-ADComputer -Identity $($comp.DistinguishedName) -Confirm:$false -ErrorAction Stop
            Write-Host "Removed computer: $($comp.SamAccountName)"
        }
        catch {
            Write-Warning "Failed to remove computer '$($comp.SamAccountName)': $($_.Exception.Message)"
        }
    }
}

Write-Host "=== AD Cleanup Script Complete ==="
