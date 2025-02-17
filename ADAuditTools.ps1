<#
    .SYNOPSIS
        Extended AD Audit Helper Functions

    .DESCRIPTION
        Includes:
         - GPO Security Permissions
         - Logon/Logoff Scripts parsing
         - Event log collection from DCs
         - Delegated Permissions on OUs
        ...plus any previously defined functions (e.g., Get-ADDomainInfo, Get-ADDomainControllersInfo, etc.)
#>

Import-Module ActiveDirectory
Import-Module GroupPolicy  # For GPO cmdlets like Get-GPPermissions

#region --- Existing Core Functions (Truncated for brevity) ---

function Get-ADDomainInfo {
    [CmdletBinding()]
    param()

    $domain = Get-ADDomain
    $forest = Get-ADForest

    [PSCustomObject]@{
        DomainName               = $domain.DNSRoot
        DomainMode               = $domain.DomainMode
        ForestName               = $forest.Name
        ForestMode               = $forest.ForestMode
        PDCEmulator              = $domain.PDCEmulator
        RidMaster                = $domain.RIDMaster
        InfrastructureMaster     = $domain.InfrastructureMaster
        DomainNamingMaster       = $forest.DomainNamingMaster
        SchemaMaster             = $forest.SchemaMaster
    }
}

function Get-ADDomainControllersInfo {
    [CmdletBinding()]
    param()

    $dcs = Get-ADDomainController -Filter *
    $dcs | Select-Object Hostname, 
                        Forest, 
                        Domain, 
                        Site, 
                        IPv4Address, 
                        IsGlobalCatalog, 
                        IsReadOnly, 
                        OperatingSystem, 
                        OperatingSystemVersion
}

function Get-ADSiteReplicationInfo {
    [CmdletBinding()]
    param()

    $sites       = Get-ADReplicationSite -Filter *
    $siteLinks   = Get-ADReplicationSiteLink -Filter *
    $connections = Get-ADReplicationConnection -Filter *

    return [PSCustomObject]@{
        Sites       = $sites
        SiteLinks   = $siteLinks
        Connections = $connections
    }
}

function Get-ADDNSInfo {
    [CmdletBinding()]
    param()

    $dnsZones = @()
    try {
        $dnsZones = Get-WmiObject -Namespace "root\MicrosoftDNS" -Class "MicrosoftDNS_Zone" -ComputerName (Get-ADDomainController -Discover).HostName |
                    Select-Object Name, ZoneType, DsIntegrated, IsReverseZone
    }
    catch {
        Write-Warning "Could not retrieve DNS info. Make sure DNS Management tools are installed or you have appropriate permissions."
    }
    return $dnsZones
}

function Get-PrivilegedGroupMembers {
    [CmdletBinding()]
    param()

    $privGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Server Operators",
        "Account Operators",
        "Backup Operators"
    )

    $results = foreach ($group in $privGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                GroupName = $group
                Members   = $members | ForEach-Object { $_.SamAccountName } -join "; "
            }
        } catch {
            Write-Warning "Unable to retrieve membership for group $group. Error: $($_.Exception.Message)"
        }
    }
    return $results
}

function Get-ADServiceAccounts {
    [CmdletBinding()]
    param()

    # Group Managed Service Accounts (gMSA)
    $gMSAs = @()
    try {
        $gMSAs = Get-ADServiceAccount -Filter * -ErrorAction SilentlyContinue |
            Select-Object Name, SamAccountName, DNSHostName, ServicePrincipalNames
    } catch {
        Write-Warning "Could not retrieve gMSAs. $($_.Exception.Message)"
    }

    # For user-based service accounts, you might filter on naming convention or OU. E.g. "svc_*"
    $userBasedSvc = @()
    try {
        $userBasedSvc = Get-ADUser -Filter 'Name -like "svc_*"' -Properties ServicePrincipalName |
            Select-Object Name, SamAccountName, ServicePrincipalName, Enabled
    } catch {
        Write-Warning "Could not retrieve user-based service accounts. $($_.Exception.Message)"
    }

    return [PSCustomObject]@{
        gMSAs             = $gMSAs
        UserBasedSvcAccts = $userBasedSvc
    }
}

function Get-AllGPOReport {
    [CmdletBinding()]
    param(
        [string]$DomainFQDN = (Get-ADDomain).DNSRoot,
        [string]$ReportPath,
        [string]$ReportType = "HTML"  # "XML" also possible
    )

    $reportFile = Join-Path $ReportPath "AllGPOs.$ReportType"

    try {
        Get-GPOReport -All -Domain $DomainFQDN -ReportType $ReportType -Path $reportFile
        return $reportFile
    } catch {
        Write-Warning "Failed to generate GPO report for domain $DomainFQDN. Error: $($_.Exception.Message)"
        return $null
    }
}

function Get-StaleAccounts {
    [CmdletBinding()]
    param(
        [int]$DaysInactive = 90
    )

    $timeSpan = New-TimeSpan -Days $DaysInactive

    $staleUsers     = Search-ADAccount -UsersOnly     -AccountInactive -TimeSpan $timeSpan -ErrorAction SilentlyContinue
    $staleComputers = Search-ADAccount -ComputersOnly -AccountInactive -TimeSpan $timeSpan -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        InactiveUsers     = $staleUsers
        InactiveComputers = $staleComputers
    }
}

function Get-PasswordPolicy {
    [CmdletBinding()]
    param(
        [string]$DomainDN = (Get-ADDomain).DistinguishedName
    )

    $domainPolicy = Get-ADDefaultDomainPasswordPolicy -Identity $DomainDN
    return $domainPolicy
}

function Get-KerbPolicy {
    [CmdletBinding()]
    param()

    $key = "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
    $kerbSettings = @()
    $params = "MaxTicketAge","MaxRenewAge","MaxServiceAge","MaxClockSkew","DefaultEncryptionType"
    foreach ($param in $params) {
        $value = (Get-ItemProperty $key -Name $param -ErrorAction SilentlyContinue).$param
        $kerbSettings += [PSCustomObject]@{
            Setting = $param
            Value   = $value
        }
    }
    return $kerbSettings
}

function Get-AuditPolicy {
    [CmdletBinding()]
    param()

    $auditSettings = (auditpol /get /category:* | Out-String)
    return $auditSettings
}

#endregion

#region --- NEW / EXTENDED Functions ---

function Get-GPOSecurityPermissions {
    <#
    .SYNOPSIS
        Retrieves security permissions (ACLs) for each GPO in the domain.
    .DESCRIPTION
        Uses Get-GPPermissions to get the PermissionLevel for each group/user with permissions on the GPO.
    .PARAMETER DomainFQDN
        The FQDN of the domain (e.g., contoso.com).
    .OUTPUTS
        A collection of permission objects.
    #>
    param(
        [string]$DomainFQDN = (Get-ADDomain).DNSRoot
    )

    $allGPOs = Get-GPO -All -Domain $DomainFQDN
    $results = @()

    foreach ($gpo in $allGPOs) {
        try {
            $permissions = Get-GPPermissions -Name $gpo.DisplayName -Domain $DomainFQDN -All
            foreach ($perm in $permissions) {
                $results += [PSCustomObject]@{
                    GPOName         = $gpo.DisplayName
                    GPOId           = $gpo.Id
                    Trustee         = $perm.Trustee
                    PermissionLevel = $perm.Permission
                }
            }
        }
        catch {
            Write-Warning "Failed to get permissions for GPO [$($gpo.DisplayName)]: $($_.Exception.Message)"
        }
    }
    return $results
}

function Get-GPOLogonLogoffScripts {
    <#
    .SYNOPSIS
        Identifies logon/logoff (and startup/shutdown) scripts assigned via Group Policy.
    .PARAMETER DomainFQDN
        The FQDN of the domain. Default uses current domain.
    .OUTPUTS
        A list of discovered scripts with GPO name, script type, and script path.
    #>
    param(
        [string]$DomainFQDN = (Get-ADDomain).DNSRoot
    )

    $allGPOs = Get-GPO -All -Domain $DomainFQDN
    $scriptInfo = @()

    foreach ($gpo in $allGPOs) {
        try {
            # Get GPO report as XML
            $xmlData = Get-GPOReport -Name $gpo.DisplayName -Domain $DomainFQDN -ReportType XML
            [xml]$xml = $xmlData

            $scriptNodes = $xml.GPO.Document.SelectNodes("//Script")

            foreach ($node in $scriptNodes) {
                $scriptType = $node.ScriptType
                $scriptPath = $node.ScriptPath
                $parameters = $node.Parameters

                $scriptInfo += [PSCustomObject]@{
                    GPOName    = $gpo.DisplayName
                    GPOId      = $gpo.Id
                    ScriptType = $scriptType
                    ScriptPath = $scriptPath
                    Parameters = $parameters
                }
            }
        }
        catch {
            Write-Warning "Failed to parse scripts for GPO [$($gpo.DisplayName)]: $($_.Exception.Message)"
        }
    }
    return $scriptInfo
}

function Get-DCEventLogs {
    <#
    .SYNOPSIS
        Collects specified event logs from all domain controllers in the domain.
    .DESCRIPTION
        By default, grabs security log events (IDs specified in $EventIds) within a specific time range.
    .PARAMETER StartTime
        The earliest timestamp to collect events from.
    .PARAMETER EndTime
        The latest timestamp for the events.
    .PARAMETER EventIds
        An array of relevant event IDs.
    .OUTPUTS
        A collection of event objects.
    #>
    param(
        [datetime]$StartTime = (Get-Date).AddDays(-7),
        [datetime]$EndTime   = (Get-Date),
        [int[]]$EventIds     = @(4624,4625,4768,4769,4776,1102)
    )

    Write-Host "Collecting Security logs from DCs between $StartTime and $EndTime..."

    $dcs = Get-ADDomainController -Filter *
    $allEvents = @()

    foreach ($dc in $dcs) {
        Write-Host "  - Collecting events from: $($dc.HostName)"

        try {
            $filterHash = @{
                LogName      = 'Security'
                ID           = $EventIds
                StartTime    = $StartTime
                EndTime      = $EndTime
            }
            $dcEvents = Get-WinEvent -ComputerName $dc.HostName -FilterHashtable $filterHash -ErrorAction SilentlyContinue

            $allEvents += $dcEvents | Select-Object `
                @{Name='DomainController';Expression={$dc.HostName}},
                @{Name='EventId';Expression={$_.Id}},
                @{Name='TimeCreated';Expression={$_.TimeCreated}},
                @{Name='Message';Expression={$_.Message}}
        }
        catch {
            Write-Warning "Failed to collect logs from $($dc.HostName): $($_.Exception.Message)"
        }
    }

    return $allEvents
}

function Get-DelegatedOUPermissions {
    <#
    .SYNOPSIS
        Enumerates delegated permissions (ACLs) on each OU in the domain.
    .DESCRIPTION
        Retrieves the Access Control Entries (ACEs) for OUs, which can reveal custom delegations.
    .PARAMETER SearchBase
        The DN to start searching from. Defaults to the domain root.
    .OUTPUTS
        A collection of ACE objects with details about OU, trustee, and permission type.
    #>
    param(
        [string]$SearchBase = (Get-ADDomain).DistinguishedName
    )

    $ous = Get-ADOrganizationalUnit -Filter * -SearchBase $SearchBase -SearchScope Subtree -ErrorAction SilentlyContinue
    $delegations = @()

    foreach ($ou in $ous) {
        try {
            $acl = Get-ACL -Path ("AD:" + $ou.DistinguishedName)
            foreach ($ace in $acl.Access) {
                $delegations += [PSCustomObject]@{
                    OU                    = $ou.Name
                    OUDN                  = $ou.DistinguishedName
                    IdentityReference     = $ace.IdentityReference
                    AccessControlType     = $ace.AccessControlType
                    ActiveDirectoryRights = $ace.ActiveDirectoryRights
                    InheritanceType       = $ace.InheritanceType
                    InheritedObjectType   = $ace.InheritedObjectType
                    ObjectType            = $ace.ObjectType
                }
            }
        }
        catch {
            Write-Warning "Failed to get ACL for OU [$($ou.DistinguishedName)]: $($_.Exception.Message)"
        }
    }
    return $delegations
}

#endregion
