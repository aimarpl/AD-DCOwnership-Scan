<#
.SYNOPSIS
Scans domain controller computer objects in an Active Directory domain and reports non-default ownership.

.DESCRIPTION
Finds every domain controller computer object in the target domain - writable DCs (primaryGroupID 516),
read-only DCs (primaryGroupID 521) and any computer flagged as SERVER_TRUST_ACCOUNT - reads the owner from
its nTSecurityDescriptor and checks that the owner is Domain Admins of the target domain, Enterprise Admins
of the forest root domain or BUILTIN\Administrators.

The owner of an object can always rewrite its permissions, so a non-privileged owner of a domain controller
computer object is a direct path to domain compromise.

The script only reads from Active Directory. It outputs one object per domain controller; objects with an
unexpected owner include a one-line RemediationCommand that resets the owner to Domain Admins of the target
domain. Review each command before running it.

.PARAMETER Domain
DNS name of the target domain (or the name of a domain controller in it). Used as -Server for all queries.

.PARAMETER Credential
Optional credential for the target domain. Generated remediation commands then reference a variable named
$Credential, which must hold a suitable credential in the session where the commands are run.

.EXAMPLE
PS> .\Scan-DomainControllerOwnership.ps1 -Domain example.com

Lists all domain controller computer objects with their owner and status.

.EXAMPLE
PS> $Credential = Get-Credential
PS> .\Scan-DomainControllerOwnership.ps1 -Domain child.example.com -Credential $Credential

Scans another domain with explicit credentials.

.EXAMPLE
PS> .\Scan-DomainControllerOwnership.ps1 -Domain example.com |
        Where-Object Status -eq 'UnexpectedOwner' |
        Select-Object -ExpandProperty RemediationCommand

Prints only the remediation commands for objects with an unexpected owner.

.OUTPUTS
PSCustomObject with Name, DistinguishedName, Status (OK, UnexpectedOwner, OwnerUnreadable), Owner, OwnerSid
and RemediationCommand.

.NOTES
Author : Łukasz Ślemp (https://github.com/aimarpl)
Version: 1.1.0
License: MIT

Requirements:
- Windows PowerShell 5.1 or PowerShell 7 with the ActiveDirectory module (RSAT).
- Reading owners works with an ordinary domain account. Running the remediation commands requires
  Domain Admins or Enterprise Admins rights (Tier 0) and should be done from a secure admin host.

Exit codes:
0 - All domain controller objects have an expected owner.
1 - Error (module missing, domain unreachable, query failed).
2 - At least one object has an unexpected or unreadable owner.

Version history:
1.1.0 - Fix parse error in the remediation command; read the owner SID correctly (the Owner property is a
        string, so every DC was reported); accept BUILTIN\Administrators as owner; find DCs by
        primaryGroupID/userAccountControl, including RODCs and DC accounts without a server object; query
        the forest root domain on its own DC; output objects instead of host text; remediation uses
        Set-ADObject against the target domain; error handling and exit codes.
1.0.0 - Initial version.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential
)

$ErrorActionPreference = 'Stop'

function Get-AllowedOwnerSid {
    param(
        [hashtable]$AdParams
    )

    $domainInfo = Get-ADDomain @AdParams
    $forestInfo = Get-ADForest @AdParams

    if ($domainInfo.DNSRoot -eq $forestInfo.RootDomain) {
        $rootDomainInfo = $domainInfo
    }
    else {
        # Query the root domain on its own DC; a DC of a child domain cannot return it.
        $rootParams = @{ Server = $forestInfo.RootDomain }
        if ($AdParams.ContainsKey('Credential')) {
            $rootParams.Credential = $AdParams.Credential
        }
        $rootDomainInfo = Get-ADDomain -Identity $forestInfo.RootDomain @rootParams
    }

    $domainAdminsSid = "$($domainInfo.DomainSID)-512"
    $enterpriseAdminsSid = "$($rootDomainInfo.DomainSID)-519"
    $builtinAdministratorsSid = 'S-1-5-32-544'

    [PSCustomObject]@{
        Allowed   = @($domainAdminsSid, $enterpriseAdminsSid, $builtinAdministratorsSid | Select-Object -Unique)
        Preferred = $domainAdminsSid
    }
}

function Resolve-AccountName {
    param(
        [string]$Sid
    )

    try {
        ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        $Sid
    }
}

function ConvertTo-QuotedLiteral {
    # Single-quoted PowerShell literal; quote characters (including typographic ones) are doubled.
    param(
        [string]$Value
    )

    "'" + ($Value -replace '[''\u2018\u2019\u201A\u201B]', '$0$0') + "'"
}

function New-RemediationCommand {
    param(
        [string]$DistinguishedName,
        [string]$OwnerSid,
        [string]$Server,
        [bool]$UseCredential
    )

    $connection = " -Server $(ConvertTo-QuotedLiteral $Server)"
    if ($UseCredential) {
        $connection += ' -Credential $Credential'
    }

    $template = '$sd = (Get-ADObject -Identity {0} -Properties nTSecurityDescriptor{1}).nTSecurityDescriptor; ' +
                '$sd.SetOwner([System.Security.Principal.SecurityIdentifier]{2}); ' +
                'Set-ADObject -Identity {0} -Replace @{{ nTSecurityDescriptor = $sd }}{1}'

    $template -f (ConvertTo-QuotedLiteral $DistinguishedName), $connection, (ConvertTo-QuotedLiteral $OwnerSid)
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false

    $adParams = @{ Server = $Domain }
    if ($Credential) {
        $adParams.Credential = $Credential
    }

    $ownerInfo = Get-AllowedOwnerSid -AdParams $adParams
    Write-Verbose "Allowed owners: $($ownerInfo.Allowed -join ', ')"

    # Writable DCs (516), RODCs (521) and any account flagged SERVER_TRUST_ACCOUNT (0x2000). This also
    # catches DC computer accounts that have no server object in Sites, which Get-ADDomainController misses.
    $ldapFilter = '(|(primaryGroupID=516)(primaryGroupID=521)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
    $domainControllers = @(Get-ADComputer -LDAPFilter $ldapFilter -Properties dNSHostName, nTSecurityDescriptor @adParams |
        Sort-Object -Property Name)

    if ($domainControllers.Count -eq 0) {
        throw "No domain controller computer objects found in domain '$Domain'."
    }
    Write-Verbose "Domain controller computer objects found in ${Domain}: $($domainControllers.Count)"

    $results = foreach ($dc in $domainControllers) {
        $name = if ($dc.dNSHostName) { $dc.dNSHostName } else { $dc.Name }
        $ownerSid = $null
        if ($dc.nTSecurityDescriptor) {
            $ownerSid = $dc.nTSecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        }

        if (-not $ownerSid) {
            $status = 'OwnerUnreadable'
            $owner = $null
            $command = $null
        }
        elseif ($ownerInfo.Allowed -contains $ownerSid) {
            $status = 'OK'
            $owner = Resolve-AccountName -Sid $ownerSid
            $command = $null
        }
        else {
            $status = 'UnexpectedOwner'
            $owner = Resolve-AccountName -Sid $ownerSid
            $command = New-RemediationCommand -DistinguishedName $dc.DistinguishedName -OwnerSid $ownerInfo.Preferred `
                -Server $Domain -UseCredential ([bool]$Credential)
        }

        [PSCustomObject]@{
            Name               = $name
            DistinguishedName  = $dc.DistinguishedName
            Status             = $status
            Owner              = $owner
            OwnerSid           = $ownerSid
            RemediationCommand = $command
        }
    }
    $results = @($results)
    $results

    $unexpected = @($results | Where-Object { $_.Status -eq 'UnexpectedOwner' })
    $unreadable = @($results | Where-Object { $_.Status -eq 'OwnerUnreadable' })

    if ($unexpected.Count -gt 0) {
        Write-Warning ("{0} of {1} domain controller object(s) have an unexpected owner. Validate each owner, then use the RemediationCommand property to reset it to Domain Admins." -f $unexpected.Count, $results.Count)
    }
    if ($unreadable.Count -gt 0) {
        Write-Warning ("The owner of {0} object(s) could not be read; check permissions of the account running the scan." -f $unreadable.Count)
    }

    if ($unexpected.Count -gt 0 -or $unreadable.Count -gt 0) {
        exit 2
    }
    exit 0
}
catch {
    Write-Error -ErrorAction Continue "Domain controller ownership scan failed: $($_.Exception.Message)"
    exit 1
}
