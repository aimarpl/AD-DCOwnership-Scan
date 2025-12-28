<#
.SYNOPSIS
Scans domain controllers in a specified Active Directory domain and reports non-default object ownership.

.DESCRIPTION
This script enumerates all domain controllers in the provided domain, inspects the owner of each domain controller's
computer object, and identifies objects that are not owned by Domain Admins or Enterprise Admins. For any deviations,
it emits one-line remediation commands that will reset ownership to the Domain Admins group of the target domain.

.EXAMPLE
PS> .\Scan-DomainControllerOwnership.ps1 -Domain ad.contoso.com

.EXAMPLE
PS> $cred = Get-Credential
PS> .\Scan-DomainControllerOwnership.ps1 -Domain ad.contoso.com -Credential $cred

.NOTES
Run from an elevated PowerShell session using a highly privileged (Tier 0) account that is a member of Domain Admins or
Enterprise Admins in the target domain. The ActiveDirectory module must be available on the host running this script.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential
)

function Get-AllowedOwnerSids {
    param(
        [string]$Domain,
        [hashtable]$AdParams
    )

    $domainInfo = Get-ADDomain @AdParams
    $forestInfo = Get-ADForest @AdParams
    $rootDomainInfo = Get-ADDomain -Identity $forestInfo.RootDomain @AdParams

    $domainAdminsSid = "$($domainInfo.DomainSID)-512"
    $enterpriseAdminsSid = "$($rootDomainInfo.DomainSID)-519"

    return [ordered]@{
        Allowed = @($domainAdminsSid, $enterpriseAdminsSid) | Select-Object -Unique
        Preferred = $domainAdminsSid
    }
}

function Resolve-AccountName {
    param(
        [string]$Sid
    )

    try {
        return ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        return $Sid
    }
}

Import-Module ActiveDirectory -ErrorAction Stop

$adParams = @{ Server = $Domain }
if ($Credential) {
    $adParams.Credential = $Credential
}

$ownerInfo = Get-AllowedOwnerSids -Domain $Domain -AdParams $adParams
$allowedOwners = $ownerInfo.Allowed
$preferredOwner = $ownerInfo.Preferred

$domainControllers = Get-ADDomainController -Filter * @adParams

$unexpectedOwners = foreach ($dc in $domainControllers) {
    $adObject = Get-ADObject -Identity $dc.ComputerObjectDN -Properties nTSecurityDescriptor @adParams
    $ownerSid = $adObject.nTSecurityDescriptor.Owner.Value

    if ($allowedOwners -notcontains $ownerSid) {
        [PSCustomObject]@{
            Name               = $dc.HostName
            DistinguishedName  = $dc.ComputerObjectDN
            OwnerSid           = $ownerSid
            Owner              = Resolve-AccountName -Sid $ownerSid
        }
    }
}

Write-Host "`nScan target domain: $Domain" -ForegroundColor Cyan
Write-Host "Total domain controllers found: $($domainControllers.Count)"

if (-not $unexpectedOwners) {
    Write-Host "All domain controller computer objects are owned by default privileged groups (Domain Admins / Enterprise Admins)." -ForegroundColor Green
    return
}

Write-Host "Domain controllers with unexpected ownership:" -ForegroundColor Yellow
$unexpectedOwners | Format-Table Name, Owner, DistinguishedName -AutoSize

Write-Host "`nRemediation commands (run individually):" -ForegroundColor Cyan
foreach ($entry in $unexpectedOwners) {
    $credentialFragment = if ($Credential) { " -Credential `$Credential" } else { "" }
    $command = "$sd = (Get-ADObject -Identity `\"$($entry.DistinguishedName)`\" -Properties nTSecurityDescriptor -Server `\"$Domain`\"$credentialFragment).nTSecurityDescriptor; $sd.SetOwner([System.Security.Principal.SecurityIdentifier]`\"$preferredOwner`\"); Set-Acl -AclObject $sd -Path `\"AD:\\$($entry.DistinguishedName)`\""
    Write-Host $command
}

Write-Host "`nExecution guidelines:" -ForegroundColor White
Write-Host "- Run from an elevated PowerShell session on a secure management host." -ForegroundColor White
Write-Host "- Use a Tier 0 account with Domain Admins or Enterprise Admins rights in the target domain." -ForegroundColor White
Write-Host "- Ensure the ActiveDirectory module is installed and you can reach the domain controllers for $Domain." -ForegroundColor White
Write-Host "- Execute each remediation command only after validating the unexpected owner is incorrect for your environment." -ForegroundColor White
