# AD-DCOwnership-Scan

`Scan-DomainControllerOwnership.ps1` checks who owns the domain controller computer objects in an
Active Directory domain and reports every object that is not owned by Domain Admins (of the target
domain), Enterprise Admins (of the forest root domain) or BUILTIN\Administrators.

The owner of an AD object can always rewrite its permissions. A domain controller computer object owned
by an ordinary user or a helpdesk/deployment account is therefore a direct path to domain compromise.
This usually happens when the computer account of a DC was pre-staged or joined by a delegated account
before promotion: the account that creates an object becomes its owner.

The script only reads from Active Directory. For each object with an unexpected owner it generates a
one-line remediation command that you can review and run yourself.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- ActiveDirectory PowerShell module (RSAT or a domain controller installation)
- Any domain account can run the scan; running the remediation commands requires Domain Admins or
  Enterprise Admins rights (Tier 0) and should be done from a secure admin host

## Usage

```powershell
.\Scan-DomainControllerOwnership.ps1 -Domain example.com | Format-Table Name, Status, Owner
```

```text
WARNING: 1 of 3 domain controller object(s) have an unexpected owner. Validate each owner, then use the
RemediationCommand property to reset it to Domain Admins.

Name             Status          Owner
----             ------          -----
dc1.example.com  OK              EXAMPLE\Domain Admins
dc2.example.com  OK              BUILTIN\Administrators
rodc.example.com UnexpectedOwner EXAMPLE\deploy-svc
```

Without `Format-Table`, PowerShell shows the full objects as a list.

Another domain, with explicit credentials:

```powershell
$Credential = Get-Credential
.\Scan-DomainControllerOwnership.ps1 -Domain child.example.com -Credential $Credential
```

Scheduled or automated runs can rely on the exit code (see below), for example:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Scan-DomainControllerOwnership.ps1" `
  -Domain example.com
```

### Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `-Domain` | yes | DNS name of the target domain (or a domain controller in it); used as `-Server` for all queries |
| `-Credential` | no | Credential for the target domain |

## Remediation

Print the remediation commands for objects with an unexpected owner:

```powershell
.\Scan-DomainControllerOwnership.ps1 -Domain example.com |
    Where-Object Status -eq 'UnexpectedOwner' |
    Select-Object -ExpandProperty RemediationCommand
```

Each command reads the security descriptor of one object, sets Domain Admins of the target domain as
owner and writes it back with `Set-ADObject`:

```powershell
$sd = (Get-ADObject -Identity 'CN=RODC,OU=Domain Controllers,DC=example,DC=com' -Properties nTSecurityDescriptor -Server 'example.com').nTSecurityDescriptor; $sd.SetOwner([System.Security.Principal.SecurityIdentifier]'S-1-5-21-...-512'); Set-ADObject -Identity 'CN=RODC,OU=Domain Controllers,DC=example,DC=com' -Replace @{ nTSecurityDescriptor = $sd } -Server 'example.com'
```

1. Validate that each reported owner is really wrong for your environment.
2. Run one command first, then re-run the scan and confirm that the object reports `OK`.
3. Run the remaining commands one at a time, from a secure admin host with a Tier 0 account.

If the scan used `-Credential`, the generated commands reference a `$Credential` variable, so define it in
the session where you run them.

## How it works

- Domain controllers are found by `primaryGroupID` 516 (writable DC), 521 (read-only DC) or the
  `SERVER_TRUST_ACCOUNT` flag in `userAccountControl`. This also catches DC computer accounts that have
  no server object in Sites and are therefore missing from `Get-ADDomainController`.
- The owner SID is read from `nTSecurityDescriptor` and compared with the Domain Admins SID of the target
  domain, the Enterprise Admins SID of the forest root domain and BUILTIN\Administrators (S-1-5-32-544).
  In a child domain the root domain SID is read from a domain controller of the root domain.
- Objects whose security descriptor cannot be read are reported as `OwnerUnreadable`.
- Owner SIDs are translated to names on the machine running the script; SIDs that cannot be resolved are
  shown as SIDs.

## Output

One object per domain controller computer object:

| Property | Description |
| --- | --- |
| `Name` | DNS host name (or the object name if it has none) |
| `DistinguishedName` | Distinguished name of the computer object |
| `Status` | `OK`, `UnexpectedOwner` or `OwnerUnreadable` |
| `Owner` | Owner account name (SID if it cannot be resolved) |
| `OwnerSid` | Owner SID |
| `RemediationCommand` | Command that resets the owner to Domain Admins (`UnexpectedOwner` only) |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | All domain controller objects have an expected owner |
| 1 | Error (module missing, domain unreachable, query failed) |
| 2 | At least one object has an unexpected or unreadable owner |

## License

[MIT](LICENSE)
