# AD-DCOwnership-Scan

`Scan-DomainControllerOwnership.ps1` checks who owns the domain controller computer objects in an
Active Directory domain and reports every object that is not owned by Domain Admins (of the target
domain) or Enterprise Admins (of the forest root domain).

The owner of an AD object can always rewrite its permissions. A domain controller computer object owned
by an ordinary user or a helpdesk/deployment account is therefore a direct path to domain compromise.
This usually happens when a DC was pre-staged or joined by a delegated account before promotion.

The script only reads from Active Directory. For each object with an unexpected owner it generates a
one-line remediation command that you can review and run yourself.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- ActiveDirectory PowerShell module (RSAT or a domain controller installation)
- Any domain account can run the scan; running the remediation commands requires Domain Admins or
  Enterprise Admins rights (Tier 0) and should be done from a secure admin host

## Usage

```powershell
.\Scan-DomainControllerOwnership.ps1 -Domain example.com
```

```text
Name            Status          Owner                 OwnerSid
----            ------          -----                 --------
dc1.example.com OK              EXAMPLE\Domain Admins S-1-5-21-...-512
dc2.example.com UnexpectedOwner EXAMPLE\deploy-svc    S-1-5-21-...-1105
```

Another domain, with explicit credentials:

```powershell
$Credential = Get-Credential
.\Scan-DomainControllerOwnership.ps1 -Domain child.example.com -Credential $Credential
```

Only the remediation commands:

```powershell
.\Scan-DomainControllerOwnership.ps1 -Domain example.com |
    Where-Object Status -eq 'UnexpectedOwner' |
    Select-Object -ExpandProperty RemediationCommand
```

If the scan used `-Credential`, the generated commands reference a `$Credential` variable, so define it in
the session where you run them. Validate each unexpected owner before resetting it, and test the command
on one object first.

## How it works

- Domain controllers are found by `primaryGroupID` 516 (writable DC), 521 (read-only DC) or the
  `SERVER_TRUST_ACCOUNT` flag in `userAccountControl`. This also catches DC computer accounts that have
  no server object in Sites and are therefore missing from `Get-ADDomainController`.
- The owner SID is read from `nTSecurityDescriptor` and compared with the Domain Admins SID of the target
  domain and the Enterprise Admins SID of the forest root domain.
- Objects whose security descriptor cannot be read are reported as `OwnerUnreadable`.

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

MIT, see [LICENSE](LICENSE).
