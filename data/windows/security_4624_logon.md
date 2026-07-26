# Windows Security Event ID 4624: An Account Was Successfully Logged On

**Vendor:** Microsoft Windows Security auditing
**Sigma category:** authentication
**Event ID:** 4624

Fires on every successful logon, local or network. `LogonType` is the
field that makes this event useful: it distinguishes an interactive
console logon from a network logon from an RDP session.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| TargetUserName | TargetUserName | user.name | Account that logged on | |
| TargetDomainName | TargetDomainName | user.domain | Domain of the logged-on account | |
| LogonType | LogonType | winlog.event_data.LogonType (Elastic Windows module field, not core ECS) | Numeric logon type: 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 10=RemoteInteractive (RDP), 11=CachedInteractive | Yes |
| IpAddress | IpAddress | source.ip | Source IP address of the logon, when applicable | |
| WorkstationName | WorkstationName | source.domain | Source workstation name | |
| AuthenticationPackageName | AuthenticationPackageName | (no ECS standard field) | NTLM or Kerberos | |

## Detection notes

`LogonType 3` (network) from an account that never normally logs on over
the network, or `LogonType 10` (RDP) to a host outside its normal jump-box
pattern, are the two highest-signal filters. Pair with 4625 (failed logon)
for brute-force/spray detection; 4624 alone only shows successes.

## Volume notes

One of the highest-volume Security log events in any domain environment:
every interactive logon, every service account authentication, every
scheduled task's service logon. Most SOCs filter to specific `LogonType`
values (3, 10) rather than ingesting all of 4624.

## References

- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
