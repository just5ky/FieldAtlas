# Windows Security Event ID 4720: A User Account Was Created

**Vendor:** Microsoft Windows Security auditing
**Sigma category:** authentication
**Event ID:** 4720

Fires when a local or domain user account is created. Low volume, high
signal: persistence via a rogue local admin account or a domain user
created outside change-management hours shows up here directly.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| SubjectUserName | SubjectUserName | user.name | Account that performed the creation | |
| TargetUserName | TargetUserName | user.target.name | Name of the newly created account | |
| TargetDomainName | TargetDomainName | user.target.domain | Domain the new account was created in | |
| SamAccountName | SamAccountName | (no ECS standard field) | SAM account name of the new user | |
| PrivilegeList | PrivilegeList | (no ECS standard field) | Privileges assigned at creation, if any | |

## Detection notes

Correlate `SubjectUserName` against an expected admin allowlist. Account
creation performed by anyone outside that list, or performed via a service
account that shouldn't have interactive rights, is the primary signal.
Pairs naturally with 4732/4728 (member added to a privileged group) to
catch "create user, then immediately add to Domain Admins."

## Volume notes

Low volume in a stable environment: user creation is an infrequent
administrative action. Safe to ingest in full; no filtering needed.

## References

- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720
