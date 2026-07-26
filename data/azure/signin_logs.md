# Microsoft Entra ID: Sign-in Logs

**Vendor:** Microsoft Entra ID (Azure AD)
**Sigma category:** azure.signinlogs
**Event ID:** (none; a continuous stream, not a discrete Windows-style event ID)

Records every interactive and non-interactive sign-in to Entra ID-backed
services (Microsoft 365, Azure Portal, any app federated through Entra).
The cloud-identity equivalent of Windows Security 4624.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| userPrincipalName | userPrincipalName | user.email | UPN of the signing-in account | |
| appDisplayName | appDisplayName | (no ECS standard field) | Application the sign-in was for | |
| ipAddress | ipAddress | source.ip | Source IP of the sign-in attempt | |
| status.errorCode | status.errorCode | error.code | 0 = success; nonzero values map to specific failure reasons (e.g. 50126 = bad password) | |
| location.countryOrRegion | location.countryOrRegion | source.geo.country_name | Geolocated country of the source IP | |
| deviceDetail.operatingSystem | deviceDetail.operatingSystem | (no ECS standard field) | OS of the signing-in device | |
| conditionalAccessStatus | conditionalAccessStatus | (no ECS standard field) | success/failure/notApplied for Conditional Access policy evaluation | |
| riskLevelDuringSignIn | riskLevelDuringSignIn | (no ECS standard field) | Identity Protection risk score: none/low/medium/high | |

## Detection notes

`riskLevelDuringSignIn` at medium/high combined with `conditionalAccessStatus:
success` is a strong signal for a risky sign-in that still got through.
Alert on it even when Entra itself didn't block the sign-in. Impossible-travel
detections (two sign-ins for one user, geographically incompatible within
the time delta) need `location` + `ipAddress` correlated across events, not
a single-event Sigma match.

## Volume notes

High volume in any org with more than a handful of users: every
interactive and non-interactive (token refresh, service-to-service) sign-in
is a separate record. Non-interactive sign-ins specifically dominate volume
and are commonly filtered or sampled separately from interactive ones.

## References

- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
- https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-azure-monitor-sign-ins-log-schema
