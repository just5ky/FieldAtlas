# Sysmon Event ID 22: DNS Query

**Vendor:** Microsoft Sysinternals Sysmon
**Sigma category:** dns_query
**Event ID:** 22

Fires when a process resolves a domain name, regardless of whether the
resolution succeeds. Available since Sysmon 8.0.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| Image | Image | process.executable | Process performing the lookup | |
| QueryName | QueryName | dns.question.name | Domain name being resolved | Yes |
| QueryStatus | QueryStatus | dns.response_code | Windows error code of the resolution (0 = success) | |
| QueryResults | QueryResults | dns.answers.data | Resolved IP address(es), semicolon-separated | |
| User | User | user.name | Account the process ran as | |

## Detection notes

Catches DNS-based C2 and DGA (domain generation algorithm) beaconing
before the process ever opens a network connection, and catches lookups
that fail (NXDOMAIN storms from a DGA) that Event ID 3 would never show
since a failed resolution has no connection to log.

## Volume notes

High volume: every process, every domain lookup, including OS
telemetry and background app checks. Typical mitigation: correlate against
a known-good domain allowlist/threat-intel blocklist at ingest rather than
shipping raw.

## References

- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/dns_query
