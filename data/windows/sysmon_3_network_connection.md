# Sysmon Event ID 3: Network Connection

**Vendor:** Microsoft Sysinternals Sysmon
**Sigma category:** network_connection
**Event ID:** 3

Fires on TCP/UDP network connections initiated or accepted by a monitored
process. Disabled by default in a minimal Sysmon config (high volume);
must be explicitly enabled via `<NetworkConnect onmatch="...">`.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| Image | Image | process.executable | Process that owns the connection | |
| User | User | user.name | Account the process ran as | |
| Protocol | Protocol | network.transport | tcp or udp | |
| Initiated | Initiated | (no ECS standard field) | true if the local host initiated the connection | |
| SourceIp | SourceIp | source.ip | Local IP address | Yes |
| SourcePort | SourcePort | source.port | Local port | Yes |
| DestinationIp | DestinationIp | destination.ip | Remote IP address | Yes |
| DestinationPort | DestinationPort | destination.port | Remote port | Yes |
| DestinationHostname | DestinationHostname | destination.domain | Reverse-resolved remote hostname, if available | |

## Detection notes

Best paired with `Image`/`ParentImage` from Event ID 1 via ProcessGuid
correlation. A network connection from an unexpected process (e.g.
mshta.exe reaching out to a raw IP on a high port) is far more actionable
than the connection alone. C2 beaconing detections rely on this event plus
timing analysis outside what Sigma's per-event matching can express.

## Volume notes

One of the noisiest Sysmon event types once enabled: every outbound and
inbound connection, including normal browser/update traffic. Filter by
process allowlist (browsers, update services) or destination port
denylist before shipping to a SIEM at scale; do not enable org-wide without
a filtering plan.

## References

- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/network_connection
