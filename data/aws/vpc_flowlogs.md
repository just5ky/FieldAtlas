# AWS VPC Flow Logs

**Vendor:** Amazon Web Services (VPC Flow Logs)
**Sigma category:** aws.vpcflow
**Event ID:** N/A (network flow record, not a discrete API event)

Captures metadata about IP traffic flowing to and from network interfaces
within a VPC: source/destination IPs, ports, protocol, byte/packet counts,
and whether traffic was accepted or rejected. One record covers an
aggregation window (`start`–`end`), not a single packet — this is the
default (version 2) field set, not the full custom-format schema AWS also
supports. Sigma rules match on these raw record field names directly, so
the native and Sigma name columns are identical.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| version | version | (no ECS standard field) | Flow log version |  |
| account-id | account-id | cloud.account.id |  |  |
| interface-id | interface-id | (no ECS standard field) | No matching ECS property |  |
| srcaddr | srcaddr | source.address, source.ip |  | Yes |
| dstaddr | dstaddr | destination.address, destination.ip |  | Yes |
| srcport | srcport | source.port |  | Yes |
| dstport | dstport | destination.port |  | Yes |
| protocol | protocol | network.iana_number | IANA protocol number |  |
| packets | packets | network.packets |  | Yes |
| bytes | bytes | network.bytes |  | Yes |
| start | start | event.start |  |  |
| end | end | event.end |  |  |
| action | action | event.action | accept or reject |  |
| log-status | log-status | (no ECS standard field) | OK, nodata, or skipdata |  |

## Detection notes

`action: REJECT` repeated across many distinct `dstport` values from one
`srcaddr` in a short window is port-scanning; the same pattern from one
`dstaddr` across many `srcaddr` values is the target-side view of a scan or
a distributed brute force against a single exposed service. `dstport`
values for known C2/tunneling ports (4444, 8080, 8443 alongside unexpected
`bytes`/`packets` ratios — many small packets vs. few large ones) is a
secondary heuristic for beaconing, best paired with Sysmon Event ID 3 /
DNS query events when the destination is also visible at the host level.
Flow logs alone give no process or user attribution — correlate `srcaddr`
against instance/ENI ownership to get there.

## Volume notes

High volume by default once enabled account-wide: every accepted and
rejected flow, on every monitored ENI. `srcaddr`/`dstaddr`/`srcport`/
`dstport`/`bytes`/`packets` are the high-cardinality fields driving storage
cost. Scope to specific VPCs/subnets of interest, or aggregate before
long-term retention, rather than shipping raw flow logs account-wide to a
SIEM.

## References

- https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
- https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
- https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws
