# GCP Cloud Audit Logs: Data Access

**Vendor:** Google Cloud Platform
**Sigma category:** gcp.audit
**Event ID:** (none; identified by protoPayload.methodName per call)

Records read operations and data-plane API calls (e.g. reading an object
from a bucket, querying a BigQuery table). Same schema as Admin Activity
logs, different `logName` and a different default-enabled state.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| protoPayload.methodName | protoPayload.methodName | event.action | API method called, e.g. "storage.objects.get" | Yes |
| protoPayload.authenticationInfo.principalEmail | protoPayload.authenticationInfo.principalEmail | user.email | Identity that made the call | |
| protoPayload.resourceName | protoPayload.resourceName | (no ECS standard field) | Full resource name accessed | Yes |
| protoPayload.requestMetadata.callerIp | protoPayload.requestMetadata.callerIp | source.ip | Source IP of the API call | |
| protoPayload.serviceName | protoPayload.serviceName | (no ECS standard field) | GCP service the call targeted | |

## Detection notes

Mirrors the AWS S3 data-events bulk-read pattern: many `storage.objects.get`
calls across distinct object names from one principal in a short window is
the primary exfiltration signal, and it requires the same rate/baseline
logic on top of the raw event that the AWS case does.

## Volume notes

Disabled by default for most services, with BigQuery as the notable
exception (its Data Access logs are on by default). Enabling this broadly
across storage/compute services produces high volume, on the order of
every read call; Google's own guidance is to scope it to specific services
and export destinations rather than enabling it project-wide.

## References

- https://cloud.google.com/logging/docs/audit/understanding-audit-logs
- https://cloud.google.com/logging/docs/audit/configure-data-access
