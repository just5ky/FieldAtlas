# GCP Cloud Audit Logs: Admin Activity

**Vendor:** Google Cloud Platform
**Sigma category:** gcp.audit
**Event ID:** (none; identified by protoPayload.methodName per call)

Records every API call that creates, modifies, or deletes a GCP resource's
configuration. Always enabled, cannot be disabled or configured. The GCP
equivalent of AWS CloudTrail management events and Azure Activity Log.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| protoPayload.methodName | protoPayload.methodName | event.action | API method called, e.g. "SetIamPolicy" | |
| protoPayload.authenticationInfo.principalEmail | protoPayload.authenticationInfo.principalEmail | user.email | Identity that made the call | |
| protoPayload.resourceName | protoPayload.resourceName | (no ECS standard field) | Full resource name affected | |
| protoPayload.requestMetadata.callerIp | protoPayload.requestMetadata.callerIp | source.ip | Source IP of the API call | |
| protoPayload.serviceName | protoPayload.serviceName | (no ECS standard field) | GCP service the call targeted, e.g. "compute.googleapis.com" | |
| severity | severity | log.level | NOTICE for most admin actions | |

## Detection notes

`SetIamPolicy` calls that grant `roles/owner` or `roles/editor` outside a
known automation service account are the direct GCP analog of the AWS
IAM-persistence and Azure role-assignment patterns in this catalog. Same
cross-cloud shape, different field names, the exact gap this reference
exists to close.

## Volume notes

Low to moderate. Configuration changes are infrequent relative to data
access, and this log type is always on regardless of volume since it
cannot be disabled.

## References

- https://cloud.google.com/logging/docs/audit
- https://cloud.google.com/logging/docs/audit/understanding-audit-logs
