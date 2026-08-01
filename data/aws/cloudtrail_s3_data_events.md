# AWS CloudTrail: S3 Data Events

**Vendor:** Amazon Web Services (CloudTrail)
**Sigma category:** aws.cloudtrail
**Event ID:** GetObject / PutObject / DeleteObject (eventName)

Object-level S3 operations. Unlike management events (IAM, console login),
**S3 data events are not logged by default.** They must be explicitly
enabled per-bucket (or per-prefix) as a separate CloudTrail data event
selector, because of the volume and cost involved.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| eventName | eventName | aws.cloudtrail.event_name | GetObject, PutObject, DeleteObject, etc. | Yes |
| eventSource | eventSource | (no ECS standard field) | Always "s3.amazonaws.com" | |
| sourceIPAddress | sourceIPAddress | source.ip | IP address the request originated from | |
| userIdentity.arn | userIdentity.arn | aws.cloudtrail.user_identity.arn | ARN of the principal making the request | |
| requestParameters.bucketName | requestParameters.bucketName | (no ECS standard field) | Target bucket | Yes |
| requestParameters.key | requestParameters.key | (no ECS standard field) | Target object key | Yes |
| requestParameters.Host | requestParameters.Host | host.name | HTTP Host header on S3 signed-URL/virtual-hosted requests; lowercased. Present alongside bucketName/key on signed-URL access | |

## Detection notes

Mass `GetObject` calls across many keys in a short window from one
principal is the primary bulk-exfiltration signal; `GetObject` from a
principal/IP that has never accessed that bucket before is the primary
anomalous-access signal. Neither pattern is expressible as a single Sigma
rule against one event; both need rate/baseline logic on top.

## Volume notes

**Off by default, and high volume once enabled.** Every object
read/write/delete, on every request. AWS's own guidance is to scope data
event logging to specific sensitive buckets/prefixes rather than an
account-wide S3 data event trail; enabling it broadly is one of the most
common CloudTrail cost surprises.

## References

- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html
- https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws
