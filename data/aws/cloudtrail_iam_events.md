# AWS CloudTrail: IAM Management Events

**Vendor:** Amazon Web Services (CloudTrail)
**Sigma category:** aws.cloudtrail
**Event ID:** CreateUser / CreateAccessKey / AttachUserPolicy / PutUserPolicy / CreateLoginProfile (eventName)

Group of related management events sharing `eventSource:
iam.amazonaws.com`. Covers the classic post-compromise IAM persistence
chain: create a new user or access key, then attach an admin-equivalent
policy to it.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| eventName | eventName | aws.cloudtrail.event_name | CreateUser, CreateAccessKey, AttachUserPolicy, PutUserPolicy, CreateLoginProfile | |
| eventSource | eventSource | (no ECS standard field) | Always "iam.amazonaws.com" | |
| sourceIPAddress | sourceIPAddress | source.ip | IP address the API call originated from | |
| userIdentity.arn | userIdentity.arn | aws.cloudtrail.user_identity.arn | ARN of the principal making the call | |
| requestParameters.userName | requestParameters.userName | (no ECS standard field) | Target IAM user name being created/modified | |
| requestParameters.policyArn | requestParameters.policyArn | (no ECS standard field) | Policy being attached (AttachUserPolicy only) | |
| errorCode | errorCode | error.code | Present only on denied/failed API calls | |

## Detection notes

The chain `CreateUser` → `CreateAccessKey` → `AttachUserPolicy` with
`policyArn: arn:aws:iam::aws:policy/AdministratorAccess`, all from the same
`userIdentity.arn` within a short window, is a near-canonical IAM
persistence pattern and one of the highest-fidelity multi-event
correlations in cloud detection.

## Volume notes

Low to moderate. IAM changes are infrequent relative to data-plane API
calls (S3, EC2). Safe to retain in full; this is a case where the raw
volume is low precisely because the events are administratively rare.

## References

- https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html
- https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws
