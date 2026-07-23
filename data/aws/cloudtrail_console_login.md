# AWS CloudTrail: ConsoleLogin

**Vendor:** Amazon Web Services (CloudTrail)
**Sigma category:** aws.cloudtrail
**Event ID:** ConsoleLogin (eventName)

Management event recorded by CloudTrail for every AWS Management Console
sign-in attempt. AWS Sigma rules match on the raw CloudTrail JSON field
names directly (no separate normalized name), so the "native" and "Sigma
name" columns below are identical.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| eventName | eventName | aws.cloudtrail.event_name | Always "ConsoleLogin" for this event | |
| eventSource | eventSource | (no ECS standard field) | Always "signin.amazonaws.com" | |
| sourceIPAddress | sourceIPAddress | source.ip | IP address the sign-in originated from | |
| userIdentity.arn | userIdentity.arn | aws.cloudtrail.user_identity.arn | ARN of the IAM principal signing in | |
| userIdentity.accountId | userIdentity.accountId | cloud.account.id | AWS account ID | |
| responseElements.ConsoleLogin | responseElements.ConsoleLogin | event.outcome (Success maps to success, Failure to failure) | Success or Failure | |
| additionalEventData.MFAUsed | additionalEventData.MFAUsed | (no ECS standard field) | Yes/No, whether MFA was used | |

## Detection notes

`responseElements.ConsoleLogin: Failure` repeated across many source IPs
for one `userIdentity.arn` is credential stuffing; `MFAUsed: No` for a
console login on an account that is supposed to require MFA is a policy
violation worth alerting on directly, independent of failure/success.

## Volume notes

Low volume relative to other CloudTrail events. Console sign-ins are
infrequent compared to API calls. Safe to retain in full.

## References

- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html
- https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws
