# AWS CloudTrail: STS AssumeRole

**Vendor:** Amazon Web Services (CloudTrail)
**Sigma category:** aws.cloudtrail
**Event ID:** AssumeRole / AssumeRoleWithSAML / AssumeRoleWithWebIdentity (eventName)

STS role-assumption calls — the mechanism behind every cross-account access,
federated login, and temporary-credential grant in AWS. `eventSource` is
always `sts.amazonaws.com`. The primary AWS-native path for both legitimate
cross-account workflows and privilege-escalation/lateral-movement after an
initial credential compromise.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| eventName | eventName | event.action | The specific API action called (e.g., RunInstances, AssumeRole). Set to "Digest" for digest events (AWS) |  |
| eventSource | eventSource | event.provider | AWS service endpoint that received the API call (e.g., ec2.amazonaws.com). Subdomain is extracted to derive cloud.service.name (AWS) |  |
| sourceIPAddress | sourceIPAddress | source.address | IP address or DNS name of the caller. Lowercased; CIDR-validated to split into source.ip (valid IP) or source.domain (hostname like lambda.amazonaws.com) (AWS) |  |
| userIdentity.arn | userIdentity.arn | user.id | Full IAM ARN of the caller (AWS) |  |
| requestParameters.roleArn | requestParameters.roleArn | user.target.roles | Target role ARN for role assumption actions. Primarily populated in sts dataset (AssumeRole, AssumeRoleWithSAML, AssumeRoleWithWebIdentity). (AWS) |  |
| requestParameters.roleSessionName | requestParameters.roleSessionName | (no ECS standard field) | Session identifier set by the caller during role assumption. Can reveal tooling (e.g., i- = EC2 instance, Botocore = SDK, @ = SSO user). Available as Vendor.requestParameters.roleSessionName. (AWS) |  |
| requestParameters.externalId | requestParameters.externalId | (no ECS standard field) | Cross-account trust verification token. Absence when required by the role's trust policy indicates misconfiguration or unauthorized assumption attempt. (AWS) |  |
| requestParameters.durationSeconds | requestParameters.durationSeconds | (no ECS standard field) | Requested session duration in seconds. Long durations (>3600) may indicate persistence intent. Default is 3600 (1 hour), max varies by role config. (AWS) |  |
| requestParameters.sourceIdentity | requestParameters.sourceIdentity | (no ECS standard field) | Original caller identity preserved through role chains. Critical for attribution when roles are chained (A→B→C). Set once and cannot be changed in subsequent assumptions. (AWS) |  |
| responseElements.credentials.accessKeyId | responseElements.credentials.accessKeyId | (no ECS standard field) | Temporary access key ID (ASIA* prefix) returned from STS. Use to track subsequent API activity performed with the assumed role's credentials. (AWS) |  |
| errorCode | errorCode | error.code | AWS error code returned on failed API calls (e.g., AccessDenied, UnauthorizedAccess) (AWS) |  |

## Detection notes

`userIdentity.arn` assuming a `requestParameters.roleArn` it has never
assumed before, especially cross-account, is the primary anomalous-assumption
signal. Missing `requestParameters.externalId` on a role whose trust policy
requires one indicates a misconfigured trust boundary or a probing attempt.
`requestParameters.durationSeconds` above 3600 is unusual and can indicate an
attacker requesting a long-lived session to outlast short-TTL detection
windows. `requestParameters.sourceIdentity` is set once and survives role
chains (A→B→C); use it to keep attribution when an attacker pivots through
multiple assumed roles. `responseElements.credentials.accessKeyId` (the
`ASIA*` temp key) is the pivot field for tracking everything the assumed
role does afterward — correlate it against subsequent CloudTrail events.

## Volume notes

Low to moderate for a single account; high in environments with heavy
service-to-service role assumption (Lambda execution roles, CI/CD pipelines
assuming deploy roles) since each invocation is a separate AssumeRole call.
Baseline the normal `userIdentity.arn` → `roleArn` pairs per environment
before alerting on new pairs, or the volume of legitimate automation will
drown the signal.

## References

- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws
