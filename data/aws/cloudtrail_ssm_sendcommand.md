# AWS CloudTrail: SSM SendCommand

**Vendor:** Amazon Web Services (CloudTrail)
**Sigma category:** aws.cloudtrail
**Event ID:** SendCommand (eventName)

Systems Manager `SendCommand` calls — remote command execution against
managed EC2/on-prem instances via the SSM agent, no SSH or RDP required.
One of the most abused AWS-native techniques for lateral movement and
execution, because it runs entirely through the AWS API and control-plane
logging, not host-level shell logging.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| eventName | eventName | event.action | The specific API action called (e.g., RunInstances, AssumeRole). Set to "Digest" for digest events (AWS) |  |
| eventSource | eventSource | event.provider | AWS service endpoint that received the API call (e.g., ec2.amazonaws.com). Subdomain is extracted to derive cloud.service.name (AWS) |  |
| sourceIPAddress | sourceIPAddress | source.address | IP address or DNS name of the caller. Lowercased; CIDR-validated to split into source.ip (valid IP) or source.domain (hostname like lambda.amazonaws.com) (AWS) |  |
| userIdentity.arn | userIdentity.arn | user.id | Full IAM ARN of the caller (AWS) |  |
| responseElements.command.documentName | responseElements.command.documentName | process.name | SSM document name from SendCommand response. Only populated for ssm dataset. (AWS) |  |
| responseElements.command.commandId | responseElements.command.commandId | process.entity_id | SSM command execution ID from SendCommand response. Only populated for ssm dataset. (AWS) |  |
| errorCode | errorCode | error.code | AWS error code returned on failed API calls (e.g., AccessDenied, UnauthorizedAccess) (AWS) |  |

## Detection notes

`SendCommand` with `responseElements.command.documentName` set to
`AWS-RunShellScript` or `AWS-RunPowerShellScript`, issued by a
`userIdentity.arn` that doesn't normally operate SSM (outside a config-
management/patching automation role), is the primary signal for
credential-compromise-driven remote execution. `responseElements.command
.commandId` is the pivot field — correlate it against the target instance's
own logs (SSM command history, CloudWatch) to recover what the command
actually did, since CloudTrail itself does not log command output or
content.

## Volume notes

Low. SendCommand calls are infrequent relative to data-plane API traffic;
volume spikes align with patch windows or CI/CD deploy runs and are easy to
baseline against.

## References

- https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html
- https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws
