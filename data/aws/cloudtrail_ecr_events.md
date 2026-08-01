# AWS CloudTrail: ECR Image Events

**Vendor:** Amazon Web Services (CloudTrail)
**Sigma category:** aws.cloudtrail
**Event ID:** PutImage / BatchGetImage / BatchDeleteImage (eventName)

Elastic Container Registry image push/pull/delete activity. `eventSource`
is always `ecr.amazonaws.com`. The only CloudTrail dataset that populates
`container.*` ECS fields, relevant for supply-chain detections (an
unexpected principal pushing an image, or pushing to a repository outside
its normal deploy pipeline).

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| eventName | eventName | event.action | The specific API action called (e.g., RunInstances, AssumeRole). Set to "Digest" for digest events (AWS) |  |
| eventSource | eventSource | event.provider | AWS service endpoint that received the API call (e.g., ec2.amazonaws.com). Subdomain is extracted to derive cloud.service.name (AWS) |  |
| sourceIPAddress | sourceIPAddress | source.address | IP address or DNS name of the caller. Lowercased; CIDR-validated to split into source.ip (valid IP) or source.domain (hostname like lambda.amazonaws.com) (AWS) |  |
| userIdentity.arn | userIdentity.arn | user.id | Full IAM ARN of the caller (AWS) |  |
| requestParameters.repositoryName | requestParameters.repositoryName | container.image.name | ECR repository name. Only populated for ecr* datasets. (AWS) |  |
| requestParameters.imageIds[].imageTag | requestParameters.imageIds[].imageTag | container.image.tag | Array of ECR image tags (e.g., latest, v1.2.3). Only populated for ecr* datasets. (AWS) |  |
| requestParameters.imageIds[].imageDigest | requestParameters.imageIds[].imageDigest | container.image.hash.all[] | Array of ECR image digest hashes. Only populated for ecr* datasets. (AWS) |  |
| errorCode | errorCode | error.code | AWS error code returned on failed API calls (e.g., AccessDenied, UnauthorizedAccess) (AWS) |  |

## Detection notes

`PutImage` from a `userIdentity.arn` outside the known CI/CD deploy role, or
outside normal build-pipeline hours, is the primary signal for a
compromised-pipeline or supply-chain push. Tag reuse (a new `imageDigest`
pushed under an existing, previously-deployed `imageTag`, e.g. `latest` or
a release tag) is a classic technique for swapping a running workload's
image without changing the reference consumers pull by name; alert when a
tag's digest changes outside a release window.

## Volume notes

Low. Image pushes/pulls happen on deploy cadence, not per-request; safe to
retain in full. Volume rises only in environments with very high deploy
frequency (multiple pushes per minute across many repositories).

## References

- https://docs.aws.amazon.com/AmazonECR/latest/APIReference/Welcome.html
- https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws
