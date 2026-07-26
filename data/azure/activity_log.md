# Azure Activity Log

**Vendor:** Microsoft Azure
**Sigma category:** azure.activitylogs
**Event ID:** (none; a continuous stream, not a discrete Windows-style event ID)

Subscription-level control-plane audit trail: every write operation
(create, update, delete) against Azure resources via ARM, the Portal, or
the CLI. The Azure equivalent of AWS CloudTrail management events.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| operationName | operationName | event.action | ARM operation, e.g. "Microsoft.Compute/virtualMachines/write" | |
| caller | caller | user.email | UPN or app ID of the principal that made the call | |
| resourceId | resourceId | (no ECS standard field) | Full ARM resource ID affected | |
| subscriptionId | subscriptionId | cloud.account.id | Azure subscription the operation ran against | |
| status.value | status.value | event.outcome | Succeeded/Failed/Started | |
| eventTimestamp | eventTimestamp | @timestamp | When the operation occurred | |

## Detection notes

A role assignment write (`Microsoft.Authorization/roleAssignments/write`)
granting Owner or Contributor to a principal outside change management is
the direct analog of the AWS IAM persistence pattern in this log. `caller`
values that are service principals rather than named users deserve a
stricter allowlist since automation accounts are a common lateral-movement
target once compromised.

## Volume notes

Moderate volume: every write operation across the subscription, but read
operations aren't included, which keeps this well below data-plane log
volumes. Safe to retain in full for most subscriptions.

## References

- https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log
- https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema
