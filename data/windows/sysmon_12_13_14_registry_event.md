# Sysmon Event ID 12/13/14: Registry Event

**Vendor:** Microsoft Sysinternals Sysmon
**Sigma category:** registry_event
**Event ID:** 12 (CreateKey/DeleteKey), 13 (SetValue), 14 (RenameKey)

Three related event IDs sharing one schema, distinguished by `EventType`.
Covers registry-based persistence (Run keys, services) and configuration
tampering (Defender exclusions, LSA protections). Matches DetectionAtlas's
`Event` struct exactly for this category (`TargetObject`, `Details`).

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| EventType | EventType | (no ECS standard field) | CreateKey / DeleteKey / SetValue / RenameKey | |
| Image | Image | process.executable | Process making the registry change | |
| TargetObject | TargetObject | registry.key | Full registry key/value path | Yes |
| Details | Details | registry.value | New value written (Event ID 13 only) | |
| User | User | user.name | Account the process ran as | |

## Detection notes

`TargetObject` containing `\Run\`, `\RunOnce\`, or a known service ImagePath
key is the classic persistence pattern. `Details` is only populated for
SetValue (13); CreateKey/DeleteKey (12) and RenameKey (14) leave it empty.

## Volume notes

High volume: normal application and OS behavior touches the registry
constantly. Scope with an explicit key-path allowlist in the Sysmon config
(persistence-relevant keys only) rather than logging all registry activity.

## References

- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry_event
