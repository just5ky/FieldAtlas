# CrowdStrike Falcon: ProcessRollup2

**Vendor:** CrowdStrike Falcon (Next-Gen SIEM)
**Sigma category:** crowdstrike.processrollup2
**Event ID:** ProcessRollup2

Falcon sensor event generated for a process that is running or has finished
running on a host. The Falcon equivalent of Sysmon Event ID 1 (process
creation): nearly every process-based technique surfaces here first.
Reported once when the process starts and again as a matching completion
event when it exits. Fields below are raw sensor field names; CrowdStrike
Sigma rules match on these directly, so the native and Sigma name columns
are identical.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| ImageFileName | ImageFileName | (no ECS standard field) | The full path to an executable (PE) file. The context of this field provides more information as to its meaning. For events, this is the full path to the main executable for the created process (MacOS,Windows) |  |
| OriginalFilename | OriginalFilename | (no ECS standard field) | The OriginalFilename of the PE, extracted from VersionInfo resource (Windows) |  |
| CommandLine | CommandLine | (no ECS standard field) | The command line used to create this process. May be empty in some circumstances. Visit CreateProcessA Function for more information (MacOS,Windows) |  |
| ParentBaseFileName | ParentBaseFileName | (no ECS standard field) | The base of the parent process (MacOS,Windows) |  |
| ParentProcessId | ParentProcessId | (no ECS standard field) | The decimal representation of the parent process (MacOS,Windows) |  |
| TargetProcessId | TargetProcessId | (no ECS standard field) | The unique ID of a target process (in decimal, non-hex format). This field exists in almost all events, and it represents the ID of the process that is responsible for the activity of the event in focus. For example, the TargetProcessId of a process that performed threat injection in an InjectedThread event (MacOS,Windows) |  |
| UserName | UserName | (no ECS standard field) | Operating system username (MacOS) |  |
| UserSid | UserSid | (no ECS standard field) | The User Security Identifier (UserSID) of the user who executed the command. A UserSID uniquely identifies a user in a system (MacOS) |  |
| SHA256HashData | SHA256HashData | (no ECS standard field) | The SHA256 has of a file. In most cases, the hash of the file referred to by the field (MacOS,Windows) |  |
| IntegrityLevel | IntegrityLevel | (no ECS standard field) | Indicates the Mandatory Integrity Control (MIC) level assigned to a process access token. Integrity levels enforce a "no-write-up" policy where lower-integrity processes cannot modify higher-integrity objects, providing defense-in-depth beyond discretionary access controls. (Windows) |  |
| TokenType | TokenType | (no ECS standard field) | Indicates the type of access token associated with the process. Primary tokens are assigned to processes, while impersonation tokens allow threads to temporarily assume a different security context. (Windows) |  |
| ProcessStartTime | ProcessStartTime | (no ECS standard field) | The time the process began in UNIX epoch time (in decimal, non-hex format) (MacOS,Windows) |  |

## Detection notes

Match on `ImageFileName` + `ParentBaseFileName` + `CommandLine` together,
same principle as Sysmon Event ID 1: a benign, signed binary launched with a
malicious command line (LOLBin patterns via rundll32/mshta/certutil
equivalents) is the common evasion shape, and `ImageFileName` alone won't
catch it. `OriginalFilename` mismatched against `ImageFileName` (e.g. a
file named `svchost.exe` whose PE resource claims a different original
name) is a strong renamed-binary signal Sysmon doesn't expose as cleanly.
`IntegrityLevel` jumping between a process and its parent, combined with
`TokenType` showing an impersonation token, is worth correlating for
privilege-escalation and token-theft detections.

## Volume notes

Highest-volume CrowdStrike event on most endpoints: every process spawn,
on every host. Pre-filter before shipping to a downstream SIEM: exclude
known noisy parent/child pairs and short-lived system utility spawns rather
than dropping the event type outright, same tradeoff as Sysmon Event ID 1.

## References

- https://docs.crowdstrike.com/r/processrollup2
- https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type
