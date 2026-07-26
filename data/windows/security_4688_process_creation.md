# Windows Security Event ID 4688: A New Process Has Been Created

**Vendor:** Microsoft Windows Security auditing
**Sigma category:** process_creation
**Event ID:** 4688

The native Windows Security log equivalent of Sysmon Event ID 1, generated
when "Audit Process Creation" is enabled via Group Policy. The one field
that makes it as useful as Sysmon (`ProcessCommandLine`) is off by default
and needs a separate registry setting.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| NewProcessName | Image | process.executable | Full path of the started executable | |
| ProcessCommandLine | CommandLine | process.command_line | Command line, empty unless a second policy is enabled (see notes) | |
| CreatorProcessName | ParentImage | process.parent.executable | Full path of the parent process | |
| SubjectUserName | User | user.name | Account that created the process | |
| TokenElevationType | (no Sigma standard field) | (no ECS standard field) | TokenElevationTypeDefault/Limited/Full, the UAC elevation state | |
| NewProcessId | ProcessId | process.pid | PID of the new process | |
| ProcessId | ParentProcessId | process.parent.pid | PID of the creator (parent) process | |

## Detection notes

`ProcessCommandLine` only populates when
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled`
is set to 1, in addition to enabling the audit subcategory itself. This is
a common gap where 4688 is "on" but command lines are silently missing and
Image/ParentImage-only detections are all that actually fire.

## Volume notes

Same order of magnitude as Sysmon Event ID 1: every process on the host.
Useful when Sysmon can't be deployed (native to Windows, no additional
install), but carries the same volume cost and the same need for
parent/child noise filtering.

## References

- https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
