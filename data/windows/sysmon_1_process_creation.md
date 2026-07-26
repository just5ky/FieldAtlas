# Sysmon Event ID 1: Process Creation

**Vendor:** Microsoft Sysinternals Sysmon
**Sigma category:** process_creation
**Event ID:** 1

Fires when a new process starts, before the process runs any of its own
code. The single highest-value Sysmon event for endpoint detection: nearly
every process-based technique (LOLBins, credential dumping, encoded
PowerShell) shows up here first.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| Image | Image | process.executable | Full path of the started executable | |
| CommandLine | CommandLine | process.command_line | Full command line, including arguments | |
| ParentImage | ParentImage | process.parent.executable | Full path of the parent process | |
| ParentCommandLine | ParentCommandLine | process.parent.command_line | Parent process's command line | |
| CurrentDirectory | CurrentDirectory | process.working_directory | Working directory of the new process | |
| User | User | user.name | Account the process ran as | |
| IntegrityLevel | IntegrityLevel | (no ECS standard field) | Process integrity level: Low/Medium/High/System | |
| Hashes | Hashes | process.hash.* | Hash(es) of the executable, per configured algorithms (MD5/SHA1/SHA256/IMPHASH) | |
| ProcessId | ProcessId | process.pid | PID of the new process | |
| ParentProcessId | ParentProcessId | process.parent.pid | PID of the parent process | |

## Detection notes

Match on `Image` + `ParentImage` + `CommandLine` together, not any one
field alone. A benign binary launched with a malicious command line
(certutil, rundll32, mshta) is the common LOLBin pattern. DetectionAtlas's
webshell rule bug (checked `Image` instead of `ParentImage`) is a live
example of this field being easy to get backwards.

## Volume notes

Highest-volume Sysmon event on most endpoints: every process spawn, on
every process. First candidate for pre-filtering before ingest: exclude known
noisy parent/child pairs (svchost.exe spawning other svchost.exe, explorer.exe
spawning known signed applications) rather than dropping the event type
outright.

## References

- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation
