# Sysmon Event ID 11: File Create

**Vendor:** Microsoft Sysinternals Sysmon
**Sigma category:** file_event
**Event ID:** 11

Fires when a file is created or overwritten. Covers drops to disk from a
payload, ransomware writing encrypted copies, and persistence artifacts
written to startup folders.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| Image | Image | process.executable | Process that created the file | |
| TargetFilename | TargetFilename | file.path | Full path of the created file | Yes |
| CreationUtcTime | CreationUtcTime | file.created | File creation timestamp reported by the filesystem | |
| User | User | user.name | Account the process ran as | |

## Detection notes

Filename/extension patterns in startup folders, Office template directories,
or with double extensions (`invoice.pdf.exe`) are the common signal here.
Ransomware detections that rely on mass-rename/mass-write behavior need
volume/rate analysis on top of this event, which per-event Sigma matching
doesn't express on its own.

## Volume notes

High volume on build servers, browsers (cache writes), and update
processes. Typical filter: exclude well-known noisy paths (browser cache
directories, temp directories used by installers) rather than the whole
event type.

## References

- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file_event
