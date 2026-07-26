# Sysmon Event ID 17/18: Pipe Event

**Vendor:** Microsoft Sysinternals Sysmon
**Sigma category:** pipe_event
**Event ID:** 17 (PipeCreated), 18 (PipeConnected)

Fires when a named pipe is created (17) or a client connects to one (18).
Named pipes are a common inter-process channel for C2 frameworks (Cobalt
Strike's default pipe names are a well-known IOC set).

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| EventType | EventType | (no ECS standard field) | PipeCreated or PipeConnected | |
| PipeName | PipeName | (no ECS standard field) | Name of the named pipe | |
| Image | Image | process.executable | Process that created/connected the pipe | |
| User | User | user.name | Account the process ran as | |

## Detection notes

**Gap found while building this reference:** DetectionAtlas defines
`CategoryPipeEvent` in `model.EventCategory` but its `Event` struct has no
`PipeName` field and `Get()` has no case for it. Pipe-based C2 detections
(e.g. matching known Cobalt Strike pipe name patterns) aren't ingestable
there until that field is added. Filed here rather than fixed there, per
this repo's standalone-reference scope.

## Volume notes

Moderate volume, much lower than process/file/registry events. Named pipe
creation is comparatively rare in normal Windows operation, which is part
of what makes this signal useful.

## References

- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/pipe_created
