# CrowdStrike Falcon: OoXmlFileWritten

**Vendor:** CrowdStrike Falcon (Next-Gen SIEM)
**Sigma category:** crowdstrike.OoXmlFileWritten
**Event ID:** OoXmlFileWritten

Generated when a Microsoft Office (post-Office 2007, OOXML: .docx/.xlsx/
.pptm etc.) file is written to disk. Useful for tracking document drops on
endpoints, including macro-enabled document payloads delivered via
phishing. Fields below are raw sensor field names; CrowdStrike Sigma rules
match on these directly, so the native and Sigma name columns are
identical.

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| TargetFileName | TargetFileName | (no ECS standard field) | The resulting file name that was downloaded (Windows) |  |
| ContextBaseFileName | ContextBaseFileName | (no ECS standard field) | The base ImageFileName of the context process (Windows) |  |
| ContextProcessId | ContextProcessId | (no ECS standard field) | UPID of process originating this event (Windows) |  |
| Size | Size | (no ECS standard field) | Size of the egressing file in bytes (Windows) |  |
| FileCategory | FileCategory | (no ECS standard field) | An enumeration field that classifies the type of file involved in a write event. The Falcon sensor assigns a category to each file based on its extension and format at the time of the write. In CrowdStrike telemetry, values appear as decimal integers. (Windows) |  |
| IsOnNetwork | IsOnNetwork | (no ECS standard field) | Set to true if the relevant file listed in the event is on a network drive. False otherwise (Windows) |  |
| IsOnRemoveableDisk | IsOnRemoveableDisk | (no ECS standard field) | If true, it means this file was located on a removable disk (Windows) |  |

## Detection notes

`TargetFileName` with a macro-enabled extension (`.docm`, `.xlsm`, `.pptm`)
written by `ContextBaseFileName` values outside Office itself (a browser,
an email client's attachment handler, or an archive utility) is the primary
phishing-payload-drop signal; correlate `ContextProcessId` forward against
ProcessRollup2 to see what that writer process does next. `IsOnNetwork` or
`IsOnRemoveableDisk` set true adds a distribution-vector signal worth
carrying into the alert (network share vs. USB vs. local/downloaded).

## Volume notes

Moderate. Scales with normal document creation/editing activity in the
org, not just malicious drops. Filter out the process's own editing
application (WINWORD.EXE writing .docx, EXCEL.EXE writing .xlsx) as
expected baseline before alerting on macro-enabled extensions from
unexpected writers.

## References

- https://docs.crowdstrike.com/r/ooxmlfilewritten
