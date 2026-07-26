# Sysmon Event ID 7: Image Load

**Vendor:** Microsoft Sysinternals Sysmon
**Sigma category:** image_load
**Event ID:** 7

Fires when a process loads a DLL. Disabled by default (high volume); must
be explicitly enabled via `<ImageLoad onmatch="...">`. Directly matches
DetectionAtlas's `Event` struct fields for this category (`ImageLoaded`,
`Signed`, `Signature`).

## Fields

| Field (native) | Sigma name | ECS name | Description | High volume? |
|---|---|---|---|---|
| Image | Image | process.executable | Process doing the loading | |
| ImageLoaded | ImageLoaded | dll.path | Full path of the loaded DLL | Yes |
| Signed | Signed | dll.code_signature.signed | true/false, whether the DLL is signed | |
| Signature | Signature | dll.code_signature.subject_name | Signer name, if signed | |
| SignatureStatus | SignatureStatus | dll.code_signature.status | Valid/Invalid/Unavailable | |
| User | User | user.name | Account the process ran as | |

## Detection notes

Core signal for DLL sideloading and unsigned/unusual DLLs loaded by
sensitive processes (lsass.exe, services.exe). `Signed: false` from a
process that normally only loads signed system DLLs is high-fidelity.

## Volume notes

High volume: every DLL load, on every process, all the time. Sysmon's
own default config guidance is to scope this to a small set of
sensitive target processes (lsass.exe, svchost.exe) rather than enabling
it system-wide.

## References

- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load
