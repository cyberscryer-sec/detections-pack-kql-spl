# Run Key Persistence (Registry Set)

**ATT&CK:** T1547.001 (Registry Run Keys / Startup Folder)  
**Severity:** High  
**Confidence:** Medium  

## What it detects
Registry modifications to common Run/RunOnce keys that enable persistence at user logon.

## Why it matters
- Extremely common persistence technique.
- Higher signal when the value points to user-writable locations or suspicious executables.

## Data requirements

### Microsoft Sentinel (KQL)
- Tables: `DeviceRegistryEvents`
- Required fields: `Timestamp`, `DeviceName`, `InitiatingProcessAccountName`, `RegistryKey`, `RegistryValueName`, `RegistryValueData`, `InitiatingProcessFileName`, `InitiatingProcessCommandLine`

### Splunk (SPL)
- Sysmon EID 13 (Registry Value Set)
- Assumptions: `index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- Required fields: `TargetObject`, `Details`, `Image`, `Computer`, `User`

## Detection logic

### KQL
```kql
let runKeys = dynamic([
  "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
  "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
  "\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
]);
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any (runKeys)
| project Timestamp, DeviceName,
          Account=InitiatingProcessAccountName,
          RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### SPL
```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| eval tgt=lower(TargetObject), det=lower(Details)
| where like(tgt, "%\\software\\microsoft\\windows\\currentversion\\run%")
   OR like(tgt, "%\\software\\microsoft\\windows\\currentversion\\runonce%")
   OR like(tgt, "%\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run%")
   OR like(tgt, "%\\software\\wow6432node\\microsoft\\windows\\currentversion\\run%")
| eval suspicious_path=if(like(det, "%\\users\\%") OR like(det, "%\\appdata\\%") OR like(det, "%\\temp\\%"), 1, 0)
| table _time Computer User Image TargetObject Details suspicious_path
| sort - _time
```
### Tuning & false positives:
- Many legitimate applications set Run keys (especially per-user).
- Raise severity if the value points to:
  - `\Users\`, `\AppData\`, `\Temp\`, script interpreters, or random folder names
- Consider allowlisting known vendor paths.

### Validation plan:
- Lab: create a benign Run key value pointing to a harmless executable and confirm Sysmon EID 13 is logged.
- Verify `TargetObject` matches one of the Run/RunOnce keys and `Details` contains the configured value.
