# LSASS Suspicious Access (Sysmon Process Access)

**ATT&CK:** T1003.001 (LSASS Memory)  
**Severity:** High  
**Confidence:** Medium  

## What it detects
Processes accessing `lsass.exe` using Sysmon **Process Access** events (Event ID 10), which can indicate credential dumping attempts or suspicious handle access.

## Why it matters
- LSASS access is a core technique for credential dumping.
- High impact: prioritize investigation if the source process is unsigned/unusual or runs from user-writable paths.

## Data requirements

### Microsoft Sentinel (KQL)
- Source: Sysmon Event ID 10 ingested into Sentinel (table/field names vary)
- Example table: `WindowsEvent` (or a custom Sysmon table)
- Required fields (conceptual): `TimeGenerated`, `Computer`, `EventID`, `EventData` containing:
  - `SourceImage`, `TargetImage`, `GrantedAccess`, `User`

> Note: If your Sentinel workspace uses a different table/schema for Sysmon, update the query accordingly.

### Splunk (SPL)
- Sysmon EID 10 (Process Access)
- Assumptions: `index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- Required fields: `SourceImage`, `TargetImage`, `GrantedAccess`, `Computer`, `User`

## Detection logic

### KQL (Sysmon-in-Sentinel example)
```kql
WindowsEvent
| where TimeGenerated > ago(7d)
| where EventID == 10
| extend TargetImage = tostring(EventData.TargetImage)
| extend SourceImage = tostring(EventData.SourceImage)
| extend GrantedAccess = tostring(EventData.GrantedAccess)
| extend User = tostring(EventData.User)
| where TargetImage endswith @"\lsass.exe"
| project TimeGenerated, Computer, User, SourceImage, TargetImage, GrantedAccess
| order by TimeGenerated desc
```

### SPL
```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| eval target=lower(TargetImage), source=lower(SourceImage)
| where like(target, "%\\lsass.exe")
| where NOT (
    like(source, "%\\taskmgr.exe")
    OR like(source, "%\\procmon.exe")
    OR like(source, "%\\procexp.exe")
    OR like(source, "%\\perfmon.exe")
)
| table _time Computer User SourceImage TargetImage GrantedAccess CallTrace
| sort - _time
```

### Tuning & false positives:
- Some legitimate tooling and security products may access LSASS.
- Start with allowlisting known-good source paths (EDR components, signed admin tools).
- Increase confidence if:
  - `SourceImage` is in `\Users\`, `\AppData\`, `\Temp\`
  - the source process is unusual for the host role
  - the event repeats frequently in a short window

### Validation plan
- Safest validation: confirm Sysmon EID 10 is being collected and that benign sources appear as expected.
- Lab-only: validate with controlled tooling that generates EID 10 access events (avoid credential dumping in production).
