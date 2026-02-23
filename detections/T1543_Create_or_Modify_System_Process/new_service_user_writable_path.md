# New Service Installed with Binary in User-Writable Path

**ATT&CK:** T1543.003 (Windows Service)  
**Severity:** High  
**Confidence:** Medium  

## What it detects
Service creation activity where the service binary points to a suspicious location such as user profile or temp directories (often indicating a dropped payload).

## Why it matters
- Windows services are a common persistence mechanism.
- A service binary in user-writable paths (`Users`, `AppData`, `Temp`) is higher risk than typical install paths.

## Data requirements

### Microsoft Sentinel (KQL)
- Tables: `DeviceProcessEvents`
- Required fields: `Timestamp`, `DeviceName`, `AccountName`, `FileName`, `ProcessCommandLine`, `InitiatingProcessFileName`, `InitiatingProcessCommandLine`

### Splunk (SPL)
- Sysmon EID 1 (Process Create)
- Assumptions: `index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- Required fields: `Image`, `CommandLine`, `ParentImage`, `User`, `Computer`

## Detection logic

### KQL
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("sc.exe","powershell.exe","cmd.exe")
| where ProcessCommandLine has_any (" create ", "New-Service", "binPath=", "binpath=")
| where ProcessCommandLine has_any ("\\Users\\", "\\AppData\\", "\\Temp\\", "C:\\ProgramData\\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
| order by Timestamp desc
```

### SPL 
```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval img=lower(Image), cmd=lower(CommandLine)
| where (like(img, "%\\sc.exe") OR like(img, "%\\powershell.exe") OR like(img, "%\\cmd.exe"))
| where like(cmd, "% create %") OR like(cmd, "%new-service%") OR like(cmd, "%binpath=%")
| where like(cmd, "%\\users\\%") OR like(cmd, "%\\appdata\\%") OR like(cmd, "%\\temp\\%") OR like(cmd, "%\\programdata\\%")
| table _time Computer User Image CommandLine ParentImage ParentCommandLine
| sort - _time
```

### Tuning & false positives:
- Legitimate installers may use `C:\ProgramData\` —treat it as “medium suspicious” vs `Users/AppData/Temp`.
- Consider allowlisting known software deployment tooling and known admin accounts.
- Increase confidence if the binary path is in a random-looking directory name or recently created folder.

### Validation plan:
- Lab: create a benign test service pointing to a harmless executable in a temp folder:
  - Example: `sc.exe create TestSvc binPath= "C:\Users\Public\test.exe"`
- Confirm the process creation event captures the command line and triggers this detection.
