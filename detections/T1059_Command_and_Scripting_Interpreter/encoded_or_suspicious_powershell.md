# Encoded / Suspicious PowerShell

**ATT&CK:** T1059.001 (PowerShell)  
**Severity:** Medium  
**Confidence:** Medium  

## What it detects
PowerShell executions with common obfuscation/abuse flags such as encoded commands, hidden window, or non-interactive execution.

## Why it matters
- Frequently used in initial execution, download cradles, and post-exploitation.
- Strong signal when combined with suspicious parent processes or network activity.

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
| where Timestamp > ago(1d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any (
    "-enc","-encodedcommand",
    "-nop","-noprofile",
    "-w hidden","-windowstyle hidden",
    "-noninteractive","-executionpolicy bypass","bypass"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
| order by Timestamp desc
```

### SPL
```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| eval cmd=lower(CommandLine)
| where like(cmd, "% -enc%") OR like(cmd, "%-encodedcommand%")
   OR like(cmd, "% -nop%") OR like(cmd, "%-noprofile%")
   OR like(cmd, "%windowstyle hidden%") OR like(cmd, "% -w hidden%")
   OR like(cmd, "%noninteractive%") OR like(cmd, "%executionpolicy%") OR like(cmd, "%bypass%")
| table _time Computer User Image CommandLine ParentImage ParentCommandLine
| sort - _time
```

### Tuning & false positives:
- Admin scripts and automation can legitimately use `-NoProfile` or `-NonInteractive`.
- Consider allowlisting known management tooling parents (e.g., software deployment agents).
- Increase confidence if parent is Office apps, browsers, or unusual LOLBins.

### Validation plan:
- Quick test (safe): run `powershell` `-NoProfile -WindowStyle Hidden -Command "Write-Host test"`
- Lab-only: run a benign base64 encoded command and verify it triggers.
