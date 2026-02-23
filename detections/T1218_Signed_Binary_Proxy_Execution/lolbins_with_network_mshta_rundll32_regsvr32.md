# LOLBins with Network: mshta / rundll32 / regsvr32

**ATT&CK:** T1218 (Signed Binary Proxy Execution)  
**Severity:** High  
**Confidence:** Medium  

## What it detects
Execution of commonly abused signed Windows binaries (LOLbins) that also generate outbound network connections shortly before/after execution.

## Why it matters
- Often used for proxy execution, script-based payloads, or living-off-the-land download/execute chains.
- Combining process + network reduces false positives vs. process-only.

## Data requirements

### Microsoft Sentinel (KQL)
- Tables: `DeviceProcessEvents`, `DeviceNetworkEvents`
- Required fields:
  - Process: `Timestamp`, `DeviceName`, `AccountName`, `FileName`, `ProcessCommandLine`, `ProcessId`
  - Network: `Timestamp`, `DeviceName`, `InitiatingProcessFileName`, `InitiatingProcessId`, `RemoteIP`, `RemoteUrl`, `RemotePort`

### Splunk (SPL)
- Sysmon EID 1 (Process Create) + EID 3 (Network)
- Required fields:
  - EID 1: `Image`, `CommandLine`, `ProcessId`, `Computer`, `User`
  - EID 3: `Image`, `ProcessId`, `DestinationIp`, `DestinationHostname`, `DestinationPort`, `Computer`

## Detection logic

### KQL
```kql
let lolbins = dynamic(["mshta.exe","rundll32.exe","regsvr32.exe"]);
let proc =
    DeviceProcessEvents
    | where Timestamp > ago(1d)
    | where FileName in~ (lolbins)
    | project ProcTime=Timestamp, DeviceName, AccountName,
              FileName, ProcessCommandLine, ProcessId;
let net =
    DeviceNetworkEvents
    | where Timestamp > ago(1d)
    | project NetTime=Timestamp, DeviceName,
              InitiatingProcessFileName, InitiatingProcessId,
              RemoteIP, RemoteUrl, RemotePort;
proc
| join kind=innerunique (net) on DeviceName
| where InitiatingProcessId == ProcessId
| where NetTime between (ProcTime - 5m .. ProcTime + 10m)
| project ProcTime, NetTime, DeviceName, AccountName, FileName, ProcessCommandLine,
          RemoteIP, RemoteUrl, RemotePort
| order by ProcTime desc
```

### SPL
```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=3)
| eval proc=lower(coalesce(Image, ""))
| eval is_lolbin=if(like(proc, "%\\mshta.exe") OR like(proc, "%\\rundll32.exe") OR like(proc, "%\\regsvr32.exe"), 1, 0)
| where is_lolbin=1
| stats
    earliest(_time) as firstTime
    latest(_time) as lastTime
    values(User) as User
    values(CommandLine) as CommandLine
    values(DestinationIp) as DestinationIp
    values(DestinationHostname) as DestinationHostname
    values(DestinationPort) as DestinationPort
  by Computer Image ProcessId
| eval duration=lastTime-firstTime
| where isnotnull(DestinationIp) OR isnotnull(DestinationHostname)
| table firstTime lastTime duration Computer User Image ProcessId CommandLine DestinationIp DestinationHostname DestinationPort
| sort - firstTime
```
### Tuning & false positives:
- Some enterprise apps use rundll32.exe legitimately; requiring network improves signal.
- Consider excluding known corporate proxy/DNS destinations or trusted internal ranges.
- Increase confidence when command line includes URLs or script-related flags.

### Validation plan:
- Lab: execute mshta.exe against a harmless internal test URL (or simulate with a local web server).
- Confirm a corresponding Sysmon EID 3 appears with matching ProcessId near the process start time.
