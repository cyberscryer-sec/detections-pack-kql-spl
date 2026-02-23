# Data sources and assumptions

## Microsoft Sentinel (KQL)
This pack assumes Defender for Endpoint (MDE) data is available in Sentinel via the Microsoft Defender XDR connector.

Common tables used:
- `DeviceProcessEvents` (process creation + command line)
- `DeviceNetworkEvents` (network connections)
- `DeviceRegistryEvents` (registry modifications)
- `DeviceFileEvents` (file creations/modifications)
- `DeviceLogonEvents` (logons)

Key fields frequently referenced:
- `Timestamp`
- `DeviceName`
- `InitiatingProcessAccountName`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `ProcessCommandLine`
- `FileName`
- `FolderPath`
- `RemoteIP`, `RemoteUrl`, `RemotePort`
- `RegistryKey`, `RegistryValueName`, `RegistryValueData`

If you do not have MDE tables, many detections can be adapted to:
- `SecurityEvent` (Windows Security logs)
- `Sysmon` data (if ingested into Sentinel)

## Splunk (SPL)
This pack assumes Sysmon logs are ingested into Splunk with:
- `index=sysmon`
- `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

Sysmon Event IDs used:
- `EventCode=1` Process Create
- `EventCode=3` Network Connection
- `EventCode=7` Image Loaded
- `EventCode=10` Process Access (useful for LSASS access)
- `EventCode=11` File Create
- `EventCode=13` Registry Value Set

Common Sysmon fields (Splunk extractions vary by TA):
- Process create (EID 1):
  - `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Computer`
- Network (EID 3):
  - `Image`, `DestinationIp`, `DestinationHostname`, `DestinationPort`, `Protocol`, `Computer`, `User`
- Process access (EID 10):
  - `SourceImage`, `TargetImage`, `GrantedAccess`, `Computer`, `User`
- Registry set (EID 13):
  - `TargetObject`, `Details`, `Image`, `Computer`, `User`

If your field names differ, update the SPL accordingly and document your mapping.
