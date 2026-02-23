# Portable Detection Pack (KQL + SPL)

A small, practical set of SOC detections written in **Microsoft Sentinel KQL** and **Splunk SPL** with:
- **MITRE ATT&CK mapping**
- **clear data requirements**
- **tuning guidance** (false positives + suggested filters)
- **validation notes** (how you’d test in a lab)

## What this repo is
This is a “portable” detection pack: the **same behavioral idea** is expressed in both KQL and SPL, with explicit assumptions about telemetry and field availability.

## Quick start
1. Pick a detection from `/detections/`
2. Review **Data requirements** (tables/indexes + required fields)
3. Copy the **KQL** into Sentinel Analytics Rule / Hunting
4. Copy the **SPL** into a Splunk saved search (adjust `index=` and sourcetypes)

## Telemetry assumptions
- Sentinel: MDE tables available in Log Analytics (see `docs/data-sources.md`)
- Splunk: Sysmon ingested (see `docs/data-sources.md`)

## Coverage summary

| Detection | ATT&CK | Primary telemetry | KQL | SPL |
|---|---|---|---|---|
| [Encoded / Suspicious PowerShell](detections/T1059_Command_and_Scripting_Interpreter/encoded_or_suspicious_powershell.md) | T1059.001 | Proc create + cmdline | ✅ | ✅ |
| [LOLBins w/ Network (mshta/rundll32/regsvr32)](detections/T1218_Signed_Binary_Proxy_Execution/lolbins_with_network_mshta_rundll32_regsvr32.md) | T1218 | Proc + network | ✅ | ✅ |
| [LSASS Suspicious Access (Sysmon EID 10)](detections/T1003_OS_Credential_Dumping/lsass_suspicious_access_sysmon10.md) | T1003.001 | Proc access + source proc | ✅ | ✅ |
| [New Local User / Added to Local Admins](detections/T1136_Create_Account/new_local_user_or_added_to_admins.md) | T1136 / T1098 | Security events | ✅ | ✅ |
| [New Service Installed (user-writable path)](detections/T1543_Create_or_Modify_System_Process/new_service_user_writable_path.md) | T1543.003 | Proc create + service binary | ✅ | ✅ |
| [Run Key Persistence](detections/T1547_Boot_or_Logon_Autostart_Execution/run_key_persistence_registry_set.md) | T1547.001 | Registry set + proc | ✅ | ✅ |

## Detections included
- **Execution:** PowerShell obfuscation/abuse flags (encoded, hidden window, bypass patterns)
- **Proxy execution:** LOLBins with near-time outbound network activity
- **Persistence:** Run/RunOnce registry key modifications; service install with suspicious binary paths
- **Credential access:** LSASS handle access via Sysmon Process Access (EID 10)
- **Account manipulation:** New local users and local admin group changes (Windows Security logs)

## How to operationalize (high-level)
### Microsoft Sentinel
- Convert KQL into **Analytics Rules**
- Start with: schedule every **5–15 minutes**, lookback **30–60 minutes**
- Use entity mappings where possible: Account, Host, IP, Process

### Splunk
- Convert SPL into a **Saved Search**
- Schedule every **5–15 minutes**
- Consider thresholds for noisy detections (e.g., multiple hits per host)

## Notes on tuning
Each detection includes:
- common false positives
- recommended allowlists
- thresholds / time window considerations

## Structure
- `/detections/` detection content grouped by ATT&CK technique
- `/docs/` data source assumptions and mapping notes
- `/templates/` a standard detection write-up template

## Disclaimer
These detections are provided as examples and require environment-specific tuning. Avoid relying on command-line string matching alone—prefer behavior + context when possible.
