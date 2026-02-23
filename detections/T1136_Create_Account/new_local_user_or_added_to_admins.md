# New Local User Created or Added to Local Administrators

**ATT&CK:** T1136 (Create Account) / T1098 (Account Manipulation)  
**Severity:** High  
**Confidence:** Medium  

## What it detects
Creation of local user accounts and/or addition of accounts to the local Administrators group using Windows Security event logs.

## Why it matters
- Creating a new local admin is a common persistence and privilege escalation technique.
- Strong signal when performed by unusual accounts, outside business hours, or across multiple endpoints.

## Data requirements

### Microsoft Sentinel (KQL)
- Tables: `SecurityEvent`
- Required Event IDs:
  - `4720` (User account created)
  - `4732` (Member added to a security-enabled local group)
- Required fields: `TimeGenerated`, `Computer`, `EventID`, `Activity`, `SubjectUserName`, `TargetUserName`

### Splunk (SPL)
- Windows Security logs ingested (not Sysmon)
- Assumptions:
  - `index=wineventlog`
  - `sourcetype="WinEventLog:Security"`
- Required fields: `EventCode`, `ComputerName`, `SubjectUserName`, `TargetUserName`, `Message`

## Detection logic

### KQL
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4720, 4732)
| extend Action = case(
    EventID == 4720, "Local user created",
    EventID == 4732, "Added to local group",
    "Other"
)
| project TimeGenerated, Computer, EventID, Action, Activity,
          SubjectAccount=SubjectUserName,
          TargetAccount=TargetUserName
| order by TimeGenerated desc
```

### SPL
```spl
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4720 OR EventCode=4732)
| eval action=case(EventCode=4720, "Local user created", EventCode=4732, "Added to local group", true(), "Other")
| table _time ComputerName action EventCode SubjectUserName TargetUserName Message
| sort - _time
```

### Tuning & false positives:
- Many orgs have legitimate provisioning processes; allowlist known IT admin/provisioning accounts.
- For `4732`, increase confidence when the target group is Local Administrators (often visible in `Message`).
- Raise severity if activity occurs outside business hours or from unusual endpoints.

### Validation plan
- Lab: create a local user and add it to local admins on a test VM; confirm events `4720` and `4732` fire.
- Confirm the initiating/subject account matches expectations for your test scenario.
