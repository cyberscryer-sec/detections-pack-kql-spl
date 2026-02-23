# Validation approach

This repo focuses on **portable detection logic** (KQL + SPL) and includes a **validation plan** for each detection.
Validations are written as:
- **telemetry prerequisites** (what needs to be collected),
- **safe simulation steps** (benign commands you can run),
- **expected observable artifacts** (what events/fields should appear),
- and **tuning guidance** (how to reduce false positives once deployed).

## How I would validate in a real environment
For each detection, execute the following workflow:

1. **Confirm the data source exists**
   - Sentinel: verify required tables (e.g., `DeviceProcessEvents`, `DeviceRegistryEvents`) or Sysmon ingestion.
   - Splunk: verify Sysmon/Windows Security logs are indexed and fields are extracted.

2. **Generate a benign signal**
   - Run a safe command or configuration change that mimics the behavior (no malware, no exploitation).
   - Capture the event(s) that should trigger the analytic.

3. **Verify the analytic returns results**
   - Run the KQL/SPL as a hunting query.
   - Confirm the returned fields match what the detection expects.

4. **Tune**
   - Add allowlists for known-good tooling/hosts/accounts.
   - Add thresholds/time windows where relevant.
   - Document any environment-specific assumptions.

5. **Operationalize**
   - Convert into a rule/saved search with a reasonable schedule (5–15 min) and lookback (30–60 min).
   - Add entity mappings / notable fields where supported.

## Benign simulation ideas 
These are examples of **safe** actions that can generate telemetry similar to the detections in this repo:

### PowerShell suspicious flags (T1059.001)
- Example:
  - `powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Host test"`

Expected observable artifacts:
- A PowerShell process with flags in command line telemetry.

### Run key persistence (T1547.001)
- Example:
  - `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v TestRunKey /t REG_SZ /d "C:\Windows\System32\notepad.exe" /f`

Expected observable artifacts:
- A registry value set under a Run/RunOnce key.

### Service creation (T1543.003)
- Example (lab/test system only):
  - `sc.exe create TestSvc binPath= "C:\Users\Public\test.exe"`

Expected observable artifacts:
- A process creation event capturing `sc.exe create ... binPath= ...`

### Local user creation / local admin add (T1136 / T1098)
- Example (test system only):
  - `net user TestLocalUser P@ssw0rd! /add`
  - `net localgroup administrators TestLocalUser /add`

Expected observable artifacts:
- Windows Security events showing account creation and group membership change.

### LOLBins with network (T1218)
- Example approach:
  - Start a local web server on a test system (e.g., `python -m http.server 8000`)
  - Trigger a benign network connection from a signed Windows binary where appropriate

Expected observable artifacts:
- A process start near a network connection event tied to the same initiating process.

### LSASS access (T1003.001)
- Note:
  - This detection relies on Sysmon Process Access telemetry (EID 10).
  - Validation should focus on **confirming EID 10 collection** and then tuning allowlists for known-good access sources.

## Future enhancement
A future plan for this repo is to build a small lab pipeline (e.g., Elastic/Sysmon) as an example of:
- sample event snippets,
- screenshots of results,
- and detection tuning changes based on observed false positives.
