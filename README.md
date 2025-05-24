<h1 align="center" style="font-size:2.5rem;">🕵️‍♂️ The Great Admin Heist – CTF Forensic Analysis</h1>

<p align="center">
  <img src="https://github.com/Bharathkasyap/The-Great-Admin-Heist-CTF/blob/main/src/CTF1.png" width="650" alt="CTF Investigation Banner"/>
</p>

<p align="center">
  <strong>Multi-Stage Malware Detection and Attribution | Red vs. Blue Simulation</strong>
</p>

<p align="center">
  <b>Analyst:</b> Venkata Bharath Devulapalli &nbsp;|&nbsp;
  <b>Target System:</b> <code>anthony-001</code> &nbsp;|&nbsp;
  <b>Threat Actor:</b> The Phantom Hackers (Simulated APT)  
</p>

<p align="center">
  <b>Platform Used:</b> Microsoft Defender for Endpoint (MDE) &nbsp;|&nbsp;
  <b>Date Completed:</b> May 17, 2025
</p>

<hr>


## 🧠 Objective

Investigate a simulated APT attack by "The Phantom Hackers" against Acme Corp.  
Analyze how a fake antivirus gained access, persisted, and maintained control over the endpoint.

---

## 🧩 Scenario Summary

An eccentric IT admin unknowingly triggered a stealthy multi-stage attack. The malware used deception, local compilation, and persistence via registry and scheduled tasks. The goal was to trace and document all forensic evidence using MDE logs and KQL queries.

---

## 🚩 Flags & Key Findings

<details>
<summary><strong>1. Suspicious Antivirus Discovery</strong></summary>

- Malware disguised as `BitSentinelCore.exe` mimicked legitimate antivirus software  
- Detected via file naming and process behavior

</details>

<details>
<summary><strong>2. Malicious File Dropped</strong></summary>

- File was locally **compiled** using `csc.exe` (not downloaded)  
- Demonstrates **Living off the Land Binary (LOLBins)** technique

</details>

<details>
<summary><strong>3. Execution Confirmation</strong></summary>

- Manual execution confirmed via `explorer.exe`  
- Indicates user deception or insider threat

</details>

<details>
<summary><strong>4. Keylogger Artifact</strong></summary>

- `.lnk` file dropped into Startup folder named `systemreport.lnk`  
- Tied to keylogger like `AutoHotkeyU32.exe`

</details>

<details>
<summary><strong>5. Registry-Based Persistence</strong></summary>

- Malware added itself under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
- Enables re-execution on reboot or login

</details>

<details>
<summary><strong>6. Scheduled Task Persistence</strong></summary>

- Created task `UpdateHealthTelemetry` using `schtasks.exe`  
- Ensured ongoing access even after reboots

</details>

<details>
<summary><strong>7. Process Spawn Chain</strong></summary>

- Chain observed: `gc_worker.exe → BitSentinelCore.exe → cmd.exe → schtasks.exe`  
- Used trusted system binaries for evasion

</details>

<details>
<summary><strong>8. Root Cause Timeline</strong></summary>

- Root timestamp: `2025-05-06T21:00`  
- Confirmed via file creation of `BitSentinelCore.exe`

</details>

----

## 🧾 Tables Used to Detect IoCs (Indicators of Compromise)

| Parameter              | Name                   | Info                                | Purpose                                                                 |
|------------------------|------------------------|-------------------------------------|-------------------------------------------------------------------------|
| DeviceProcessEvents    | Process Execution Logs | [Docs – DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) | Trace malware execution, parent-child chains, scheduled task creation, and persistence |
| DeviceFileEvents       | File Creation Logs     | [Docs – DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) | Detect malware drops (e.g., `BitSentinelCore.exe`), keylogger files, and `.lnk` artifacts |
| DeviceRegistryEvents   | Registry Persistence   | [Docs – DeviceRegistryEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) | Identify registry-based persistence (`Run`, `RunOnce` keys) |
| DeviceNetworkEvents    | Network Connections    | [Docs – DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) | *(Optional)* Monitor outbound C2 (Command & Control) behavior |
| DeviceImageLoadEvents  | DLL Injection Tracing  | [Docs – DeviceImageLoadEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table) | Validate stealthy DLL injections (e.g., `rundll32` loading `PcaSvc.dll`) tied to memory execution |

---

## 🛠️ Tools Used

- **Microsoft Defender for Endpoint (MDE)**  
  Used for real-time threat telemetry, process tracking, and artifact correlation

- **KQL (Kusto Query Language)**  
  Used for advanced threat hunting, log correlation, timeline generation, and MITRE mapping

---

## 🔍 Threat Hunting Methodology

- **Log Sources Used:** `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`
- **KQL Queries Executed:** To detect each flag and correlate artifacts
- **Timeline Reconstructed:** Chronologically aligned all IOCs
- **MITRE ATT&CK Mapping:** Used to tag each tactic and technique
- **Root Cause Confirmed:** Fake antivirus compiled and executed, enabled full-stage persistence

---

## 🧩 Flags and KQL Analysis

**Detect Execution:**

### Flag 1 – Suspicious Antivirus Discovery

```kusto
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceName == "anthony-001"
| where InitiatingProcessAccountName == '4nth0ny!'
| where FileName endswith ".exe" or ProcessCommandLine has ".exe"
| where FileName startswith 'a' or FileName startswith 'b' or FileName startswith 'c'
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName
```
<img width="1212" alt="image" src="https://github.com/Bharathkasyap/The-Great-Admin-Heist-CTF/blob/main/src/step1.png">


### Observation: 
  BitSentinelCore.exe was executed by explorer.exe, suggesting manual execution by the user.

---


### Flag 2 – Malicious File Dropped

```kusto
DeviceFileEvents
| where Timestamp > ago(30d)
| where DeviceName == "anthony-001"
| where FileName == "BitSentinelCore.exe"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
```
<img width="1212" alt="image" src="https://github.com/Bharathkasyap/The-Great-Admin-Heist-CTF/blob/main/src/step2.png">

Observation: The malware was compiled on the system using csc.exe, not downloaded—classic LOLBin misuse.

---

### Flag 3 – Execution Confirmation

```kusto

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp > ago(30d)
| where FileName == "BitSentinelCore.exe"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
```
<img width="1212" alt="image" src="https://github.com/Bharathkasyap/The-Great-Admin-Heist-CTF/blob/main/src/step3.png">

### Observation: 
User 4nth0ny! manually executed the binary.

### Flag 4 – Keylogger Artifact

```kusto

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp > ago(30d)
| where FileName has_any("key", "log", "input", "lnk")
| where InitiatingProcessFileName contains "explorer.exe"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, ActionType
```
<img width="1212" alt="image" src="https://github.com/Bharathkasyap/The-Great-Admin-Heist-CTF/blob/main/src/step4.png">

### Observation: 
systemreport.lnk placed in Startup folder — tied to AutoHotkey keylogger.

### Flag 5 – Registry-Based Persistence

```kusto

DeviceRegistryEvents
| where DeviceName == "anthony-001"
| where Timestamp > ago(30d)
| where RegistryKey has_any ("Run", "RunOnce")
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```
<img width="1212" alt="image" src="https://github.com/Bharathkasyap/The-Great-Admin-Heist-CTF/blob/main/src/step5.png">

### Observation: 
Registry Run key pointing to systemreport.lnk confirmed registry persistence.

### Flag 6 – Scheduled Task Persistence

```kusto

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp > ago(30d)
| where ProcessCommandLine contains "schtasks" or ProcessCommandLine contains "Schedule.Service"
| project Timestamp, InitiatingProcessFileName, ProcessCommandLine
| sort by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/Bharathkasyap/The-Great-Admin-Heist-CTF/blob/main/src/step6.png">

### Observation: 
Task UpdateHealthTelemetry was created to ensure silent re-execution of the payload.

### Flag 7 – Process Spawn Chain

```kusto

DeviceProcessEvents
| where DeviceName == "anthony-001"
| where Timestamp > ago(30d)
| where ProcessCommandLine has "schtasks" or ProcessCommandLine has "/Create"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
<img width="1212" alt="image" src="https://github.com/Bharathkasyap/The-Great-Admin-Heist-CTF/blob/main/src/step7.png">

### Observation: 
Full process chain: gc_worker.exe → BitSentinelCore.exe → cmd.exe → schtasks.exe.

### Flag 8 – Root Cause Timestamp

```kusto

DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp > ago(30d)
| where FileName == "BitSentinelCore.exe"
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, FileName
```
<img width="1212" alt="image" src="https://github.com/Bharathkasyap/The-Great-Admin-Heist-CTF/blob/main/src/step8.png">

### Observation: 
File creation timestamp 2025-05-07T02:00:36.794406Z marked the start of the chain.

## 🕒 Timeline of Events

| Time (UTC)             | Event                      | Description                                          |
|------------------------|----------------------------|------------------------------------------------------|
| 2025-05-06T22:01:28Z   | PowerShell Execution       | Initiated by `senseir.exe` to load malware stages    |
| 2025-05-06T22:01:58Z   | csc.exe Execution          | Built binary from source using .NET compiler         |
| 2025-05-06T22:02:25Z   | gc_worker.exe Activity     | Harvested credentials via in-memory method           |
| 2025-05-06T22:03:16Z   | schtasks.exe Scheduling    | Created task `UpdateHealthTelemetry` for persistence |
| 2025-05-06T22:06:51Z   | systemreport.lnk Dropped   | Planted keylogger shortcut in Startup folder         |
| 2025-05-06T20:23:40Z   | rundll32.exe Injection     | Code injection into memory using DLL techniques      |
| 2025-05-07T02:00:36Z   | BitSentinelCore.exe Drop   | First malware appearance on disk                     |

---

## 🧠 MITRE ATT&CK Mapping

| Tactic             | Technique                | ID                | Example Activity                            |
|--------------------|--------------------------|--------------------|----------------------------------------------|
| Execution          | User Execution           | T1204              | `senseir.exe` launching PowerShell           |
| Defense Evasion    | Obfuscated Scripts       | T1027              | PowerShell with encoded commands             |
| Persistence        | Registry & Task Schedule | T1053.005 / T1547.001 | Registry key and `UpdateHealthTelemetry` task |
| Credential Access  | OS Credential Dumping    | T1003              | `gc_worker.exe` using reversible encryption  |
| Collection         | Input Capture            | T1056              | Keylogger via `systemreport.lnk`             |

---

## 🛡 Incident Response & Recommendations

### ✅ Containment Steps
- Isolated `anthony-001` from the network  
- Disabled malicious scheduled task  
- Deleted `BitSentinelCore.exe`, `systemreport.lnk`  
- Removed registry-based persistence keys  

### 🗃 Forensic Preservation
- Exported MDE logs and memory captures  
- Archived all artifact hashes and paths  

### 🔐 Recommendations
- Implement AppLocker or WDAC to block LOLBins like `csc.exe`  
- Enable PowerShell transcription and command logging  
- Monitor `%Startup%` paths and Run registry keys  
- Regularly audit scheduled tasks across all endpoints  
- Train users to recognize disguised internal malware  
- Use EDR with behavior-based detection and alerting  




