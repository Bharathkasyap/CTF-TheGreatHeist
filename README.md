<h1 align="center" style="font-size:2.5rem;">🕵️‍♂️ The Great Admin Heist – CTF Forensic Analysis</h1>

<p align="center">
  <img src="https://media.giphy.com/media/kQH61fV8d2g7k/giphy.gif" width="650" alt="CTF Investigation Banner"/>
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
---

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


## 🔍 Threat Hunting Methodology

- **Log Sources Used:** `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`
- **KQL Queries Executed:** To detect each flag and correlate artifacts
- **Timeline Reconstructed:** Chronologically aligned all IOCs
- **MITRE ATT&CK Mapping:** Used to tag each tactic and technique
- **Root Cause Confirmed:** Fake antivirus compiled and executed, enabled full-stage persistence

---

## 🧪 Sample KQL Queries

**Detect Execution:**
```kusto
DeviceProcessEvents
| where DeviceName == "anthony-001"
| where FileName == "BitSentinelCore.exe"
