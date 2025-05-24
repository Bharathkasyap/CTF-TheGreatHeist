# 🕵️‍♂️ The Great Admin Heist – CTF Forensic Analysis

**Project Title:** Multi-Stage Malware Detection and Attribution  
**Analyst:** Venkata Bharath Devulapalli  
**Target System:** Acme Corp Endpoint (`anthony-001`)  
**Simulated Threat Actor:** The Phantom Hackers (APT Simulation)  
**Platform Used:** Microsoft Defender for Endpoint (MDE)  
**Date Completed:** May 19, 2025

---

## 🧠 Objective

Investigate a simulated APT attack by "The Phantom Hackers" against Acme Corp.  
Analyze how a fake antivirus (`BitSentinelCore.exe`) gained access, persisted, and maintained control over the endpoint.

---

## 🧩 Scenario Summary

An eccentric IT admin unknowingly triggered a stealthy multi-stage attack. The malware used deception, local compilation, and persistence via registry and scheduled tasks. The goal was to trace and document all forensic evidence using MDE logs and KQL queries.

---

## 🚩 Flags & Key Findings

### 1. **Suspicious Antivirus Discovery**
- Malware disguised as `BitSentinelCore.exe` mimicked legitimate antivirus software
- Detected via file naming and process behavior

### 2. **Malicious File Dropped**
- File was locally **compiled** using `csc.exe` (not downloaded)
- Demonstrates **Living off the Land Binary (LOLBins)** technique

### 3. **Execution Confirmation**
- Manual execution confirmed via `explorer.exe`
- Indicates user deception or insider threat

### 4. **Keylogger Artifact**
- `.lnk` file dropped into Startup folder named `systemreport.lnk`
- Tied to keylogger like `AutoHotkeyU32.exe`

### 5. **Registry-Based Persistence**
- Malware added itself under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Enables re-execution on reboot or login

### 6. **Scheduled Task Persistence**
- Created task `UpdateHealthTelemetry` using `schtasks.exe`
- Ensured ongoing access even after reboots

### 7. **Process Spawn Chain**
- Chain observed: `gc_worker.exe → BitSentinelCore.exe → cmd.exe → schtasks.exe`
- Used trusted system binaries for evasion

### 8. **Root Cause Timeline**
- Root timestamp: `2025-05-06T21:00`  
- Confirmed via file creation of `BitSentinelCore.exe`

---

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
