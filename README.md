# Dynamic Malware Analysis: AsyncRAT Loader Stub

## Executive Summary
This repository contains an analysis documentation and a custom YARA signature for an **AsyncRAT remote access trojan loader** (`meccha-camouflageV3.exe`). The sample was analyzed dynamically in a secure, isolated Windows 10 sandbox environment using Process Monitor (ProcMon) and Regshot. 

* **Malware Family:** AsyncRAT (Trojan.MSIL.Crypter)
* **Sample SHA-256:** `0aac658075b7d9e81419d0beaa3db796569bc14fd57512f4479fb36e9cc4c1a2`
* **Overall Verdict:** Highly Malicious (Loader designed for security evasion, anti-sandbox checks, and privilege persistence).

---

## Technical Analysis & Lifecycle

### 1. Initialization & Anti-Analysis Guardrails
Upon execution, the binary maps base Windows layers (`ntdll.dll`, `kernel32.dll`) and immediately inspects system configuration hives (`Safer\CodeIdentifiers` and `sysmain.sdb`) to identify if administrative software blocklists or guardrails are active.

### 2. Defense Evasion & Discovery
The malware targets host defenses by:
* Probing the native `C:\Program Files\Windows Defender` directories.
* Mapping `amsi.dll` in an attempt to hook and blind the Windows Antivirus Scan Interface.
* Attempting defensive self-deletion by wiping transient keys under `SmsRouter` and `NGenService` to remove forensic configuration footprints.

### 3. Network Activation Staging
The sample successfully initialized the Windows network stack (`ws2_32.dll`) to stage communication infrastructure. Code path analysis reveals configurations targeted at gathering environment profiling data and preparing connections to command-and-control (C2) domains or validation platforms (`ip-api[.]com`).

### 4. Fatal Crash Sequence
The binary encountered a fatal dependency mismatch while attempting to invoke hidden payload assets inside the Microsoft .NET Framework cache (`C:\Windows\Microsoft.NET\Framework\...`). Because the test lab environment lacked these specific directories, the runtime environment threw an unhandled exception, invoking Windows Error Reporting (`WerFault.exe`) which safely terminated the threat.

---

## MITRE ATT&CK TTP Mapping

| Tactic | Technique | ID | Observables / Evidence |
| :--- | :--- | :--- | :--- |
| **Discovery** | Security Software Discovery | T1518.001 | Audited active directory paths of Windows Defender |
| **Execution** | Windows Management Instrumentation | T1047 | Utilized `SWbemLocator` queries to profile hardware configurations |
| **Defense Evasion** | Impair Defenses / Indicator Removal | T1562.001 / T1070 | Loaded `amsi.dll` to blind scanning; wiped `SmsRouter` registry entries |
| **Command & Control** | Network Staging | T1105 | Initialized Winsock stack (`ws2_32.dll`) for socket mapping |

---

## Repository Contents
* `asyncrat_detector.yar`: Custom YARA signature engineered to detect structural compile paths, specific anti-sandbox strings, and aggressive Windows API definitions matching this threat.
