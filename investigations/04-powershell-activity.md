# Investigation 04: PowerShell Activity & Telemetry Gaps

## 1. Investigation Objective
Conduct an in-depth forensic examination of the PowerShell process (`PID 5192`) spawned during session `0x14A28F`. Correlate process execution with outbound network telemetry (Sysmon Event ID 3), evaluate Living-off-the-Land (LotL) tradecraft, and document critical telemetry gaps when PowerShell Script Block Logging (Event 4104) is absent.

> **Data Notice:** Findings documented in this report are simulated results derived from the sanitized test fixture [sysmon-events.json](file:///c:/Users/YOGESH/Downloads/SOC%20Home%20Lab/sample-data/sysmon-events.json).

---

## 2. Scenario & Data Sources
- **Target Host:** `WIN-LAB-01.LAB.LOCAL` (`192.168.10.25`)
- **Telemetry Channels:** 
  - `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (Events 1 & 3)
  - `WinEventLog:Microsoft-Windows-PowerShell/Operational` (Event 4104 - Script Block)
- **Target Process:** `powershell.exe` (PID: 5192)
- **Time Window:** `2026-10-24 14:25:00 UTC` to `2026-10-24 14:30:00 UTC`

---

## 3. Initial Observation
Sysmon Event ID 1 recorded `powershell.exe` launching with multiple defense evasion flags. Approximately 2 minutes and 45 seconds later, Sysmon Event ID 3 recorded an outbound network socket initiated by the exact same process ID (`5192`).

---

## 4. Relevant Event IDs & Fields

| Event ID | Source Channel | Key Fields Analyzed | Meaning in this Context |
| :--- | :--- | :--- | :--- |
| **Sysmon 1** | Sysmon Operational | `ProcessId`, `CommandLine`, `User` | Identified PID 5192 executing reconnaissance commands under user `LAB\jdoe`. |
| **Sysmon 3** | Sysmon Operational | `ProcessId`, `SourceIp`, `DestinationIp`, `DestinationPort` | Tracks network socket from `192.168.10.25:49812` to `198.51.100.42:443`. |
| **Win 4104** | PowerShell Operational | `ScriptBlockText` | Script block logging (evaluated for telemetry gap analysis). |

---

## 5. SPL Process & Network Correlation Query

```spl
index=* (EventCode=1 OR EventID=1 OR EventCode=3 OR EventID=3) ProcessId=5192
| eval Action=if(EventCode==1 OR EventID==1, "Process Execution", "Network Connection")
| eval Details=if(Action=="Process Execution", CommandLine, "Connected to: ".DestinationIp.":".DestinationPort." via ".Protocol)
| table _time, Action, ProcessId, Image, Details
| sort _time
```

---

## 6. Evidence Table

| Timestamp (UTC) | Event | PID | Image | Activity / Destination | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `14:25:30.450` | Sysmon 1 (Create) | `5192` | `C:\...\powershell.exe` | CLI: `-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "Get-NetTCPConnection..."` | Output redirected to `C:\Users\Public\net_recon.txt` |
| `14:28:15.820` | Sysmon 3 (Network) | `5192` | `C:\...\powershell.exe` | Egress: `192.168.10.25:49812` -> `198.51.100.42:443` (TCP/HTTPS) | Initiated socket to external IP |

---

## 7. Forensic Analysis of Tradecraft

### 1. Command-Line Deconstruction
```powershell
powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Out-File C:\Users\Public\net_recon.txt"
```
- `-ExecutionPolicy Bypass`: Disregards machine script restrictions set by administrators.
- `-NoProfile`: Prevents loading the user's profile (`profile.ps1`), speeding up execution and avoiding local administrative telemetry hooks.
- `-WindowStyle Hidden`: Suppresses console rendering, ensuring any visual observer of the desktop does not see a flashing blue PowerShell terminal.
- `Get-NetTCPConnection`: Native cmdlet used to identify open listening ports (e.g., local web services, databases, or management endpoints).

### 2. Network Egress Correlation (Sysmon Event ID 3)
At `14:28:15 UTC`, PID 5192 established an outbound TCP connection to `198.51.100.42:443`. 
- `198.51.100.42` is an external IP address (RFC 5737 test simulation).
- PowerShell connecting outbound over port 443 immediately following local reconnaissance strongly indicates an adversary establishing external Command and Control (C2) or exfiltrating staging files.

---

## 8. Telemetry Gap Analysis: The Need for Event ID 4104

### The Limitation of Sysmon Event 1 Alone:
In our simulated test, the adversary passed their command as plain text on the CLI (`-Command "..."`). Sysmon Event 1 successfully recorded this string.

However, in real-world attacks, threat actors rarely pass unencoded plaintext on the CLI. Common evasion techniques include:
1. **Base64 Encoding:** `powershell.exe -enc SQBFAFgA...`
2. **File Execution:** `powershell.exe -File C:\temp\payload.ps1`
3. **Memory Injection / IEX:** `powershell.exe "IEX (New-Object Net.WebClient).DownloadString('...')" `

Under those conditions, **Sysmon Event 1 only records the encoded string or file path**. It cannot unpack the in-memory execution.

### The Remediation: PowerShell Script Block Logging (Event 4104)
Enabling Script Block Logging via Group Policy (`Computer Configuration -> Policies -> Administrative Templates -> Windows Components -> Windows PowerShell -> Turn on PowerShell Script Block Logging`):
- Forces the PowerShell engine to generate **Event ID 4104** in the `Microsoft-Windows-PowerShell/Operational` channel.
- Automatically decodes Base64 payloads and captures the complete code block executed at runtime, regardless of obfuscation.

---

## 9. Severity Assessment & MITRE ATT&CK Mapping
- **Assessed Severity:** **Critical**
- **Justification:** Execution of evasion-flagged PowerShell combined with verified outbound network communication to an external destination from a high-integrity session.
- **MITRE ATT&CK Mappings:**
  - **T1059.001 - Command and Scripting Interpreter: PowerShell**
  - **T1071.001 - Application Layer Protocol: Web Protocols (C2 Egress)**
  - **T1049 - System Network Connections Discovery**
  - **T1562.001 - Impair Defenses: Disable or Modify Tools**

---

## 10. Conclusion
Process `5192` confirmed active network reconnaissance and outbound external network traffic. This confirms an active interactive compromise requiring immediate host containment.
