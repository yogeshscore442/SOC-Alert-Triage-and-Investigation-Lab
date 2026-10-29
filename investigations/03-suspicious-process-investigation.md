# Investigation 03: Suspicious Process Creation & Post-Logon Triage

## 1. Investigation Objective
Inspect process creation telemetry under the authenticated RDP session `0x14A28F` on endpoint `WIN-LAB-01.LAB.LOCAL`. Evaluate process lineage, command-line arguments, execution integrity levels, and determine whether post-authentication activity represents legitimate employee workflow or unauthorized adversary reconnaissance.

> **Data Notice:** Findings documented in this report are simulated results derived from the sanitized test fixture [sysmon-events.json](file:///c:/Users/YOGESH/Downloads/SOC%20Home%20Lab/sample-data/sysmon-events.json).

---

## 2. Scenario & Data Sources
- **Target Host:** `WIN-LAB-01.LAB.LOCAL` (`192.168.10.25`)
- **Telemetry Channel:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- **Primary Event ID:** Sysmon Event ID 1 (Process Create)
- **Pivot Filter:** `LogonId = "0x14A28F"`
- **Time Window:** `2026-10-24 14:22:10 UTC` to `2026-10-24 14:32:00 UTC`

---

## 3. Initial Observation
Within 90 seconds of the interactive RDP logon under account `LAB\jdoe`, multiple command-line interpreters were initiated from the desktop shell, executing discovery commands and writing output into `C:\Users\Public\`.

---

## 4. Relevant Event IDs & Fields

| Event ID | Key Fields Analyzed | Meaning in this Context |
| :--- | :--- | :--- |
| **Sysmon 1** | `LogonId` | Binds execution directly to Session `0x14A28F`. |
| **Sysmon 1** | `Image` | Executable invoked (`cmd.exe`, `powershell.exe`). |
| **Sysmon 1** | `CommandLine` | Full arguments executed. |
| **Sysmon 1** | `ParentImage` & `ParentProcessId` | Spawning parent binary and PID. |
| **Sysmon 1** | `IntegrityLevel` | `High` (Elevated admin token active). |
| **Sysmon 1** | `Hashes` | SHA256 of binaries (Verified Microsoft-signed system binaries). |

---

## 5. SPL Process Triage Query

```spl
index=* (EventCode=1 OR EventID=1) LogonId="0x14A28F"
| eval Parent=coalesce(ParentImage, parent_process_path)
| eval Process=coalesce(Image, process_path)
| eval CLI=coalesce(CommandLine, process_exec)
| table _time, User, LogonId, ParentProcessId, Parent, ProcessId, Process, CLI, IntegrityLevel
| sort _time
```

---

## 6. Evidence Table (Process Execution Lineage)

| Timestamp (UTC) | PID | Process Image | Parent PID | Parent Image | Command Line | Integrity |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `14:23:45.102` | `4820` | `C:\Windows\System32\cmd.exe` | `2840` | `C:\Windows\explorer.exe` | `"cmd.exe" /c whoami /all` | High |
| `14:25:30.450` | `5192` | `C:\Windows\System32\...\powershell.exe` | `4820` | `C:\Windows\System32\cmd.exe` | `powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Out-File C:\Users\Public\net_recon.txt"` | High |
| `14:30:02.115` | `6044` | `C:\Windows\System32\cmd.exe` | `2840` | `C:\Windows\explorer.exe` | `"cmd.exe" /c dir C:\Users\jdoe\Desktop /s > C:\Users\Public\file_list.txt` | High |

---

## 7. Process Lineage & Tree Reconstruction

```
explorer.exe (PID: 2840 | RDP Desktop Shell)
 │
 ├── [14:23:45] cmd.exe (PID: 4820)
 │     │
 │     └── [14:25:30] powershell.exe (PID: 5192)
 │                     Arguments: -ExecutionPolicy Bypass -WindowStyle Hidden
 │                     Output: C:\Users\Public\net_recon.txt
 │
 └── [14:30:02] cmd.exe (PID: 6044)
       Arguments: dir C:\Users\jdoe\Desktop /s > C:\Users\Public\file_list.txt
```

---

## 8. Analyst Reasoning: Resolving the Benign vs. Malicious Conflict

In Investigation 02, we noted two competing hypotheses: an authorized employee mistyping their password vs. an adversary who guessed the password.

### Evaluating the Post-Logon Behavior:
1. **Command 1 (`whoami /all`):** Normal users do not log onto their desktop and immediately execute `whoami /all` via an unprompted CLI command. This is standard adversary "situational awareness" to enumerate group memberships and user privilege flags.
2. **Command 2 (Hidden PowerShell Evasion):** The operator intentionally executed PowerShell with `-WindowStyle Hidden` and `-ExecutionPolicy Bypass`. Legitimate users working interactively on a remote desktop do not suppress their own windows unless attempting to hide execution from visual monitoring.
3. **Command 3 (Staging to `C:\Users\Public\`):** Both the network reconnaissance (`net_recon.txt`) and directory listing (`file_list.txt`) were directed to `C:\Users\Public\`. `C:\Users\Public\` is a notorious staging location utilized by threat actors because it possesses relaxed write permissions across standard and guest security contexts.

### Conclusion:
This sequence **disproves the benign user hypothesis**. The observed behavior is consistent with an adversary utilizing Living-off-the-Land Binaries (LOLBins) for local discovery and data staging.

---

## 9. Severity Assessment & MITRE ATT&CK Mapping
- **Assessed Severity:** **High**
- **Justification:** Confirmed adversary reconnaissance activity using administrative privileges under a compromised user session.
- **MITRE ATT&CK Mappings:**
  - **T1033 - System Owner/User Discovery:** Executing `whoami /all`.
  - **T1049 - System Network Connections Discovery:** Querying `Get-NetTCPConnection` for listening services.
  - **T1083 - File and Directory Discovery:** Recursively enumerating `Desktop` files.
  - **T1074.001 - Data Staged: Local Data Staging:** Writing artifacts to `C:\Users\Public\`.
  - **T1562.001 - Impair Defenses: Disable or Modify Tools:** Passing `-ExecutionPolicy Bypass`.

---

## 10. Next Steps
1. Investigate whether the PowerShell process (PID 5192) initiated network connections to internal or external destinations (Investigation 04 & 05).
2. Check for file modifications or persistence mechanisms (Registry `Run` keys, scheduled tasks) created in the same time frame.
