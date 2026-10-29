# Investigation 02: Authentication Correlation & Session Identification

## 1. Investigation Objective
Correlate the failed authentication events identified in Investigation 01 with subsequent logon activity from source IP `192.168.10.105`, isolate the resulting LSA Session LogonId, inspect assigned privilege rights, and evaluate whether the success indicates credential guessing success or legitimate user access.

> **Data Notice:** Findings documented in this report are simulated results derived from the sanitized test fixture [windows-security-events.json](file:///c:/Users/YOGESH/Downloads/SOC%20Home%20Lab/sample-data/windows-security-events.json).

---

## 2. Scenario & Data Sources
- **Target Host:** `WIN-LAB-01.LAB.LOCAL` (`192.168.10.25`)
- **Telemetry Channel:** `WinEventLog:Security`
- **Events Analyzed:** 
  - Event ID 4625 (Logon Failure)
  - Event ID 4624 (Successful Logon)
  - Event ID 4672 (Special Privileges Assigned)
- **Time Window:** `2026-10-24 14:15:00 UTC` to `2026-10-24 14:25:00 UTC`

---

## 3. Initial Observation
Following two consecutive failed RDP authentications against account `jdoe` ending at 14:18:02 UTC, a successful logon event occurred from the identical source IP (`192.168.10.105`) at 14:22:10 UTC.

---

## 4. Relevant Event IDs & Fields

| Event ID | Key Fields Analyzed | Meaning in this Context |
| :--- | :--- | :--- |
| **4624** | `TargetUserName` | Authenticated user (`jdoe`). |
| **4624** | `TargetLogonId` | Session token `0x14A28F`. Primary anchor for process correlation. |
| **4624** | `LogonType` | `10` (RemoteInteractive / RDP session). |
| **4624** | `IpAddress` | Remote source (`192.168.10.105`). |
| **4672** | `SubjectLogonId` | Matches `0x14A28F`. Confirms privilege rights assigned to session. |
| **4672** | `PrivilegeList` | `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeBackupPrivilege`. |

---

## 5. SPL Correlation Query

```spl
index=* (EventCode=4625 OR EventID=4625 OR EventCode=4624 OR EventID=4624) IpAddress="192.168.10.105"
| eval Action=if(EventCode==4625 OR EventID==4625, "Failure", "Success")
| eval User=coalesce(TargetUserName, user)
| eval Session=coalesce(TargetLogonId, LogonId, "-")
| table _time, Action, User, LogonType, Session, IpAddress, WorkstationName
| sort _time
```

---

## 6. Evidence Table

| Timestamp (UTC) | Action | Target User | Logon Type | Session ID | Source IP | Workstation | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-10-24 14:17:15` | Failure (4625) | `jdoe` | 10 (RDP) | - | `192.168.10.105` | `ATTACK-HOST` | Bad password (`0xC000006A`) |
| `2026-10-24 14:18:02` | Failure (4625) | `jdoe` | 10 (RDP) | - | `192.168.10.105` | `ATTACK-HOST` | Bad password (`0xC000006A`) |
| `2026-10-24 14:22:10` | **Success (4624)** | `jdoe` | 10 (RDP) | **`0x14A28F`** | `192.168.10.105` | `ATTACK-HOST` | Negotiate package |
| `2026-10-24 14:22:11` | Privileges (4672) | `jdoe` | - | `0x14A28F` | `WIN-LAB-01` | - | Assigned `SeDebugPrivilege` |

---

## 7. Timeline & Correlation Analysis
- **Delta:** Exactly 248 seconds (4 minutes, 8 seconds) elapsed between the last failure (14:18:02) and the successful logon (14:22:10).
- **Session Identity:** The successful session received `TargetLogonId = 0x14A28F`.
- **Privilege Escalation Risk:** Event 4672 reveals that account `jdoe` is a member of the local Administrators group, inheriting sensitive rights including `SeDebugPrivilege` (which allows attaching debuggers to arbitrary processes, including `lsass.exe`) and `SeTakeOwnershipPrivilege`.

---

## 8. Analyst Reasoning: Why Success Does Not Equal Breach

A common junior analyst error is immediately escalating a ticket as a "Confirmed Ransomware / Data Breach" upon seeing a successful logon after failed attempts. 

### The Competing Explanations:
1. **Scenario A (Credential Compromise):** An external or rogue internal actor engaged in password guessing and discovered the valid password on the 3rd or 4th attempt.
2. **Scenario B (Benign User Password Mistype):** An authorized employee (`jdoe`) working from workstation `ATTACK-HOST` miskeyed their complex password twice, verified their caps-lock setting, and successfully authenticated on the next attempt.

### Ground Truth Rule:
Authentication logs alone **cannot** resolve this ambiguity. Both scenarios generate identical 4625 and 4624 records. To prove or disprove compromise, the analyst must pivot into **endpoint process telemetry (Sysmon Event ID 1)** executed under Session `0x14A28F` immediately following 14:22:10 UTC.

---

## 9. Severity Assessment & MITRE ATT&CK Mapping
- **Assessed Severity:** **Medium-High (Elevated Triage Required)**
- **Justification:** High-privilege session (`SeDebugPrivilege`) established via RDP from an internal workstation that previously generated failed authentications against administrative accounts.
- **MITRE ATT&CK Mappings:**
  - **T1078.003 - Valid Accounts: Local Accounts**
  - **T1021.001 - Remote Services: Remote Desktop Protocol**
  - **T1068 - Exploitation for Privilege Escalation (Privilege Abuse Context)**

---

## 10. Conclusion & Pivot Instructions
Session `0x14A28F` represents a confirmed RDP connection with administrative privileges. The investigation now transitions from network authentication logs to endpoint telemetry to inspect every command and child process spawned under `0x14A28F`.
