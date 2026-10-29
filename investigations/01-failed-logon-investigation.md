# Investigation 01: Failed Windows Logon Analysis (Event ID 4625)

## 1. Investigation Objective
Analyze repeated Windows authentication failures targeting endpoint `WIN-LAB-01.LAB.LOCAL`, identify attempted accounts, isolate source network coordinates, and evaluate failure sub-status codes to determine whether activity reflects password guessing, spraying, or benign user error.

> **Data Notice:** Findings documented in this report are simulated results derived from the sanitized test fixture [windows-security-events.json](file:///c:/Users/YOGESH/Downloads/SOC%20Home%20Lab/sample-data/windows-security-events.json).

---

## 2. Scenario & Data Sources
- **Target Host:** `WIN-LAB-01.LAB.LOCAL` (`192.168.10.25`)
- **Telemetry Channel:** `WinEventLog:Security` (Windows Security Auditing)
- **Primary Event ID:** 4625 (An account failed to log on)
- **Time Window:** `2026-10-24 14:15:00 UTC` to `2026-10-24 14:20:00 UTC`

---

## 3. Initial Observation
An alert triggered on SIEM monitoring indicating 4 failed authentication attempts across 3 distinct account names originating from a single internal IP (`192.168.10.105`) within a 3-minute window.

---

## 4. Relevant Event IDs & Fields

| Event ID | Key Fields Analyzed | Meaning in this Context |
| :--- | :--- | :--- |
| **4625** | `TargetUserName` | Targeted account name (`admin_svc`, `Administrator`, `jdoe`). |
| **4625** | `IpAddress` / `IpPort` | Client source address (`192.168.10.105:49210-49238`). |
| **4625** | `WorkstationName` | Client hostname reported (`ATTACK-HOST`). |
| **4625** | `LogonType` | Type 3 (Network) and Type 10 (RemoteInteractive / RDP). |
| **4625** | `Status` | `0xC000006D` (Generic logon failure). |
| **4625** | `SubStatus` | `0xC0000064` (User does not exist) & `0xC000006A` (Bad password). |

---

## 5. SPL Query Used

```spl
index=* (EventCode=4625 OR EventID=4625)
| eval TargetUser=coalesce(TargetUserName, user)
| eval SourceIP=coalesce(IpAddress, src_ip)
| eval SubStatusCode=coalesce(SubStatus, Sub_Status)
| eval FailureReason=case(
    SubStatusCode="0xC0000064", "Username does not exist",
    SubStatusCode="0xC000006A", "Bad password",
    true(), "Other: ".SubStatusCode
  )
| eval LogonTypeDesc=case(
    LogonType=3, "3: Network (SMB/RPC)",
    LogonType=10, "10: Remote Desktop (RDP)",
    true(), "Type: ".LogonType
  )
| table _time, SourceIP, WorkstationName, TargetUser, LogonTypeDesc, FailureReason
| sort _time
```

---

## 6. Evidence Table

| Timestamp (UTC) | Source IP | Workstation | Target User | Logon Type | SubStatus Code | Failure Reason |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-10-24 14:15:22` | `192.168.10.105` | `ATTACK-HOST` | `admin_svc` | Type 3 (Network) | `0xC0000064` | User does not exist |
| `2026-10-24 14:16:04` | `192.168.10.105` | `ATTACK-HOST` | `Administrator` | Type 3 (Network) | `0xC000006A` | Bad password |
| `2026-10-24 14:17:15` | `192.168.10.105` | `ATTACK-HOST` | `jdoe` | Type 10 (RDP) | `0xC000006A` | Bad password |
| `2026-10-24 14:18:02` | `192.168.10.105` | `ATTACK-HOST` | `jdoe` | Type 10 (RDP) | `0xC000006A` | Bad password |

---

## 7. Chronological Timeline
- **14:15:22 UTC:** Probing starts via Network logon (SMB/RPC) testing service account `admin_svc`. The system rejected it with `0xC0000064`, revealing the account is non-existent.
- **14:16:04 UTC:** The source shifted to the built-in `Administrator` account via SMB. The system rejected it with `0xC000006A` (bad password), confirming the account is active.
- **14:17:15 UTC:** The source shifted logon protocol to RDP (LogonType 10), targeting developer account `jdoe`. Failed with bad password.
- **14:18:02 UTC:** Second RDP failure on account `jdoe` with bad password.

---

## 8. Analyst Reasoning & Alternative Explanations

### Competing Hypotheses:
1. **Hypothesis 1 (Targeted Credential Spraying / Recon):** An attacker on `192.168.10.105` is testing common default accounts (`admin_svc`, `Administrator`) via SMB to discover valid usernames, then pivoting to a named user (`jdoe`) over RDP.
2. **Hypothesis 2 (Benign Administrative Misconfiguration):** An IT staff member or automated provisioning script from workstation `ATTACK-HOST` attempted scheduled service tasks with outdated credentials.

### Evaluation:
The progression from a non-existent account (`admin_svc`) to the local `Administrator` over SMB, followed by switching to an interactive RDP session targeting `jdoe`, is inconsistent with automated service misconfigurations. Automated services do not switch protocols from SMB to RDP while iterating through different user names. This pattern strongly supports deliberate credential testing.

---

## 9. Severity Assessment & MITRE ATT&CK Mapping

- **Assessed Severity:** **Medium** (Elevates to High if authentication succeeds)
- **Justification:** Multiple accounts targeted from a single internal host using multiple authentication protocols. Failed attempts alone do not establish system compromise, but indicate active reconnaissance.
- **MITRE ATT&CK Mappings:**
  - **T1110.003 - Brute Force: Password Spraying:** Testing a limited number of passwords against multiple accounts.
  - **T1078 - Valid Accounts:** Attempting to identify and authenticate as legitimate accounts.

---

## 10. Conclusion & Recommended Next Steps
Authentication logs confirm that host `192.168.10.105` conducted credential testing against `WIN-LAB-01`. Because the attempts were rejected, no immediate host compromise occurred during this 3-minute window.

### Recommended Next Steps:
1. Pivot immediately to check for successful logons (Event 4624) from `192.168.10.105` following 14:18:02 UTC (see Investigation 02).
2. Inspect network identity of `192.168.10.105` (DHCP leases, ARP tables, DNS registration) to identify the machine owner.
3. Review account lockout policies to verify thresholds for consecutive failures.

---

## 11. Limitations
- This dataset only captures authentication failures at the host level. It does not record failed network handshakes blocked prior to reaching the Windows LSA subsystem.
