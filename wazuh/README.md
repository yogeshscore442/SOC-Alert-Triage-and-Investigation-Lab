# Wazuh Detection Engineering & Custom Rules

## Overview
This directory contains custom detection rules designed for the Wazuh manager to monitor Windows endpoint telemetry, specifically detecting brute-force / password spraying patterns (Event 4625), rapid authentication success correlations (Event 4624), and Sysmon process evasion flags (Event 1).

---

## Rule Inventory

| Rule ID | Level | Target Event | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| **100050** | 8 | Event 4625 (Failures) | T1110.001 (Password Guessing) | Triggers when >= 3 authentication failures occur from a single source IP in 120 seconds. |
| **100051** | 12 | Event 4624 (Logon) | T1078 (Valid Accounts), T1110 | Correlates a successful logon event occurring within 300 seconds of Rule 100050 from the same source IP. |
| **100052** | 10 | Sysmon Event 1 | T1059.001, T1562.001 | Detects `powershell.exe` execution featuring evasion arguments (`-ExecutionPolicy Bypass`, `-WindowStyle Hidden`). |
| **100053** | 9 | Sysmon Event 1 | T1083 (File Discovery), T1074.001 | Detects process command lines redirecting output (`>`, `Out-File`) into `C:\Users\Public\`. |

---

## Configuration & Deployment Guide

### 1. File Placement on Wazuh Manager
Custom rules must be added inside the `/var/ossec/etc/rules/local_rules.xml` file on the Wazuh server:
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```
Paste the contents of [local-rules.xml](file:///c:/Users/YOGESH/Downloads/SOC%20Home%20Lab/wazuh/local-rules.xml) inside the `<group name="local,syslog,sshd,">` tags (or as an independent group).

### 2. Syntax Validation Before Restarting
Always test the rule syntax before restarting the Wazuh manager. If syntax is invalid, the manager service will fail to restart:
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```
*Expected successful output:*
```
2026/10/24 15:00:00 wazuh-analysisd: INFO: Configuration status at '/var/ossec/etc/rules/local_rules.xml': OK.
```

### 3. Testing with `wazuh-logtest`
Wazuh includes a live test harness called `wazuh-logtest` that evaluates simulated log strings against active decoders and rules without affecting production alerts:
```bash
sudo /var/ossec/bin/wazuh-logtest
```
Paste the raw JSON or Event Log string when prompted. The tool prints:
- `**Phase 1: Completed pre-decoding.`
- `**Phase 2: Completed decoding. (win_event_channel)`
- `**Phase 3: Completed filtering (rules).`
  - Rule ID fired, level, description, and MITRE mapping.

### 4. Restarting the Service
Once validated:
```bash
sudo systemctl restart wazuh-manager
```

---

## Common Pitfalls & Troubleshooting Notes

1. **Parent Rule Mismatch:** Rule `100050` relies on `<if_matched_sid>60122</if_matched_sid>`. In standard Wazuh versions, rule `60122` fires on Windows Event ID 4625. If using custom Windows decoders or third-party log forwarders, verify that the initial event triggers the expected base rule.
2. **Field Path Formatting in Wazuh 4.x+:** In modern Wazuh Windows EventChannel decoders, fields are nested under `win.eventdata.*` (e.g., `win.eventdata.image`, `win.eventdata.commandLine`). Older OSSEC / Wazuh 3.x installations expected `data.win.system.*`. Always verify the decoded field names using `wazuh-logtest`.
3. **Regex Engine:** Wazuh rules use PCRE2 (`type="pcre2"`). Ensure regex flags like case-insensitivity (`(?i)`) are properly closed to avoid compile warnings.

---

> **Testing Disclaimer:** These rules were authored to standard Wazuh 4.x schema specifications and syntactically structured for Windows EventChannel and Sysmon decoders. In this repository, rules are reviewed statically against the synthetic dataset. Live execution on a running Wazuh manager is planned for hands-on validation in Phase 6.
