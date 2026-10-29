# Synthetic Sample Datasets

## Purpose and Scope
This directory contains explicitly simulated, sanitized JSON datasets designed to model a Windows endpoint attack scenario for SIEM ingestion, triage, and correlation.

> **Disclaimer:** These events are synthetic. They were constructed for educational analysis, search verification, and pipeline testing. They do not represent live telemetry extracted from any production system or personal device. IP addresses use private ranges (RFC 1918) and reserved documentation addresses (RFC 5737: `198.51.100.42`).

---

## Dataset Files

| File | Source | Description | Event IDs Included |
| :--- | :--- | :--- | :--- |
| `windows-security-events.json` | Windows Security Event Log (`WinEventLog:Security`) | Authentication failures and logon events | Event ID 4625, Event ID 4624, Event ID 4672 |
| `sysmon-events.json` | Microsoft-Windows-Sysmon/Operational (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`) | Endpoint process creation and network sockets | Event ID 1 (Process Create), Event ID 3 (Network Connect) |

---

## Scenario Metadata & Correlation Keys

All synthetic records in these files share a unified scenario context:

- **Target Endpoint:** `WIN-LAB-01.LAB.LOCAL` (`192.168.10.25`)
- **Attacker / Source Station:** `ATTACK-HOST` (`192.168.10.105`)
- **Target Accounts:** `admin_svc`, `Administrator`, `jdoe`
- **Compromised Session LogonId:** `0x14A28F`
- **External C2 Simulation IP:** `198.51.100.42` (Port 443)
- **Investigation Window:** `2026-10-24T14:15:00Z` to `2026-10-24T14:35:00Z`

### Ingestion into Splunk
To ingest these events for testing in a standalone Splunk instance:
1. In Splunk Web, navigate to **Settings > Add Data > Upload**.
2. Select `windows-security-events.json` with sourcetype `_json` (or map to `WinEventLog:Security`).
3. Select `sysmon-events.json` with sourcetype `_json` (or map to `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`).
4. Set index to `main` (or dedicated index `endpoint_lab`).
