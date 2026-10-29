# Lab Scope, Limitations & Enterprise Differences

## 1. Scope & Design Philosophy

This project was built to practice, demonstrate, and document core SOC triage fundamentals: reading raw event logs, understanding Windows authentication semantics, correlating cross-source events, and writing detection rules.

To maintain accessibility for a student workstation with 16 GB of RAM, intentional design choices and trade-offs were made. This document records those limitations honestly.

---

## 2. Key Differences Between This Home Lab and an Enterprise SOC

| Dimension | This Lab Environment | Enterprise SOC Environment | Impact on Investigation |
| :--- | :--- | :--- | :--- |
| **Domain Architecture** | Standalone Windows Workstation (`WIN-LAB-01`) | Multi-tier Active Directory Domain Forest with Redundant Domain Controllers | In this lab, authentication events (4625/4624) occur locally via NTLM/LSA. In an enterprise, Kerberos events (Event 4768 TGT Request, Event 4769 TGS Service Ticket) provide primary visibility into domain-wide credential attacks. |
| **Log Volume & Noise** | Clean, targeted event stream focused on simulated incident steps | 50,000 to 2,000,000+ events per second per cluster | In a real SOC, detection rules require rigorous tuning to avoid alert fatigue caused by normal administrative activity, health checks, and noisy business software. |
| **Network Visibility** | Host-based network socket telemetry via Sysmon Event ID 3 | Comprehensive perimeter telemetry (Zeek/Suricata, Next-Gen Firewalls, TLS Decrypting Proxies, NetFlow) | Host-only socket logs cannot inspect HTTP headers, TLS certificate details, or payload contents beyond IP and port coordinates. |
| **EDR Capabilities** | Wazuh EDR (Open-source, host-agent log inspection, basic FIM and rule matching) | Tier-1 Commercial EDRs (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne) | Commercial EDRs collect deep kernel call stacks, process memory injections, AMSI inspection, and automated sandbox detonate capabilities. |
| **Data Scope** | Curated synthetic test datasets designed for logic verification and reproducible testing | Live continuous production telemetry streaming from hundreds of diverse assets | The synthetic dataset serves as a structured test fixture to prove query correctness, pipeline logic, and correlation accuracy. |

---

## 3. Telemetry Gaps Identified During Testing

1. **PowerShell Script Block Logging:**
   - In standard out-of-the-box Windows configurations, Event ID 4104 (Script Block Logging) is disabled.
   - Without Event 4104, an analyst cannot view dynamic scripts executed from memory, Base64 decoded commands, or downloaded remote payloads. Sysmon Event 1 only exposes command-line strings passed at launch.

2. **Process Command Line Truncation:**
   - Large or heavily obfuscated commands exceeding buffer limits can be truncated in standard Windows Event 4688 logs. Sysmon mitigates this partially, but complete payload inspection requires script-level logging or memory dump capture.

3. **Network Connection Duration & Volume:**
   - Sysmon Event ID 3 captures TCP socket establishment (`SYN/ACK`), but does **not** log total bytes transferred or connection termination (`FIN/RST`). Determining exfiltration volume requires network flow logs or proxy logs.
