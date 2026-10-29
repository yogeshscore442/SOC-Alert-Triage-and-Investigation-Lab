# SOC Triage Dashboard Design Specification

## Overview
This document specifies the layout, panel configurations, and underlying Search Processing Language (SPL) queries for a practical SOC triage dashboard in Splunk. The dashboard provides tier-1 and tier-2 analysts with rapid situational awareness during authentication anomalies and post-logon investigations.

> **Status Notice:** This document represents a structural design and query specification. It has not been imported into a running Splunk cluster.

---

## 1. Visual Layout Architecture

```
+----------------------------------------------------------------------------------------------------+
| DASHBOARD HEADER: Windows Authentication Anomaly & Endpoint Triage                                 |
| Time Range Picker: Default [Last 4 Hours] | Target Host Filter: [WIN-LAB-01*]                      |
+----------------------------------------------------------------------------------------------------+
| PANEL 1 (Chart - 60% Width)                         | PANEL 2 (Bar Chart - 40% Width)              |
| Failed Authentication Volume Over Time              | Top Targeted Accounts (Event 4625)           |
+-----------------------------------------------------+----------------------------------------------+
| PANEL 3 (Table - 50% Width)                         | PANEL 4 (Single Value / Alert Table - 50%)   |
| Source IP Geolocation & Attempt Counts              | Successful Logons Following Failures (<15m)  |
+-----------------------------------------------------+----------------------------------------------+
| PANEL 5 (Full Width Table)                                                                         |
| High-Integrity & Evasion Process Creations (Sysmon Event ID 1)                                     |
+----------------------------------------------------------------------------------------------------+
| PANEL 6 (Full Width Interactive Timeline)                                                          |
| Cross-Source Investigation Timeline (4625, 4624, 4672, Sysmon 1, Sysmon 3)                         |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Panel Specifications & Underlying SPL

### Panel 1: Failed Logons Over Time
- **Visualization:** Time Chart (Line / Column)
- **Purpose:** Detect sudden spikes in authentication failures indicative of automated brute force or password spraying.
- **SPL Query:**
```spl
index=* (EventCode=4625 OR EventID=4625)
| timechart span=5m count by TargetUserName
```

---

### Panel 2: Top Targeted Accounts
- **Visualization:** Horizontal Bar Chart
- **Purpose:** Distinguish between targeted brute force (single username with high volume) and password spraying (many usernames with low volume per account).
- **SPL Query:**
```spl
index=* (EventCode=4625 OR EventID=4625)
| eval User=coalesce(TargetUserName, user)
| stats count as Failures by User
| sort - Failures
| head 10
```

---

### Panel 3: Source IP Breakdown & SubStatus Analysis
- **Visualization:** Statistics Table
- **Purpose:** Correlate external or internal source IP addresses with failure reasons (invalid account vs. invalid password).
- **SPL Query:**
```spl
index=* (EventCode=4625 OR EventID=4625)
| eval SourceIP=coalesce(IpAddress, src_ip)
| eval SubStatusCode=coalesce(SubStatus, Sub_Status)
| eval FailureReason=case(
    SubStatusCode="0xC0000064", "Username does not exist",
    SubStatusCode="0xC000006A", "Bad password",
    true(), "Code: ".SubStatusCode
  )
| stats count as Attempts, 
        values(TargetUserName) as TargetedUsers,
        values(FailureReason) as FailureCodes,
        earliest(_time) as FirstSeen,
        latest(_time) as LastSeen
        by SourceIP, WorkstationName
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(FirstSeen) ctime(LastSeen)
| sort - Attempts
```

---

### Panel 4: Rapid Success After Failure (Correlation Triage)
- **Visualization:** Table with Color Formatting (High Severity)
- **Purpose:** Alert analysts when a successful authentication (Event 4624) occurs from an IP that recently generated failures.
- **SPL Query:**
```spl
index=* (EventCode=4625 OR EventID=4625 OR EventCode=4624 OR EventID=4624)
| eval EventType=if(EventCode==4625 OR EventID==4625, "Failure", "Success")
| eval User=coalesce(TargetUserName, user)
| eval SourceIP=coalesce(IpAddress, src_ip)
| eval SessionID=coalesce(TargetLogonId, LogonId)
| stats count(eval(EventType=="Failure")) as FailCount,
        count(eval(EventType=="Success")) as SuccessCount,
        latest(eval(if(EventType=="Failure", _time, null()))) as LastFailureTime,
        earliest(eval(if(EventType=="Success", _time, null()))) as SuccessTime,
        values(SessionID) as SessionTokens
        by SourceIP, User
| where FailCount > 0 AND SuccessCount > 0 AND (SuccessTime - LastFailureTime) >= 0 AND (SuccessTime - LastFailureTime) <= 900
| eval DeltaSeconds = SuccessTime - LastFailureTime
| convert timeformat="%H:%M:%S" ctime(LastFailureTime) ctime(SuccessTime)
| table SourceIP, User, FailCount, LastFailureTime, SuccessTime, DeltaSeconds, SessionTokens
```

---

### Panel 5: High-Integrity & Evasion Process Creations
- **Visualization:** Table
- **Purpose:** Triage newly executed processes featuring living-off-the-land utilities or evasion flags under elevated security contexts.
- **SPL Query:**
```spl
index=* (EventCode=1 OR EventID=1)
| eval Process=coalesce(Image, process_path)
| eval CLI=coalesce(CommandLine, process_exec)
| eval UserContext=coalesce(User, user)
| where match(CLI, "(?i)(-ExecutionPolicy|-WindowStyle\s+Hidden|whoami|Get-NetTCPConnection|C:\\Users\\Public\\)")
| table _time, UserContext, LogonId, ParentImage, Process, CLI, IntegrityLevel
| sort - _time
```

---

### Panel 6: Cross-Source Investigation Timeline
- **Visualization:** Event List / Timeline Table
- **Purpose:** Provide complete multi-source narrative for incident reporting.
- **SPL Query:**
```spl
index=* (EventCode=4625 OR EventID=4625 OR EventCode=4624 OR EventID=4624 OR EventCode=1 OR EventID=1 OR EventCode=3 OR EventID=3)
| eval EID=coalesce(EventCode, EventID)
| eval UserContext=coalesce(TargetUserName, User, user, "SYSTEM")
| eval Summary=case(
    EID=4625, "Logon Failure [".UserContext."] from ".coalesce(IpAddress, src_ip)." (".SubStatus.")",
    EID=4624, "Logon Success [".UserContext."] Session: ".coalesce(TargetLogonId, LogonId),
    EID=1,    "Process Spawn: ".coalesce(Image, process_path)." | CLI: ".coalesce(CommandLine, process_exec),
    EID=3,    "Network Socket: ".coalesce(Image, process_path)." -> ".DestinationIp.":".DestinationPort,
    true(),   "Event ID: ".EID
  )
| table _time, Computer, EID, UserContext, Summary
| sort _time
```
