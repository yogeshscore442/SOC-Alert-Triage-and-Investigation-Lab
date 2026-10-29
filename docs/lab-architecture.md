# Lab Architecture & Data Pipeline Specification

## 1. Network & Component Architecture

This home lab is designed to simulate an enterprise Windows workstation under active monitoring by both a Security Information and Event Management (SIEM) system and an Endpoint Detection and Response (EDR) platform.

```mermaid
graph TD
    subgraph Host["Host Machine: Windows 11 (16 GB Physical RAM)"]
        Splunk["Splunk Enterprise (Native Service)<br>Web UI: Port 8000<br>Listening Receiver: Port 9997"]
    end

    subgraph Hypervisor["VMware Workstation (NAT Subnet: 192.168.10.0/24)"]
        subgraph VictimVM["Target Endpoint: WIN-LAB-01 (192.168.10.25)"]
            OS["Windows 10/11 Enterprise x64<br>(4 GB RAM, 2 vCPUs)"]
            WinLog["Windows Security Event Log<br>(Audit Policies Enabled)"]
            SysmonEngine["Sysmon Service (v15+)<br>(Process & Socket Telemetry)"]
            UF["Splunk Universal Forwarder<br>(Port 9997/TCP)"]
            WazuhAg["Wazuh Agent Service<br>(Port 1514/TCP)"]
            
            OS --> WinLog
            OS --> SysmonEngine
            WinLog --> UF
            SysmonEngine --> UF
            WinLog --> WazuhAg
            SysmonEngine --> WazuhAg
        end

        subgraph WazuhServer["Wazuh SIEM / EDR Server (192.168.10.50)"]
            WazuhMgr["Wazuh Manager 4.x<br>(Ubuntu Server 22.04 LTS)<br>Web Dashboard: Port 443"]
        end
    end

    UF -->|TCP 9997 (Log Pipeline)| Splunk
    WazuhAg -->|TCP 1514 (Encrypted Events)| WazuhMgr
```

---

## 2. Telemetry Pipeline Workflow

1. **Event Generation:**
   - Operating system events (Logons, privilege assignments) generate Windows Security Event Log records via `lsass.exe` and `winlogon.exe`.
   - Kernel driver `SysmonDrv.sys` intercepts low-level process creations, image loads, and TCP socket creations, outputting structured XML into the `Microsoft-Windows-Sysmon/Operational` event log channel.

2. **Log Transport (Splunk Pipeline):**
   - The Splunk Universal Forwarder (UF) monitors Windows event logs locally via the `inputs.conf` configuration.
   - Events are buffered, batched, and transmitted over TCP port `9997` to the Splunk Enterprise indexer running on the host.
   - Splunk parses the timestamp, extracts indexed fields, and makes records searchable via Search Processing Language (SPL).

3. **Log Transport (Wazuh EDR Pipeline):**
   - The Wazuh agent service (`ossec-agent`) hooks into the Windows Event Channel via its `ossec.conf` file.
   - Raw records are encrypted and shipped across port `1514` to the Wazuh Manager.
   - The manager decodes fields (`wazuh-analysisd`) and evaluates them against XML detection rules (`local_rules.xml`).
   - If alert thresholds are met (e.g., severity level >= 3), alerts are indexed into the Wazuh Indexer and surfaced on the dashboard.

---

## 3. Communication Matrix

| Source Asset | Destination Asset | Port / Protocol | Service / Purpose |
| :--- | :--- | :--- | :--- |
| `WIN-LAB-01` (`192.168.10.25`) | Physical Host (`192.168.10.1`) | `9997/TCP` | Splunk Forwarder to Indexer |
| `WIN-LAB-01` (`192.168.10.25`) | Wazuh Server (`192.168.10.50`)| `1514/TCP` | Wazuh Agent to Manager |
| Host Browser (`localhost`) | Physical Host (`localhost`) | `8000/TCP` | Splunk Web Management Interface |
| Host Browser (`localhost`) | Wazuh Server (`192.168.10.50`)| `443/TCP`  | Wazuh Web Dashboard (Kibana/OpenSearch) |
| Simulated Attacker (`192.168.10.105`)| `WIN-LAB-01` (`192.168.10.25`) | `3389/TCP` | RDP Interactive Logon (Testing) |
| Simulated Attacker (`192.168.10.105`)| `WIN-LAB-01` (`192.168.10.25`) | `445/TCP`  | SMB / Network Auth Testing |
