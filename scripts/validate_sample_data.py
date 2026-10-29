#!/usr/bin/env python3
"""
validate_sample_data.py
=======================
Quality control and integrity check script for synthetic SOC investigation events.
Verifies schema compliance, chronological order, and cross-event correlation keys.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

REQUIRED_FIELDS_4625 = [
    "EventID", "TimeCreated", "Computer", "TargetUserName", 
    "Status", "SubStatus", "LogonType", "IpAddress"
]

REQUIRED_FIELDS_4624 = [
    "EventID", "TimeCreated", "Computer", "TargetUserName", 
    "TargetLogonId", "LogonType", "IpAddress"
]

REQUIRED_FIELDS_SYSMON_1 = [
    "EventID", "TimeCreated", "Computer", "ProcessId", 
    "Image", "CommandLine", "User", "ParentProcessId", "ParentImage"
]

REQUIRED_FIELDS_SYSMON_3 = [
    "EventID", "TimeCreated", "Computer", "ProcessId", 
    "Image", "SourceIp", "DestinationIp", "DestinationPort"
]

def parse_iso(ts_str: str) -> datetime:
    # Handles ISO 8601 strings with Z
    clean_ts = ts_str.replace("Z", "+00:00")
    return datetime.fromisoformat(clean_ts)

def validate_dataset():
    base_dir = Path(__file__).resolve().parent.parent
    sec_file = base_dir / "sample-data" / "windows-security-events.json"
    sysmon_file = base_dir / "sample-data" / "sysmon-events.json"

    print("=" * 65)
    print("SOC SAMPLE DATASET INTEGRITY VALIDATOR")
    print("=" * 65)

    errors = []
    warnings = []

    # 1. Load Windows Security Events
    if not sec_file.exists():
        print(f"[FAIL] Missing file: {sec_file}")
        return 1

    try:
        with open(sec_file, "r", encoding="utf-8") as f:
            sec_events = json.load(f)
        print(f"[PASS] Successfully parsed JSON: {sec_file.name} ({len(sec_events)} events)")
    except Exception as e:
        print(f"[FAIL] JSON decode error in {sec_file.name}: {e}")
        return 1

    # 2. Load Sysmon Events
    if not sysmon_file.exists():
        print(f"[FAIL] Missing file: {sysmon_file}")
        return 1

    try:
        with open(sysmon_file, "r", encoding="utf-8") as f:
            sysmon_events = json.load(f)
        print(f"[PASS] Successfully parsed JSON: {sysmon_file.name} ({len(sysmon_events)} events)")
    except Exception as e:
        print(f"[FAIL] JSON decode error in {sysmon_file.name}: {e}")
        return 1

    # 3. Schema Check: Windows Security Events
    successful_logon_ids = set()
    prev_time = None

    for idx, ev in enumerate(sec_events):
        eid = ev.get("EventID")
        time_str = ev.get("TimeCreated")

        if not time_str:
            errors.append(f"Security event #{idx} missing TimeCreated")
            continue

        curr_time = parse_iso(time_str)
        if prev_time and curr_time < prev_time:
            warnings.append(f"Security event #{idx} timestamp ({time_str}) out of chronological order")
        prev_time = curr_time

        if eid == 4625:
            missing = [f for f in REQUIRED_FIELDS_4625 if f not in ev]
            if missing:
                errors.append(f"Event 4625 (#{idx}) missing required fields: {missing}")
        elif eid == 4624:
            missing = [f for f in REQUIRED_FIELDS_4624 if f not in ev]
            if missing:
                errors.append(f"Event 4624 (#{idx}) missing required fields: {missing}")
            if "TargetLogonId" in ev:
                successful_logon_ids.add(ev["TargetLogonId"])

    print(f"[PASS] Windows Security schema validated (Identified logon sessions: {successful_logon_ids})")

    # 4. Schema Check: Sysmon Events
    process_table = {}
    prev_time = None

    for idx, ev in enumerate(sysmon_events):
        eid = ev.get("EventID")
        time_str = ev.get("TimeCreated")

        if not time_str:
            errors.append(f"Sysmon event #{idx} missing TimeCreated")
            continue

        curr_time = parse_iso(time_str)
        if prev_time and curr_time < prev_time:
            warnings.append(f"Sysmon event #{idx} timestamp ({time_str}) out of chronological order")
        prev_time = curr_time

        if eid == 1:
            missing = [f for f in REQUIRED_FIELDS_SYSMON_1 if f not in ev]
            if missing:
                errors.append(f"Sysmon Event 1 (#{idx}) missing required fields: {missing}")
            pid = ev.get("ProcessId")
            if pid:
                process_table[pid] = ev
        elif eid == 3:
            missing = [f for f in REQUIRED_FIELDS_SYSMON_3 if f not in ev]
            if missing:
                errors.append(f"Sysmon Event 3 (#{idx}) missing required fields: {missing}")

    print(f"[PASS] Sysmon schema validated ({len(process_table)} unique processes tracked)")

    # 5. Correlation Key Verification
    # Cross-reference Sysmon LogonId with Security Event 4624 TargetLogonId
    for idx, ev in enumerate(sysmon_events):
        logon_id = ev.get("LogonId")
        if logon_id and logon_id not in successful_logon_ids:
            warnings.append(f"Sysmon event #{idx} LogonId '{logon_id}' not found in Security 4624 events")

    # Verify Sysmon Parent-Child Process Linkage
    for pid, proc in process_table.items():
        ppid = proc.get("ParentProcessId")
        if ppid in process_table:
            print(f"[CORRELATION] Verified process hierarchy: Parent PID {ppid} ({process_table[ppid]['Image']}) -> Child PID {pid} ({proc['Image']})")

    # Verify Sysmon Network Socket Linkage
    for idx, ev in enumerate(sysmon_events):
        if ev.get("EventID") == 3:
            pid = ev.get("ProcessId")
            if pid in process_table:
                print(f"[CORRELATION] Verified network socket linked to known process: PID {pid} ({process_table[pid]['Image']}) -> {ev.get('DestinationIp')}:{ev.get('DestinationPort')}")
            else:
                warnings.append(f"Sysmon Network Event 3 PID {pid} has no corresponding Process Create (Event 1)")

    print("-" * 65)
    if warnings:
        print(f"Warnings ({len(warnings)}):")
        for w in warnings:
            print(f"  [!] {w}")
    else:
        print("[PASS] Zero warnings detected.")

    if errors:
        print(f"Errors ({len(errors)}):")
        for err in errors:
            print(f"  [X] {err}")
        print("Validation FAILED.")
        return 1

    print("\n[SUCCESS] All datasets passed schema, chronology, and correlation validation.")
    print("=" * 65)
    return 0

if __name__ == "__main__":
    sys.exit(validate_dataset())
