# Investigation Evidence & Screenshot Guidelines

## Overview
This directory is designated for storing sanitized screenshots, console captures, and visual evidence collected during hands-on lab execution.

> **Integrity Notice:** In accordance with academic and professional honesty standards, no synthetic or fabricated screenshots have been placed in this folder. When you spin up your local VMware workstation and Splunk instances, replace this guide with your verified captures.

---

## Recommended Evidence Captures for Portfolio Presentation

When preparing this repository for a technical interview or portfolio submission, capture and place the following images in this directory:

| Filename | System / View | Recommended Capture Content |
| :--- | :--- | :--- |
| `01-splunk-failed-logon-panel.png` | Splunk Web | SPL search results showing 4625 failed logon statistics grouped by `TargetUserName` and `IpAddress`. |
| `02-splunk-auth-correlation.png` | Splunk Web | Correlation search showing the transition from Event 4625 to Event 4624 under user `jdoe`. |
| `03-splunk-sysmon-process-tree.png` | Splunk Web | Sysmon Event ID 1 search highlighting `whoami.exe` and `powershell.exe` parent-child relationships. |
| `04-wazuh-alert-dashboard.png` | Wazuh Dashboard | Wazuh Security Events dashboard displaying alerts for Rule `100050` and `100052`. |
| `05-sysmon-event-viewer.png` | Windows VM | Windows Event Viewer (`Eventvwr.msc`) inspecting raw Sysmon Event ID 1 details. |

---

## Sanitization Checklist Before Uploading

Before committing screenshots to GitHub:
- [ ] Obscure any personal email addresses, organizational names, or actual physical location coordinates.
- [ ] Confirm no private API keys, cloud tokens, or live credentials appear in browser URL bars or command prompts.
- [ ] Verify image resolution is readable (minimum 1280x720 recommended).
- [ ] Use PNG format for clean text rendering.
