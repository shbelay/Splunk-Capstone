# Splunk Capstone

Report PDF: https://shbelay.com/files/SOC_Reports/Splunk101Capstone.pdf

## Highlights
- Investigated a simulated endpoint compromise using Splunk Enterprise
- Correlated Windows Security, Sysmon, and network telemetry
- Identified brute-force RDP, persistence, and C2 activity
- Reconstructed the complete attack timeline
- Produced a SOC-style incident report with IOCs and remediation recommendations

---

## Scenario
Ryan Adams, a local administrator at a small dental clinic, contacted the MahCyberDefense SOC hotline after suspecting his computer may have been compromised. He explained that around October 15 2025 at 13:00 UTC, his mouse was randomly moving so he became suspicious.

As a SOC analyst, your task is to investigate this incident using Splunk. Analyze the available data to determine what occurred, identify any indicators of compromise, and document your findings in a SOC report using the provided format found in the community.

---

## Project Overview
This project demonstrates an end-to-end SOC investigation performed in Splunk Enterprise using Windows Security logs, Sysmon telemetry, and network events. The objective was to investigate a suspected workstation compromise, reconstruct the attack timeline, identify indicators of compromise (IOCs), and document findings in a professional SOC incident report.

Working from a real-world style scenario, I analyzed authentication events, process creation, file activity, scheduled task creation, and network connections to determine how an attacker gained access, established persistence, and attempted command-and-control communication. The investigation followed the same analytical workflow used by SOC analysts when responding to endpoint security incidents.

---

## Investigation Workflow
1. Investigated failed authentication attempts.
2. Identified successful logons following the brute-force attack.
3. Confirmed RDP access from the attacker's IP.
4. Traced the download of a malicious executable.
5. Investigated process execution and PowerShell activity.
6. Identified persistence via Windows Scheduled Tasks.
7. Correlated outbound network connections to suspicious IP addresses.
8. Built a chronological timeline of attacker activity.
9. Produced a professional incident report with recommended containment and remediation actions.

---

# Tools Used

- Splunk Enterprise
- Windows Event Logs
- Sysmon
- SPL (Search Processing Language)
- IP Reputation Analysis
- MITRE ATT&CK Framework

---

## Key Technical Skills
- Splunk SPL
- Threat Hunting
- Windows Event Logs
- Sysmon
- Authentication Analysis
- IOC Analysis
- Process Investigation
- Network Traffic Analysis
- MITRE ATT&CK
- Incident Response
- Timeline Analysis
- SOC Reporting
