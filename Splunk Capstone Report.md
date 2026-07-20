# Splunk SOC Investigation
## Brute Force → RDP Compromise → Persistence → Command & Control

---

## Executive Summary

**Date:** October 15, 2025

A user at a local dental clinic reported suspicious activity after noticing their mouse moving without user interaction. Using Splunk Enterprise, I investigated Windows Security, Sysmon, and network logs to determine whether the endpoint had been compromised.

The investigation revealed that an attacker successfully brute-forced user credentials, established an RDP session, downloaded a malicious executable (`python.exe`), created persistence through Windows Task Scheduler, and attempted outbound command-and-control (C2) communication.

---

# Environment

| Item | Value |
|------|-------|
| SIEM | Splunk Enterprise |
| Operating System | Windows |
| Endpoint | FRONTDESK-PC1.KCD.local |
| Investigation Type | Endpoint Compromise |
| Framework | MITRE ATT&CK |

---

# Indicators of Compromise (IOCs)

| IOC | Value |
|------|------|
| Host | FRONTDESK-PC1.KCD.local |
| Internal IP | 172.16.0.110 |
| Attacker IP | 172.16.0.184 |
| Malicious IP | 157.245.46.190 |
| Suspicious IP | 20.189.173.7 |
| File | python.exe |
| SHA256 | CFFAB896E9F0B12101034D9CED76332EF5AA4036AFA08E940E825E277C21A044 |

---

# Attack Timeline

## 1. Brute Force Attack

**Time**

12:51:44 PM – 12:52:57 PM UTC

### Findings

Multiple failed authentication attempts targeted several Windows accounts:

- administrator
- guest
- andrew.henderson
- ryan.adams

**Source IP**

172.16.0.184

### SPL

```spl
index="splunk101" EventCode=4625
| table _time EventCode user src_ip dest_nt_host
| sort +_time
```

**MITRE ATT&CK**

- T1110 - Brute Force

---

## 2. Successful Authentication

### Findings

The attacker successfully authenticated using Ryan.Adams' account multiple times.

### SPL

```spl
index="splunk101" EventCode=4624
| table _time EventCode user src_ip dest_nt_host
| sort +_time
```

**MITRE ATT&CK**

- T1078 - Valid Accounts

---

## 3. Remote Desktop Access

### Findings

Following successful authentication, the attacker established an RDP session from:

```
172.16.0.184
```

to

```
FRONTDESK-PC1.KCD.local
```

**MITRE ATT&CK**

- T1021.001 - Remote Desktop Protocol

---

## 4. Alternate Credential Usage

### Findings

Windows Event ID 4648 indicated alternate credentials were used, suggesting attacker activity through RDP, RunAs, or similar authentication mechanisms.

### SPL

```spl
index="splunk101"
user="Ryan.Adams"
EventCode=4648
```

---

## 5. Malicious File Download

### Time

12:57 PM UTC

### Findings

Google Chrome downloaded

```
python.exe
```

to

```
C:\Users\Ryan.Adams\Music\
```

This executable later became the persistence mechanism.

### SPL

```spl
index="splunk101"
"C:\\Users\\Ryan.Adams\\Music"
```

**MITRE ATT&CK**

- T1105 - Ingress Tool Transfer

---

## 6. Malicious Network Connection

The endpoint connected to

```
157.245.46.190
```

shortly after downloading the executable.

This activity suggests beaconing or initial command-and-control communication.

---

## 7. PowerShell Activity

### Findings

PowerShell executed shortly after the malware was downloaded.

```
PowerShell.exe
-noexit
-command Set-Location
```

**MITRE ATT&CK**

- T1059.001 - PowerShell

---

## 8. Persistence

### Findings

The attacker created a Scheduled Task named

```
PythonUpdate
```

configured to execute

```
python.exe
```

at every system startup using SYSTEM privileges.

### Command

```text
schtasks.exe /create
/tn PythonUpdate
/tr C:\Users\Ryan.Adams\Music\python.exe
/sc onstart
/ru SYSTEM
```

**MITRE ATT&CK**

- T1053.005 - Scheduled Task

---

## 9. Command & Control Attempt

At

```
1:09 PM UTC
```

the endpoint attempted communication with

```
20.189.173.7
```

The TLS connection failed due to a certificate validation error.

Although unsuccessful, this activity indicates an attempted outbound communication.

---

# Attack Chain

```text
Brute Force
      │
      ▼
Successful Login
      │
      ▼
RDP Access
      │
      ▼
Malware Download
      │
      ▼
PowerShell Execution
      │
      ▼
Scheduled Task Persistence
      │
      ▼
Outbound Network Connection
      │
      ▼
Attempted Command & Control
```

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Initial Access | T1110 - Brute Force |
| Initial Access | T1078 - Valid Accounts |
| Lateral Movement | T1021.001 - Remote Desktop Protocol |
| Execution | T1059.001 - PowerShell |
| Persistence | T1053.005 - Scheduled Task |
| Command and Control | T1071 - Application Layer Protocol |
| Command and Control | T1105 - Ingress Tool Transfer |

---

# Recommendations

- Isolate the compromised endpoint.
- Reset affected user accounts.
- Enable MFA.
- Remove the malicious scheduled task.
- Block malicious IP addresses.
- Block the SHA256 hash across the environment.
- Perform enterprise-wide IOC hunting.
- Review additional endpoints for similar persistence mechanisms.

---

# Skills Demonstrated

- Splunk Enterprise
- Search Processing Language (SPL)
- Windows Event Log Analysis
- Sysmon Analysis
- Authentication Analysis
- Threat Hunting
- IOC Analysis
- Timeline Reconstruction
- Incident Response
- MITRE ATT&CK Mapping
- Digital Forensics
- SOC Reporting

---

# Author

**Surapheal Belay**

Cybersecurity | SOC Analyst | Threat Hunter | Microsoft Defender XDR | Microsoft Sentinel | Splunk | Azure Security
