# Splunk 101 Capstone — Incident Investigation Report

## Findings

| Field | Value |
|---|---|
| **Time** | 2025-10-15 12:51:44 PM UTC |
| **Host** | FRONTDESK-PC1.KCD.local |
| **IOC IPs** | 157.245.46.190, 20.189.173.7 |
| **File name** | python.exe |
| **SHA256 Hash** | `CFFAB896E9F0B12101034D9CED76332EF5AA4036AFA08E940E825E277C21A044` |

## Investigation Summary

On 2025-10-15 12:51:44 PM, a brute force attack occurred against the user account **Ryan.Adams** on host **FRONTDESK-PC1.KCD.local**. Once the attacker successfully compromised the account, an RDP session was executed from source (attacker) IP **172.16.0.184** to **FRONTDESK-PC1.KCD.local (172.16.0.110)**.

The attacker downloaded a file, `python.exe`, to the directory `C:\Users\Ryan.Adams\Music\` via the Chrome browser on the host. Subsequently, a connection was made to a malicious IP, **157.245.46.190**, at 12:59 PM.

The attacker created persistence via the Task Scheduler at 1:04 PM, configuring `python.exe` to execute with **SYSTEM** privileges every time Windows starts.

At 1:09 PM, the host attempted a connection to a second malicious IP, **20.189.173.7**; the connection failed due to a certificate issue.

### Who / What / When / Where / Why / How

| | |
|---|---|
| **WHO** | Host: 172.16.0.110 |
| **WHAT** | Downloaded malicious file: `python.exe` |
| **WHEN** | October 15, 2025 — file downloaded at 12:57 PM |
| **WHERE** | Host with IP address 172.16.0.110 |
| **WHY** | To create a persistent connection to the network via a Task Scheduler entry |
| **HOW** | Attacker brute-forced user credentials, gained access to FRONTDESK-PC1.KCD.local, then downloaded and ran the malicious file |

---

## Investigation Details

### 1. Brute Force Attack
**2025-10-15 12:51:44 PM – 12:52:57 PM**
Brute force attack against host FRONTDESK-PC1.KCD.local. Usernames attempted: `administrator`, `guest`, `andrew.henderson`, `ryan.adams`. Source IP: `172.16.0.184`.

```spl
index="splunk101" EventCode IN (4625) | table _time, EventCode, user, src_ip, dest_nt_host | sort +_time
```

<img width="975" height="416" alt="image" src="https://github.com/user-attachments/assets/585e9ee7-c08e-468b-b2e8-e21c3e10d87e" />


| _time | EventCode | user | src_ip | dest_nt_host |
|---|---|---|---|---|
| 2025-10-15 12:52:08 | 4625 | ryan.adams | 172.16.0.184 | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:52:08 | 4625 | ryan.adams | 172.16.0.184 | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:52:09 | 4625 | ryan.adams | 172.16.0.184 | FRONTDESK-PC1.KCD.local |
| ... | 4625 | ryan.adams | 172.16.0.184 | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:52:13 | 4625 | ryan.adams | 172.16.0.184 | FRONTDESK-PC1.KCD.local |

*(Repeated 4625 failed logon events between 12:52:08–12:52:13, all against `ryan.adams` from `172.16.0.184`.)*

### 2. RDP Connection Attempts
**10/15/25 12:52:12.000 PM**
Attacker (`172.16.0.184`) made several attempts to RDP into FRONTDESK-PC1.KCD.local (`172.16.0.110`).

```spl
index="splunk101" 172.16.0.184 | where NOT EventCode IN (4624,4625) | table _time, EventID, src_ip, dest, DestinationPort, EventDescription host | sort +_time
```

<img width="975" height="459" alt="image" src="https://github.com/user-attachments/assets/e031c887-d1e0-48f9-8941-15e46d54a5c8" />


| _time | EventID | src_ip | dest | DestinationPort | EventDescription | host |
|---|---|---|---|---|---|---|
| 2025-10-15 12:52:03 – 12:52:09 | 3 | 172.16.0.184 | 172.16.0.110 | 3389 | Network connection | FRONTDESK-PC1 |

*(Repeated network connection events on port 3389 — RDP — from 172.16.0.184 to 172.16.0.110.)*

### 3. Successful Logons
**2025-10-15 12:52:12 PM – 12:55:20 PM**
Attacker successfully logged in 4 times as `Ryan.Adams` on FRONTDESK-PC1.KCD.local. Source IP: `172.16.0.184`.

```spl
index="splunk101" EventCode IN (4624) | table _time, EventCode, user, src_ip, dest_nt_host | sort +_time
```

<img width="975" height="300" alt="image" src="https://github.com/user-attachments/assets/f9aeee4d-85e0-4764-b86a-ba423358e260" />


| _time | EventCode | user | src_ip | dest_nt_host |
|---|---|---|---|---|
| 2025-10-15 12:52:12 | 4624 | Ryan.Adams | 172.16.0.184 | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:52:12 | 4624 | SYSTEM | | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:54:29 | 4624 | Ryan.Adams | 172.16.0.184 | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:54:51 | 4624 | SYSTEM | | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:55:17 | 4624 | Ryan.Adams | 172.16.0.184 | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:55:17 | 4624 | UMFD-3 | | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:55:17 | 4624 | DWM-3 | | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:55:18 | 4624 | SYSTEM | | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:55:20 | 4624 | Ryan.Adams | 172.16.0.184 | FRONTDESK-PC1.KCD.local |
| 2025-10-15 12:55:20 | 4624 | Ryan.Adams | | FRONTDESK-PC1.KCD.local |

### 4. Alternate Credential Use
**10/15/25 12:55:20.000 PM**
`Ryan.Adams` used alternate credentials — a process/user used alternate credentials (runas, PsExec, or lateral movement indicator).

```spl
index="splunk101" user="Ryan.Adams" EventCode=4648
```

<img width="975" height="269" alt="image" src="https://github.com/user-attachments/assets/296124d4-3f88-41f7-a94f-1fa1287fb8a8" />


Two `4648` events recorded at `12:55:20.000 PM`, both flagged: *"A logon was attempted using explicit credentials."*
- `dest = localhost`, `dest_nt_domain = KCD`, `dest_nt_host = localhost`, `dvc_nt_host = FRONTDESK-PC1`, `host = FRONTDESK-PC1`, `source = security.csv`, `sourcetype = WinEventSecurity`

### 5. Malicious File Download & Network Connections
**10/15/25 12:57:00.000 PM**
File create event: `C:\Users\Ryan.Adams\Music\python.exe`. Parent image: Google Chrome (`C:\Program Files\Google\Chrome\Application\chrome.exe`) on host FRONTDESK-PC1.KCD.local.

- Network connection made to malicious IP **157.245.46.190** from source IP `172.16.0.110`.
- DNS query made to `172.16.0.7` from source IP `172.16.0.110`.

<img width="826" height="665" alt="image" src="https://github.com/user-attachments/assets/1ebb510d-7ae2-4a53-93ba-4503d96e6409" />

**IP Reputation — 157.245.46.190**
| Field | Value |
|---|---|
| Reports | 117 |
| Confidence of Abuse | 10% |
| ISP | DigitalOcean, LLC |
| Usage Type | Data Center/Web Hosting/Transit |
| ASN | AS14061 |
| Domain | digitalocean.com |
| Country | United Kingdom |
| City | London, England |

**2025-10-15 13:00:44** — Command line execution:
```
"PowerShell.exe" -noexit -command Set-Location -literalPath 'C:\Users\Ryan.Adams\Music'
```

**2025-10-15 13:02:14** — Task Scheduler execution:
```
"C:\Windows\system32\mmc.exe" "C:\Windows\system32\taskschd.msc" /s
```

**2025-10-15 13:04:59** — Task Scheduler execution (persistence created):
```
"C:\Windows\system32\schtasks.exe" /create /tn PythonUpdate /tr C:\Users\Ryan.Adams\Music\python.exe /sc onstart /ru SYSTEM /f
```

```spl
index="splunk101" C:\\Users\\Ryan.Adams\\Music | table _time, EventDescription, parent_process_name, Image, file_path, src_ip, dest_ip, CommandLine | sort +_time
```
<img width="975" height="225" alt="image" src="https://github.com/user-attachments/assets/e77b5811-18b8-45a4-afdc-afa62b27b26b" />
<img width="975" height="34" alt="image" src="https://github.com/user-attachments/assets/6c28abb8-df2c-4297-ae28-349332dcc96c" />
<img width="975" height="54" alt="image" src="https://github.com/user-attachments/assets/e43669e0-3e20-4ccb-8590-71f3804f18f4" />

| _time | EventDescription | parent_process_name | Image | dest_ip |
|---|---|---|---|---|
| 2025-10-15 12:57:00 | FileCreate | chrome.exe | C:\Users\Ryan.Adams\Music\python.exe | |
| 2025-10-15 12:57:18 | FileCreateStreamHash | chrome.exe | C:\Users\Ryan.Adams\Music\python.exe | |
| 2025-10-15 13:00:33 | Process creation | explorer.exe | C:\Users\Ryan.Adams\Music\python.exe | |
| 2025-10-15 13:00:33 | Image loaded | | C:\Users\Ryan.Adams\Music\python.exe | |
| 2025-10-15 13:00:34 | DNSEvent (DNS query) | | C:\Users\Ryan.Adams\Music\python.exe | |
| 2025-10-15 13:00:34 | Network connection | | C:\Users\Ryan.Adams\Music\python.exe | 157.245.46.190 |
| 2025-10-15 13:00:34 | Network connection | | C:\Users\Ryan.Adams\Music\python.exe | 172.16.0.110 |
| 2025-10-15 13:00:35 | Network connection | | C:\Users\Ryan.Adams\Music\python.exe | 172.16.0.7 |
| 2025-10-15 13:00:44 | Process creation | explorer.exe | PowerShell.exe | |
| 2025-10-15 13:02:14 | Process creation | explorer.exe | mmc.exe (taskschd.msc) | |
| 2025-10-15 13:04:59 | Process creation | powershell.exe | schtasks.exe (create PythonUpdate) | |

### 6. Failed Connection to Second Malicious IP
**10/15/25 1:09:39 PM**
Source IP `172.16.0.110` attempted a connection to `20.189.173.7`. Connection unsuccessful due to a certificate issue.

<img width="884" height="703" alt="image" src="https://github.com/user-attachments/assets/7e337876-4fbb-4d57-8cd8-7cb3c16b6a4d" />

**IP Reputation — 20.189.173.7**
| Field | Value |
|---|---|
| Reports | 74 |
| Confidence of Abuse | 8% |
| ISP | Microsoft Corporation |
| Usage Type | Data Center/Web Hosting/Transit |
| ASN | AS8075 |
| Domain | microsoft.com |
| Country | United States of America |
| City | San Jose, California |

```spl
index="splunk101" dest="20.189.173.7" | table _time, host, id_orig_h, dest, msg | sort +_time
```
<img width="975" height="47" alt="image" src="https://github.com/user-attachments/assets/46a53af3-4498-48bc-ac80-36411c57b4cf" />

| _time | host | id_orig_h | dest | msg |
|---|---|---|---|---|
| 2025-10-15 13:09:39.291 | FRONTDESK-PC1 | 172.16.0.110 | 20.189.173.7 | SSL certificate validation failed with (unable to get local issuer certificate) |

---

## Remediation Recommendations

1. **Isolate** FRONTDESK-PC1 (172.16.0.110) from the network to prevent further lateral movement and continued C2 communication.
2. **Reset passwords** for `Ryan.Adams` and `Andrew.Henderson`, and apply MFA where available.
   - Do the same for `administrator` and `guest` accounts if legitimate; otherwise, **disable** them.
3. **Block IPs** `157.245.46.190` and `20.189.173.7` at the firewall.
4. **Block the hash** for `python.exe` from executing anywhere on the network:
   `CFFAB896E9F0B12101034D9CED76332EF5AA4036AFA08E940E825E277C21A044`
5. **Remove** the `PythonUpdate` Task Scheduler entry.
