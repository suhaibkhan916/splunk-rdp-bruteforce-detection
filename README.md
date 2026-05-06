# Splunk SIEM Detection Lab — RDP Brute-Force, Reconnaissance and Reverse Shell

> **TL;DR.** End-to-end SIEM lab. Splunk Enterprise on Ubuntu, Universal Forwarder on Windows, Kali as attacker. Hydra brute-forces RDP, an interactive session is established, a PowerShell reverse shell is fired. Detections are written in SPL against Windows Security Event Logs and validated. Useful for SOC analysts, Security+ and SC-200 candidates who want to see a full attack-and-detect cycle.

MSc Cyber Security lab, University of the West of England, 2024.

---

## Lab Architecture

| System | Role | IP |
|---|---|---|
| Ubuntu | Splunk Enterprise (indexer + search head) | 192.168.128.133 |
| Windows | Target with Splunk Universal Forwarder | 192.168.128.131 |
| Kali Linux | Attacker | 192.168.128.132 |

Logs flow: Windows Security Event Log → Universal Forwarder → Splunk receiver on TCP 9997 → indexed and searched in SPL.

![Lab architecture](Screenshots/01-architecture-diagram.png)
*Figure 1: Lab infrastructure across the three VMs.*

---

## Splunk Server Setup (Ubuntu)

Splunk Enterprise installed via the official `.deb` package and started with `sudo /opt/splunk/bin/splunk start --accept-license`. Web UI exposed on port 8000.

![Splunk services starting](Screenshots/02-splunk-services-starting.png)
*Figure 2: Splunk service initialising on Ubuntu.*

![Splunk login page](Screenshots/03-splunk-login-page.jpeg)
*Figure 3: Splunk web UI on port 8000.*

![Splunk dashboard](Screenshots/04-splunk-dashboard.jpeg)
*Figure 4: Splunk dashboard after first login.*

---

## Universal Forwarder Setup (Windows)

The Splunk Universal Forwarder was installed on the Windows target and configured to forward security event logs to the Splunk indexer on TCP 9997.

![Forwarder installation](Screenshots/05-forwarder-installation.jpeg)
*Figure 5: Universal Forwarder installation on Windows.*

![Forwarder connection verified](Screenshots/06-forwarder-connection-verified.png)
*Figure 6: Forwarder successfully connecting to the Splunk receiver.*

### Forwarder Configuration in Splunk

The receiver was configured to accept incoming data on TCP 9997, a server class was created, forwarding inputs were selected, and the relevant Windows Event Logs (Security, System, Application) were chosen.

![Port 9997 configuration](Screenshots/07-port-9997-config.png)
*Figure 7: Receiver configured on TCP 9997.*

![Server class naming](Screenshots/08-server-class-naming.jpeg)
*Figure 8: Server class created for the Windows forwarder.*

![Forwarding inputs](Screenshots/09-forwarding-inputs.jpeg)
*Figure 9: Forwarding inputs selected.*

![Event logs selection](Screenshots/10-event-logs-selection.jpeg)
*Figure 10: Windows event logs selected for forwarding.*

![Input defaults](Screenshots/11-input-defaults.jpeg)
*Figure 11: Default input settings applied.*

![Setup review](Screenshots/12-setup-review.jpeg)
*Figure 12: Final configuration review.*

Once configured, Windows event logs began streaming into Splunk in near real time.

![Event logs received](Screenshots/13-event-logs-received.jpeg)
*Figure 13: Windows security event logs flowing into Splunk.*

---

## Attack Chain Simulated

| Phase | Tool | Action | MITRE ATT&CK |
|---|---|---|---|
| Reconnaissance | Nmap | Port scan against TCP 3389 | T1046 — Network Service Discovery |
| Credential Access | Hydra | Brute-force RDP with wordlist | T1110.001 — Password Guessing |
| Lateral Movement | xfreerdp, Remmina | Interactive RDP session with cracked credentials | T1021.001 — Remote Services: RDP |
| Execution | PowerShell | Reverse shell back to attacker on TCP 4444 | T1059.001 — PowerShell |

### 1. Reconnaissance — Nmap

```bash
sudo nmap -A -p 3389 192.168.128.131
```

Confirmed RDP service exposed on the standard port.

![Nmap port scan](Screenshots/14-nmap-port-scan.jpeg)
*Figure 14: Nmap scan confirms TCP 3389 open on the target.*

### 2. Credential Access — Hydra

```bash
hydra -t 4 -V -f -l test -P passwordlist.txt rdp://192.168.128.131
```

Brute-force run against the user `test` using a wordlist. Hydra eventually returned valid credentials.

![Hydra brute-force](Screenshots/15-hydra-bruteforce.jpeg)
*Figure 15: Hydra cracking the RDP password.*

![Hydra brute-force second run](Screenshots/16-hydra-bruteforce-2nd-attempt.png)
*Figure 16: Repeat brute-force run on a separate date for detection validation.*

### 3. Lateral Movement — RDP Session

```bash
xfreerdp /u:test /p:123456 /v:192.168.128.131 /dynamic-resolution
```

![xfreerdp session](Screenshots/17-xfreerdp-session.jpeg)
*Figure 17: Interactive RDP session established with cracked credentials.*

![Remmina session](Screenshots/18-remmina-session.jpeg)
*Figure 18: Same access reproduced via Remmina to confirm the credentials worked across clients.*

### 4. Execution — PowerShell Reverse Shell

A PowerShell reverse-shell payload was executed from the RDP session, calling back to the Kali listener on TCP 4444.

![Reverse shell](Screenshots/19-reverse-shell.png)
*Figure 19: Reverse shell connecting back to the attacker.*

---

## Detections Written in SPL

### 1. Failed RDP Login Attempts

```spl
source="WinEventLog:Security" EventCode=4625
```

Windows logs every failed authentication as Event ID 4625. During the Hydra run, this query showed a clear spike in failed logons within a short window — the signature pattern of a brute-force attempt.

![Failed RDP spike](Screenshots/20-failed-rdp-spike.jpeg)
*Figure 20: Spike in EventCode 4625 events during the Hydra run.*

![Event 4625 detail](Screenshots/21-event-4625-detail.jpeg)
*Figure 21: Event-level detail showing source IP, target user, logon type.*

![Hydra failed attempts](Screenshots/22-hydra-failed-attempts.png)
*Figure 22: Failed-logon volume during the second Hydra run.*

![Hydra attempts volume](Screenshots/23-hydra-attempts-volume.png)
*Figure 23: Total failed login count from the brute-force run.*

### 2. Successful RDP Logins (Interactive)

```spl
source="WinEventLog:Security" EventCode=4624 Logon_Type=10
```

Event ID 4624 is a successful logon. `Logon_Type=10` filters specifically for RemoteInteractive sessions (RDP). Pairing this query with the failed-logon query above is the standard analyst workflow for confirming a successful brute-force compromise: a spike of 4625 followed by a 4624 with `Logon_Type=10` from the same source.

![Successful RDP login](Screenshots/24-successful-rdp-4624.jpeg)
*Figure 24: Successful 4624 event after the brute-force window — credentials worked.*

![Login event details](Screenshots/25-login-event-details.jpeg)
*Figure 25: Logon event detail confirming the source IP and logon type.*

### 3. Brute-Force Denial Pattern

```spl
source="WinEventLog:Security" EventCode=4625
| sort 0 -total_count percent_denied
```

Sorts failed-logon volume to surface the loudest source IP, useful when triaging multiple noisy hosts.

![Brute-force denial activities](Screenshots/26-bruteforce-denial-activities.jpeg)
*Figure 26: Sorted view of denial activity.*

### 4. Combined Logon and Logoff Activity

```spl
source="WinEventLog:Security" EventCode=4624 OR EventCode=4625
```

Gives the full session picture: every successful and failed logon side by side, useful for timeline reconstruction during incident review.

![Logon and logoff activities](Screenshots/27-logon-logoff-activities.jpeg)
*Figure 27: Combined logon and logoff timeline.*

![Overall events graph](Screenshots/28-overall-events-graph.png)
*Figure 28: Aggregate event view — the brute-force spikes are visually unmistakable.*

---

## Findings

- The Hydra brute-force generated several hundred Event ID 4625 entries inside a few minutes, an obvious detection signal that a basic alerting rule would catch.
- The successful 4624 with `Logon_Type=10` immediately after the spike confirmed credentials had been guessed and the session was now authenticated.
- The reverse shell triggered no clean Event Log signature on its own, highlighting the gap between authentication-layer detections and process-execution detections. Sysmon would close that gap. Noted as a follow-up improvement.
- Splunk's timeline visualisation made the attack stages distinguishable at a glance, which is the operational value of a SIEM versus raw log review.

## Repeat Run for Validation

The lab was re-run on a separate date to validate detections held under different network conditions. IPs differ between the two runs, but the detection logic and the failed-logon spike pattern reproduced consistently.

---

## What This Demonstrates

- Splunk Enterprise installation and Universal Forwarder configuration
- Forwarder-to-indexer pipeline (TCP 9997, server class, input selection)
- SPL query construction against Windows Security Event Logs
- Mapping of attack actions to MITRE ATT&CK techniques
- T1 SOC analyst workflow: alert → triage → correlate → confirm compromise

## Limitations and Honest Notes

- Lab environment. Real production SOC work involves alert tuning at scale, false-positive triage volumes, ticketing handoff, and on-call rotations that this lab does not simulate.
- Detections rely on Windows Security Event Logs only. A real SOC would also consume Sysmon, EDR telemetry, network flow data, and threat intelligence feeds.
- No SOAR or automated response was integrated. All triage was manual.

## References

- Splunk Documentation, https://docs.splunk.com
- MITRE ATT&CK Framework, https://attack.mitre.org
- Microsoft Windows Security Auditing Event IDs

---

**Author**

Muhammad Suhaib
MSc Cyber Security (Distinction), University of the West of England
CompTIA Security+
[LinkedIn](https://linkedin.com/in/muhsuhaib) · suhaibkhan916@gmail.com
