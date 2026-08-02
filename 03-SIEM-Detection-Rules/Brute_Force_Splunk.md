# SIEM Detection Report — SSH Brute Force Leading to Privilege Escalation and Persistence (Linux)

> **Platform:** Splunk
> **Log Source:** `linux_secure` (auth.log)
> **Detection Type:** Brute Force / Account Compromise / Privilege Escalation / Persistence
> **Severity:** Critical
> **MITRE ATT&CK:** T1110.001, T1078, T1548.003, T1136.001

---

## Executive Summary

A Brute Force Activity Detection alert flagged SSH authentication activity against host `tryhackme-2404` from internal IP `10.10.242.248`. Investigation in Splunk confirmed a sustained SSH brute force campaign against the `john.smith` account — 500 failed password attempts within an approximately 5-minute window, interspersed with 3 successful authentications. Shortly after the final successful login, `john.smith` escalated privileges to `root` via `su`, and a new local account (`system-utm`) was created one minute later for persistence.

Because the source IP is an internal address, this activity is consistent with an attacker already present inside the network (e.g. via a prior VPN compromise or other foothold), rather than a purely external, internet-facing brute force.

---

## 5W Analysis

| Question | Answer |
|---|---|
| **Who** | Compromised account: `john.smith`; source IP `10.10.242.248` (internal) |
| **What** | SSH brute force → successful login → privilege escalation to root (`su`) → new local account created for persistence |
| **When** | 17 September 2025, ~09:00 (alert) — 09:12 (persistence established) |
| **Where** | Host `tryhackme-2404`, SSH service (`sshd`) |
| **Why** | Consistent with an attacker establishing privileged, persistent access following credential compromise |

---

## Alert Overview

| Field | Value |
|---|---|
| Alert Name | Brute Force Activity Detection |
| Time | 17/09/2025 09:00:21 AM |
| Target Host | tryhackme-2404 |
| Source IP | 10.10.242.248 |
| Severity | High (escalated to Critical upon confirmation) |

---

## Investigation Timeline

| Time (UTC) | Event |
|---|---|
| 09:00:18 – 09:00:47 | Failed SSH logins for invalid users (`emma.johnson`, `sarah.williams`) from 10.10.242.248 — consistent with username enumeration preceding the targeted brute force |
| ~09:06:00 – 09:06:35 | Sustained failed password attempts against `john.smith` (500 total observed across the campaign) |
| 09:06:01.591 | First successful login: `Accepted password for john.smith ... port 35932` |
| 09:07:25.040 | Second successful login: `Accepted password for john.smith ... port 47336` |
| 09:11:21.177 | Third (final) successful login: `Accepted password for john.smith ... port 53244` |
| 09:11:28.976 | `sudo: john.smith : TTY=pts/1 ; PWD=/home/john.smith ; USER=root ; COMMAND=/usr/bin/su` — privilege escalation to root |
| 09:12:10.914 | `useradd[3430]: new user: name=system-utm, UID=1002, GID=1002, home=/home/system-utm, shell=/bin/bash` — persistence account created |

**Brute force duration:** ~5 minutes (first observed failed attempts ~09:06:00 → final successful login 09:11:21), matching the confirmed 500 failed attempts against a single account in a short, high-frequency window.

---

## Detection Logic (SPL — Splunk)

**Scope activity by source IP and classify login outcomes per user:**
```spl
index="linux-alert" sourcetype="linux_secure" "10.10.242.248"
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval process="sshd"
| stats count values(action) values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username
```

**Result:**

| username | count | values(action) | src_ip | hostname | process |
|---|---|---|---|---|---|
| john.smith | 503 | Accepted, Failed | 10.10.242.248 | tryhackme-2404 | sshd |
| david.miller | 3 | Failed | 10.10.242.248 | tryhackme-2404 | sshd |
| sarah.williams | 3 | Failed | 10.10.242.248 | tryhackme-2404 | sshd |
| emma.johnson | 2 | Failed | 10.10.242.248 | tryhackme-2404 | sshd |

`john.smith` is the only targeted account with any `Accepted` result — confirming this was the sole successfully compromised account. 503 total events − 3 successful logins = **500 failed attempts**, internally consistent with the confirmed finding.

**Confirm persistence (account creation):**
```spl
index="linux-alert" sourcetype="linux_secure" useradd
```

Failed password for john.smith from 10.10.242.248 port 36706 ssh2
Failed password for john.smith from 10.10.242.248 port 36702 ssh2
Failed password for john.smith from 10.10.242.248 port 35976 ssh2

High-frequency, closely-spaced failed attempts (sub-second to few-second intervals) from a single source IP against a single username — a clear brute force signature.

### Successful Compromise
Accepted password for john.smith from 10.10.242.248 port 35932 ssh2 (09:06:01.591)
Accepted password for john.smith from 10.10.242.248 port 47336 ssh2 (09:07:25.040)
Accepted password for john.smith from 10.10.242.248 port 53244 ssh2 (09:11:21.177)

### Privilege Escalation
sudo: john.smith : TTY=pts/1 ; PWD=/home/john.smith ; USER=root ; COMMAND=/usr/bin/su

`john.smith` used `su` (via `sudo` invocation of `/usr/bin/su`) to escalate to `root`, 7.8 seconds after the final successful SSH login.

### Persistence
useradd[3430]: new user: name=system-utm, UID=1002, GID=1002, home=/home/system-utm, shell=/bin/bash, from=/dev/pts/3

A new local account, `system-utm`, was created ~42 seconds after the privilege escalation event — from a pty session (`/dev/pts/3`), consistent with interactive attacker activity rather than an automated script artifact.

---

## Attack Chain
Source IP: 10.10.242.248 (internal)
│
▼
Username enumeration (invalid users: emma.johnson, sarah.williams)
│
▼
SSH Brute Force against john.smith
(500 failed attempts, ~5 min window)
│
▼
Successful Authentication (3x, final at 09:11:21)
│
▼
Privilege Escalation: su → root
(09:11:28)
│
▼
Persistence: new local account "system-utm"
(09:12:10)

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Source IP | 10.10.242.248 |
| Host | tryhackme-2404 |
| Compromised account | john.smith |
| Enumerated/targeted usernames | emma.johnson, sarah.williams (confirmed invalid); david.miller (targeted, validity not confirmed in reviewed evidence) |
| Privilege escalation command | `/usr/bin/su` |
| Persistence account | system-utm (UID 1002, GID 1002, home=/home/system-utm, shell=/bin/bash) |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| Credential Access | T1110.001 | Brute Force: Password Guessing — 500 failed SSH attempts against john.smith |
| Initial Access | T1078 | Valid Accounts — successful authentication using guessed credentials |
| Privilege Escalation | T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching — `su` to root |
| Persistence | T1136.001 | Create Account: Local Account — `system-utm` created via `useradd` |

---

## Security Assessment

Indicators supporting a high-confidence malicious assessment:

- Sustained, high-frequency failed login attempts (500) against a single account from a single source in a short window — a textbook brute force signature, not user error.
- Only one of four targeted usernames (`john.smith`) was ever authenticated successfully — consistent with credential guessing rather than legitimate access.
- Privilege escalation to `root` occurred within 8 seconds of the final successful login — too fast to be routine administrative behavior.
- A new local account was created from an interactive pty session less than a minute after gaining root — consistent with manual, hands-on-keyboard persistence setup rather than automated tooling noise.

---

## Analyst Notes & Caveats

- **Source IP is internal.** `10.10.242.248` is not an internet-facing address, meaning the attacker either already had a foothold inside the network (e.g. compromised VPN, another host) or this traffic was routed through an internal proxy/jump host. The origin of this internal access was not determined in this investigation and requires further scoping.
- **Unrelated `ubuntu` account activity observed, not attributed to this incident.** The same log source shows `sudo`/`su` activity by a separate local account (`ubuntu`) at 08:56 and 09:10 UTC — both outside the four usernames targeted by the brute force. This activity is noted for completeness but was not investigated further, as there is no evidence connecting it to the `john.smith` compromise chain.
- **`david.miller` validity unconfirmed.** Unlike `emma.johnson` and `sarah.williams`, the reviewed evidence did not explicitly confirm whether `david.miller` is a valid or invalid account on this host.

---

## Detection Opportunities

- Alert on >N failed SSH authentications against a single username within a short time window (e.g. >20 failures/minute).
- Alert on successful authentication immediately following a high-volume failed-attempt burst against the same account.
- Alert on `su`/`sudo` to root occurring within seconds of a new SSH session.
- Alert on `useradd` executions immediately following privilege escalation events.
- Correlate internal-source brute force activity with VPN/remote access logs to identify the attacker's true entry point.

---

## Recommendations

- Disable/quarantine the `system-utm` account immediately.
- Force credential reset for `john.smith` and review for credential reuse across other systems.
- Investigate how the attacker obtained internal network access (VPN logs, other host compromises).
- Review authentication logs for `10.10.242.248` across other internal hosts for lateral movement.
- Confirm whether `david.miller` is a valid account; if so, treat as at-risk given targeting.
- Review shell history and further Sysmon/auditd activity under `system-utm` for post-persistence actions.
- Implement SSH rate-limiting / account lockout policies to prevent high-volume brute force in future.

---

## Conclusion

This investigation confirms a high-confidence SSH brute force attack originating from internal IP `10.10.242.248`, targeting the `john.smith` account with 500 failed authentication attempts over approximately 5 minutes before succeeding. Within roughly a minute and a half of the final successful login, the attacker escalated privileges to `root` via `su` and created a new local account (`system-utm`) for persistence. The internal origin of the source IP indicates the attacker already had some level of network access prior to this activity, and determining that initial entry point is the critical next step for the incident response team.

## Evidence

### Brute Force — Failed Authentication
