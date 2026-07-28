# SIEM Detection Report — Off-Hours Administrator Logon Leading to Backdoor Account Creation and Privilege Escalation

> **Platform:** Elastic Security (Kibana)
> **Log Sources:** Windows Security Event Log, Sysmon
> **Detection Type:** Account Compromise / Persistence / Privilege Escalation
> **Severity:** Critical
> **MITRE ATT&CK:** T1078, T1059.003, T1136, T1098.007, T1098

---

## Executive Summary

During SIEM monitoring in Elastic, a high-severity alert flagged a successful **Administrator** logon to `winserv2019.some.corp` outside business hours, originating from external IP `203.0.113.55`. Investigation of correlated Windows Security and Sysmon logs confirmed that, within roughly two minutes of this logon, the Administrator session created a new account (`svc_backup`) — using a command line that exposed its password in plaintext and requested **domain-scoped** creation — and then added that account to three privileged local groups: **Server Operators**, **Remote Desktop Users**, and **Administrators**.

The full sequence — off-hours privileged logon, backdoor account creation, and rapid privilege assignment — is consistent with an attacker having obtained valid Administrator credentials and establishing persistent, privileged access under a secondary identity.

---

## 5W Analysis

| Question | Answer |
|---|---|
| **Who** | Built-in `Administrator` account (session); new account `svc_backup` created and escalated |
| **What** | Off-hours RDP logon → domain-scoped account creation with plaintext password → addition to Server Operators, Remote Desktop Users, and Administrators |
| **When** | 20 July 2025, 05:11:22 – 05:13:28 (UTC), total window ~2 minutes |
| **Where** | `winserv2019.some.corp` |
| **Why** | Consistent with establishing a privileged backdoor account for persistent access following credential compromise |

---

## Alert Overview

| Field | Value |
|---|---|
| Alert ID | SOC-20250720-0014 |
| Severity | High |
| Detection | Administrator authentication outside business hours |
| User | Administrator |
| Host | winserv2019.some.corp |
| Source IP | 203.0.113.55 |
| Logon Type | RemoteInteractive (RDP) |
| Time | 2025-07-20 05:11:22.545 |

### Correlated Alert

| Field | Value |
|---|---|
| Alert ID | SOC-20250720-0015 |
| Severity | Critical |
| Detection | New User Account Created |
| User | Administrator |
| Host | winserv2019.some.corp |
| Time | 2025-07-20 05:13:09.417 |

---

## Investigation Timeline

| Time (UTC) | Event Source | Detail |
|---|---|---|
| 05:11:22.545 | Security 4624 | Administrator successful logon, RemoteInteractive (RDP), from 203.0.113.55 |
| 05:13:09.417 | Sysmon 1 | `cmd.exe`: `net user svc_backup Passw0rd123! /add /domain` |
| 05:13:09.539 | Sysmon 1 | `net.exe` → `net1.exe` executes the account creation |
| 05:13:10.009 | Security 4720 | Account `svc_backup` created (SID ...-1114), created by Administrator, Logon ID `0x4ff5f` |
| 05:13:15.436 | Sysmon 1 | `cmd.exe`: `net localgroup "Server Operators" svc_backup /add` |
| 05:13:15.588 | Security 4732 | `svc_backup` added to **Server Operators**, by Administrator, Logon ID `0x4ff5f` |
| 05:13:22.251 | Sysmon 1 | `cmd.exe`: `net localgroup "Remote Desktop Users" svc_backup /add` |
| 05:13:22.336 | Security 4732 | `svc_backup` added to **Remote Desktop Users**, by Administrator, Logon ID `0x4ff5f` |
| 05:13:27.999 | Sysmon 1 | `cmd.exe`: `net localgroup Administrators svc_backup /add` |
| 05:13:28.091 | Security 4732 | `svc_backup` added to **Administrators**, by Administrator, Logon ID `0x4ff5f` |

**Pattern:** each privilege-assignment step follows the same two-stage process signature — `cmd.exe` invokes `net.exe`, which spawns `net1.exe` to perform the actual action — repeated three times, once per targeted group, at ~6–7 second intervals.

---

## Detection Logic (KQL — Kibana Discover)

**Detect Administrator logon:**
```kql
winlog.event_id:4624 and host.name:"winserv2019.some.corp" and winlog.event_data.TargetUserName:Admin*
```

**Detect security group membership changes:**
```kql
winlog.event_id:4732
```

**Detect account creation:**
```kql
winlog.event_id:4720 and @timestamp >= "2025-07-20T05:11:22"
```

**Correlate Sysmon process creation for the Administrator session:**
```kql
winlog.event_id:1 and user.name:Admin* and @timestamp >= "2025-07-20T05:11:22"
```

---

## Windows Security Evidence

### Event ID 4624 — Successful Logon
| Field | Value |
|---|---|
| Account | Administrator |
| Logon Type | RemoteInteractive (RDP) |
| Source IP | 203.0.113.55 |
| Host | winserv2019.some.corp |

### Event ID 4720 — Account Created
| Field | Value |
|---|---|
| New Account | svc_backup |
| New Account SID | S-1-5-21-363149898-3377733843-3686914969-**1114** |
| Created By | Administrator (Logon ID `0x4ff5f`) |
| Account Domain | SOME |

### Event ID 4732 — Group Membership Changes (×3)
| Time | Group | Member SID |
|---|---|---|
| 05:13:15.588 | Server Operators | ...-1114 (svc_backup) |
| 05:13:22.336 | Remote Desktop Users | ...-1114 (svc_backup) |
| 05:13:28.091 | Administrators | ...-1114 (svc_backup) |

All three additions performed by Administrator under the same Logon ID (`0x4ff5f`), confirming a single continuous session carried out the entire escalation sequence.

---
Administrator (RDP session)
│
▼
cmd.exe
│
▼
net.exe
│
▼
net1.exe (executes the actual account/group operation)
**Full command sequence:**
```cmd
net user svc_backup Passw0rd123! /add /domain
net localgroup "Server Operators" svc_backup /add
net localgroup "Remote Desktop Users" svc_backup /add
net localgroup Administrators svc_backup /add
```

**Analyst note — plaintext credential exposure:** the account creation command carries the password `Passw0rd123!` in cleartext within the process command line, fully visible in Sysmon Event ID 1 logs (`process.command_line`). This is a significant secondary finding — anyone with read access to process creation logs (or EDR telemetry) could recover the new account's credentials directly.

**Analyst note — local vs. domain account ambiguity:** the creation command includes the `/add /domain` flag, indicating an attempt to create a **domain-scoped** account rather than a local one. The corresponding Event ID 4720 was captured on `winserv2019.some.corp` itself. Confirming whether this account was actually provisioned at the domain level (vs. the domain flag failing silently on a non-DC host) would require correlating Domain Controller-side logs, which were not available in this investigation. This distinction matters significantly for scope: a domain-level account with Administrators/Server Operators/RDP rights would extend risk beyond this single host.

---

## Attack Chain
External source IP
203.0.113.55
│
▼
Administrator RDP Logon (off-hours)
(Event 4624)
│
▼
cmd.exe → net.exe → net1.exe
│
▼
Create Account: svc_backup
(plaintext password, /domain flag)
(Event 4720)
│
├──► Add to Server Operators (Event 4732)
├──► Add to Remote Desktop Users (Event 4732)
└──► Add to Administrators (Event 4732)
---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Source IP | 203.0.113.55 |
| Host | winserv2019.some.corp |
| Compromised/abused account | Administrator |
| Newly created account | svc_backup |
| New account SID | S-1-5-21-363149898-3377733843-3686914969-1114 |
| Correlating Logon ID | 0x4ff5f |
| Exposed credential | `Passw0rd123!` (plaintext in command line) |
| Processes | cmd.exe, net.exe, net1.exe |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| Initial Access | T1078 | Valid Accounts — off-hours RDP logon using Administrator credentials |
| Execution | T1059.003 | Windows Command Shell — `cmd.exe` orchestrating `net`/`net1` |
| Persistence | T1136 | Create Account (local/domain scope unconfirmed — see analyst note) |
| Persistence / Privilege Escalation | T1098.007 | Additional Local or Domain Groups — svc_backup added to Server Operators, RDP Users, Administrators |
| Privilege Escalation | T1098 | Account Manipulation |

---

## Security Assessment

Indicators supporting a malicious assessment:

- Administrator authentication outside expected business hours, from an external-looking source IP.
- Immediate (within ~2 minutes) creation of a new account under that session.
- Password for the new account exposed in plaintext in the process command line.
- Domain-scope flag (`/domain`) used on account creation — broader potential impact than a local-only account.
- Rapid, sequential addition of the new account to three separate privileged groups (Server Operators, Remote Desktop Users, Administrators) within under 15 seconds each.
- Consistent process lineage (`cmd.exe → net.exe → net1.exe`) across every action, and a single correlating Logon ID (`0x4ff5f`) tying account creation and all group changes to one session.

**Caveat:** this evidence confirms the Administrator session performed these actions; it does not, on its own, prove the Administrator account itself was compromised by an external attacker versus misused by an insider. Both scenarios remain consistent with the evidence and require further investigation (see below).

---

## Detection Opportunities

- Alert on Administrator/privileged logons outside business hours (already in place).
- Alert on any `net user ... /add` or `net localgroup ... /add` command line containing a plaintext password pattern.
- Alert on account creation immediately followed (within minutes) by addition to Administrators or Server Operators.
- Alert on `/domain` account creation attempts originating from non-Domain-Controller hosts.
- Correlate Logon ID across 4624/4720/4732 automatically to speed up session-level triage.

---

## Recommendations

- Disable/quarantine the `svc_backup` account immediately.
- Force credential reset for the `Administrator` account and review for signs of compromise (password spray, phishing, credential reuse).
- Investigate source IP `203.0.113.55` (reputation, ASN, prior activity) via threat intel lookups.
- Correlate with Domain Controller logs to confirm whether `svc_backup` was provisioned at domain scope.
- Review RDP exposure/configuration on `winserv2019.some.corp` — confirm whether external RDP access to this host is expected.
- Hunt for `svc_backup` or the same source IP across other hosts for lateral movement.
- Review PowerShell/Sysmon logs following 05:13:28 for further post-escalation activity.

---

## Conclusion

The investigation confirms a high-confidence, correlated sequence: an off-hours Administrator RDP logon from `203.0.113.55`, followed within two minutes by the creation of a new account (`svc_backup`) with a plaintext-exposed password and a domain-scope flag, and its rapid addition to three privileged groups — Server Operators, Remote Desktop Users, and Administrators. The consistent process lineage and shared Logon ID across all Security and Sysmon events confirm this was executed as a single, deliberate session rather than unrelated background activity. This pattern is consistent with an attacker establishing a privileged backdoor account for persistent access following compromise of Administrator credentials, and warrants immediate containment and escalation.
