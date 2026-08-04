# Windows Event Log Analysis — RDP Brute Force & Initial Access

> **Tool:** Windows Event Viewer
> **Log Source:** Security Event Log (`RDP-Security.evtx`)
> **Detection Type:** Brute Force / Initial Access via Exposed Remote Service
> **Severity:** Critical
> **MITRE ATT&CK:** T1110.001, T1133, T1078

---

## 5W Analysis

| Question | Answer |
|---|---|
| **Who** | Multiple external source IPs conducting brute force; successful breach ultimately attributed to a host identifying itself as `DESKTOP-QNBC4UU` |
| **What** | Sustained RDP brute force against common usernames (Administrator, Admin, User, User1), culminating in a successful Administrator logon over RDP |
| **When** | Sustained brute force activity throughout the captured log (1,559 failed logon events); confirmed successful logons recorded as 8 total `4624` events |
| **Where** | Production Windows server `WIN-F89VT9IER10`, with RDP exposed directly to the internet |
| **Why** | Consistent with opportunistic, automated scanning and credential-guessing against an internet-facing RDP service — a textbook "Ransomware Deployment Protocol" initial access scenario |

---

## Detection Logic (Windows Event Viewer)

**Step 1 — Isolate failed logons:**
Filter Current Log → Event ID `4625`
→ Returned **1,559 events** out of 1,567 total in the log.

**Step 2 — Narrow to remote logon types:**
Within the `4625` results, focus on `LogonType 3` (Network) and `LogonType 10` (RemoteInteractive/RDP) — both consistent with RDP-facing brute force (NLA-enabled RDP typically generates Type 3 during credential negotiation).

**Step 3 — Confirm external source:**
Review the `IpAddress` field on each event — all observed source IPs in this investigation are external/public addresses, confirming the attack originates from outside the network.

**Step 4 — Pivot to successful logons:**
Filter Current Log → Event ID `4624`
→ Returned **8 events**, a sharp contrast to the 1,559 failures — confirming the vast majority of attempts failed before one succeeded.

---

## Investigation

### Stage 1 — Brute Force Against Common Usernames

Reviewing `4625` events shows a clear password-guessing pattern: multiple external IPs, each targeting a small set of predictable usernames, all failing with `Status: 0xc000006d` (logon failure — bad username or password):

| Source IP | Targeted Username | Logon Type |
|---|---|---|
| 102.88.21.218 | USER | 3 |
| 196.188.63.191 | USER1 | 3 |
| 172.236.177.129 | ADMINISTRATOR | 3 |
| 110.39.6.180 | ADMINISTRATOR | 3 |
| 109.205.213.46 | ADMIN | 3 |

`Administrator` (and case variants) appears as the most frequently targeted account across the full 1,559-event set — consistent with attackers prioritizing the well-known, always-present built-in admin account over guessed/enumerated usernames.

### Stage 2 — Successful Breach

Two related `4624` (successful logon) events, both from IP **`203.205.34.107`**, confirm the breach:

**Event A — LogonType 10 (RemoteInteractive):**
```
TargetUserName: Administrator
LogonType: 10
WorkstationName: WIN-F89VT9IER10   (local/target machine name — not yet resolved to attacker's real host)
ProcessName: C:\Windows\System32\svchost.exe
IpAddress: 203.205.34.107
```

**Event B — LogonType 3 (Network), same session window:**
```
TargetUserName: Administrator
LogonType: 3
WorkstationName: DESKTOP-QNBC4UU   ← attacker's real hostname
AuthenticationPackageName: NTLM
LmPackageName: NTLM V2
IpAddress: 203.205.34.107
```

The `LogonType 3` event — which accompanies the RDP session as part of NTLM network authentication — is what actually discloses the attacker's **real workstation name**, `DESKTOP-QNBC4UU`, since the `LogonType 10` event alone only reported the target server's own name.

### Stage 3 — Additional Notable Finding: Same Attacker, Second Source IP

A third `4624` event shows the **same attacker workstation name** (`DESKTOP-QNBC4UU`) authenticating as `Administrator`, but from a **different source IP**:

```
TargetUserName: Administrator
LogonType: 3
WorkstationName: DESKTOP-QNBC4UU
IpAddress: 118.69.32.92
```

This is a notable pivot point for further investigation: the same physical/virtual attacker machine (identified by hostname) accessed the target from two distinct public IPs (`203.205.34.107` and `118.69.32.92`), suggesting use of a VPN, proxy rotation, or a multi-hop infrastructure by the threat actor.

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Compromised account | Administrator |
| Attacker hostname | DESKTOP-QNBC4UU |
| Confirmed breach IP | 203.205.34.107 |
| Secondary IP (same attacker host) | 118.69.32.92 |
| Brute-force source IPs (sample) | 102.88.21.218, 196.188.63.191, 172.236.177.129, 110.39.6.180, 109.205.213.46 |
| Usernames targeted | Administrator, Admin, User, User1 |
| Target host | WIN-F89VT9IER10 |
| Failed logon count | 1,559 (Event ID 4625) |
| Successful logon count | 8 (Event ID 4624) |

**Note on credentials:** per the engagement scenario context, the exposed account was configured with a weak password (`Administrator:Summer2025`). This detail comes from the exercise background, not from the Security log itself — Windows logon events never record the password value, only success/failure.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| Credential Access | T1110.001 | Brute Force: Password Guessing — 1,559 failed logons against predictable usernames |
| Initial Access | T1133 | External Remote Services — RDP exposed directly to the internet, used as the entry point |
| Initial Access | T1078 | Valid Accounts — successful authentication as `Administrator` following credential guessing |

---

## Analyst Notes & Caveats

- **Network scanning stage not covered.** The reconnaissance step (botnet identifying the exposed RDP port) precedes any Windows Security log evidence and is out of scope for this log source — it would require perimeter/firewall/NetFlow data to investigate.
- **"WorkstationName" differs by logon type.** The `LogonType 10` (RDP session) event reported the *target* server's own name, not the attacker's. The attacker's real hostname only surfaced via the accompanying `LogonType 3` (NTLM network logon) event — a useful pattern to remember when hunting for attacker infrastructure in RDP breach logs.
- **Two source IPs, one attacker hostname.** This was not explicitly investigated further in this report (no Sysmon/network data was reviewed alongside it), but is flagged as a lead worth pursuing in a full incident response — e.g. checking whether `118.69.32.92` and `203.205.34.107` share ASN/hosting provider, indicating shared attacker infrastructure.

---

## Recommendations

- Remove direct internet exposure of RDP (TCP/3389); require VPN or a jump host for remote administration.
- Enforce strong, unique passwords and account lockout policies on all privileged accounts, especially `Administrator`.
- Enable and enforce Network Level Authentication (NLA) if RDP must remain enabled.
- Block/monitor the identified source IPs (`203.205.34.107`, `118.69.32.92`, and the brute-force IP set above).
- Reset the `Administrator` account password immediately and audit for any changes made during the compromised session.
- Correlate the confirmed breach `Logon ID` with Sysmon Event ID 1 (Process Creation) to identify any post-compromise attacker activity.
- Consider geo-blocking or rate-limiting authentication attempts at the network perimeter for internet-facing management services.

---

## Conclusion

This investigation confirms a successful RDP breach against `WIN-F89VT9IER10`, preceded by a sustained brute force campaign (1,559 failed login attempts) targeting common usernames, with `Administrator` as the primary target. The attacker successfully authenticated from `203.205.34.107`, with their real workstation name (`DESKTOP-QNBC4UU`) recovered from the accompanying NTLM network logon event. The same attacker hostname was also observed authenticating from a second IP (`118.69.32.92`), suggesting the use of rotating or proxied infrastructure. This pattern — internet-facing RDP, weak/guessable credentials, and rapid automated brute forcing — is one of the most common initial access vectors behind ransomware incidents, and warrants immediate remediation of the exposed service.
