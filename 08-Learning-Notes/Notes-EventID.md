# Windows & Sysmon Event IDs — Organized by Attack Stage (MITRE ATT&CK)


---

## Quick Reference — Filtering by Event ID

**Splunk (SPL):**
```spl
index=windows (EventCode=4624 OR EventCode=4625 OR EventCode=4720 OR EventCode=4732)
| table _time host EventCode Account_Name Logon_Type src_ip
| sort - _time
```

**Elastic (KQL):**
```kql
winlog.event_id:(4624 or 4625 or 4720 or 4732) and host.name:"winserv2019.some.corp"
```

Swap the Event ID list for whichever stage you're hunting — the tables below map each one to what it actually tells you.

---

## 🔐 Initial Access / Authentication
*Who logged on? From where? How?*

| Event ID | Description |
|---|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4634 | Logoff |
| 4648 | Logon using explicit credentials (`runas`) |
| 4768 | Kerberos TGT requested |
| 4769 | Kerberos Service Ticket requested |

---

## 👑 Privilege Escalation
*Did the user gain higher privileges?*

| Event ID | Description |
|---|---|
| 4672 | Special privileges assigned to new logon |
| 4732 | User added to local security group (e.g. Administrators) |
| 4728 | User added to global/domain group |
| 4738 | User account changed |

---

## 👤 Account Manipulation / Persistence
*Was a new account created or an existing one modified?*

| Event ID | Description |
|---|---|
| 4720 | User account created |
| 4722 | User account enabled |
| 4723 | Password change attempted |
| 4724 | Password reset |
| 4725 | User account disabled |
| 4726 | User account deleted |

---

## 📅 Persistence — Scheduled Tasks

| Event ID | Description |
|---|---|
| 4698 | Scheduled Task created |
| 4699 | Scheduled Task deleted |
| 4700 | Scheduled Task enabled |
| 4701 | Scheduled Task disabled |
| 4702 | Scheduled Task updated |

---

## ⚙️ Persistence — Services

| Event ID | Description |
|---|---|
| 7045 | New Windows service installed |
| 7036 | Service started/stopped |

---

## 💻 Execution
*What was run?*

| Event ID | Description |
|---|---|
| 4688 | Process Creation |
| 4689 | Process Termination |

**If Sysmon is installed** (preferred — richer data: hash, full command line, parent-child context, Logon ID):

| Sysmon ID | Description |
|---|---|
| 1 | Process Create |

---

## 🌐 Network Activity

| Sysmon ID | Description |
|---|---|
| 3 | Network Connection |
| 22 | DNS Query |

---

## 🗂️ File Activity

| Sysmon ID | Description |
|---|---|
| 11 | File Created |
| 23 | File Deleted |

---

## 📝 Registry Persistence

| Sysmon ID | Description |
|---|---|
| 12 | Registry Object Create/Delete |
| 13 | Registry Value Set |
| 14 | Registry Key Rename |

---

## 💉 Process Injection / Credential Access

| Sysmon ID | Description |
|---|---|
| 8 | CreateRemoteThread |
| 10 | Process Access (e.g. LSASS) |

---

## 🔍 Discovery

There's no single dedicated Event ID for Discovery — this is where you analyze **4688** or **Sysmon 1**, looking at *which* processes were run.

**Common Discovery commands to watch for:**
```
whoami
hostname
ipconfig
systeminfo
net user
net localgroup
nltest
net group
quser
```

---



**Rule of thumb:** if Sysmon is available, use it as the primary source for process monitoring — 4688 is the fallback when Sysmon isn't deployed in an environment.
