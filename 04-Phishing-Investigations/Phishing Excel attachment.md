# Malicious Excel Attachment — Dynamic Sandbox Analysis (ANY.RUN)

## Summary (5W)

| | |
|---|---|
| **What** | Multi-stage exploit chain leveraging **Microsoft Equation Editor vulnerability (CVE-2017-11882)**. The analyzed sample is an Excel spreadsheet (`CBJ200620039539.xlsx`) that embeds a malicious OLE object. Upon opening, the Equation Editor process (`EQNEDT32.EXE`) is spawned via COM, triggering memory corruption. The exploit downloads and executes a remote executable (`COVID19.exe`) from compromised hosting infrastructure, followed by JavaScript-based redirect attacks toward malicious domains. |
| **When** | 2021-07-22 05:05:05 (sandbox execution timestamp). |
| **Who** | File creator metadata: `Microsoft Corporation` (legitimate metadata spoofed). Exploit vector targets end users opening the spreadsheet. Final payload delivery targets: `biz9holdings.com` (VG), `findresults.site` (AU). |
| **Where** | Windows 7 Professional SP1 (32-bit) sandbox host. Spreadsheet opened from standard Explorer context; Equation Editor spawned as child process. |
| **Why** | **Consistent with targeted malware delivery via office document exploit**. The CVE-2017-11882 vulnerability allows arbitrary code execution without user interaction beyond opening the document. The secondary redirect attacks suggest additional payload staging or credential theft infrastructure. |
| **How** | Excel.exe opens `CBJ200620039539.xlsx` → triggers embedded OLE object → COM server launches `EQNEDT32.EXE` → buffer overflow in Equation Editor → spawns `ntvdm.exe` (16-bit subsystem) → HTTP requests to malicious domains → downloads executable and serves JavaScript-based redirects. |

---

## Tools

**ANY.RUN** — interactive dynamic malware sandbox

---

## File Identification

| Field | Value |
|---|---|
| File name | `CBJ200620039539.xlsx` |
| File type | Microsoft Excel 2007+ XLSX (MIME: `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`) |
| SHA256 | `5f94a66e0ce78d17afc2dd27fc17b44b3ffc13ac5f42d3ad6a5dcfb36715f3eb` |
| MD5 | `F7F4EC2A0ADC9CC33CDBC7D548A6BEF9` |
| Creator tool | Microsoft Excel (metadata spoofed) |
| Creator metadata | `Microsoft Corporation` |
| Last Modified By | `Windows User` |
| App Version | `15.03` (Office 2013 compatible) |
| Modified Date | 2019-03-25 09:18:59 UTC |
| Create Date | 1996-10-14 23:33:28 UTC (suspiciously old) |
| Last Printed | 2018-03-26 10:27:58 UTC |
| ANY.RUN verdict | **Malicious activity** (1 malicious process, exploit signature detected) |

---

## Exploit Vulnerability & Execution Chain

| Stage | Component | Technique | Evidence |
|---|---|---|---|
| 1 — Document opening | **Excel.exe** | COM object instantiation | Spreadsheet contains embedded OLE object; Excel spawns Equation Editor via COM server |
| 2 — Privilege escalation | **EQNEDT32.EXE** (Equation Editor) | **CVE-2017-11882 buffer overflow** | ANY.RUN behavioral log flags: `Equation Editor starts application (CVE-2017-11882)` — marked as **MALICIOUS** |
| 3 — Payload staging | **ntvdm.exe** (16-bit subsystem) | Process spawning via exploit | Child process launched by Equation Editor; crashes with exit code `3221225477` (0xC0000005 — access violation) after executing payload delivery code |
| 4 — Remote download | **EQNEDT32.EXE** | HTTP GET requests | Three HTTP requests initiated, returning HTTP 302/200 responses from malicious hosts |
| 5 — Execution & redirect | **JavaScript/HTML delivery** | Malware staging & redirect chain | Downloaded files include HTML and temporary binary executables; secondary redirect infrastructure suggests multi-stage payload delivery |

**Critical Detail — Vulnerability Significance:** CVE-2017-11882 is an **unpatched remote code execution flaw** in Microsoft Equation Editor (pre-Office 2016 SP1). No user interaction beyond opening the file is required — the vulnerability triggers automatically during document rendering.

---

## Network Payload & Malicious Infrastructure

| Stage | Process | Destination | HTTP Code | Type | Reputation | Assessment |
|---|---|---|---|---|---|---|
| Download attempt | `EQNEDT32.EXE` | `biz9holdings.com/INVOICE/COVID19.exe` (204.11.56.48:80) | 302 | executable | **malicious** | **Primary payload** — COVID-19-themed executable; VG geolocation (Virgin Islands); 302 redirect suggests further staging |
| Redirect attack #1 | `EQNEDT32.EXE` | `findresults.site/?rpid=2POQ7BC1G` (103.224.182.251:80) | 302 | — | **malicious** | Secondary redirect; AU geolocation (Australia); likely credential-harvesting or exploit kit gateway |
| Redirect attack #2 | `EQNEDT32.EXE` | `ww38.findresults.site/?rpid=...&subid1=...` (75.2.11.242:80) | 200 | HTML | **malicious** | Final landing page; US hosting; contains JavaScript payload and session tracking parameters (`subid1` timestamp hash) |

**Notable Pattern:** The `findresults.site` domain appears twice with identical campaign IDs (`rpid=2POQ7BC1G`), indicating **coordinated multi-stage attack infrastructure** rather than accidental redirects. The HTML response (2.44 KB) likely contains browser-based exploits, keyloggers, or form-stealing JavaScript.

---

## Process Execution Tree & Behavioral Indicators

Explorer.EXE
└── EXCEL.EXE (PID 1016)              opens CBJ200620039539.xlsx
├── [Registry writes]            startup items persistence attempt
│     └── HKCU\Software\Microsoft\Office\14.0\Excel\Resiliency\StartupItems
│           Value: ik(
│
└── EQNEDT32.EXE (PID 1068)      spawned via COM (CVE-2017-11882)
│
├── [MALICIOUS]            buffer overflow exploited
├── [Actions]              reads computer name, executes crashed process
│
├── HTTP GET #1            http://biz9holdings.com/INVOICE/COVID19.exe
├── HTTP GET #2            http://findresults.site/?rpid=...
├── HTTP GET #3            http://ww38.findresults.site/?rpid=...&subid1=...
│
├── ARASW5VS.txt           cookie/temp file dropped to Roaming\Cookies\
├── GJE0REO4.htm           HTML payload cached to Temporary Internet Files\
└── regasms.exe            suspicious binary (masqueraded as .NET tool, marked as HTML) dropped to AppData\Roaming\

               └── ntvdm.exe (PID 1328)      16-bit subsystem invoked (legacy emulation)
                     ├── scsB9C2.tmp         temporary binary/script
                     ├── scsB9B1.tmp         temporary binary/script
                     └── [CRASH]             exit code 0xC0000005 (access violation)

**Behavioral Flags:**
- ✓ **MALICIOUS** — CVE-2017-11882 exploit execution detected  
- ✓ **SUSPICIOUS** — Executed via COM (Office macro/object activation)  
- ✓ **INFO** — Reads computer name (post-exploitation reconnaissance)  
- ✓ **INFO** — Registry key modifications targeting Office startup paths (persistence mechanism)  

---

## Registry & Persistence Artifacts

| Registry Path | Operation | Value | Process | Assessment |
|---|---|---|---|---|
| `HKCU\Software\Microsoft\Office\14.0\Excel\Resiliency\StartupItems` | write | `ik(` (hex: `696B2800F8030000...`) | `EXCEL.EXE` | **Persistence attempt** — Resiliency key used to auto-load malicious code on Excel startup |
| `HKCU\Software\Microsoft\Office\14.0\Common\LanguageResources\EnabledLanguages` | write (×8) | `Off` (multiple language packs) | `EXCEL.EXE` | **Evasion technique** — disabling language support may suppress warnings or bypass locale-based security checks |

---

## Dropped Files & Forensic Artifacts

| PID | Process | Filename | Type | Hash (SHA256) | Assessment |
|---|---|---|---|---|---|
| 1016 | `EXCEL.EXE` | `C:\Users\admin\AppData\Local\Temp\CVRAB69.tmp.cvr` | unknown | — | **Crash dump / recovery file** — generated during exploit crash |
| 1068 | `EQNEDT32.EXE` | `C:\Users\admin\AppData\Roaming\Microsoft\Windows\Cookies\ARASW5VS.txt` | text | `DF5252E37F08EC06A33239C9C39C7653956030F1F02BC61B41F05B04333D75C7` | **Cookie/tracking file** — unusual location (Cookies dir, not browser cache) |
| 1068 | `EQNEDT32.EXE` | `...Temporary Internet Files\Content.IE5\78RFYB7Z\GJE0REO4.htm` | HTML | `F72D64F5F29FD03F5AD75F09E4ADFAF097B1E15803FB571E6499E8844AB80132` | **Cached malicious HTML** — likely JavaScript payload from `findresults.site` |
| 1068 | `EQNEDT32.EXE` | `C:\Users\admin\AppData\Roaming\regasms.exe` | html (mislabeled) | `F72D64F5F29FD03F5AD75F09E4ADFAF097B1E15803FB571E6499E8844AB80132` | **Executable masquerade** — dropped as `.exe` but marked as HTML; name spoofs legitimate .NET tool (`regasm.exe`); **persistence candidate** |
| 1328 | `ntvdm.exe` | `C:\Users\admin\AppData\Local\Temp\scsB9C2.tmp` | text | `06D61C23E6CA59B9DDAD1796ECCC42C032CD8F6F424AF6CFEE5D085D36FF7DFD` | **Temporary payload staging** — 16-bit subsystem artifact |
| 1328 | `ntvdm.exe` | `C:\Users\admin\AppData\Local\Temp\scsB9B1.tmp` | text | `EE06792197C3E025B84860A72460EAF628C66637685F8C52C5A08A9CC35D376C` | **Temporary payload staging** — 16-bit subsystem artifact |

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| File name | `CBJ200620039539.xlsx` |
| SHA256 | `5f94a66e0ce78d17afc2dd27fc17b44b3ffc13ac5f42d3ad6a5dcfb36715f3eb` |
| CVE exploited | **CVE-2017-11882** (Microsoft Equation Editor RCE) |
| Malicious URL #1 | `hxxp://biz9holdings[.]com/INVOICE/COVID19.exe` |
| Malicious URL #2 | `hxxp://findresults[.]site/?rpid=2POQ7BC1G` |
| Malicious URL #3 | `hxxp://ww38[.]findresults[.]site/?rpid=2POQ7BC1G&subid1=20210722-1505-2609-bac9-8bc8329e748d` |
| Malicious IP #1 | `204.11.56.48` (VG hosting) |
| Malicious IP #2 | `103.224.182.251` (AU hosting) |
| Malicious IP #3 | `75.2.11.242` (US hosting) |
| Dropped file (persistence) | `C:\Users\admin\AppData\Roaming\regasms.exe` |
| Campaign ID | `rpid=2POQ7BC1G` |
| Dropped HTML payload SHA256 | `F72D64F5F29FD03F5AD75F09E4ADFAF097B1E15803FB571E6499E8844AB80132` |

---

## Conclusion

This sample represents a **sophisticated multi-stage malware delivery attack exploiting an unpatched Office vulnerability**. The CVE-2017-11882 buffer overflow in Microsoft Equation Editor provides **unauthenticated remote code execution** at the moment a user opens the spreadsheet — no macro enable prompts or additional user interaction required. 

The attack progresses through three distinct stages:

1. **Initial Compromise** — Exploit execution and reconnaissance (computer name enumeration)
2. **Payload Staging** — HTTP redirect chain through bulletproof hosting infrastructure with campaign tracking  
3. **Persistence & Secondary Payload** — Registry modification for startup persistence; downloaded executable (`COVID19.exe`) and JavaScript-based exploitation

The presence of legitimate-looking metadata (creator: `Microsoft Corporation`, timestamps: 2018–2019) combined with the old document creation date (1996) indicates **deliberate metadata spoofing** to evade static analysis. The multi-region hosting (Virgin Islands → Australia → US) and campaign-tracking parameters (`rpid`, `subid1`) suggest this is part of a **coordinated, ongoing phishing/malware campaign**.

**Mitigation:** Systems still running Office versions vulnerable to CVE-2017-11882 should immediately apply security patches or disable the Equation Editor entirely.
