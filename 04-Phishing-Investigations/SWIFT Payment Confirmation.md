
# Suspicious SWIFT Payment Phishing Email Analysis



## Summary (5W)

| | |
|---|---|
| **What** | A phishing email impersonating a legitimate SWIFT payment notification attempted to lure the recipient into opening a malicious attachment masquerading as a PDF document. |
| **When** | Email Date: **09 Jun 2020 22:58:27 |
| **Who** | Display Name: **Mr. James Jackson** (`info@mutawamarine.com`) |
| **Where** | Originating IP: **192.119.71.157** (HostPapa) |
| **Why** | Social engineering campaign abusing a fake financial transaction to convince the victim to open a disguised archive attachment. |
| **How** | The attacker spoofed a business payment notification, used a Reply-To mismatch, failed SPF authentication, and attached a CAB archive disguised as a PDF. |

---

## Executive Summary

The analyzed email represents a **financial-themed phishing campaign** impersonating a SWIFT transfer confirmation.

The attacker attempted to convince the recipient that a payment of **149,650 USD** had been successfully transferred and instructed the victim to review the attached payment receipt.

Although the attachment appeared to be a PDF, its filename (`SWT_#09674321____PDF__.CAB`) concealed a compressed archive. VirusTotal identified the file as a **RAR archive**, indicating an attempt to bypass user suspicion and email filtering mechanisms.

Several indicators strongly suggest malicious intent, including:

- SPF authentication failure
- Reply-To address different from the sender
- Suspicious archive masquerading as a PDF
- Generic greeting
- Financial urgency
- Hosting provider infrastructure used for email delivery

---

## Tools

- Email Header Analysis
- VirusTotal
- WHOIS
- SPF Record Lookup
- DMARC Lookup
- SHA256 Hash Analysis

---

## Email Identification

| Field | Value |
|---|---|
| Subject | `webmaster@redacted.org your: Transfer Reference Number:(09674321)` |
| Transfer Reference | `09674321` |
| Sender Display Name | `Mr. James Jackson` |
| From | `info@mutawamarine.com` |
| Reply-To | `info.mutawamarine@mail.com` |
| Recipient | `webmaster@redacted.org` |
| Attachment | `SWT_#09674321____PDF__.CAB` |
| Actual Type | RAR Archive |
| SHA256 | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` |
| Size | 400.26 KB |

---

## Header Analysis

### Sender Analysis

The sender impersonates a business representative named **Mr. James Jackson** using the address `info@mutawamarine.com`.

Although the sender appears legitimate, the message contains multiple authentication anomalies.

---

### Reply-To Mismatch

The email specifies a different Reply-To address.

| Header | Value |
|---|---|
| From | `info@mutawamarine.com` |
| Reply-To | `info.mutawamarine@mail.com` |

This is a common phishing technique intended to redirect replies to an attacker-controlled mailbox.

---

### SPF Analysis

| Field | Value |
|---|---|
| SPF Record | `v=spf1 include:spf.protection.outlook.com -all` |
| SPF Result | **FAIL** |

The sending server was **not authorized** to send emails on behalf of the claimed domain.

---

### DMARC Analysis

| Field | Value |
|---|---|
| DMARC Record | `v=DMARC1; p=quarantine; fo=1` |
| Authentication Result | Unknown / Failed |

The message failed authentication checks and should be considered suspicious.

---

### Originating IP Analysis

| Field | Value |
|---|---|
| Originating IP | `192.119.71.157` |
| Provider | HostPapa |

The email originated from infrastructure hosted by HostPapa. While the hosting provider itself is legitimate, attacker-controlled VPS infrastructure is frequently abused for phishing campaigns.

---

## Social Engineering Analysis

The campaign attempts to exploit trust by:

- impersonating a financial transaction
- creating urgency through a completed payment notification
- using a fake transfer reference number
- disguising an archive as a PDF receipt
- encouraging the recipient to open the attachment without verification

---

## Attachment Analysis

| Field | Value |
|---|---|
| Filename | `SWT_#09674321____PDF__.CAB` |
| Advertised Type | PDF Receipt |
| Actual Type | RAR Archive |
| SHA256 | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` |
| Size | 400.26 KB |

The attachment uses **masquerading**, attempting to convince the victim that the archive is a harmless PDF document.

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Sender | `info@mutawamarine.com` |
| Reply-To | `info.mutawamarine@mail.com` |
| Originating IP | `192.119.71.157` |
| Attachment | `SWT_#09674321____PDF__.CAB` |
| SHA256 | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` |

---

## MITRE ATT&CK

| Tactic | Technique |
|---|---|
| Initial Access | T1566.001 – Spearphishing Attachment |
| User Execution | T1204 |
| Defense Evasion | T1036 – Masquerading |

---

## Detection Opportunities

- SPF failure
- Reply-To mismatch
- Archive masquerading as PDF
- Financial urgency
- Generic greeting
- External sender
- Suspicious attachment extension

---

## Risk Assessment

| Category | Rating |
|---|---|
| Likelihood | High |
| Impact | High |
| Overall Risk | High |

---

## Conclusion

This email exhibits multiple characteristics commonly associated with phishing campaigns. Authentication failures, sender inconsistencies, financial social engineering, and a disguised archive attachment collectively indicate a high probability of malicious intent. The attachment should not be opened, and the associated indicators should be blocked and monitored within the organization's email security infrastructure.

