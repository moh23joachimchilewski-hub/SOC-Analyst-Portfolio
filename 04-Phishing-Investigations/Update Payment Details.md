# Malicious PDF Attachment — Dynamic Sandbox Analysis (ANY.RUN)

## Summary (5W)

| | |
|---|---|
| **What** | Multi-stage phishing attack. The analyzed sample is a PDF attachment (`Payment-updateid.pdf`) whose **rendered content is styled as a Netflix billing/payment notification** (confirmed via sandbox screenshots of the opened PDF — the original delivery email itself was not available for this analysis). The document's embedded link redirects toward a **PayPal**-themed page. No embedded exploit or dropped executable — the PDF functions purely as a redirect vector. |
| **When** | 2021-07-22 05:45:38 (sandbox execution timestamp). |
| **Who** | Document content impersonates Netflix (rendered PDF branding); redirect target impersonates PayPal (per PDF metadata). Target: end user opening the attachment. |
| **Where** | Windows 7 SP1 (32-bit) sandbox host. Attachment opened from `%LocalAppData%\Temp\` — standard path for a directly-opened email attachment. |
| **Why** | Consistent with **credential harvesting via phishing redirect**. No evidence of malware delivery or C2 beaconing. |
| **How** | PDF opens in Adobe Acrobat Reader → spawns Internet Explorer → navigates to a shortened URL (`lihi1.com/JqdmJ`), not further followed in this session. |

---

## Tools
**ANY.RUN** — interactive dynamic malware sandbox

---

## File Identification

| Field | Value |
|---|---|
| File name | `Payment-updateid.pdf` |
| File type | PDF document, v1.7 (MIME: `application/pdf`) |
| SHA256 | `CC6F1A04B10BCB168AEEC8D870B97BD7C20FC161E8310B5BCE1AF8ED420E2C24` |
| MD5 | `4A2775EAE2EBEF41901A3F08D3B857C8` |
| Creator tool | Microsoft Word 2016 |
| Author (metadata) | `PayPaI Support` — typosquatted (capital "I" for lowercase "l") |
| ANY.RUN verdict | **Suspicious activity** (0 malicious processes, 1 suspicious) |

---

## Multi-Stage Brand Impersonation

| Stage | Brand | Evidence |
|---|---|---|
| 1 — Document content | **Netflix** | Rendered PDF content is styled as a Netflix billing/payment notification, complete with logo and "Update Payment Account" CTA (see screenshots in Investigation Process, section 2) |
| 2 — Redirect target | **PayPal** | PDF metadata `Author: PayPaI Support`; embedded link redirects toward a PayPal-themed page |

**Scope note:** this analysis covers the PDF attachment only. The original delivery email (sender address, headers, subject line) was not part of the available sandbox data, so no claims are made about the email itself — only about what the PDF displays once opened.

**Why it matters:** a "payment declined" Netflix notice creates urgency and feels routine, lowering the recipient's guard. The higher-value target (PayPal financial credentials) is only revealed after the redirect — by which point the victim has already clicked through, assuming continuity with the initial context.

---

## Investigation Process

**1. Initial triage** — Submitted to ANY.RUN as a suspected phishing attachment. Sandbox verdict: **Suspicious activity**, not Malicious — signals behavioral anomalies rather than confirmed malware execution.

**2. Process execution analysis**

![Rendered PDF content — Netflix-styled billing notification](./screenshots/01-pdf-rendered-content-netflix.png)
*Rendered PDF content, as displayed in the sandbox — styled as a Netflix payment/billing notification.*

![Rendered PDF content — CTA button and footer](./screenshots/01b-pdf-rendered-content-cta-button.png)
*Second page view — "Update Payment Account" call-to-action button and Netflix-styled footer.*

**Notable detail — overlapping text rendering:** the phrase "Please update" and the "Update Payment Account" button both show visible character/element overlap (e.g. duplicated glyphs, a hyperlink object misaligned over the button label — "Ac" / "count" rendered as separate overlapping elements). This is consistent with a hastily assembled phishing-kit template, where a malicious hyperlink layer was pasted over a copied legitimate-looking design without properly aligning the underlying text objects.

```
Explorer.EXE
 └── AcroRd32.exe (PID 2088)      opens Payment-updateid.pdf
       ├── RdrCEF.exe (x8)         Adobe's Chromium rendering engine — normal
       ├── AdobeARM.exe            Adobe Update Manager — normal
       │     └── Reader_sl.exe     Adobe SpeedLauncher — normal
       └── iexplore.exe (PID 1840) launched with URL: https://lihi1.com/JqdmJ
             └── iexplore.exe (x3) additional IE tab instances
```

Key event: `AcroRd32.exe` launches Internet Explorer **directly with a URL argument** — the PDF's embedded link action opens a browser to an external shortened URL rather than displaying static content.


**3. Network activity correlation** — most connections were routine (Windows Update, certificate OCSP checks, Bing). Two entries stand out:

| Process | Destination | Reputation | Assessment |
|---|---|---|---|
| `iexplore.exe` | `lihi1.com` (35.244.149.249) | unknown | **Notable** — URL shortener, consistent with a phishing redirect chain; final destination not resolved in this session |
| `AcroRd32.exe` | `acroipm2.adobe.com` (2.16.107.24) | flagged malicious | **Likely false positive** — legitimate Adobe telemetry endpoint |
| `iexplore.exe` | `www.google.com` (142.250.186.132) | flagged malicious | **Likely false positive** — shared reputation on Google infrastructure |

**4. Threat classification**

| Process | Class | Message |
|---|---|---|
| `svchost.exe` | Potentially Bad Traffic | `ET INFO TLS Handshake Failure` |

Informational-severity signature (`ET INFO`, not `ET MALWARE`/`ET TROJAN`) — commonly triggered by routine OS connectivity checks, not strong evidence of compromise on its own.

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| File name | `Payment-updateid.pdf` |
| SHA256 | `CC6F1A04B10BCB168AEEC8D870B97BD7C20FC161E8310B5BCE1AF8ED420E2C24` |
| MD5 | `4A2775EAE2EBEF41901A3F08D3B857C8` |
| Redirect URL | `hxxps://lihi1[.]com/JqdmJ` |
| Redirect IP | `35.244.149.249` |

---

## Conclusion

Best classified as a **multi-stage phishing attack using a browser-redirect technique**, not a malware dropper — Netflix as low-friction bait, PayPal as the actual credential-harvesting target. No evidence in this sandbox run supports C2 communication, payload dropping, or malware execution.


---

*Analysis based on a public ANY.RUN sandbox report: [app.any.run/tasks/8bfd4c58-ec0d-4371-bfeb-52a334b69f59](https://app.any.run/tasks/8bfd4c58-ec0d-4371-bfeb-52a334b69f59)*
