# Analiza incydentu IR - phishing -> Account Takeover (ATO) w Microsoft 365

> **Platforma:** Splunk
> **Źródła logów:** Entra ID Sign-in (`azure:aad:signin`), Message Trace (`o365:reporting:messagetrace`), Unified Audit Logs (`o365:management:activity`)
> **Typ zdarzenia:** Initial Access (Phishing) -> Valid Accounts -> Persistence (Inbox Rule) -> Internal Spearphishing
> **Severity:** High
> **MITRE ATT&CK:** T1566.002, T1078.004, T1564.008, T1534

---

## Podsumowanie

Alert SIEM "Anomalous Sign-in Detected" wskazał udane logowanie na konto `l.chen@nexusfinancial.thm` (Finance Manager) z IP spoza sieci korporacyjnej (`197.32.45.112` = biuro Londyn). Walidacja potwierdziła prawdziwy incydent Account Takeover.

Wektorem wejścia był **phishing**: sfałszowany mail "HR Policy Update — Immediate Action Required" od `hr-support@nexus-verify.thm` (domena podszywająca się pod Nexus). Po przejęciu konta atakujący (z IP **223.123.4.50**, Amsterdam/NL) utworzył w skrzynce **regułę automatycznie ukrywającą przychodzące maile** (np. przenoszącą powiadomienia o bezpieczeństwie do kosza, żeby ofiara nie zobaczyła alertów o włamaniu), a następnie **rozesłał phishing do innych pracowników** z przejętej skrzynki Finance Managera. Drugie konto - `k.patel@nexusfinancial.thm` - również zostało przejęte z tego samego IP.

---

## Kontekst (z fazy Preparation)

Nexus Financial miał znane, niezałatane luki, które ten atak wykorzystał:
- **brak MFA** na kontach standardowych,
- **brak kontroli uwierzytelniania poczty** (SPF/DKIM/DMARC) - dlatego spoofing domeny przeszedł,
- wcześniejszy incydent phishingowy zamknięty **bez naprawy przyczyny**,
- reguły detekcji nie pokrywające kluczowych scenariuszy.

**Dlaczego to ważne dla analityka:** brak MFA = samo skradzione hasło wystarczyło do logowania. Brak DMARC = mail od `nexus-verify.thm` wyglądał wiarygodnie.

---

## IOC (Indicators of Compromise)

| Typ | Wartość |
|---|---|
| IP atakującego | `223.123.4.50` (Amsterdam, NL) |
| Sfałszowany nadawca (phishing) | `hr-support@nexus-verify.thm` |
| Domena phishingu | `nexus-verify.thm` |
| Temat phishingu | `HR Policy Update — Immediate Action Required` |
| FromIP phishingu | `2a00:1450:4864:20::234` |
| Przejęte konta | `l.chen@nexusfinancial.thm`, `k.patel@nexusfinancial.thm` |
| Złośliwe reguły skrzynki | `Junk Filter Update` (l.chen), `Security Updates` (k.patel) |
| Wewnętrzny phishing (z l.chen) | do `allan.senna`, `m.harris`, `k.patel` @nexusfinancial.thm |

---

## 5W

| Pytanie | Odpowiedź |
|---|---|
| **Who** (kto) | Atakujący z IP `223.123.4.50` (Amsterdam/NL), operujący na kontach `l.chen` i `k.patel` |
| **What** (co) | Przejęcie konta przez phishing, założenie reguły ukrywającej maile, rozesłanie phishingu wewnętrznie |
| **When** (kiedy) | 2026-03-30: phishing 16:20, pierwsze udane logowanie 16:41:30, reguła + wewnętrzny phishing ~16:57-16:58 |
| **Where** (gdzie) | Microsoft 365 (Entra ID + Exchange Online), konta Nexus Financial |
| **Why** (po co) | Dostęp do skrzynki finansów, utrzymanie dostępu (inbox rule) i rozsyłanie phishingu do kolejnych pracowników |

---

## Przebieg analizy (filtry faktycznie użyte)

### Krok 1 - potwierdzenie podejrzanego logowania Finance Managera (IP, miasto)

```spl
index=ir userPrincipalName=l.chen@nexusfinancial.thm ipAddress!="197.32.45.112"
| table _time, userPrincipalName, ipAddress, location.city, location.countryOrRegion, appDisplayName, status.errorCode
| sort _time
```
**Ujawniło:** 18 zdarzeń z `223.123.4.50`, `location.city=Amsterdam`, `countryOrRegion=NL`. To potwierdza finding analityka L1 (logowanie spoza UK).
<img width="1920" height="928" alt="Zrzut ekranu (1077)" src="https://github.com/user-attachments/assets/4718a88a-6696-44f7-b6f8-739724fa9e5b" />


### Krok 2 - pierwsze UDANE logowanie (dokładny czas)

Uwaga na `status.errorCode`: pierwszy wpis 16:41:28 miał **`50140`** (interrupt "Keep me signed in", nie czysty sukces). Pierwsze realne wejście to `errorCode=0`:
```spl
index=ir userPrincipalName=l.chen@nexusfinancial.thm ipAddress!="197.32.45.112" "status.errorCode"=50140
```
-> wiersz 16:41:28 (próba). Pierwsze `errorCode=0` = **2026-03-30 16:41:30** (pierwsze udane logowanie).

*Lekcja: nie każdy wpis to sukces. `0` = udane, inne kody (np. 50140) to przerwania/błędy - łatwo wziąć zły timestamp.*
<img width="1920" height="932" alt="Zrzut ekranu (1079)" src="https://github.com/user-attachments/assets/43bb24bb-973a-40b6-8a7b-4198baf97943" />
<img width="1920" height="925" alt="Zrzut ekranu (1078)" src="https://github.com/user-attachments/assets/25c1cb98-d597-4e3e-987f-7ae5a13ee996" />


### Krok 3 - jak zdobył poświadczenia (Message Trace)

```spl
index=ir RecipientAddress="l.chen@nexusfinancial.thm"
| table Received, SenderAddress, Subject, Status, FromIP
| sort Received
```
**Ujawniło:** mail `HR Policy Update — Immediate Action Required` od `hr-support@nexus-verify.thm` dostarczony 16:20:01 (przed logowaniem 16:41). Domena nadawcy = **`nexus-verify.thm`** (phishing). FromIP `2a00:1450:4864:20::234`.
<img width="1920" height="926" alt="Zrzut ekranu (1080)" src="https://github.com/user-attachments/assets/9d1de04a-37e5-46fa-a1c3-6dda458337fa" />


### Krok 4 - pełny zasięg logowań z IP atakującego (drugie konto)

```spl
index=ir ipAddress!=197.32.45.112 status.errorCode=0
| table _time, ipAddress, userPrincipalName, appDisplayName
| sort _time
```
**Ujawniło:** 54 zdarzenia - obok `l.chen` pojawia się **`k.patel@nexusfinancial.thm`** z tego samego `223.123.4.50`. Drugie przejęte konto.
<img width="1920" height="928" alt="Zrzut ekranu (1081)" src="https://github.com/user-attachments/assets/aaab6893-0d20-4bf2-886d-d12ddc7453fa" />


### Krok 5 - persystencja: reguły skrzynki (Unified Audit Logs)

```spl
index=ir Operation=New-InboxRule
| table _time, ClientIP, ObjectId, Operation
```
**Ujawniło:** 2 reguły z `223.123.4.50`:
- 16:58:48 -> `Junk Filter Update` (skrzynka Finance Managera - tuż po jej przejęciu o 16:41),
- 17:02:40 -> `Security Updates` (skrzynka k.patel).

Nazwa reguły jest w `ObjectId` (na końcu, po `\`). Reguła na koncie Finance Managera = **`Junk Filter Update`**.

*Dlaczego to robią: reguła auto-przenosi maile od "security/IT/HR" do kosza, żeby ofiara nie zobaczyła alertów o resetach i logowaniach. Klasyczny krok zaraz po przejęciu skrzynki.*
<img width="1920" height="937" alt="Zrzut ekranu (1082)" src="https://github.com/user-attachments/assets/f4a509a8-6689-4e9c-aee9-d596a86ec52a" />


### Krok 6 - maile wysłane Z przejętej skrzynki (internal phishing)

```spl
index=ir FromIP=223.123.4.50
| table _time, SenderAddress, RecipientAddress, Subject, Status
```
**Ujawniło:** 3 maile wysłane 16:57:09 **od `l.chen`** do `m.harris`, `k.patel`, `allan.senna` - ten sam temat "HR Policy Update". To atakujący rozsyła phishing wewnętrznie z konta Finance Managera (T1534 Internal Spearphishing).
<img width="1920" height="935" alt="Zrzut ekranu (1083)" src="https://github.com/user-attachments/assets/1f8b9959-cec2-4705-8a0f-058c1266875a" />


### Krok 7 - ilu ludzi dostało INITIAL phishing (rozdzielenie fal)

Temat był reużyty w dwóch falach, więc filtr po samym `Subject` mieszał je. Najpierw wylistowałem maile z nadawcą, żeby zobaczyć rozdział na fale:
```spl
index=ir Subject="HR Policy Update — Immediate Action Required" Status="Delivered"
| table _time, SenderAddress, RecipientAddress
| sort _time
```
Widać dwie fale: 16:20 od zewnętrznego `hr-support@nexus-verify.thm` i 16:57 od `l.chen` (już z przejętej skrzynki).
<img width="1920" height="928" alt="Zrzut ekranu (1086)" src="https://github.com/user-attachments/assets/585b6caa-f056-4166-8f45-53bafc1434af" />


Potem potwierdziłem liczbę kont, grupując po nadawcy:
```spl
index=ir Subject="HR Policy Update — Immediate Action Required" Status="Delivered"
| stats dc(RecipientAddress) as accounts values(RecipientAddress) as odbiorcy by SenderAddress
```
**Ujawniło:** dwa nadawcy:
- `hr-support@nexus-verify.thm` (spoofed, zewnętrzny) -> **2 konta** (`l.chen`, `k.patel`) = **initial phishing**,
- `l.chen@nexusfinancial.thm` (po przejęciu) -> 3 konta (`allan.senna`, `k.patel`, `m.harris`) = wewnętrzna fala.

**Initial phishing = 2 konta** (liczymy tylko sfałszowanego, zewnętrznego nadawcę - nie maile wysłane już z przejętej skrzynki).
<img width="1920" height="931" alt="Zrzut ekranu (1085)" src="https://github.com/user-attachments/assets/35cbbcfb-2f0d-4b25-b973-ddd04990df86" />


---

## Oś czasu (2026-03-30)

| Czas | Zdarzenie | Źródło |
|---|---|---|
| 16:20:01 | Phishing dostarczony do `l.chen` (16:20:37 do `k.patel`) | Message Trace |
| 16:41:28 | Pierwsza próba logowania z `223.123.4.50` (errorCode 50140) | Sign-in |
| **16:41:30** | **Pierwsze udane logowanie** (errorCode 0) - przejęcie `l.chen` | Sign-in |
| 16:57:09 | Internal phishing wysłany z `l.chen` do 3 userów | Message Trace |
| 16:58:48 | Reguła skrzynki `Junk Filter Update` na `l.chen` | UAL (New-InboxRule) |
| ~17:00 | Logowania `k.patel` z `223.123.4.50` | Sign-in |
| 17:02:40 | Reguła skrzynki `Security Updates` na `k.patel` | UAL (New-InboxRule) |

---

## MITRE ATT&CK

| Technika | ID | Gdzie w incydencie |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | mail od `nexus-verify.thm` |
| Valid Accounts: Cloud Accounts | T1078.004 | logowanie skradzionymi creds (brak MFA) |
| Email Hiding Rules | T1564.008 | reguły `Junk Filter Update` / `Security Updates` |
| Internal Spearphishing | T1534 | phishing rozesłany z przejętej skrzynki `l.chen` |
