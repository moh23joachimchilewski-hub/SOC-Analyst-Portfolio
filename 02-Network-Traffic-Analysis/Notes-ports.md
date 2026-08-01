# Security+ — Najważniejsze porty i protokoły

Ściąga portów i protokołów pod egzamin CompTIA Security+ (SY0-701)

---

## Pełna tabela portów

| Port | TCP/UDP | Protokół | Do czego służy |
|---|---|---|---|
| 20/21 | TCP | FTP | Transfer plików |
| 22 | TCP | SSH | Zdalne logowanie (Linux) |
| 23 | TCP | Telnet | Niezaszyfrowane zdalne logowanie |
| 25 | TCP | SMTP | Wysyłanie poczty |
| 49 | TCP | TACACS+ | AAA dla urządzeń sieciowych |
| 53 | TCP/UDP | DNS | Rozwiązywanie nazw domen |
| 67/68 | UDP | DHCP | Przydzielanie adresów IP |
| 69 | UDP | TFTP | Prosty transfer plików |
| 80 | TCP | HTTP | Strony WWW |
| 88 | TCP/UDP | Kerberos | Uwierzytelnianie w Active Directory |
| 110 | TCP | POP3 | Pobieranie poczty |
| 123 | UDP | NTP | Synchronizacja czasu |
| 137-139 | TCP/UDP | NetBIOS | Starsze usługi Windows |
| 143 | TCP | IMAP | Odczyt poczty |
| 161/162 | UDP | SNMP | Monitoring urządzeń |
| 389 | TCP/UDP | LDAP | Usługi katalogowe (AD) |
| 443 | TCP | HTTPS | Szyfrowane WWW |
| 445 | TCP | SMB | Udostępnianie plików Windows |
| 465 | TCP | SMTPS | SMTP przez TLS |
| 514 | UDP | Syslog | Logi urządzeń |
| 636 | TCP | LDAPS | LDAP przez TLS |
| 989/990 | TCP | FTPS | FTP przez TLS |
| 993 | TCP | IMAPS | IMAP przez TLS |
| 995 | TCP | POP3S | POP3 przez TLS |
| 1812/1813 | UDP | RADIUS | AAA |

---

## 

| Port | Protokół |
|---|---|
| 20/21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 67/68 | DHCP |
| 80 | HTTP |
| 88 | Kerberos |
| 110 | POP3 |
| 123 | NTP |
| 143 | IMAP |
| 161 | SNMP |
| 389 | LDAP |
| 443 | HTTPS |
| 445 | SMB |
| 514 | Syslog |
| 636 | LDAPS |
| 993 | IMAPS |
| 995 | POP3S |
| 1812 | RADIUS |

---

## 🌍 Protokoły bez numerów portów

Te również są bardzo ważne na egzaminie:

| Protokół | Do czego służy |
|---|---|
| ICMP | Ping, diagnostyka sieci |
| ARP | Zamiana IP ↔ MAC |
| IP | Adresowanie i routing |
| TCP | Połączeniowy, niezawodny transport |
| UDP | Bezpołączeniowy, szybki transport |
| GRE | Tunelowanie |
| ESP | Szyfrowanie w IPsec |
| AH | Uwierzytelnianie w IPsec |

---

## 🦈 Bonus: Wireshark — filtry do szybkiej analizy PCAP

Skoro znasz porty, warto od razu umieć je filtrować w praktyce:

**1. Filtruj ruch po konkretnym porcie (np. podejrzany SMB)**
```
tcp.port == 445
```

**2. Filtruj po protokole aplikacyjnym (czytelniej niż numer portu)**
```
dns
http
ftp
```
*(Wireshark rozpoznaje protokół po zawartości pakietu, nie tylko po porcie — złapie nawet ruch na nietypowym porcie, jeśli faktycznie jest to np. HTTP)*

**3. Znajdź niezaszyfrowane logowania (cleartext credentials)**
```
ftp.request.command == "PASS" or http.request.method == "POST" or pop.request.command == "PASS"
```
