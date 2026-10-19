# SPF / DKIM / DMARC - uwierzytelnianie poczty (notatka)

Trzy rekordy DNS, które pozwalają serwerowi odbiorcy sprawdzić, czy mail naprawdę pochodzi z domeny, którą podaje nadawca - brak ich konfiguracji otwiera drogę do **email spoofingu** i **phishingu** podszywającego się pod zaufaną domenę.

- **SPF (Sender Policy Framework)** - rekord DNS z listą adresów IP/serwerów uprawnionych do wysyłania poczty w imieniu domeny; sprawdza, czy mail przyszedł z dozwolonego serwera, a jego brak pozwala atakującemu wysyłać maile z dowolnego serwera jako Twoja domena.
- **DKIM (DomainKeys Identified Mail)** - podpis kryptograficzny dodawany do nagłówka maila i weryfikowany kluczem publicznym z DNS; potwierdza, że treść nie została zmieniona w drodze i pochodzi od domeny, a jego brak umożliwia podszywanie się i modyfikację wiadomości bez wykrycia.
- **DMARC (Domain-based Message Authentication, Reporting & Conformance)** - polityka mówiąca serwerowi odbiorcy, co zrobić z mailem, który nie przeszedł SPF lub DKIM (none / quarantine / reject) plus raportowanie; jego brak (lub `p=none`) sprawia, że nawet wykryty spoofing i tak trafia do skrzynki ofiary.

**Ataki przy braku tych polityk:** email spoofing (podszywanie się pod domenę), phishing / spearphishing, Business Email Compromise (BEC), oszustwa "na prezesa" / fałszywe faktury.

**Dla analityka:** w nagłówkach maila szukaj wyników `spf=`, `dkim=`, `dmarc=` (pass/fail/none). `fail`/`none` przy mailu podszywającym się pod zaufaną domenę = mocny wskaźnik phishingu.
