# Analiza pcap pod kątem SQL Injection: laboratorium WebInvestigation

> **Uwaga:** notatka edukacyjna. Opisuje publiczne laboratorium treningowe (CyberDefenders, plik `WebInvestigation.pcap`). Wszystkie adresy IP, domeny i dane uwierzytelniające pochodzą z laboratorium, nie ze środowiska klienta.

## Kontekst zadania

Otrzymałem plik pcap z ruchem do serwera WWW sklepu z książkami i miałem go przeanalizować **pod kątem SQL Injection**: znaleźć źródło ataku, podatny skrypt, pierwszą próbę SQLi, sposób odczytu bazy oraz skutki (dostęp do panelu administracyjnego i wgrany plik).

Narzędzia: Wireshark 4.6.9, AbuseIPDB, CyberChef.

Przechwycony plik: **88 862 pakiety**.

## Podsumowanie (5W)

| Pytanie | Odpowiedź |
|---|---|
| **Kto** | Atakujący: `111.224.250.131` (CHINANET Hebei province network, AS4134, Shijiazhuang, Hebei, Chiny). Cel: serwer `73.124.22.98` (`bookworldstore.com`, Apache/2.4.52 na Ubuntu) |
| **Co** | SQL Injection w parametrze `search` skryptu `search.php` (próby błędów, testy logiczne, UNION), odczyt nazw baz danych, następnie logowanie do panelu `/admin/` poświadczeniami `admin:admin123!` i wgranie pliku PHP `NVri2vhp.php` z poleceniem reverse shell |
| **Kiedy** | 15.03.2024, ok. 12:01-12:24 UTC |
| **Gdzie** | `bookworldstore.com`: `/search.php`, `/admin/login.php`, `/admin/index.php` (upload) |
| **Dlaczego** | Motyw nie wynika z pcap. Zachowanie wskazuje na dostęp do danych w bazie i próbę przejęcia kontroli nad serwerem (reverse shell) |

## IOC: hosty

| IOC | Rola | Uwagi |
|---|---|---|
| `111.224.250.131` | Atakujący | CHINANET Hebei, AS4134, Shijiazhuang (dane lokalizacji: IPinfo przez AbuseIPDB, orientacyjne). AbuseIPDB: brak zgłoszeń (0%) |
| `73.124.22.98` | Ofiara (serwer WWW) | Apache/2.4.52 (Ubuntu), host `bookworldstore.com` |
| `170.40.150.126` | Sprawdzony i odrzucony | DST Systems, Inc. (USA, Kansas City). AbuseIPDB: brak zgłoszeń. Tylko 256 pakietów, nie analizowany dalej |

## Techniki MITRE ATT&CK

| ID | Technika |
|---|---|
| T1190 | Exploit Public-Facing Application (SQLi w `search.php`) |
| T1078 | Valid Accounts (logowanie do panelu `admin`) |
| T1505.003 | Server Software Component: Web Shell (wgrany plik PHP) |

## Krok po kroku

### 1. Statystyki ruchu: znalezienie podejrzanego adresu
**Statystyki, IPv4 Statistics, All Addresses.** Prawie cały ruch dotyczył dwóch adresów: `73.124.22.98` (99,86% pakietów) i `111.224.250.131` (99,57%, 88 484 pakiety). Poza pulą `73.124.22.x` był jeszcze jeden zewnętrzny adres: `170.40.150.126` (256 pakietów).

<img width="998" height="602" alt="Zrzut ekranu (1508)" src="https://github.com/user-attachments/assets/b65d50d0-6372-4b06-9b1a-7bb712d7ab69" />

*Statystyki IPv4: dwa adresy generują prawie cały ruch, a trzeci zewnętrzny ma tylko 256 pakietów.*

### 2. Sprawdzenie adresów w AbuseIPDB
- `170.40.150.126`: DST Systems, Inc., USA (Kansas City). Brak zgłoszeń.
- `111.224.250.131`: CHINANET Hebei, Chiny, **Shijiazhuang, Hebei**. Brak zgłoszeń.

Brak zgłoszeń w AbuseIPDB nie oznacza, że adres jest bezpieczny. Podejrzenie wynikało z kontekstu: adres z Chin odwiedza angielskojęzyczny sklep internetowy i generuje prawie cały ruch w pliku. Dalej oceniałem już zachowanie, nie reputację.

<img width="1781" height="703" alt="Zrzut ekranu (1509)" src="https://github.com/user-attachments/assets/b2ac1df0-86e9-4e2f-a654-ddf170cd5824" />

*AbuseIPDB dla `170.40.150.126`: USA, Kansas City, 0% zgłoszeń.*

<img width="1770" height="707" alt="Zrzut ekranu (1510)" src="https://github.com/user-attachments/assets/4fa7dad2-e24e-4b2a-99a3-b8bce7a81625" />

*AbuseIPDB dla `111.224.250.131`: Chiny, Shijiazhuang (Hebei), AS4134, 0% zgłoszeń.*

### 3. Filtr HTTP dla podejrzanego adresu
`ip.addr == 111.224.250.131 && http`

### 4. Podatny skrypt
Zawężenie do plików PHP: `... && http.request.uri contains ".php"`. Na liście widać zwykłe odwiedziny (`/contact.php`, `/faq.php`, `/search.php?search=test+test`, `search=war`, `search=book`), a potem wiele żądań do **`/search.php`** z coraz dziwniejszą wartością parametru `search`. Tylko w tym skrypcie parametr `search` zawierał znaki i słowa SQL, więc to on był celem ataku.

<img width="1920" height="958" alt="Zrzut ekranu (1514)" src="https://github.com/user-attachments/assets/93dc8e6e-8d40-464f-b3eb-15ccc0e1023a" />

*Filtr `.php`: zwykłe odwiedziny, a potem seria żądań do `search.php` (m.in. `book%27` z odpowiedzią 500 i `book and 1=1; -- -`).*

### 5. Pierwsza próba SQL Injection
W filtrze dla `search.php` (także z kodem 200) przeglądałem wartości parametru `search` i szukałem znaków i słów typowych dla SQLi: apostrof (`%27`), `and 1=1`, `--`, `UNION`, `SELECT`. Wskazówka: żądanie i odpowiedź to osobne pakiety, a adres żądania w pakiecie odpowiedzi jest w polu `http.response_for.uri`.

Zaobserwowane rodzaje payloadów:

| Rodzaj | Przykład | Odpowiedź serwera |
|---|---|---|
| Sonda z apostrofem | `search=book%27` | `500 Internal Server Error` (nieobsłużony błąd SQL, wejście trafia do zapytania) |
| Test logiczny | `search=book and 1=1; -- -` | `200 OK` |
| Warunek zawsze prawdziwy (or 1=1) | `search=' or 1=1; -- -` | `200 OK`, pakiet odpowiedzi większy niż zwykle (722 B wobec 462 B przy zwykłych wyszukiwaniach) |
| Testy automatu | `book' AND 7459=3526 AND 'PyAo'='PyAo` i podobne | `200` lub `500` zależnie od payloadu |
| Oparte na błędzie | `EXTRACTVALUE(...)` | m.in. `500` |
| UNION | `book' UNION ALL SELECT NULL,CONCAT(...)` | `200 OK` |

Dziesiątki żądań z losowymi ciągami znaków i numerami w ułamku sekundy wyglądają na ruch automatu, nie ręczne wpisywanie.

<img width="1920" height="954" alt="Zrzut ekranu (1515)" src="https://github.com/user-attachments/assets/771489e3-8021-431e-8e4f-bfcd7530c727" />

*Seria żądań automatu: testy logiczne, `EXTRACTVALUE` i odpowiedzi `500` oraz `200`.*

Wartość parametru jest zakodowana (`%20` = spacja), więc w **CyberChef (operacja URL Decode)** zdekodowałem pierwszy test logiczny:
`book%20and%201=1;%20--%20-` → `book and 1=1; -- -`

<img width="1920" height="608" alt="Zrzut ekranu (1513)" src="https://github.com/user-attachments/assets/e5ddf163-eaa3-49ae-8cd8-6608dcd36128" />

*CyberChef, URL Decode: zdekodowane pierwsze żądanie `search.php?search=book and 1=1; -- -`.*

Jako pierwsze żądanie SQLi laboratorium zaakceptowało test logiczny, a nie sondę z samym apostrofem (`book%27`).

### 6. Odczyt baz danych
Do odczytu nazw baz w MySQL służy tabela `INFORMATION_SCHEMA.SCHEMATA`, kolumna `schema_name`. Filtr: `... && http.request.uri contains "schema"`. Wynik zawierał kilka podobnych żądań `UNION ALL SELECT NULL,CONCAT(...JSON_ARRAYAGG(CONCAT_WS(...,schema_name))...) FROM INFORMATION_SCHEMA.SCHEMATA`.

<img width="1920" height="965" alt="Zrzut ekranu (1516)" src="https://github.com/user-attachments/assets/6de34646-ccdc-444c-a3ce-d06d252e7633" />

*Filtr `schema`: żądania `UNION ALL SELECT ... INFORMATION_SCHEMA.SCHEMATA` z odpowiedzią 200 oraz seria żądań `404` o nazwach `/schema.*`.*

Zdekodowałem je w CyberChef (URL Decode):
```
/search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -
```
Znaczniki w hex w zapytaniu to krótkie ciągi (`0x7178766271` = `qxvbq`), a taki sposób oznaczania wyniku jest typowy dla automatycznych narzędzi do SQLi (np. sqlmap).

<img width="1920" height="647" alt="Zrzut ekranu (1518)" src="https://github.com/user-attachments/assets/3799072c-b596-42d1-9cae-79a4cfe8eb3e" />

*CyberChef, URL Decode: zapytanie odczytujące nazwy baz z `INFORMATION_SCHEMA.SCHEMATA`.*

Ten sam filtr pokazał też dużą liczbę żądań `404 Not Found` o nazwach typu `/schema`, `/schema.html`, `/schema.txt`, `/schema.php`, `/schemas`... w tej samej chwili. To ślad skanowania katalogów i plików z gotowej listy słów.

### 7. Panel administracyjny i poświadczenia
Filtr metody POST: `ip.addr == 111.224.250.131 && http && http.request.method == POST`. Wynik: 4 żądania `POST /admin/login.php` (`application/x-www-form-urlencoded`) i 1 żądanie `POST /admin/index.php` (`application/x-php`). Skrót `Follow, HTTP Stream` dla wybranych strumieni:

<img width="1920" height="966" alt="Zrzut ekranu (1520)" src="https://github.com/user-attachments/assets/f2d89e85-1fb7-4cf4-b2f8-e4fc8483202c" />

*Filtr `POST`: cztery próby logowania do `/admin/login.php` i jedno wgranie pliku przez `/admin/index.php`.*

- `tcp.stream eq 645`: `username=admin&password=admin` → `200 OK`, treść: `Invalid username or password.` (logowanie nieudane).

<img width="1282" height="1011" alt="Zrzut ekranu (1522)" src="https://github.com/user-attachments/assets/739da99d-1439-4cb5-8dc3-a0a984d1a3cc" />

*Strumień 645: odpowiedź `Invalid username or password.`*

- `tcp.stream eq 647`: `username=admin&password=admin123%21` (po zdekodowaniu `admin123!`) → **`302 Found`**, `Location: index.php`, a zaraz potem `GET /admin/index.php` → `200 OK`. Logowanie udane.

<img width="1290" height="1015" alt="Zrzut ekranu (1523)" src="https://github.com/user-attachments/assets/30b26ca2-74c9-4e5b-bf7c-d6ea071b0988" />

*Strumień 647: `302 Found` z przekierowaniem do `index.php`, potem `200 OK` na panelu.*

Przy logowaniu kod `302` z przekierowaniem do panelu jest sygnałem sukcesu, a nie `200` z komunikatem o błędzie.

### 8. Wgrany plik
`tcp.stream eq 650`: `POST /admin/index.php`, `multipart/form-data`, pole `fileToUpload`, `filename="NVri2vhp.php"`, `Content-Type: application/x-php`. Zawartość pliku to jednowierszowy skrypt PHP wywołujący powłokę bash z połączeniem do `111.224.250.131:443` (reverse shell). Odpowiedź: `The file NVri2vhp.php has been uploaded.` Ze zrzutów nie wynika, czy plik został później uruchomiony.

<img width="1261" height="1015" alt="Zrzut ekranu (1526)" src="https://github.com/user-attachments/assets/6a8486d5-d321-4d46-98c0-b40a29df8802" />

*Strumień 650: wgranie `NVri2vhp.php` i potwierdzenie serwera.*

## Potwierdzenie wyników

<img width="987" height="392" alt="Zrzut ekranu (1527)" src="https://github.com/user-attachments/assets/44a778ce-ae5f-4171-b815-af3eb70f24ec" />

<img width="984" height="707" alt="Zrzut ekranu (1528)" src="https://github.com/user-attachments/assets/0a8e5c21-f269-4eb9-bfcf-d229d7902c31" />

<img width="986" height="627" alt="Zrzut ekranu (1529)" src="https://github.com/user-attachments/assets/994bedea-3bfa-4e2d-a94a-4dc75098415b" />

<img width="987" height="201" alt="Zrzut ekranu (1530)" src="https://github.com/user-attachments/assets/94c63a27-8080-4ea7-9a45-33a85034fef1" />

