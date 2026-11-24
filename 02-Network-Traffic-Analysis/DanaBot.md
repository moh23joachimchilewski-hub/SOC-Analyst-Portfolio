# Analiza pcap: pobranie skryptu JavaScript i drugiego pliku DLL (laboratorium DanaBot)

> **Uwaga:** notatka edukacyjna. Opisuje publiczne laboratorium treningowe (CyberDefenders, plik `205-DanaBot.pcap`). Wszystkie adresy, domeny i skróty pochodzą z laboratorium, nie ze środowiska klienta. Adresy i domeny podaję w formie zdefangowanej (`[.]`).

## Kontekst zadania

Zespół SOC wykrył podejrzaną aktywność na stacji roboczej, a ja miałem przeanalizować zapis ruchu (pcap): ustalić źródło ataku, plik użyty do początkowego dostępu, jego skrót, proces, który go uruchamia, oraz drugi pobrany plik.

Narzędzia: Wireshark, CyberChef, VirusTotal.

**Bezpieczeństwo:** analizowałem wyłącznie ruch sieciowy i reputację. Żadnej próbki nie uruchamiałem na swoim komputerze.

## Podsumowanie (5W)

| Pytanie | Odpowiedź |
|---|---|
| **Kto** | Infrastruktura atakującego: `62[.]173[.]142[.]148`, serwer pierwszego pliku `portfolio[.]serveirc[.]com`, serwer drugiego pliku `soundata[.]top` (`188[.]114[.]97[.]3`, Cloudflare) |
| **Co** | Pobranie obfuskowanego skryptu JavaScript `allegato_708.js` z `/login.php`, uruchamianego przez Windows Script Host (`wscript.exe`), a następnie pobranie drugiego pliku `resources.dll` (ok. 11,9 MB) |
| **Kiedy** | 14.02.2024, ok. 16:25-16:28 UTC |
| **Gdzie** | Stacja `10.2.14.101`, DNS `10.2.14.1` |
| **Dlaczego** | Schemat odpowiada pobraniu ładunku przez loader: skrypt jest nośnikiem, a właściwy ładunek to DLL. `allegato` to po włosku "załącznik" |

## IOC

### Hosty i domeny

| IOC | Rola | Uwagi |
|---|---|---|
| `62[.]173[.]142[.]148` | Atakujący (początkowy dostęp) | Adres użyty podczas początkowego dostępu |
| `portfolio[.]serveirc[.]com` | Serwer pierwszego pliku | Nginx/1.14.0 (Ubuntu), ścieżka `/login.php` |
| `soundata[.]top` | Serwer drugiego pliku | Domena utworzona 2024-02-12, rejestrator Eranet International Limited |
| `188[.]114[.]97[.]3` | Adres obsługujący drugi plik | Cloudflare |
| `10.2.14.101` | Ofiara (stacja robocza) | Adres wewnętrzny |

### Pliki i adresy URL

| IOC | Wartość |
|---|---|
| Pierwszy plik | `allegato_708.js` (ok. 5,4 KB, obfuskowany JavaScript) |
| SHA-256 pierwszego pliku | `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268` |
| Adres drugiego pliku | `hxxp://soundata[.]top/resources[.]dll` |
| Drugi plik | `resources.dll` (rozszerzenie `.dll`, ok. 11,9 MB wg nagłówka `Content-Length`) |

## Techniki MITRE ATT&CK (orientacyjne)

| ID | Technika |
|---|---|
| T1204.002 | User Execution: Malicious File (uruchomienie pobranego skryptu) |
| T1059.007 | Command and Scripting Interpreter: JavaScript |
| T1105 | Ingress Tool Transfer (pobranie drugiego pliku) |

## Krok po kroku

### 1. Szukanie pobranych plików w ruchu HTTP
W Wireshark szukałem żądań HTTP, po których pobierane są skrypty i pliki wykonywalne. Użyte filtry: `http.request.method=="GET"`, `http.request.uri contains "php"`, `http.request.uri contains ".js"`, `http.request.uri contains "exe"`, `http contains "js"`, `ip.addr == 62.173.142.148`, a potem `tcp.stream eq 0`, `tcp.stream eq 7`, `tcp.stream eq 8`.

<img width="1920" height="960" alt="Zrzut ekranu (1546)" src="https://github.com/user-attachments/assets/c9c5a2de-1bdb-4400-ab5f-3065c8353afa" />

*Historia użytych filtrów. W tle widać transfer z `188.114.97.3` do `10.2.14.101` (pakiet 9952, odpowiedź `200 OK` o rozmiarze ok. 11,9 MB po złożeniu strumienia TCP).*

### 2. Pierwszy plik: odpowiedź na `/login.php`
`Follow, HTTP Stream` dla `tcp.stream eq 0`: `GET /login.php`, host `portfolio[.]serveirc[.]com`. Odpowiedź serwera to `200 OK`, ale zamiast strony logowania serwer zwraca **załącznik**: `Content-Type: application/octet-stream` i `Content-disposition: attachment; filename=allegato_708.js`. To podejrzane, bo strona o nazwie `login.php` nie powinna wysyłać skryptów do pobrania. Treść pliku to obfuskowany JavaScript.

<img width="1272" height="1010" alt="Zrzut ekranu (1532)" src="https://github.com/user-attachments/assets/119f7c1a-3416-4040-b75d-d53cc89b4dda" />

*Strumień `tcp.stream eq 0`: odpowiedź `200 OK` z załącznikiem `allegato_708.js`.*

### 3. Skrót SHA-256 i reputacja pliku
W CyberChef obliczyłem skrót SHA-256 zawartości pliku (operacja SHA2, rozmiar 256):
`847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`

Wyszukanie skrótu w VirusTotal: **32/60** dostawców oznaczyło plik jako złośliwy, znaczniki `javascript`, `spreader`, `obfuscated`, `long-sleeps`. W zakładce Relations widać kontaktowany adres `hxxp://soundata[.]top/resources[.]dll` oraz domenę `soundata[.]top`.

<img width="1920" height="863" alt="Zrzut ekranu (1534)" src="https://github.com/user-attachments/assets/8cc816ef-0ab3-4052-89fc-f574490ddd00" />

*CyberChef, operacja SHA2 (256): skrót pliku `allegato_708.js`.*

<img width="1920" height="860" alt="Zrzut ekranu (1539)" src="https://github.com/user-attachments/assets/f3ffa8b0-5c03-4ff8-a2f1-5f1f15f9fc60" />

*VirusTotal dla skrótu: 32/60, powiązany adres `soundata[.]top/resources[.]dll`.*

### 4. Proces uruchamiający plik `.js`
Pliki `.js` otwierane z poziomu Windows uruchamia **Windows Script Host**, czyli proces **`wscript.exe`**. Kod jest obfuskowany (nazwy zmiennych `_0x...`, duża tablica ciągów), więc nie analizowałem go linijka po linijce. W CyberChef (operacja JavaScript Beautify) przeszukałem sformatowany tekst pod kątem słowa `WScript`, które potwierdza użycie obiektów Windows Script Host (`WScript`, `ActiveXObject`).

<img width="1920" height="864" alt="Zrzut ekranu (1536)" src="https://github.com/user-attachments/assets/08f0a768-5359-486b-802a-4b49b186cd55" />

*CyberChef, JavaScript Beautify: wyróżnione wystąpienia `WScript` w sformatowanym kodzie.*

### 5. Drugi plik
Powiązanie z VirusTotal wskazało na adres `hxxp://soundata[.]top/resources[.]dll`, a w pcap jest odpowiadający mu transfer z `188[.]114[.]97[.]3` (pakiet 9952, ok. 16:26:58 UTC). Rozszerzenie drugiego pliku to **`.dll`**.

VirusTotal dla adresu URL: **16/93** (stan z analizy 08.11.2026), kategorie `Malicious`, `spyware and malware`, `Dead Sites`. Pierwsze zgłoszenie adresu: 14.02.2024 09:41 UTC, więc adres był znany jeszcze przed przechwyceniem ruchu. Obecnie nie odpowiada (status błędu).

Wyodrębniony plik nie był przeze mnie uruchamiany.

<img width="1920" height="841" alt="Zrzut ekranu (1541)" src="https://github.com/user-attachments/assets/653e35f0-2b2c-4994-8fec-ea30ba3bb792" />

*VirusTotal dla `hxxp://soundata[.]top/resources[.]dll`: 16/93.*

<img width="1920" height="853" alt="Zrzut ekranu (1540)" src="https://github.com/user-attachments/assets/08fc9dd2-90d3-4cf1-97a3-892c93087cde" />

*Kategorie, historia zgłoszeń i status adresu.*

## Potwierdzenie wyników

<img width="984" height="662" alt="Zrzut ekranu (1542)" src="https://github.com/user-attachments/assets/5ca4d7e4-eab8-4ed4-a19c-74a496021bbc" />

<img width="993" height="178" alt="Zrzut ekranu (1543)" src="https://github.com/user-attachments/assets/79f3cea5-5fba-4518-b82e-74ebafc07295" />
