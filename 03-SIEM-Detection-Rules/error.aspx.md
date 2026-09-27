# Detekcja uploadu web shella (error.aspx) - Initial Access przez podatny upload na IIS w domenie AD

> **Platforma:** Splunk
> **Źródła logów:** IIS (`index=iis`), Sysmon (`index=win`, Event ID 1 i 11)
> **Typ detekcji:** Initial Access / Persistence (Web Shell) / Discovery
> **Severity:** Critical
> **MITRE ATT&CK:** T1595.003, T1190, T1505.003, T1059.003, T1082, T1057, T1049, T1083, T1069.002

---

## Podsumowanie

Atakujący z adresu `198.51.100.23` przeskanował aplikację webową na serwerze IIS, znalazł formularz uploadu `/internalapp/upload.aspx` i wgrał przez niego web shella `error.aspx`. Plik trafił do katalogu `C:\inetpub\wwwroot\aspnet_client\system_web\`. Około 5 minut później atakujący zaczął wysyłać przez web shella komendy rekonesansu. Ostatnia z nich, `net group "Domain Admins" /domain`, pokazuje, że serwer jest w domenie Active Directory i że atakujący szuka już kont z najwyższymi uprawnieniami w domenie.

---

## Kontekst

### Czym jest web shell

Web shell to złośliwy skrypt wgrany na serwer WWW. W środowisku IIS jest to zwykle plik `.aspx`. Pozwala on wykonywać komendy systemowe przez zwykłe żądania HTTP, np.:

```
GET /aspnet_client/system_web/error.aspx?cmd=hostname
```

Serwer uruchamia komendę z parametru `cmd` i odsyła wynik w odpowiedzi HTTP. Web shell działa po restarcie serwera, komunikuje się przez standardowe porty 80/443 i nie wymaga od atakującego żadnych dodatkowych narzędzi.

### Czym jest w3wp.exe i dlaczego to on "odpalił" nasz plik

`w3wp.exe` to **IIS Worker Process**, czyli proces serwera WWW IIS, który obsługuje żądania HTTP i wykonuje kod aplikacji ASP.NET. Sam w sobie nie jest częścią Active Directory. Jest procesem serwera WWW, który w tym przypadku stoi na maszynie dołączonej do domeny.

W tym incydencie `w3wp.exe` pojawia się w dwóch rolach:

1. **Zapisał plik na dysk** (Sysmon Event ID 11). Formularz `upload.aspx` działa wewnątrz `w3wp.exe`, więc to ten proces fizycznie zapisał `error.aspx` do katalogu `aspnet_client`.
2. **Uruchamiał komendy atakującego** (Sysmon Event ID 1). Za każdym razem, gdy atakujący wywołał `error.aspx?cmd=...`, `w3wp.exe` tworzył proces potomny `cmd.exe /c <komenda>`.

Przy normalnej pracy `w3wp.exe` obsługuje żądania i generuje odpowiedzi bez uruchamiania powłoki systemowej. **Proces `cmd.exe` uruchomiony przez `w3wp.exe` to podstawowa sygnatura aktywności web shella.**

Jedyny proces potomny, który w tym przypadku jest normalny, to `csc.exe` (kompilator C#). ASP.NET kompiluje plik `.aspx` przy pierwszym wywołaniu, więc `csc.exe` pojawia się raz, tuż przed pierwszą komendą atakującego.

### Dlaczego to ma znaczenie w domenie AD

Serwer IIS dołączony do domeny daje atakującemu punkt zaczepienia wewnątrz sieci firmowej. Komenda `net group "Domain Admins" /domain` odpytuje kontroler domeny o członków grupy Domain Admins. Oznacza to, że atakujący przeszedł już od rozpoznania samego serwera do rozpoznania domeny i szuka celu do eskalacji uprawnień lub lateral movement.

---

## 5W

| Pytanie | Odpowiedź |
|---|---|
| **Who** (kto) | Atakujący z adresu IP `198.51.100.23` |
| **What** (co) | Upload web shella `error.aspx` przez formularz `/internalapp/upload.aspx`, a następnie wykonanie 5 komend rekonesansu systemu i domeny |
| **When** (kiedy) | 2026-02-17: upload o 10:40:33, komendy od 10:45:13 do 10:46:49 |
| **Where** (gdzie) | Serwer IIS w domenie AD, plik zapisany w `C:\inetpub\wwwroot\aspnet_client\system_web\error.aspx` |
| **Why** (po co) | Uzyskanie trwałego zdalnego dostępu do serwera i rozpoznanie środowiska (host, procesy, połączenia sieciowe, pliki aplikacji, administratorzy domeny) jako przygotowanie do dalszych działań w domenie |

---

## Przebieg dochodzenia (zapytania SPL)

### Krok 1 - Skanowanie katalogów (odpowiedzi 404)

```spl
index=iis sc_status=404
| stats count by c_ip
| sort - count
```

Wszystkie 21 odpowiedzi 404 pochodzą z jednego adresu: `198.51.100.23`. Seria nieudanych żądań z jednego IP to typowy ślad skanera katalogów, który szuka istniejących stron i miejsc do zapisu.

<img width="1920" height="873" alt="Zrzut ekranu (804)" src="https://github.com/user-attachments/assets/16884fe3-9589-4d03-95ef-39ffcfb352dd" />



### Krok 2 - Co atakujący znalazł (odpowiedzi 200)

```spl
index=iis c_ip=198.51.100.23 sc_status=200
| stats count by cs_uri_stem
```

| cs_uri_stem | count |
|---|---|
| `/aspnet_client/system_web/error.aspx` | 5 |
| `/internalapp/upload.aspx` | 2 |
| `/internalapp/` | 1 |
| `/internalapp/default.aspx` | 1 |

Wyróżniają się dwie rzeczy: formularz uploadu `/internalapp/upload.aspx` oraz plik `error.aspx` w katalogu `/aspnet_client/`. Katalog `aspnet_client` to domyślny katalog IIS na skrypty klienckie ASP.NET. Nie powinien zawierać kodu aplikacji, a `w3wp.exe` ma w nim prawo zapisu, dlatego jest częstym miejscem podrzucania web shelli.

<img width="1920" height="873" alt="Zrzut ekranu (805)" src="https://github.com/user-attachments/assets/2adf25d7-a848-43e5-be58-eba8237164f1" />



### Krok 3 - Aktywność na web shellu

```spl
index=iis cs_uri_stem="*/error.aspx"
| table _time, c_ip, cs_method, cs_uri_query, sc_status
| sort _time
```

| Czas | Metoda | cs_uri_query | Komenda po zdekodowaniu |
|---|---|---|---|
| 10:45:15 | GET | `cmd=hostname` | `hostname` |
| 10:45:46 | GET | `cmd=tasklist` | `tasklist` |
| 10:46:10 | GET | `cmd=netstat%20-an` | `netstat -an` |
| 10:46:28 | GET | `cmd=dir%20C:%5Cinetpub%5Cwwwroot` | `dir C:\inetpub\wwwroot` |
| 10:46:49 | GET | `cmd=net%20group%20%22Domain%20Admins%22%20/domain` | `net group "Domain Admins" /domain` |

Wszystkie żądania zakończyły się kodem 200, czyli każda komenda została przyjęta przez web shella. W polu `cs_uri_query` widać komendy zakodowane w URL (`%20` to spacja, `%5C` to `\`, `%22` to cudzysłów).

<img width="1920" height="865" alt="Zrzut ekranu (806)" src="https://github.com/user-attachments/assets/6356b308-e7e6-4f0e-8ee4-d22588699fe1" />


### Krok 4 - Łańcuch procesów: w3wp.exe -> cmd.exe (Sysmon Event ID 1)

```spl
index=win EventCode=1 ParentImage="*\\w3wp.exe"
| table _time, ParentImage, CommandLine
| sort _time
```

| Czas | ParentImage | CommandLine |
|---|---|---|
| 10:45:13 | w3wp.exe | `csc.exe /noconfig /fullpaths @"...\5brphhrq.cmdline"` (kompilacja `error.aspx`) |
| 10:45:13 | w3wp.exe | `"cmd.exe" /c hostname` |
| 10:45:44 | w3wp.exe | `"cmd.exe" /c tasklist` |
| 10:46:10 | w3wp.exe | `"cmd.exe" /c netstat -an` |
| 10:46:26 | w3wp.exe | `"cmd.exe" /c dir C:\inetpub\wwwroot` |
| 10:46:49 | w3wp.exe | `"cmd.exe" /c net group "Domain Admins" /domain` |

Te same 5 komend, które widać w logach IIS, zostało faktycznie wykonanych na serwerze jako procesy potomne `w3wp.exe`. `csc.exe` przy pierwszym wywołaniu to kompilacja pliku `.aspx` przez ASP.NET i sama w sobie nie jest złośliwa. Złośliwe są dopiero wywołania `cmd.exe`.

**Obserwacja:** czasy w Sysmonie są o około 2 sekundy wcześniejsze niż w IIS (np. `hostname`: 10:45:13 w Sysmonie, 10:45:15 w IIS). IIS zapisuje wpis dopiero po zakończeniu obsługi żądania, czyli po wykonaniu komendy i wysłaniu odpowiedzi. Do precyzyjnej chronologii lepiej opierać się na Sysmonie, a logi IIS traktować jako potwierdzenie kanału, którym przyszła komenda.

<img width="1920" height="869" alt="Zrzut ekranu (807)" src="https://github.com/user-attachments/assets/dd6b9816-aeea-4be0-aeeb-2f6762b19f61" />


### Krok 5 - Moment zapisania web shella na dysk (Sysmon Event ID 11)

```spl
index=win EventCode=11 TargetFilename="*error.aspx"
| table _time, Image, TargetFilename
```

| Czas | Image | TargetFilename |
|---|---|---|
| 10:40:33 | `c:\windows\system32\inetsrv\w3wp.exe` | `C:\inetpub\wwwroot\aspnet_client\system_web\error.aspx` |

Plik `error.aspx` został utworzony o **10:40:33** przez proces `w3wp.exe`, czyli przez samą aplikację webową, a nie przez użytkownika zalogowanego na serwerze.

<img width="1920" height="867" alt="Zrzut ekranu (808)" src="https://github.com/user-attachments/assets/9656432c-bc1f-491c-bad6-281ef09c4e42" />


### Krok 6 - Którędy plik trafił na serwer (żądanie POST)

```spl
index=iis cs_method=POST cs_uri_query="*error.aspx"
| table _time, c_ip, cs_uri_stem, cs_uri_query, sc_status
| sort _time
```

| Czas | c_ip | cs_uri_stem | cs_uri_query | sc_status |
|---|---|---|---|---|
| 10:40:33 | 198.51.100.23 | `/internalapp/upload.aspx` | `file=error.aspx` | 200 |

Żądanie POST do `/internalapp/upload.aspx` z parametrem `file=error.aspx` ma dokładnie ten sam czas co utworzenie pliku w Sysmonie (10:40:33). To potwierdza wektor wejścia: atakujący wgrał web shella przez formularz uploadu aplikacji `internalapp`. Formularz nie blokował plików wykonywalnych `.aspx` i zapisał plik w katalogu dostępnym z internetu.

<img width="1920" height="858" alt="Zrzut ekranu (809)" src="https://github.com/user-attachments/assets/dd2aaccb-2e79-4427-9e79-51081bbb6af5" />


---

## Oś czasu ataku

| Czas | Zdarzenie | Źródło |
|---|---|---|
| przed 10:40 | 21 odpowiedzi 404 z `198.51.100.23` - skanowanie katalogów | IIS |
| przed 10:40 | Odkrycie `/internalapp/`, `/internalapp/default.aspx`, `/internalapp/upload.aspx` | IIS |
| 10:40:33 | POST do `/internalapp/upload.aspx` z `file=error.aspx` - upload web shella | IIS |
| 10:40:33 | `w3wp.exe` zapisuje `C:\inetpub\wwwroot\aspnet_client\system_web\error.aspx` | Sysmon EID 11 |
| 10:45:13 | `w3wp.exe` uruchamia `csc.exe` - kompilacja `error.aspx` przy pierwszym wywołaniu | Sysmon EID 1 |
| 10:45:13 | `cmd.exe /c hostname` - **pierwsza komenda rekonesansu** | Sysmon EID 1 / IIS |
| 10:45:44 | `cmd.exe /c tasklist` | Sysmon EID 1 / IIS |
| 10:46:10 | `cmd.exe /c netstat -an` | Sysmon EID 1 / IIS |
| 10:46:26 | `cmd.exe /c dir C:\inetpub\wwwroot` | Sysmon EID 1 / IIS |
| 10:46:49 | `cmd.exe /c net group "Domain Admins" /domain` - rekonesans domeny AD | Sysmon EID 1 / IIS |

```
198.51.100.23
      |
      v
Skanowanie katalogów (21 x 404)
      |
      v
Odkrycie formularza /internalapp/upload.aspx
      |
      v
POST upload.aspx  (file=error.aspx)       10:40:33
      |
      v
w3wp.exe zapisuje error.aspx w aspnet_client\system_web   (EID 11)
      |
      v
GET error.aspx?cmd=...  ->  w3wp.exe  ->  cmd.exe /c ...  (EID 1)
      |
      +--> hostname
      +--> tasklist
      +--> netstat -an
      +--> dir C:\inetpub\wwwroot
      +--> net group "Domain Admins" /domain
```

---

## Komendy rekonesansu - co atakujący chciał się dowiedzieć

| Komenda | Co zwraca | Po co atakującemu | MITRE |
|---|---|---|---|
| `hostname` | Nazwę serwera | Potwierdzenie, że web shell działa, i identyfikacja maszyny | T1082 System Information Discovery |
| `tasklist` | Listę uruchomionych procesów | Sprawdzenie, czy działa antywirus/EDR i jakie usługi są na serwerze | T1057 Process Discovery |
| `netstat -an` | Otwarte porty i aktywne połączenia | Mapowanie sieci wewnętrznej i innych hostów, z którymi serwer rozmawia | T1049 System Network Connections Discovery |
| `dir C:\inetpub\wwwroot` | Zawartość katalogu aplikacji webowych | Szukanie plików konfiguracyjnych (np. `web.config` z hasłami do baz) i innych aplikacji | T1083 File and Directory Discovery |
| `net group "Domain Admins" /domain` | Członków grupy Domain Admins z kontrolera domeny | Wskazanie kont o najwyższych uprawnieniach w domenie jako celu dalszego ataku | T1069.002 Permission Groups Discovery: Domain Groups |

Kolejność komend pokazuje typowy schemat: najpierw "gdzie jestem" (host, procesy), potem "co jest wokół" (sieć, pliki), na końcu "kogo warto przejąć" (administratorzy domeny).

---

## Indicators of Compromise (IOC)

| Typ | Wartość | Opis |
|---|---|---|
| IP atakującego | `198.51.100.23` | Skanowanie, upload i sterowanie web shellem |
| Nazwa pliku web shella | `error.aspx` | Złośliwy plik ASP.NET, nazwa podszywa się pod stronę błędu |
| Ścieżka na dysku | `C:\inetpub\wwwroot\aspnet_client\system_web\error.aspx` | Domyślny katalog IIS, w którym nie powinno być kodu aplikacji |
| URI web shella | `/aspnet_client/system_web/error.aspx` | Endpoint, przez który przychodzą komendy |
| URI wektora uploadu | `/internalapp/upload.aspx` | Podatny formularz uploadu (brak walidacji typu pliku) |
| Parametr uploadu | `file=error.aspx` | Żądanie POST, które wgrało web shella |
| Parametr komend | `cmd=<komenda>` | Mechanizm przekazywania komend do web shella przez GET |
| Proces nadrzędny | `C:\Windows\System32\inetsrv\w3wp.exe` | IIS Worker Process zapisujący plik i uruchamiający `cmd.exe` |
| Proces potomny | `cmd.exe` | Powłoka wykonująca komendy atakującego |
| Czas uploadu | 2026-02-17 10:40:33 | Zgodny w IIS (POST) i Sysmonie (EID 11) |

---

## MITRE ATT&CK Mapping

| Taktyka | Technika | Opis | Dowód |
|---|---|---|---|
| Reconnaissance | T1595.003 Active Scanning: Wordlist Scanning | Skanowanie katalogów w poszukiwaniu istniejących stron | 21 x 404 z `198.51.100.23` (IIS) |
| Initial Access | T1190 Exploit Public-Facing Application | Wgranie pliku `.aspx` przez formularz uploadu bez walidacji typu pliku | POST `/internalapp/upload.aspx`, `file=error.aspx` (IIS) |
| Persistence | T1505.003 Server Software Component: Web Shell | `error.aspx` w katalogu `aspnet_client` daje trwały dostęp przez HTTP | `w3wp.exe` tworzy `error.aspx` (Sysmon EID 11) |
| Execution | T1059.003 Command and Scripting Interpreter: Windows Command Shell | `w3wp.exe` uruchamia `cmd.exe /c <komenda>` | 5 x `cmd.exe` z rodzicem `w3wp.exe` (Sysmon EID 1) |
| Discovery | T1082 System Information Discovery | Identyfikacja serwera | `cmd.exe /c hostname` |
| Discovery | T1057 Process Discovery | Sprawdzenie uruchomionych procesów i zabezpieczeń | `cmd.exe /c tasklist` |
| Discovery | T1049 System Network Connections Discovery | Mapowanie połączeń i otwartych portów | `cmd.exe /c netstat -an` |
| Discovery | T1083 File and Directory Discovery | Przegląd plików aplikacji webowych | `cmd.exe /c dir C:\inetpub\wwwroot` |
| Discovery | T1069.002 Permission Groups Discovery: Domain Groups | Rozpoznanie administratorów domeny AD | `cmd.exe /c net group "Domain Admins" /domain` |

---

## Wzorzec detekcji

Najmocniejszy pojedynczy sygnał w tym incydencie to **`w3wp.exe` jako proces nadrzędny dla `cmd.exe`** (albo `powershell.exe`). Legalne aplikacje IIS prawie nigdy nie uruchamiają powłoki systemowej. Jedyny wyjątek widoczny w tych logach, `csc.exe`, to kompilacja ASP.NET. Odróżnia ją to, co się uruchamia i z jakimi argumentami, a nie sam fakt, że `w3wp.exe` utworzył proces potomny.

Drugi sygnał to **utworzenie pliku `.aspx` przez `w3wp.exe`** (Sysmon EID 11), szczególnie w katalogu `aspnet_client`. Aplikacja webowa zapisująca nowe pliki wykonywalne w katalogu serwowanym z internetu to niemal zawsze upload web shella.

---

