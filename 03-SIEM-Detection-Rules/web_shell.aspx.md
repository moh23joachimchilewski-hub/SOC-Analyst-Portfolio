# Detekcja Deploymentu Web Shella - Analiza w Splunk (IIS + Sysmon)

Analiza incydentu polegającego na wykryciu web shella wgranego na serwer IIS (prawdopodobnie Exchange, na podstawie ścieżek `/owa/`, `/ecp/`) oraz odtworzenie pełnego łańcucha ataku - od skanowania, przez upload, po wykonanie komend rekonesansu - na podstawie logów IIS i Sysmon w Splunku.

## Kontekst

Web shell to złośliwy skrypt (w środowisku IIS najczęściej `.aspx`), który po umieszczeniu na serwerze pozwala atakującemu wykonywać dowolne komendy systemowe przez zwykłe żądania HTTP. Web shelle przetrwają restart serwera, komunikują się przez standardowe porty webowe (80/443) i nie wymagają dodatkowych narzędzi ze strony atakującego - jedynie przeglądarki lub `curl`.

Przykład realnych kampanii wykorzystujących ten wzorzec: HAFNIUM (marzec 2021, ProxyLogon, China Chopper `.aspx` w `C:\inetpub\wwwroot\aspnet_client\`) oraz atak na serwery IIS administracji USA w 2023 (podatność Telerik UI) - różne podatności wejściowe, ten sam wzorzec detekcji końcowej.

## 5W's

| Pytanie | Odpowiedź |
|---|---|
| **Who** (kto) | Atakujący posługujący się adresem IP `203.0.113.47` |
| **What** (co) | Wgranie i wykorzystanie web shella `shell.aspx` do zdalnego wykonywania komend systemowych na serwerze IIS |
| **When** (kiedy) | 2026-02-12, aktywność skoncentrowana ok. 10:43-10:45 (deployment + wykonanie komend rekonesansu) |
| **Where** (gdzie) | Serwer IIS, plik umieszczony w `C:\inetpub\wwwroot\aspnet_client\system_web\shell.aspx` - domyślny katalog ASP.NET, który nigdy nie powinien zawierać kodu aplikacji |
| **Why** (po co) | Uzyskanie trwałego zdalnego dostępu do serwera w celu przeprowadzenia rekonesansu systemu i środowiska (identity, network, users, privileges) jako przygotowanie do dalszych działań (lateral movement / eskalacja) |

## Indicators of Compromise (IOC)

| Typ IOC | Wartość | Opis |
|---|---|---|
| IP źródłowe (atakujący) | `203.0.113.47` | Adres wykonujący skanowanie (404) oraz interakcję z web shellem |
| Nazwa pliku web shella | `shell.aspx` | Złośliwy plik ASP.NET umożliwiający RCE |
| Ścieżka pliku na dysku | `C:\inetpub\wwwroot\aspnet_client\system_web\shell.aspx` | Nietypowa lokalizacja - domyślny katalog klienta ASP.NET |
| URI web shella | `/aspnet_client/system_web/shell.aspx` | Endpoint HTTP wykorzystywany do wysyłania komend |
| Proces nadrzędny (parent) | `w3wp.exe` (`C:\Windows\System32\inetsrv\w3wp.exe`) | Worker process IIS, który nie powinien spawnować `cmd.exe` |
| Proces potomny | `cmd.exe` | Powłoka wywoływana przez web shell w celu wykonania komend OS |
| Parametr HTTP | `cs_uri_query=cmd=<komenda>` | Mechanizm przekazywania komend do web shella przez GET |
| Inne odkryte przez atakującego ścieżki | `/owa/auth/logon.aspx`, `/internalapp/upload.aspx`, `/internalapp/default.aspx`, `/ecp/` | Wynik skanowania katalogów - wskazuje na środowisko Exchange (OWA/ECP) |
| Liczba prób skanowania (404) | 114 zdarzeń z jednego IP | Sygnatura directory/path scannera przed właściwym atakiem |

## Rekonstrukcja łańcucha ataku (Timeline)

| Czas | Zdarzenie | Źródło |
|---|---|---|
| przed 10:43 | 114 żądań HTTP zakończonych `404` z IP `203.0.113.47` - skanowanie katalogów w poszukiwaniu zapisywalnych ścieżek | IIS (`sc_status=404`) |
| przed 10:43 | Żądania `200` z tego samego IP ujawniają m.in. `/aspnet_client/system_web/shell.aspx`, `/internalapp/upload.aspx`, `/owa/auth/logon.aspx` | IIS (`sc_status=200`) |
| 10:43:18 | Utworzenie pliku `shell.aspx` na dysku przez proces `w3wp.exe` | Sysmon EventID 11 (FileCreate) |
| 10:44:12 | `w3wp.exe` spawnuje `csc.exe` (kompilator C#) - pierwsze wywołanie `.aspx` powoduje jego kompilację JIT przez ASP.NET (zachowanie samo w sobie normalne dla nowego pliku `.aspx`) | Sysmon EventID 1 |
| 10:44:15 | `w3wp.exe` -> `cmd.exe /c whoami` - **pierwsza komenda rekonesansu wykonana przez atakującego** | Sysmon EventID 1 / IIS `cs_uri_query=cmd=whoami` |
| 10:44:29 | `w3wp.exe` -> `cmd.exe /c ipconfig` | Sysmon EventID 1 |
| 10:44:41 | `w3wp.exe` -> `cmd.exe /c net user` | Sysmon EventID 1 |
| 10:44:58 | `w3wp.exe` -> `cmd.exe /c net localgroup administrators` | Sysmon EventID 1 |
| 10:45:10 | `w3wp.exe` -> `cmd.exe /c dir C:\Users` | Sysmon EventID 1 |
| 10:45:20 | `w3wp.exe` -> `cmd.exe /c systeminfo` | Sysmon EventID 1 |

**Obserwacja:** wszystkie żądania HTTP w logach IIS (`cs_uri_query`) mają ten sam znacznik czasu (10:44:15), podczas gdy Sysmon pokazuje rzeczywiste, rozłożone w czasie momenty wykonania komend. To typowa rozbieżność wynikająca z buforowania logów IIS i opóźnień sieciowych - do precyzyjnej rekonstrukcji chronologii zawsze lepiej opierać się na zdarzeniach endpointowych (Sysmon/Security), a logi IIS traktować jako potwierdzenie kanału dostarczenia komendy.

## Zapytania SPL użyte w dochodzeniu

**Krok 1 - identyfikacja skanowania katalogów:**
```spl
index=iis sc_status=404
| stats count by c_ip
| sort - count
```
<img width="1920" height="856" alt="Zrzut ekranu (776)" src="https://github.com/user-attachments/assets/204bbc41-87ef-4e51-adb0-ff90b387bb7c" />


**Krok 2 - co odkrył atakujący (żądania zakończone sukcesem z podejrzanego IP):**
```spl
index=iis c_ip=203.0.113.47 sc_status=200
| stats count by cs_uri_stem
| sort - count
```
<img width="1920" height="863" alt="Zrzut ekranu (777)" src="https://github.com/user-attachments/assets/589e4f7a-8eb8-4159-b3d2-8a0ef49aabf7" />


**Krok 3a - aktywność na samym web shellu:**
```spl
index=iis cs_uri_stem="*/shell.aspx"
| table _time, c_ip, cs_method, cs_uri_query, sc_status
| sort _time
```
<img width="1920" height="859" alt="Zrzut ekranu (775)" src="https://github.com/user-attachments/assets/775102f9-32f1-48a5-a7df-11a942b956f7" />


**Krok 3b - łańcuch procesów spawnowanych przez w3wp.exe:**
```spl
index=win EventCode=1 ParentImage="*\\w3wp.exe"
| table _time, ParentImage, CommandLine
| sort _time
```
<img width="1920" height="862" alt="Zrzut ekranu (778)" src="https://github.com/user-attachments/assets/5ff375a0-b666-4072-870b-853e9df1ace5" />


**Krok 4 - moment zapisania pliku web shella na dysku:**
```spl
index=win EventCode=11 TargetFilename="*shell.aspx"
| table _time, Image, TargetFilename
```
<img width="1920" height="858" alt="Zrzut ekranu (779)" src="https://github.com/user-attachments/assets/9d1f0a37-4b47-4fdc-983a-942b5dc39020" />


## Wzorzec detekcji (Core Detection Pattern)

W normalnej pracy IIS proces `w3wp.exe` obsługuje żądania HTTP i generuje odpowiedzi **bez** uruchamiania innych procesów. Gdy `w3wp.exe` zaczyna spawnować `cmd.exe`, `powershell.exe` lub inne narzędzia systemowe, które nie są typowe dla działania aplikacji webowej, jest to niemal zawsze sygnał do dalszego dochodzenia - legalne aplikacje IIS rzadko potrzebują uruchamiać powłoki systemowej.

**Uwaga:** niektóre legalne aplikacje .NET powodują, że `w3wp.exe` spawnuje `csc.exe` (kompilator C#) - to normalne zachowanie przy pierwszym wywołaniu strony `.aspx` (kompilacja JIT). Czynnikiem odróżniającym złośliwą aktywność nie jest sam fakt spawnowania procesu potomnego, lecz **jakie konkretnie komendy są wykonywane**.
