# Raport: zdalne uruchomienie ransomware przez WMIC (task5)

**Ocena:** próba wdrożenia ransomware na 6 hostach przez WMIC. W dostępnych logach brak dowodu uruchomienia `fixer.exe` na hostach docelowych (Sysmon EID 1, Process Create).

---

## 1. Podsumowanie

Z kontrolera domeny **DC-01** przejęte konto domenowe wykonało 6 poleceń `wmic ... process call create C:\Windows\fixer.exe`, kolejno na hostach `tsm-prod-01` do `tsm-prod-06`. Polecenia zawierały jawnie podane poświadczenia. Wcześniej, o 11:19:58, plik `C:\Windows\fixer.exe` został utworzony na `TSM-PROD-01` przez 32-bitowy PowerShell. Zapytanie o uruchomienie procesu `fixer.exe` (Sysmon EID 1) nie zwróciło żadnych zdarzeń.

---

## 2. 5W

| Pytanie | Odpowiedź |
|---|---|
| **Who** (kto) | Atakujący na przejętym koncie domenowym `TRYSAVEME\maria.garcia`. Procesem nadrzędnym poleceń jest `C:\Users\maria.garcia\AppData\Roaming\updater.exe` (spójne z wcześniejszym alertem o `updater.exe` na DC-01). |
| **What** (co) | Zdalne uruchomienie `C:\Windows\fixer.exe` przez `wmic process call create` (T1047). |
| **When** (kiedy) | 2026-02-20. Plik `fixer.exe` utworzony na TSM-PROD-01 o **11:19:58**. Polecenia WMIC od **11:31:50** do **11:32:29** (godziny jak w Splunku, strefa nie jest podana). |
| **Where** (gdzie) | Źródło: `DC-01.trysaveme.local`. Cele: `tsm-prod-01` ... `tsm-prod-06` (`.trysaveme.local`). |
| **Why** (dlaczego) | Hipoteza: wdrożenie ransomware przed szyfrowaniem (etap poprzedzający szyfrowanie). Skutków szyfrowania w logach nie zweryfikowano. |
| **How** (jak) | `cmd.exe /C wmic /node:<host> /user:<konto> /password:<ukryte> process call create C:\Windows\fixer.exe` uruchamiane z DC-01. |

---

## 3. Oś czasu

| Czas (Splunk) | Host | Zdarzenie |
|---|---|---|
| 2026-02-20 11:19:58 | TSM-PROD-01 | EID 11: `powershell.exe` (SysWOW64) tworzy `C:\Windows\fixer.exe` jako `TRYSAVEME\maria.garcia` |
| 11:31:50 | DC-01 | WMIC → `tsm-prod-01` |
| 11:31:56-57 | DC-01 | WMIC → `tsm-prod-02` |
| 11:32:01 | DC-01 | WMIC → `tsm-prod-03` |
| 11:32:09 | DC-01 | WMIC → `tsm-prod-04` |
| 11:32:16 | DC-01 | WMIC → `tsm-prod-05` |
| 11:32:29 | DC-01 | WMIC → `tsm-prod-06` |

---

## 4. Filtry Splunk i wnioski

### 4.1 Gdzie powstał plik ransomware (host TSM-PROD-01)

```
index=task5 EventCode=11 ComputerName="TSM-PROD-01*"
| table _time, ComputerName, Image, TargetFilename, User
```
<img width="1920" height="935" alt="Zrzut ekranu (1072)" src="https://github.com/user-attachments/assets/5e42c70b-c68d-4223-81d8-52991ee78f31" />

**Wynik:** 1 zdarzenie. `TargetFilename = C:\Windows\fixer.exe`, `Image = c:\windows\syswow64\windowspowershell\v1.0\powershell.exe`, `User = TRYSAVEME\maria.garcia`, 2026-02-20 11:19:58.
**Wniosek:** plik z payloadem znajdował się w `C:\Windows` na TSM-PROD-01 i został utworzony przez PowerShell na koncie `maria.garcia`. Samo utworzenie pliku nie dowodzi jego uruchomienia.

### 4.2 Jak plik został uruchomiony (metoda)

```
index=task5 EventCode=1 CommandLine="*fixer.exe*"
| table _time, ComputerName, User, ParentImage, CommandLine
| sort _time
```
<img width="1920" height="930" alt="Zrzut ekranu (1073)" src="https://github.com/user-attachments/assets/57b9fb3c-2800-4504-a90b-7c5a72d8403d" />
<img width="1920" height="928" alt="Zrzut ekranu (1074)" src="https://github.com/user-attachments/assets/8e8443bc-e6ee-4186-ae28-b0b39dd285e2" />


**Wynik:** 12 zdarzeń, wszystkie na `DC-01`, konto `maria.garcia`. Dla każdego hosta docelowego pojawiają się **dwa** zdarzenia:
1. `cmd.exe /C wmic /node:... process call create C:\Windows\fixer.exe` (rodzic: `...\AppData\Roaming\updater.exe`),
2. `wmic /node:... process call create C:\Windows\fixer.exe` (rodzic: `cmd.exe`).

**Wniosek:** to metoda **WMIC (WMI), T1047**. Łańcuch: `updater.exe` → `cmd.exe` → `wmic.exe` → zdalny host. Hasło jest podane w parametrach polecenia (jawnym tekstem w logu).

### 4.3 Ile systemów było celem

```
index=task5 EventCode=1 CommandLine="*wmic*" CommandLine="*process call create*" CommandLine="*fixer.exe*"
| stats count by CommandLine
```
<img width="1920" height="932" alt="Zrzut ekranu (1075)" src="https://github.com/user-attachments/assets/dc8e3298-76ba-4190-93c9-bfc3b6df6dfd" />

**Wynik:** 12 wierszy, każdy z `count = 1`.
**Wniosek:** unikalnych hostów jest **6** (`tsm-prod-01` do `tsm-prod-06`), a nie 12. Każdy host występuje dwa razy: raz w poleceniu opakowanym w `cmd.exe /C`, raz w samym `wmic`. Liczba wierszy w `stats count by CommandLine` **nie** równa się liczbie hostów, gdy to samo polecenie jest zalogowane przez dwa procesy.

### 4.4 Czy ransomware uruchomiono

```
index=task5 EventCode=1 Image="*fixer.exe"
| stats count by ComputerName
```
<img width="1920" height="933" alt="Zrzut ekranu (1076)" src="https://github.com/user-attachments/assets/0b6ab9c6-bb79-4c94-b259-d676585e659b" />

**Wynik:** 0 zdarzeń ("No results found").
**Wniosek:** w indeksie nie ma procesu `fixer.exe` utworzonego na żadnym hoście (brak EID 1 z `Image` zakończonym na `fixer.exe`). W logach nie ma więc dowodu skutecznego uruchomienia. Atakujący **próbował** wykonać plik na 6 hostach.

---

## 5. IOC

| Typ | Wartość |
|---|---|
| Plik (payload) | `C:\Windows\fixer.exe` (hash niedostępny w użytych zdarzeniach) |
| Plik (proces macierzysty poleceń) | `C:\Users\maria.garcia\AppData\Roaming\updater.exe` |
| Konto | `TRYSAVEME\maria.garcia` (domenowe, wykorzystane do WMI) |
| Host źródłowy | `DC-01.trysaveme.local` |
| Hosty docelowe | `tsm-prod-01` do `tsm-prod-06` (`.trysaveme.local`) |
| Wzorzec polecenia | `wmic /node:<host> /user:<konto> /password:<haslo> process call create C:\Windows\fixer.exe` |
| Proces tworzący plik | `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` (TSM-PROD-01) |

---

## 6. MITRE ATT&CK

| ID | Technika | Dowód |
|---|---|---|
| **T1047** | Windows Management Instrumentation | `wmic ... process call create` na hostach zdalnych |
| T1078.002 | Valid Accounts: Domain Accounts | użycie konta `TRYSAVEME\maria.garcia` |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | `cmd.exe /C wmic ...` |
| T1059.001 | Command and Scripting Interpreter: PowerShell | `powershell.exe` tworzy `fixer.exe` na TSM-PROD-01 |
| T1486 | Data Encrypted for Impact | **cel prawdopodobny, nie zaobserwowany** w logach |

---

## 7. Kontekst: WMIC i `wmiprvse.exe`

- **WMIC** (`wmic.exe`) to narzędzie wiersza poleceń do WMI. Parametr `/node:<host>` kieruje polecenie na zdalny komputer, a `process call create <plik>` uruchamia na nim proces. Wymaga uprawnień administracyjnych na celu (tu: poświadczenia podane w `/user` i `/password`).
- Atakujący lubią WMI, bo nie wymaga wgrywania agenta, korzysta z narzędzi Windows (living off the land) i działa przez RPC/DCOM (porty 135 i dynamiczne).
- **`wmiprvse.exe`** (WMI Provider Host) to proces, który na **hoście docelowym** faktycznie tworzy proces zlecony przez WMI. Dlatego na celu udane `process call create` zwykle wygląda tak: `ParentImage = ...\wmiprvse.exe` → `Image = <uruchamiany plik>` (Sysmon EID 1).
- Po stronie **źródła** (tu DC-01) widać tylko samo polecenie `wmic` (EID 1) i połączenia sieciowe (EID 3), a po stronie **celu** `wmiprvse.exe` jako rodzica. Stąd wniosek: o skuteczności decydują logi z hostów docelowych.
- `ReturnValue = 0` w wyjściu `wmic` oznacza poprawne utworzenie procesu, ale to wynik widoczny w konsoli, nie w Sysmonie.
