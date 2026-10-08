# Analiza incydentu lateral movement - przemianowany PsExec (serwis `svcupdate`) na THM-SHR-SRV

> **Platforma:** Splunk
> **Źródła logów:** System (`index=challenge`, Event 7045), Security (Event 5140, 5145), Sysmon (Event 1)
> **Typ zdarzenia:** Lateral Movement / Remote Service Execution
> **Severity:** High
> **MITRE ATT&CK:** T1021.002, T1569.002, T1570

---

## Podsumowanie

Zespół SOC dostał alert z EDR o instalacji podejrzanego serwisu `svcupdate` na serwerze `THM-SHR-SRV`. Nazwa serwisu nie pasowała do żadnego znanego wdrożenia, a na ten wieczór nie było zgłoszonych żadnych zaplanowanych zmian w infrastrukturze (change requestów) - czyli nikt z IT nie zlecił tej instalacji.

Analiza wykazała **lateral movement techniką PsExec ze zmienioną nazwą binarki**. Atakujący, posługując się przejętym kontem `ryan.chen`, połączył się z udziału `ADMIN$` serwera `THM-SHR-SRV` z adresu `10.5.50.15`, wgrał binarkę serwisu `svcupdate.exe` do `C:\Windows`, zainstalował z niej serwis działający jako `LocalSystem` i wykonał przez niego zdalne komendy rozpoznania. Nazwy named pipe'ów zdradziły maszynę źródłową: **THM-HR-WS**.

To klasyczny PsExec, ale z serwisem nazwanym `svcupdate` zamiast domyślnego `PSEXESVC` - czyli próba ominięcia detekcji opartej na nazwie. Sygnatura **user mode service + demand start** oraz schemat nazw pipe'ów zdemaskowały atak mimo zmiany nazwy.

---

## Kontekst

### Czym jest PsExec i dlaczego zostawia ślad

PsExec to legalne narzędzie Sysinternals do uruchamiania komend na zdalnych maszynach. Łączy dostęp do udziału `ADMIN$` przez SMB z instalacją serwisu Windows - i dzięki temu wykonuje kod zdalnie. Pod spodem zawsze robi to samo:

1. łączy się z `ADMIN$` celu przez SMB (port 445),
2. kopiuje binarkę serwisu do `C:\Windows`,
3. tworzy i startuje nowy serwis -> **Event 7045**,
4. serwis tworzy named pipes (stdin/stdout/stderr) -> **Sysmon Event 17**,
5. serwis wykonuje komendę atakującego -> **Sysmon Event 1** (`ParentImage` = binarka serwisu),
6. po sesji czyści serwis i binarkę.

### Dlaczego nazwa `svcupdate` nie uchroniła atakującego

Domyślnie serwis PsExec nazywa się `PSEXESVC`. Flaga `-r` pozwala go przemianować (tu na `svcupdate`), a narzędzia typu Impacket generują losowe nazwy. Ale **Event 7045 odpala niezależnie od nazwy**, a sam serwis zawsze ma te same cechy:

- `Service_Type` = **user mode service**,
- `Service_Start_Type` = **demand start**.

To jest sygnatura, której szuka się zamiast nazwy. Dodatkowo named pipe'y PsExec zachowują schemat `<nazwa>-<hostname_źródła>-<pid>-stdin/stdout/stderr` - i to właśnie one zdradziły maszynę źródłową.

---
 
## Użyte Event ID (ściąga)
 
| Event ID | Źródło logu | Znaczenie | Rola w tym incydencie |
|---|---|---|---|
| **7045** | System | A New Service Was Installed | sygnatura PsExec - serwis `svcupdate`, user mode service + demand start, LocalSystem |
| **5140** | Security | A network share object was accessed | dostęp do `ADMIN$` z `10.5.50.15` kontem `ryan.chen` |
| **5145** | Security | Detailed File Share | nazwy named pipe'ów (`svcupdate-THM-HR-WS-5104-*`) zdradzające host źródłowy |
| **1** (Sysmon) | Sysmon | Process Creation | komendy odpalone przez serwis (`ParentImage=svcupdate.exe`) |
 
---

## 5W

| Pytanie | Odpowiedź |
|---|---|
| **Who** (kto) | Przejęte konto `ryan.chen`, operujące z maszyny `THM-HR-WS` (`10.5.50.15`) |
| **What** (co) | Lateral movement przez PsExec z przemianowanym serwisem `svcupdate`; zdalne wykonanie komend rozpoznania jako `LocalSystem` |
| **When** (kiedy) | 2026-03-06, ok. 06:43:37 - 06:44:03 (dwie fale: pierwsza komenda 06:43:39, druga 06:44:03) |
| **Where** (gdzie) | Cel: `THM-SHR-SRV`; binarka `C:\Windows\svcupdate.exe`; dostęp przez `ADMIN$` |
| **Why** (po co) | Rozpoznanie przejętego hosta (`hostname`, `whoami`, `ipconfig`) i lokalnych administratorów - przygotowanie do dalszego ruchu w sieci |

---

## Przebieg analizy

### Krok 1 - Potwierdzenie instalacji serwisu (Event 7045)

Zaczynamy od sygnału z alertu: instalacji serwisu. Event 7045 (A New Service Was Installed) to sygnatura PsExec na maszynie docelowej.

```spl
index=challenge EventCode=7045
| table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Service_Account
| sort _time
```

**Co ujawnił:** dwa serwisy `svcupdate` na `THM-SHR-SRV`, binarka `%SystemRoot%\svcupdate.exe`, konto `LocalSystem`. Oba z `Service_Type = user mode service` i `Service_Start_Type = demand start` - **sygnatura PsExec mimo nienaturalnej nazwy** (`svcupdate` nie jest domyślnym `PSEXESVC`). `LocalSystem` oznacza użycie flagi `-s`, czyli wykonanie jako SYSTEM.

> Ustalono: pełna ścieżka binarki serwisu to `%SystemRoot%\svcupdate.exe`.

<img width="1920" height="621" alt="Zrzut ekranu (912)" src="https://github.com/user-attachments/assets/f9ae0c36-72c1-45c5-8709-448885457c8e" />


---

### Krok 2 - Kto i skąd dotknął ADMIN$ (Event 5140)

Skoro PsExec używa `ADMIN$`, sprawdzamy dostęp do udziałów administracyjnych na celu.

```spl
index=challenge EventCode=5140 Share_Name IN ("*\\ADMIN$\*", "*\\C$\*")
| table _time, host, Source_Address, user, Share_Name
| sort _time
```

**Co ujawnił:** dostęp do `ADMIN$` na `THM-SHR-SRV` z adresu `10.5.50.15`, konto `ryan.chen`. Jedno konto, jedno źródłowe IP, udział administracyjny - wzorzec lateral movement.

> Ustalono: konto `ryan.chen`, źródłowy adres IP `10.5.50.15`.

<img width="1920" height="690" alt="Zrzut ekranu (913)" src="https://github.com/user-attachments/assets/47f928f3-b95c-435e-b54a-db69ec92eae3" />


---

### Krok 3 - Jakie komendy odpalił serwis (Sysmon Event 1)

Binarka serwisu (`svcupdate.exe`) jest rodzicem wszystkich zdalnie odpalonych komend. Filtrujemy po `ParentImage`.

```spl
index=challenge EventCode=1 host=THM-SHR-SRV ParentImage="*svcupdate*"
| table _time, host, User, ParentImage, Image, CommandLine
| sort _time
```

**Co ujawnił:** `C:\Windows\svcupdate.exe` jako rodzic procesów `cmd.exe`, uruchamianych przez `ryan.chen`. Pierwsza komenda (06:43:39) to `"cmd" /c "hostname & whoami & ipconfig"` - typowy rozpoznawczy one-liner (kim jestem, na jakim hoście, jaka sieć). Druga fala (06:44:03) to `"cmd" /c "net localgroup administrators"` - enumeracja lokalnych adminów.

> Ustalono: pierwsza zdalna komenda to `"cmd" /c "hostname & whoami & ipconfig"`.

<img width="1920" height="860" alt="Zrzut ekranu (915)" src="https://github.com/user-attachments/assets/06362685-9f3b-4503-a72a-ee5b71c43ea8" />


---

### Krok 4 - Ustalenie maszyny źródłowej (Event 5145)

Named pipe'y PsExec zawierają w nazwie hostname maszyny źródłowej. Event 5145 (Detailed File Share) loguje konkretne obiekty dotknięte przez udział.

```spl
index=challenge EventCode=5145 user=ryan.chen Relative_Target_Name="*svcupdate*"
| table _time, user, Source_Address, Share_Name, Relative_Target_Name
| sort _time
```

**Co ujawnił:** dostęp z `10.5.50.15` do `ADMIN$` i `IPC$`, a w polu `Relative_Target_Name` nazwy pipe'ów: `svcupdate-THM-HR-WS-5104-stderr`, `-stdout`, `-stdin`. Schemat `<serwis>-<HOSTNAME_ŹRÓDŁA>-<pid>-std*` jednoznacznie wskazuje maszynę źródłową: **THM-HR-WS**.

> Ustalono: maszyna źródłowa to `THM-HR-WS`. Nawet gdyby atakujący przemianował binarkę, schemat nazw pipe'ów i tak zdradza hosta źródłowego.

<img width="1920" height="863" alt="Zrzut ekranu (916)" src="https://github.com/user-attachments/assets/f76423b5-cfeb-4890-b017-a45f7d71d5f2" />


---

## Oś czasu

| Czas (2026-03-06) | Zdarzenie | Event | Dowód |
|---|---|---|---|
| 06:43:37 | Dostęp do `ADMIN$` na THM-SHR-SRV z 10.5.50.15 (`ryan.chen`) | 5140 / 5145 | pierwszy kontakt SMB |
| 06:43:38 | Instalacja serwisu `svcupdate` (`%SystemRoot%\svcupdate.exe`, LocalSystem) | 7045 | sygnatura PsExec |
| 06:43:39 | Pierwsza komenda: `"cmd" /c "hostname & whoami & ipconfig"` | Sysmon 1 | `ParentImage=svcupdate.exe` |
| 06:44:02 | Druga instalacja serwisu `svcupdate` | 7045 | druga fala |
| 06:44:03 | Druga komenda: `"cmd" /c "net localgroup administrators"` | Sysmon 1 | enumeracja adminów |

**Źródło:** THM-HR-WS (10.5.50.15) ---PsExec/SMB---> **Cel:** THM-SHR-SRV, konto `ryan.chen`.

---

## MITRE ATT&CK

| Technika | ID | Gdzie w incydencie |
|---|---|---|
| Remote Services: SMB/Windows Admin Shares | T1021.002 | dostęp do `ADMIN$` (5140/5145) |
| System Services: Service Execution | T1569.002 | serwis `svcupdate` (7045) |
| Lateral Tool Transfer | T1570 | kopia `svcupdate.exe` na `ADMIN$` celu |
