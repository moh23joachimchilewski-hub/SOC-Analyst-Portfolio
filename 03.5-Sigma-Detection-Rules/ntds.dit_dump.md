# Detekcja ekstrakcji NTDS.dit (ntdsutil / vssadmin) - Sigma Rule

Reguła Sigma wykrywająca próbę kradzieży bazy Active Directory (`ntds.dit`) z kontrolera domeny za pomocą narzędzi `ntdsutil` (IFM) oraz `vssadmin` (Volume Shadow Copy). Napisana i testowana w ramach nauki SOC L2 / Internshipu.

## Kontekst

Plik `NTDS.dit` (`C:\Windows\NTDS\ntds.dit`) to baza Active Directory na kontrolerze domeny - zawiera hashe haseł **wszystkich** kont w domenie. Windows blokuje ten plik podczas pracy AD DS, więc atakujący obchodzą blokadę na dwa sposoby:

- **vssadmin** - tworzy migawkę dysku (Volume Shadow Copy), z której kopiuje `ntds.dit` i hive `SYSTEM` (potrzebny do odszyfrowania hashy).
- **ntdsutil IFM** - nadużywa funkcji Install From Media (legalnie służącej do promocji nowego kontrolera domeny), by wygenerować czystą kopię bazy.

Obie metody dają offline kopię bazy, z której narzędzia typu `secretsdump.py` wyciągają wszystkie hashe domeny. MITRE: **T1003.003 (OS Credential Dumping: NTDS)**.

## Reguła (YAML)

```yaml
title: Potencjalny credentialds dump z użyciem NTDS.dit
id: 3694f61d-9ef1-4e0c-8975-88a3e04d36be
status: experimental
description: Sigma rule wykrywająca próbę kopiowania bazy NTDS.dit z DC
references:
  - https://attack.mitre.org/techniques/T1003/003/
author: Joachim
date: 2026/10/04
tags:
  - attack.credential-access
  - attack.t1003.003
logsource:
  category: process_creation
  product: windows
detection:
  selection_ntdsutil:
    Image|endswith: '\ntdsutil.exe'
    CommandLine|contains|all:
      - 'ifm'
      - 'create'
  selection_vssadmin:
    Image|endswith: '\vssadmin.exe'
    CommandLine|contains: 'create shadow'
  condition: 1 of selection_*
falsepositives:
  - Legalny backup DC (kontrolera domeny) - oprogramowanie backupowe tworzy Volume shadow copy
  - Administrator DC wykonuje ntdsutil IFM przy promocji nowego DC
  - Planowane zadania konserwacyjne
  - Rozwiązania do recovery systemu/backup
level: high
```

**Logika:**
- `selection_ntdsutil` - proces `ntdsutil.exe` z linią komend zawierającą **jednocześnie** `ifm` **i** `create` (modyfikator `|all`, żeby nie łapać innych, niezłośliwych operacji `ntdsutil`).
- `selection_vssadmin` - proces `vssadmin.exe` tworzący Volume Shadow Copy (`create shadow`).
- `condition: 1 of selection_*` - alert, gdy wystąpi którakolwiek z metod.

<img width="1920" height="782" alt="Zrzut ekranu (894)" src="https://github.com/user-attachments/assets/28215b99-2b6e-4bbc-9157-7516233cc471" />


<img width="1920" height="802" alt="Zrzut ekranu (895)" src="https://github.com/user-attachments/assets/1172666a-d440-4077-a6d4-26c21d932dd4" />


## Generowanie ID reguły (uuidgen)

Pole `id` to globalnie unikalny UUID v4, wygenerowany lokalnie:

```bash
uuidgen
3694f61d-9ef1-4e0c-8975-88a3e04d36be
```

<img width="1009" height="160" alt="Zrzut ekranu (893)" src="https://github.com/user-attachments/assets/b4f5a7d7-f117-4e5c-a587-c7bb886fd2d2" />


## Proces pracy

Reguła napisana w **Visual Studio Code**, zwalidowana lokalnie przy pomocy `sigma-cli`:

```bash
sigma check sigma-creddump.yml
```

Wynik walidacji:

```
Parsing Sigma rules  [####################################]  100%
Checking Sigma rules  [####################################]  100%

=== Summary ===
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

<img width="926" height="763" alt="Zrzut ekranu (897)" src="https://github.com/user-attachments/assets/0ea6483d-39ca-4a6f-80fb-a59bf674aaf1" />
<img width="1209" height="718" alt="Zrzut ekranu (898)" src="https://github.com/user-attachments/assets/1d1d6645-6994-4f6d-a16f-3c2a8021ff86" />


## Konwersja na zapytania SIEM-owe

Tym razem konwersja poszła gładko na **wszystkie trzy backendy** - w przeciwieństwie do reguły LSASS (`process_access`), kategoria `process_creation` ma pełne wsparcie pipeline'ów, więc CIM i Kusto zadziałały bez błędów.

### a) Splunk (pipeline: `splunk_cim`)

```bash
sigma convert -t splunk -p splunk_cim sigma-creddump.yml
```

```
(Processes.process_path="*\\ntdsutil.exe" Processes.process="*ifm*" Processes.process="*create*") OR (Processes.process_path="*\\vssadmin.exe" Processes.process="*create shadow*")
```

### b) Microsoft XDR (Kusto / KQL, pipeline: `microsoft_xdr`)

```bash
sigma convert -t kusto -p microsoft_xdr sigma-creddump.yml
```

```
DeviceProcessEvents
| where (FolderPath endswith "\\ntdsutil.exe" and (ProcessCommandLine contains "ifm" and ProcessCommandLine contains "create")) or (FolderPath endswith "\\vssadmin.exe" and ProcessCommandLine contains "create shadow")
```

### c) Elastic (EQL, pipeline: `ecs_windows`)

```bash
sigma convert -t eql -p ecs_windows sigma-creddump.yml
```

```
any where (process.executable:"*\\ntdsutil.exe" and (process.command_line:"*ifm*" and process.command_line:"*create*")) or (process.executable:"*\\vssadmin.exe" and process.command_line:"*create shadow*")
```

<img width="1920" height="610" alt="Zrzut ekranu (899)" src="https://github.com/user-attachments/assets/71f8918e-f9e9-40e7-ae5a-7b19e4150549" />


## MITRE ATT&CK

| Taktyka | Technika | Opis |
|---|---|---|
| Credential Access | T1003.003 - OS Credential Dumping: NTDS | Kopiowanie bazy `ntds.dit` z DC przez ntdsutil IFM lub vssadmin shadow copy |

## Uwagi do reguły (do zapamiętania)

- **Modyfikator `|all` jest tu kluczowy.** W `selection_ntdsutil` lista pod `CommandLine|contains` domyślnie działa jak OR. Samo `create` jest bardzo ogólne (`ntdsutil` ma wiele operacji z `create`), więc bez `|all` reguła łapałaby też niezłośliwe użycia. `|all` wymusza obecność **obu** słów (`ifm` ORAZ `create`) w jednej linii komend.
- **Dlaczego nie ma bloku `filter_` jak w regule LSASS.** W LSASS dało się odfiltrować legalne procesy (`csrss`, `svchost`), bo legalne i złośliwe użycie to były różne procesy. Tutaj legalne i złośliwe użycie to **ta sama komenda** (`ntdsutil ifm create` robi i admin przy promocji DC, i atakujący przy kradzieży). Nie da się ich rozdzielić polem - rozróżnia je kontekst (kto, kiedy, dokąd trafił plik, co było potem), a nie wartość w logu. Dlatego false positives zostają jako dokumentacja dla analityka, nie jako filtr w silniku.
- **Najważniejszy false positive: ntdsutil IFM przy promocji nowego DC.** Admin stawiający kolejny kontroler domeny używa dokładnie tej samej komendy. Przy triażu trzeba sprawdzić: czy faktycznie stawiano wtedy DC, kto uruchomił, dokąd trafił plik (standardowa ścieżka vs `C:\temp`), czy potem kopiowano bazę dalej lub uruchamiano `secretsdump`.
- **vssadmin `create shadow`** ma też legalne zastosowania (backup) - to normalne zachowanie oprogramowania backupowego. Sygnałem ataku jest dopiero to, co dzieje się dalej (kopiowanie `ntds.dit` + hive `SYSTEM` z shadow copy).

## Wniosek

Reguła jest poprawna składniowo (`sigma check` = 0 errors) i konwertuje się bezproblemowo na wszystkie trzy backendy, bo oparta jest na dobrze wspieranej kategorii `process_creation`. Wykrywa obie główne metody ekstrakcji NTDS.dit. Jej ograniczeniem (świadomym) jest to, że nie da się odfiltrować legalnego IFM/backupu regułą - te przypadki rozstrzyga analityk kontekstem podczas triażu.
