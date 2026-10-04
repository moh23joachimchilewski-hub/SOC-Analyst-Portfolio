# Detekcja LSASS Credential Dump (CallTrace: dbgcore.dll / dbghelp.dll) - Sigma Rule

Reguła Sigma wykrywająca podejrzany dostęp do procesu `lsass.exe` z użyciem **MiniDump API** (biblioteki `dbgcore.dll` / `dbghelp.dll` w polu CallTrace). To klasyczna sygnatura zrzucania poświadczeń z pamięci LSASS narzędziami typu ProcDump czy comsvcs.dll. Napisana i testowana w ramach nauki SOC L2 / Internshipu.

## Kontekst

LSASS (`lsass.exe`) trzyma w pamięci poświadczenia zalogowanych użytkowników (hashe NTLM, bilety Kerberos). Atakujący, który zrzuci jego pamięć, dostaje te poświadczenia od razu, bez łamania. Detekcja opiera się na **Sysmon Event ID 10 (ProcessAccess)** - loguje on, gdy jeden proces otwiera uchwyt do innego. Gdy w polu `CallTrace` pojawiają się `dbgcore.dll` / `dbghelp.dll`, oznacza to użycie MiniDump API (metoda ProcDump / comsvcs.dll) - legalne API użyte w złośliwym celu. MITRE: **T1003.001 (OS Credential Dumping: LSASS Memory)**.

## Reguła (YAML)

```yaml
title: Potencjalny credentialds dump z użyciem LSASS
id: 944b2720-fd0d-49f8-8d53-c56c28d0e3f4
status: experimental
description: Sigma rule zbierająca podejrzane użycie LSASS z wykorzystaniem znanych DLL w CallTrace np. dbgcore.dll lub dbghelp.dll
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: Joachim
date: 2026/10/04
tags:
  - attack.credential-access
  - attack.t1003.001
logsource:
  category: process_access
  product: windows
detection:
  selection_target:
    TargetImage|endswith: '\lsass.exe'
  selection_calltrace:
    CallTrace|contains:
      - 'dbgcore.dll'
      - 'dbghelp.dll'
  filter_main_legit_tools:
    SourceImage|endswith:
      - '\csrss.exe'
      - '\svchost.exe'
      - '\WerFault.exe'
  condition: selection_target and selection_calltrace and not filter_main_legit_tools
falsepositives:
  - EDR/AV robiący legalny dump do analizy/skanu
level: high
```

**Logika:** proces docelowy to `lsass.exe` **ORAZ** CallTrace zawiera `dbgcore.dll`/`dbghelp.dll` (MiniDump) **ORAZ** proces źródłowy nie jest jednym ze znanych, legalnych procesów systemowych (`csrss.exe`, `svchost.exe`, `WerFault.exe`).

<img width="1920" height="796" alt="Zrzut ekranu (886)" src="https://github.com/user-attachments/assets/03ffbf3c-5b67-4504-8441-9ef1ef9efb29" />


<img width="1920" height="793" alt="Zrzut ekranu (887)" src="https://github.com/user-attachments/assets/c109d359-edda-404f-b53d-f49a7f77f5ed" />


## Generowanie ID reguły (uuidgen)

Pole `id` w regule Sigma musi być globalnie unikalnym UUID v4. Wygenerowałem je lokalnie komendą `uuidgen`:

```bash
uuidgen
944b2720-fd0d-49f8-8d53-c56c28d0e3f4
```

<img width="623" height="246" alt="Zrzut ekranu (885)" src="https://github.com/user-attachments/assets/c2a880ed-79c3-4dcd-8a85-5349b9650e8b" />


## Proces pracy

Reguła została napisana w **Visual Studio Code**, a następnie zwalidowana lokalnie przy pomocy `sigma-cli`:

```bash
sigma check sigma-lsass.yml
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

<img width="1920" height="730" alt="Zrzut ekranu (889)" src="https://github.com/user-attachments/assets/26dac726-82ee-4f2f-890b-e51d875f307a" />
<img width="1920" height="723" alt="Zrzut ekranu (890)" src="https://github.com/user-attachments/assets/9ca1ec55-424f-45ee-9a98-a8fd9376d707" />



## Konwersja na zapytania SIEM-owe

### a) Splunk (bez pipeline - surowe pola Sysmon)

```bash
sigma convert -t splunk --without-pipeline sigma-lsass.yml
```

```
TargetImage="*\\lsass.exe" CallTrace IN ("*dbgcore.dll*", "*dbghelp.dll*") NOT (SourceImage IN ("*\\csrss.exe", "*\\svchost.exe", "*\\WerFault.exe"))
```

### b) Elastic (EQL, pipeline: `ecs_windows`)

```bash
sigma convert -t eql -p ecs_windows sigma-lsass.yml
```

```
any where winlog.event_data.TargetImage:"*\\lsass.exe" and (winlog.event_data.CallTrace like~ ("*dbgcore.dll*", "*dbghelp.dll*")) and (not (process.executable like~ ("*\\csrss.exe", "*\\svchost.exe", "*\\WerFault.exe")))
```

<img width="1736" height="628" alt="Zrzut ekranu (892)" src="https://github.com/user-attachments/assets/6574a258-ec2c-4010-8737-6f9f5ce47631" />


## Problemy napotkane podczas pisania (do zapamiętania na przyszłość)

W przeciwieństwie do poprzedniej reguły (recon), tutaj sama składnia YAML była poprawna od razu (`sigma check` = 0 errors). Problemy pojawiły się dopiero na etapie **konwersji** i wynikały z **pipeline'ów**, a nie z samej reguły. Dowodem, że reguła jest poprawna, jest udana konwersja do EQL.

### Problem 1 - Splunk CIM nie wspiera `process_access`

```bash
sigma convert -t splunk -p splunk_cim sigma-lsass.yml
# Error: Rule type not yet supported by the Splunk data model CIM pipeline!
```

CIM (Common Information Model) w Splunku to zestaw predefiniowanych datamodeli (Authentication, Network_Traffic, Endpoint.Processes itd.). **Nie ma datamodelu dla process access** (Sysmon Event 10 - ProcessAccess, czyli `OpenProcess` na innym procesie), więc pipeline `splunk_cim` nie wie, jak zmapować regułę. 

**Rozwiązanie:** konwersja bez CIM, na surowe pola Sysmon:
```bash
sigma convert -t splunk --without-pipeline sigma-lsass.yml
```
To standardowe podejście dla danych Sysmon - większość analityków i tak odpytuje `index=sysmon EventCode=10` z natywnymi polami (`TargetImage`, `CallTrace`), nie przez CIM.

## Ściąga: dostępne targety (`-t`) w sigma-cli

Z komunikatu błędu wyszła przydatna lista backendów dostępnych w tej instalacji:

```
lucene, eql, esql, elastalert, kusto, splunk, splunk_spl2
```

## Wniosek

`sigma check` sprawdza tylko składnię reguły. Udana konwersja zależy dodatkowo od **pipeline'u** - czy dana kategoria (`process_access`) ma mapowanie w konkretnym backendzie. Rzadsze kategorie (jak Sysmon Event 10) nie mają gotowych mapowań wszędzie: czasem trzeba zrezygnować z warstwy normalizacji (CIM) na rzecz surowych pól (`--without-pipeline`), a czasem dopisać `EventID`, żeby backend wiedział, do jakiej tabeli trafić. Sama reguła była poprawna - potwierdza to bezproblemowa konwersja do EQL.
