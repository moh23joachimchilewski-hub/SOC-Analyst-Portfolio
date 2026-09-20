# Detekcja Windows Recon Commands — Sigma Rule

Reguła Sigma wykrywająca podejrzane komendy rekonesansu (discovery) uruchamiane na Windowsie, takie jak `whoami`, `ipconfig`, `systeminfo` oraz `net user` / `net group` / `net localgroup`. Napisana i testowana w ramach nauki SOC L2/Internshipu.

## Reguła (YAML)

```yaml
title: Detekcja Windows Recon Commands
id: 82309d72-38a3-4e85-9c5f-aac6f3417bfe
status: experimental
description: <Sigma rule zbierajaca podejrzane komendy rekonesansu typu whoami, ipconfig, systeminfo etc>
references:
  - https://attack.mitre.org/techniques/T1033/
  - https://attack.mitre.org/techniques/T1087/
  - https://attack.mitre.org/techniques/T1082/
  - https://attack.mitre.org/techniques/T1016/
author: Joachim
date: 2026/09/20
tags:
  - attack.discovery
  - attack.t1087
  - attack.t1033
  - attack.t1082
  - attack.t1016
logsource:
  category: process_creation
  product: windows
detection:
  selection_recon_binaries:
    Image|endswith:
      - '\whoami.exe'
      - '\ipconfig.exe'
      - '\systeminfo.exe'
  selection_net_recon:
    Image|endswith: '\net.exe'
    CommandLine|contains:
      - ' user'
      - ' group'
      - ' localgroup'
  condition: 1 of selection_*
falsepositives:
  - Legitna aktywność IT Admina
  - Troubleshooting skrypt Helpdeska
  - Programy do śledzenia info o zasobach
  - Asset Inventory - Lista zasobów
level: low
```
<img width="1920" height="791" alt="Zrzut ekranu (755)" src="https://github.com/user-attachments/assets/b184fd6b-fe95-40d7-bf61-4ac49a8d4ccc" />
<img width="1920" height="785" alt="Zrzut ekranu (756)" src="https://github.com/user-attachments/assets/98cc0bf8-e8f8-4161-ace6-bfa9567f5f21" />



## Proces pracy

Reguła została napisana w **Visual Studio Code**, a następnie zwalidowana lokalnie przy pomocy `sigma-cli`:

```bash
sigma check first-detection.yml
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
<img width="1015" height="701" alt="Zrzut ekranu (757)" src="https://github.com/user-attachments/assets/98ebf71f-2e62-424a-b693-95ec7cc867eb" />

## Konwersja na zapytania SIEM-owe

Po walidacji reguła została skonwertowana za pomocą `sigma convert` na trzy różne backendy.

### a) Splunk (pipeline: `splunk_cim`)

```bash
sigma convert -t splunk -p splunk_cim first-detection.yml
```

```
Processes.process_path IN ("*\\whoami.exe", "*\\ipconfig.exe", "*\\systeminfo.exe") OR (Processes.process_path="*\\net.exe" Processes.process IN ("*user*", "*group*", "*localgroup*"))
```

### b) Microsoft XDR (Kusto / KQL, pipeline: `microsoft_xdr`)

```bash
sigma convert -t kusto -p microsoft_xdr first-detection.yml
```

```
DeviceProcessEvents
| where (FolderPath endswith "\\whoami.exe" or FolderPath endswith "\\ipconfig.exe" or FolderPath endswith "\\systeminfo.exe") or (FolderPath endswith "\\net.exe" and (ProcessCommandLine contains "user" or ProcessCommandLine contains "group" or ProcessCommandLine contains "localgroup"))
```

### c) Elastic (EQL, pipeline: `ecs_windows`)

```bash
sigma convert -t eql -p ecs_windows first-detection.yml
```

```
any where (process.executable like~ ("*\\whoami.exe", "*\\ipconfig.exe", "*\\systeminfo.exe")) or (process.executable:"*\\net.exe" and (process.command_line like~ ("*user*", "*group*", "*localgroup*")))
```
<img width="1920" height="795" alt="Zrzut ekranu (759)" src="https://github.com/user-attachments/assets/39dc9f7e-9082-47ce-9549-bf821376984a" />



## Problemy napotkane podczas pisania (do zapamiętania na przyszłość)

Podczas pisania tej reguły napotkałem kilka błędów składniowych YAML, które warto mieć na uwadze przy każdej kolejnej regule:

- **Wcięcia (indentation) muszą być konsekwentne** — każdy zagnieżdżony poziom (np. klucz pod `selection_recon_binaries`, elementy listy pod `Image|endswith`) musi być wcięty głębiej niż jego rodzic, zawsze o tę samą liczbę spacji (2 spacje na poziom), nigdy tabulatorem.
- **`condition`, `Image|endswith` i inne klucze nie mogą stać w tej samej linii co ich wartość, jeśli wartość to lista** — lista musi zaczynać się w nowej linii, wcięta względem klucza.
- **Zawsze spacja po dwukropku** (`:`) przed wartością — np. `Image|endswith: '\net.exe'`, a nie `Image|endswith:'\net.exe'`.
- **Zawsze spacja po myślniku** (`-`) w elemencie listy — np. `- ' user'`, a nie `-' user'`.
- **`Image|endswith:` z listą wartości pod spodem** wymaga, żeby myślniki (`-`) były wyrównane w jednej kolumnie i wcięte głębiej niż sam klucz

