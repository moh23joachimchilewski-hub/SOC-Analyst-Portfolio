# Analiza zdarzeń — Windows Endpoint (Mini-SOC Home Lab)
 
## Środowisko
 
Maszyna wirtualna **Windows-Endpoint** utworzona w Oracle VM VirtualBox, z zainstalowanym systemem **Windows 10 (64-bit)**, podłączona do izolowanej sieci laboratoryjnej (VirtualBox Host-Only Adapter, `192.168.56.0/24`).
 
Na maszynie zainstalowano i skonfigurowano:
- **Sysmon** (Sysinternals) z konfiguracją [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config), rejestrujący zdarzenia tworzenia procesów, połączeń sieciowych i inne wskaźniki aktywności systemowej.
- **Wazuh Agent**, przesyłający logi systemowe oraz zdarzenia z kanału `Microsoft-Windows-Sysmon/Operational` do centralnego Wazuh Servera (`192.168.56.101`).
Adresacja: `192.168.56.103`
 
Poniżej udokumentowano zdarzenie wygenerowane na tej maszynie w ramach symulacji technik ofensywnych, wraz z analizą 5W, wskaźnikami kompromitacji (IOC) i mapowaniem na MITRE ATT&CK.
## Zdarzenie 2 — Utworzenie Scheduled Task (Persistence)
 
### Opis
 
Utworzono nowy Scheduled Task w systemie Windows, skonfigurowany do uruchamiania się automatycznie przy każdym logowaniu z uprawnieniami konta **SYSTEM** — klasyczna technika utrzymania trwałości (persistence) wykorzystywana do zapewnienia ponownego uruchomienia złośliwego kodu po restarcie systemu lub wylogowaniu użytkownika.
 
### Komenda wykonana
 
```powershell
schtasks /create /tn "UpdateChecker" /tr "C:\Windows\System32\calc.exe" /sc onlogon /ru SYSTEM
```
 
### 5W
 
| | |
|---|---|
| **Who (kto)** | Użytkownik `WINDOWS\pendragon`, proces macierzysty `powershell.exe` |
| **What (co)** | Utworzenie Scheduled Task `UpdateChecker`, uruchamiającego `calc.exe` przy każdym logowaniu, z podniesionymi uprawnieniami SYSTEM |
| **When (kiedy)** | 2026-09-13 19:32:22 UTC |
| **Where (gdzie)** | Windows-Endpoint (192.168.56.103) |
| **Why (dlaczego)** | Symulacja mechanizmu persistence — zapewnienie automatycznego wykonania kodu bez interakcji użytkownika, przetrwanie restartu systemu |
 
### IOC
 
- **Proces:** `schtasks.exe` (`C:\Windows\System32\schtasks.exe`)
- **Parametry:** `/create /tn UpdateChecker /tr C:\Windows\System32\calc.exe /sc onlogon /ru SYSTEM`
- **Nazwa zadania:** `UpdateChecker` (nazwa maskująca się pod legalny proces aktualizacji)
- **SHA256 procesu:** `9A80453518078BADF0679B0CF30F50A83163E5264A2665C6052CC27F168C50F2`
- **Proces macierzysty (ParentImage):** `powershell.exe`
- **Uprawnienia docelowe:** SYSTEM (najwyższy poziom uprawnień w systemie Windows)
### Źródło detekcji
 
- Sysmon Event ID **1** (Process Create)
- Własna reguła Wazuh `100012` (dopasowanie `schtasks.exe` + parametr `/create`)
### MITRE ATT&CK
 
- **T1053.005** — Scheduled Task/Job: Scheduled Task
### Surowy log (Sysmon Event ID 1)
 
```
Process Create: RuleName: - UtcTime: 2026-09-13 19:32:22.866 ProcessGuid: {73d7f956-fa46-6aa6-a901-000000000a00} ProcessId: 6292 Image: C:\Windows\System32\schtasks.exe FileVersion: 10.0.19041.3636 (WinBuild.160101.0800) Description: Task Scheduler Configuration Tool Product: Microsoft® Windows® Operating System Company: Microsoft Corporation OriginalFileName: schtasks.exe CommandLine: "C:\Windows\system32\schtasks.exe" /create /tn UpdateChecker /tr C:\Windows\System32\calc.exe /sc onlogon /ru SYSTEM CurrentDirectory: C:\Windows\system32\ User: WINDOWS\pendragon LogonGuid: {73d7f956-eac2-6aa6-8ba7-030000000000} LogonId: 0x3A78B TerminalSessionId: 1 IntegrityLevel: High Hashes: MD5=D4DA03B7BB20B7E4F1B762A365D4DD4F,SHA256=9A80453518078BADF0679B0CF30F50A83163E5264A2665C6052CC27F168C50F2,IMPHASH=ECCE05491F2E8F279F4790BCB1318C05 ParentProcessGuid: {73d7f956-f5d4-6aa6-9901-000000000a00} ParentProcessId: 2312 ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" ParentUser: WINDOWS\pendragon
```
 
---
 <img width="1122" height="920" alt="Zrzut ekranu (725)" src="https://github.com/user-attachments/assets/ebba54b9-c7e6-4550-961d-50ee970d11d4" />
 <img width="1107" height="925" alt="Zrzut ekranu (727)" src="https://github.com/user-attachments/assets/e448ffd0-05bf-443c-a7cb-52ac3d1c81bc" />
 <img width="955" height="126" alt="image" src="https://github.com/user-attachments/assets/a1b2bba8-b2ea-4bcd-b084-f57085f9918c" />
 <img width="1920" height="961" alt="image" src="https://github.com/user-attachments/assets/b3078df7-22a1-4520-8954-f7fa6a00bd88" />
