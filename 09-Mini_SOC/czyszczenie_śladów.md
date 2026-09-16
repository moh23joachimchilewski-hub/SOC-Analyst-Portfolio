# Analiza zdarzeń — Windows Endpoint (Mini-SOC Home Lab)
 
## Środowisko
 
Maszyna wirtualna **Windows-Endpoint** utworzona w Oracle VM VirtualBox, z zainstalowanym systemem **Windows 10 (64-bit)**, podłączona do izolowanej sieci laboratoryjnej (VirtualBox Host-Only Adapter, `192.168.56.0/24`).
 
Na maszynie zainstalowano i skonfigurowano:
- **Sysmon** (Sysinternals) z konfiguracją [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config), rejestrujący zdarzenia tworzenia procesów, połączeń sieciowych i inne wskaźniki aktywności systemowej.
- **Wazuh Agent**, przesyłający logi systemowe oraz zdarzenia z kanału `Microsoft-Windows-Sysmon/Operational` do centralnego Wazuh Servera (`192.168.56.101`).
Adresacja: `192.168.56.103`
 
Poniżej udokumentowano zdarzenie wygenerowane na tej maszynie w ramach symulacji technik ofensywnych, wraz z analizą 5W, wskaźnikami kompromitacji (IOC) i mapowaniem na MITRE ATT&CK.

## Zdarzenie 3 — Czyszczenie dziennika zdarzeń Security
 
### Opis
 
Wyczyszczono dziennik zdarzeń Security za pomocą wbudowanego narzędzia systemowego `wevtutil`, symulując technikę antyforenics mającą na celu usunięcie śladów wcześniejszej aktywności i utrudnienie analizy powłamaniowej.
 
### Komenda wykonana
 
```powershell
wevtutil cl Security
```
 
### 5W
 
| | |
|---|---|
| **Who (kto)** | Użytkownik `WINDOWS\pendragon` (SID: `S-1-5-21-812322891-1584829564-2687271151-1000`) |
| **What (co)** | Wyczyszczenie całego dziennika zdarzeń Security, usuwając wszystkie zapisane wcześniej logi audytowe |
| **When (kiedy)** | 2026-09-13 21:20:09 UTC |
| **Where (gdzie)** | Windows-Endpoint (192.168.56.103) |
| **Why (dlaczego)** | Symulacja działań antyforensycznych — próba ukrycia śladów wcześniejszej aktywności (w tym poprzednich dwóch zdarzeń w tym raporcie) |
 
### IOC
 
- **Proces:** `wevtutil.exe`
- **Parametry:** `cl Security`
- **Wygenerowane zdarzenie:** Event ID **1102** ("The audit log was cleared" / "Dziennik inspekcji został wyczyszczony")
- **Identyfikator logowania (LogonId):** `0x3A78B`
- **Konto wykonujące akcję:** `WINDOWS\pendragon`
### Źródło detekcji
 
- Windows Security Event Log, Event ID **1102**
- Własna reguła Wazuh `100015` (dopasowanie Event ID 1102 w grupie `windows`)
### MITRE ATT&CK
 
- **T1070.001** — Indicator Removal: Clear Windows Event Logs
### Surowy log (Windows Security Event ID 1102)
 
```
Dziennik inspekcji został wyczyszczony.
Podmiot:
    Identyfikator zabezpieczeń: S-1-5-21-812322891-1584829564-2687271151-1000
    Nazwa konta: pendragon
    Nazwa domeny: WINDOWS
    Identyfikator logowania: 0x3A78B
```
 
---
 
## Podsumowanie
 
| Zdarzenie | Event ID (Sysmon/Windows) | Reguła Wazuh | Poziom alertu | MITRE ATT&CK |
|---|---|---|---|---|
| Czyszczenie logów | Security ID 1102 | 100015 | 13 | T1070.001 |

<img width="1122" height="920" alt="Zrzut ekranu (725)" src="https://github.com/user-attachments/assets/2f4c5be6-43a2-450f-83f5-0f0be03298cf" />
<img width="1107" height="925" alt="Zrzut ekranu (727)" src="https://github.com/user-attachments/assets/363304b8-ad94-4944-abb1-63be9a27c4b4" />
<img width="955" height="136" alt="image" src="https://github.com/user-attachments/assets/70248fd5-26c1-49e9-baec-31f8afbdf60c" />
<img width="1920" height="969" alt="image" src="https://github.com/user-attachments/assets/349ceeca-b33d-4664-973e-11051cf88fae" />



