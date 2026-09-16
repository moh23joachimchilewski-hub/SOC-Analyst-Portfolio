# Analiza zdarzeń — Windows Endpoint (Mini-SOC Home Lab)
 
## Środowisko
 
Maszyna wirtualna **Windows-Endpoint** utworzona w Oracle VM VirtualBox, z zainstalowanym systemem **Windows 10 (64-bit)**, podłączona do izolowanej sieci laboratoryjnej (VirtualBox Host-Only Adapter, `192.168.56.0/24`).
 
Na maszynie zainstalowano i skonfigurowano:
- **Sysmon** (Sysinternals) z konfiguracją [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config), rejestrujący zdarzenia tworzenia procesów, połączeń sieciowych i inne wskaźniki aktywności systemowej.
- **Wazuh Agent**, przesyłający logi systemowe oraz zdarzenia z kanału `Microsoft-Windows-Sysmon/Operational` do centralnego Wazuh Servera (`192.168.56.101`).
Adresacja: `192.168.56.103`
 
Poniżej udokumentowałem zdarzenie wygenerowane na tej maszynie w ramach symulacji technik ofensywnych, wraz z analizą 5W, wskaźnikami kompromitacji (IOC) i mapowaniem na MITRE ATT&CK.
 
---
 
## Zdarzenie 1 — Uruchomienie zakodowanej komendy PowerShell (Base64)
 
### Opis
 
Uruchomiono proces `powershell.exe` z parametrem `-EncodedCommand`, przekazując zakodowaną w Base64 (UTF-16LE) komendę `Invoke-WebRequest`, symulującą technikę obfuskacji poleceń stosowaną do ukrywania rzeczywistej treści wykonywanego kodu przed powierzchowną analizą (np. przez administratora przeglądającego logi lub proste reguły antywirusowe).
 
### Komenda wykonana
 
```powershell
$command = 'Invoke-WebRequest -Uri https://example.com -OutFile $env:USERPROFILE\Desktop\password.txt'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded
```
 
### 5W
 
| | |
|---|---|
| **Who (kto)** | Użytkownik `WINDOWS\pendragon`, proces macierzysty `powershell.exe` |
| **What (co)** | Uruchomienie zagnieżdżonego procesu `powershell.exe` z zakodowaną w Base64 komendą pobierającą zawartość URL i zapisującą ją pod zwodniczą nazwą `password.txt` |
| **When (kiedy)** | 2026-09-13 19:36:47 UTC |
| **Where (gdzie)** | Windows-Endpoint (192.168.56.103), katalog roboczy `C:\Windows\system32\` |
| **Why (dlaczego)** | Symulacja techniki obfuskacji poleceń wykorzystywanej przez malware do unikania detekcji oraz utrudnienia analizy powłamaniowej |
 
### IOC (Indicators of Compromise)
 
- **Proces:** `powershell.exe` (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`)
- **Parametr wiersza poleceń:** `-EncodedCommand`
- **Base64 (fragment):** `SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0...`
- **Proces macierzysty (ParentImage):** `powershell.exe`
- **Docelowa nazwa pliku:** `password.txt` (nazwa sugerująca eksfiltrację danych uwierzytelniających, mimo nieszkodliwej zawartości)
### Źródło detekcji
 
- Sysmon Event ID **1** (Process Create), kanał `Microsoft-Windows-Sysmon/Operational`
- Własna reguła Wazuh `100013` (dopasowanie frazy `-EncodedCommand`)
### MITRE ATT&CK
 
- **T1027** — Obfuscated Files or Information
- **T1059.001** — Command and Scripting Interpreter: PowerShell
---
 ### Surowy log (Sysmon Event ID 1)
 
```
Process Create: RuleName: - UtcTime: 2026-09-13 19:36:47.992 ProcessGuid: {73d7f956-fb4f-6aa6-ac01-000000000a00} ProcessId: 6300 Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe FileVersion: 10.0.19041.3636 (WinBuild.160101.0800) Description: Windows PowerShell Product: Microsoft® Windows® Operating System Company: Microsoft Corporation OriginalFileName: PowerShell.EXE CommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgAGgAdAB0AHAAcwA6AC8ALwBlAHgAYQBtAHAAbABlAC4AYwBvAG0AIAAtAE8AdQB0AEYAaQBsAGUAIAAkAGUAbgB2ADoAVQBTAEUAUgBQAFIATwBGAEkATABFAFwARABlAHMAawB0AG8AcABcAHAAYQBzAHMAdwBvAHIAZAAuAHQAeAB0AA== CurrentDirectory: C:\Windows\system32\ User: WINDOWS\pendragon LogonGuid: {73d7f956-eac2-6aa6-8ba7-030000000000} LogonId: 0x3A78B TerminalSessionId: 1 IntegrityLevel: High Hashes: MD5=6726185B70B5ADF05E8A1A1DF82EBF30,SHA256=64DD55E1C2373DEED25C2776F553C632E58C45E56A0E4639DFD54EE97EAB9C19,IMPHASH=E3007C8E0098D06ABF617EEE6F0C5ABD ParentProcessGuid: {73d7f956-f5d4-6aa6-9901-000000000a00} ParentProcessId: 2312 ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" ParentUser: WINDOWS\pendragon
```
 
---
 <img width="1122" height="920" alt="Zrzut ekranu (725)" src="https://github.com/user-attachments/assets/271e59df-e90a-4ae9-8cd7-d100288f3041" />
 <img width="1107" height="925" alt="Zrzut ekranu (727)" src="https://github.com/user-attachments/assets/01cfab5c-32e8-44f5-9797-99aae0f3c78f" />
<img width="955" height="254" alt="image" src="https://github.com/user-attachments/assets/c11f6dd6-9a04-47e3-86ca-4c3b140a630c" />
<img width="1920" height="966" alt="Zrzut ekranu (733)" src="https://github.com/user-attachments/assets/1e9fe364-a240-4609-bc72-c89a7c185469" />


