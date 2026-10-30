# Analiza incydentu - XLMRat: PowerShell w pliku .jpg -> AsyncRAT w RegSvcs.exe

> **Platforma:** Wireshark + CyberChef + VirusTotal (+ NetworkMiner do szybkiego przeglądu hostów)
> **Źródło:** CyberDefenders - lab XLMRat (analiza PCAP)
> **Typ zdarzenia:** Execution (PowerShell) -> Ingress Tool Transfer -> Defense Evasion (Reflective Loading, LOLBin) -> Persistence/Execution (bat/vbs) -> C2
> **Severity:** High
> **MITRE ATT&CK:** T1105, T1036, T1027, T1059.001, T1059.003, T1059.005, T1620, T1218.009, T1055.012, T1571, T1568

---

## Podsumowanie

Monitoring wygenerował alert na maszynę `10.1.9.101` (Windows) z powodu podejrzanego ruchu sieciowego. Host pobrał po HTTP z serwera `45.126.209.4` (`madmrx.duckdns.org`, hosting **ReliableSite.Net**) na **niestandardowym porcie 222** plik **`mdm.jpg`**. Mimo rozszerzenia `.jpg` to nie był obrazek, tylko **skrypt PowerShell** z dwoma plikami PE zapisanymi jako hex:
- **loader** (.NET), ładowany prosto do pamięci przez `[Reflection.Assembly]::Load`,
- **właściwy malware - AsyncRAT**, który loader wstrzykuje do legalnego **`RegSvcs.exe`** (LOLBin).

Skrypt zrzuca też na dysk `Conted.ps1`, `Conted.bat` i `Conted.vbs` w `C:\Users\Public\`, które ukrycie uruchamiają PowerShell. Następnie zainfekowany host łączy się z C2 na `45.126.209.4:8808` (zaszyfrowany ruch).

---

## Kontekst

### Dlaczego `.jpg` to nie obrazek

Rozszerzenie pliku nic nie znaczy. Liczy się zawartość. W Follow HTTP Stream widać, że `mdm.jpg` zaczyna się od kodu PowerShell (`$hexString_bbb = "4D_5A_90_00..."`), a nie od nagłówka JPEG. Atakujący udaje obrazek, żeby plik nie rzucał się w oczy w logach proxy.

### Loader + payload

| Zmienna w skrypcie | Co to | Co się z tym dzieje |
|---|---|---|
| `$hexString_pe` -> `$pe` | **loader** (.NET DLL) | `[Reflection.Assembly]::Load($pe)` - ładowany tylko do pamięci, nie ma go na dysku |
| `$hexString_bbb` -> `$NKbb` | **AsyncRAT** (malware) | przekazany do metody `Execute` loadera razem ze ścieżką do `RegSvcs.exe` |

Loader (`NewPE2.PE` -> `Execute`) uruchamia `RegSvcs.exe` i podmienia w nim kod na AsyncRAT (process hollowing). W menedżerze zadań widać więc podpisany program Microsoftu, a w środku działa RAT.

### Obfuskacja przez `#`

Nazwy wrażliwych funkcji są poprzerywane znakami `#` i sklejane przez `-replace '#', ''`, żeby ominąć proste sygnatury AV:
- `'L####...o####...a#d'` -> `Load`
- `'In####...vo####...ke'` -> `Invoke`
- `'C:\W####indow####s\Mi####cr' + 'osof####t.NET\Fra###mework\v4.0.303###19\R##egSvc####s.exe'` -> `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`

### LOLBin

**LOLBin (Living Off the Land Binary)** to legalny, podpisany program systemowy, który atakujący wykorzystuje do swoich celów. `RegSvcs.exe` to narzędzie .NET do rejestrowania komponentów. Jest w każdym Windowsie, więc uruchomienie go nie wzbudza podejrzeń.

### Łańcuch plików na dysku

`Conted.vbs` -> uruchamia (ukryte okno, `visibility = 0`) -> `Conted.bat` -> uruchamia `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass` -> `Conted.ps1`

Trzy warstwy (VBS -> BAT -> PS1) utrudniają powiązanie procesów i pozwalają odpalić PowerShell bez widocznego okna.

---

## IOC (Indicators of Compromise)

| Typ | Wartość |
|---|---|
| Zainfekowany host | `10.1.9.101` (Windows) |
| Serwer atakującego / C2 | `45.126.209.4` |
| Domena | `madmrx.duckdns.org` (dynamiczny DNS) |
| Hosting | ReliableSite.Net LLC (AS23470, Miami, US) |
| URL pierwszego etapu | `http://45.126.209.4:222/mdm.jpg` |
| Inny pobrany plik | `http://45.126.209.4:222/xlm.txt` |
| Port C2 | `8808/tcp` |
| Serwer atakującego (banner) | `Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30` |
| SHA256 `mdm.jpg` (skrypt) | `83babee77db36512c0eab8ea6b35e981aa4288a4095985d69b3841f8b684fe11` |
| Nazwa malware (VirusTotal) | `Stub.exe` |
| SHA256 malware (AsyncRAT) | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` |
| Rodzina malware | AsyncRAT (Alibaba: `Backdoor:MSIL/AsyncRat.a2786761`) |
| LOLBin | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` |
| Zrzucone pliki | `C:\Users\Public\Conted.ps1`, `Conted.bat`, `Conted.vbs` |

---

## 5W

| Pytanie | Odpowiedź |
|---|---|
| **Who** (kto) | Atakujący z infrastrukturą `45.126.209.4` (`madmrx.duckdns.org`, ReliableSite.Net); ofiara `10.1.9.101` |
| **What** (co) | Pobranie skryptu PowerShell udającego `.jpg` -> loader w pamięci -> AsyncRAT wstrzyknięty w `RegSvcs.exe` -> pliki `Conted.*` -> połączenie C2 |
| **When** (kiedy) | 2024-01-09, ok. 17:27 - 17:40 UTC |
| **Where** (gdzie) | Host `10.1.9.101`, katalog `C:\Users\Public\`, proces `RegSvcs.exe`; ruch na `45.126.209.4:222` (pobieranie) i `:8808` (C2) |
| **Why** (po co) | Zdalny dostęp i kontrola nad hostem (RAT: keylogging, kradzież danych, wykonywanie komend) |

---

## Przebieg analizy

### Krok 0 - szybki przegląd w NetworkMiner

PCAP wrzuciłem do **NetworkMinera**, żeby od razu zobaczyć wszystkie hosty i sesje. Wyszło:
- `10.1.9.101` (Windows) - ofiara,
- `45.126.209.4` z nazwą **`madmrx.duckdns.org`**, otwarte porty **222** (HTTP, `GET /xlm.txt`) i **8808** (wysoka entropia = zaszyfrowany ruch),
- reszta to serwery DNS `ns*.duckdns.org`.

<img width="1920" height="1011" alt="Zrzut ekranu (1189)" src="https://github.com/user-attachments/assets/253c851c-c555-4ee9-9d4d-424675f1c66d" />


---

### Krok 1 - kto z kim rozmawia (Statistics -> Endpoints)

**Statistics -> Endpoints**, zakładki IPv4 i TCP.

**Ujawniło:**
- tylko 3 adresy IPv4: `10.1.9.1` (DNS), `10.1.9.101` (ofiara), `45.126.209.4` (zewnętrzny),
- prawie cały ruch (~1550 pakietów) to `10.1.9.101` <-> `45.126.209.4`,
- porty po stronie `45.126.209.4`: **222** (453 kB - pobieranie plików) i **8808** (133 kB - długa sesja = C2).

> Ustalono: podejrzany serwer to `45.126.209.4`, porty 222 i 8808.

*Lekcja: HTTP na porcie 222 to od razu sygnał - legalne serwery WWW używają 80/443.*

<img width="1920" height="302" alt="Zrzut ekranu (1180)" src="https://github.com/user-attachments/assets/c73d7220-96a4-479f-83d6-b3d7f68d52f4" />

<img width="1920" height="329" alt="Zrzut ekranu (1181)" src="https://github.com/user-attachments/assets/f5ad6603-5b0e-415f-88b2-04f314a58cfe" />


---

### Krok 2 - URL pierwszego etapu

```
http.request.method=="GET"
```
**Ujawniło:** tylko 2 żądania z `10.1.9.101` do `45.126.209.4`:
- `GET /xlm.txt`,
- `GET /mdm.jpg` z nagłówkiem `Host: 45.126.209.4:222`.

> Ustalono: pierwszy etap malware pobrany z `http://45.126.209.4:222/mdm.jpg`.

<img width="1920" height="1024" alt="Zrzut ekranu (1183)" src="https://github.com/user-attachments/assets/314ab881-4799-4f2d-b373-93470764f19a" />


---

### Krok 3 - hosting (AbuseIPDB)

IP `45.126.209.4` sprawdzone w **AbuseIPDB**: ISP **ReliableSite.Net LLC**, typ *Data Center/Web Hosting/Transit*, AS23470, Miami (US).

> Ustalono: dostawca hostingu to `reliablesite.net`.

<img width="1920" height="853" alt="Zrzut ekranu (1185)" src="https://github.com/user-attachments/assets/5a2e1783-7445-4296-8faf-cb08fdb30180" />


---

### Krok 4 - co jest w mdm.jpg (Follow HTTP Stream)

Prawy klik na `GET /mdm.jpg` -> **Follow -> HTTP Stream**:
```
tcp.stream eq 1
```
**Ujawniło:** odpowiedź `200 OK` (Content-Length 431208) to **skrypt PowerShell**, a nie obrazek:
- dwie długie zmienne hex `$hexString_bbb` i `$hexString_pe`, obie zaczynają się od `4D_5A_90_00` (`MZ` = plik PE),
- zamiana hex na bajty: `-split '_' | ForEach-Object { [byte]([convert]::ToInt32($_, 16)) }`,
- `[Reflection.Assembly]::Load($pe)` -> `GetType('NewPE2.PE')` -> `GetMethod('Execute')` -> `Invoke($null, @(RegSvcs.exe, $NKbb))`,
- zapis plików `Conted.ps1`, `Conted.bat`, `Conted.vbs` do `C:\Users\Public\`.

> Ustalono: `mdm.jpg` to dropper w PowerShellu z loaderem i payloadem w formie hex.

<img width="1274" height="975" alt="Zrzut ekranu (1326)" src="https://github.com/user-attachments/assets/688ad637-61b3-4f99-b3bc-020752968f83" />
<img width="1278" height="966" alt="Zrzut ekranu (1327)" src="https://github.com/user-attachments/assets/3a0a5b30-4792-4535-b82a-194e9d51cd21" />


---

### Krok 5 - hash malware (CyberChef + VirusTotal)

Z HTTP Stream skopiowałem samą wartość hex payloadu (`4D_5A_90_00_...` bez cudzysłowów i bez reszty skryptu) do **CyberChef**:
```
From Hex (Delimiter: Auto) -> SHA2 (Size: 256)
```
Wynik: `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`

Hash wrzucony do **VirusTotal** - **61/71** silników oznacza plik jako złośliwy, oryginalna nazwa **`Stub.exe`** (65 KB, .NET), Threat label `trojan.asyncrat/msil`.

> Ustalono: SHA256 malware to `1eb7b02e...81d798`.

*Lekcja: hash całego `mdm.jpg` (`83babee7...`) to hash skryptu PowerShell, a nie malware. Pytanie dotyczyło pliku wykonywalnego, więc trzeba wyciągnąć sam PE ze zmiennej hex i dopiero jego zahashować. W SHA2 trzeba też ustawić rozmiar 256 (domyślnie jest 512).*

<img width="1920" height="951" alt="Zrzut ekranu (1210)" src="https://github.com/user-attachments/assets/307dc9be-5950-4eee-8707-8ebd8daf59e8" />

<img width="1920" height="918" alt="Zrzut ekranu (1330)" src="https://github.com/user-attachments/assets/56b66b91-a7f7-4aff-93e2-dbff7ba32563" />

---

### Krok 6 - rodzina malware (Alibaba)

W VirusTotal, zakładka **Detection**, wiersz **Alibaba**: `Backdoor:MSIL/AsyncRat.a2786761`.

> Ustalono: rodzina malware to **AsyncRAT**.

*AsyncRAT to darmowy RAT open source napisany w .NET (stąd `MSIL`). Daje zdalny pulpit, keylogger, kradzież haseł i pobieranie kolejnych plików.*

<img width="932" height="80" alt="image" src="https://github.com/user-attachments/assets/a0b859a3-239a-4f27-bb30-f7d5a00c4253" />


---

### Krok 7 - czas kompilacji (VirusTotal)

VirusTotal -> zakładka **Details** -> **Portable Executable Info** -> **Header** -> **Compilation Timestamp**.

> Ustalono: czas kompilacji PE - `2023-10-30 15:08:44` UTC.


<img width="1920" height="894" alt="Zrzut ekranu (1331)" src="https://github.com/user-attachments/assets/8d02ca51-0b9f-4163-9ee1-eb352653c00c" />


---

### Krok 8 - LOLBin (deobfuskacja ścieżki)

W tym samym HTTP Stream:
```powershell
$NA = 'C:\W#######indow############s\Mi####cr' -replace '#', ''
$AC = $NA + 'osof######t.NET\Fra###mework\v4.0.303###19\R##egSvc#####s.exe' -replace '#', ''
```
Po usunięciu `#` i sklejeniu:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
```

> Ustalono: LOLBin to `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`.



<img width="1272" height="1002" alt="Zrzut ekranu (1204)" src="https://github.com/user-attachments/assets/d0549ce5-b8be-4bdd-a4a9-b0daf3ff51ab" />


---

### Krok 9 - zrzucone pliki

Koniec skryptu w tym samym HTTP Stream - trzy wywołania `[IO.File]::WriteAllText`:
```
C:\Users\Public\Conted.ps1
C:\Users\Public\Conted.bat
C:\Users\Public\Conted.vbs
```
- `Conted.bat` - `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass` uruchamiający `Conted.ps1`,
- `Conted.vbs` - przez `WScript.Shell` odpala `Conted.bat` z `visibility = 0` (bez okna).

> Ustalono: zrzucone pliki to `Conted.ps1`, `Conted.bat`, `Conted.vbs`.



<img width="1279" height="1017" alt="Zrzut ekranu (1205)" src="https://github.com/user-attachments/assets/26cf6c4c-b2d7-4f60-9676-be8f81d8ee2a" />

<img width="1270" height="1011" alt="Zrzut ekranu (1206)" src="https://github.com/user-attachments/assets/a934c3ed-7ab5-49c1-8a91-78106094840b" />


---

### Krok 10 - ruch C2

```
tcp.port==8808
```
**Ujawniło:** jedna długa sesja `10.1.9.101:49723` -> `45.126.209.4:8808` (ok. 17:29:49 - 17:40:13):
- zaraz po handshake TCP idzie **TLS** (`Client Hello`, `Server Hello, Certificate`),
- dalej tylko `Application Data` w regularnych odstępach - zaszyfrowany kanał C2 AsyncRAT (beaconing).

Połączenie startuje ok. 2 minuty po pobraniu `mdm.jpg` (17:27:29), czyli po tym, jak skrypt odpalił malware.

> Ustalono: C2 na `45.126.209.4:8808`.

<img width="1920" height="1020" alt="Zrzut ekranu (1329)" src="https://github.com/user-attachments/assets/edd15d48-29a7-4e32-9991-d4335b41fd29" />


---

## MITRE ATT&CK

| Technika | ID | Gdzie w incydencie |
|---|---|---|
| Ingress Tool Transfer | T1105 | pobranie `mdm.jpg` z `45.126.209.4:222` |
| Masquerading | T1036 | skrypt PowerShell udający plik `.jpg` |
| Obfuscated Files or Information | T1027 | payloady jako hex, nazwy funkcji poprzerywane `#` |
| Command and Scripting Interpreter: PowerShell | T1059.001 | `mdm.jpg`, `Conted.ps1` |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `Conted.bat` |
| Command and Scripting Interpreter: Visual Basic | T1059.005 | `Conted.vbs` (`WScript.Shell`) |
| Reflective Code Loading | T1620 | `[Reflection.Assembly]::Load($pe)` |
| System Binary Proxy Execution: Regsvcs/Regasm | T1218.009 | `RegSvcs.exe` jako LOLBin |
| Process Injection: Process Hollowing | T1055.012 | AsyncRAT wstrzyknięty w `RegSvcs.exe` |
| Non-Standard Port | T1571 | HTTP na 222, C2 na 8808 |
| Dynamic Resolution | T1568 | domena `madmrx.duckdns.org` (DDNS) |

<img width="1061" height="672" alt="Zrzut ekranu (1332)" src="https://github.com/user-attachments/assets/a83b0f5e-3fd5-4ffb-a3a4-3cdd3eb4aed6" />
<img width="1058" height="652" alt="Zrzut ekranu (1333)" src="https://github.com/user-attachments/assets/1b5cab8d-b2b8-43af-a753-18e98fecc654" />
<img width="1055" height="235" alt="Zrzut ekranu (1334)" src="https://github.com/user-attachments/assets/0fcaa65a-6612-44fb-95e2-262d119ee14f" />
