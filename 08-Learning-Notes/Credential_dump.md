# Ataki na poświadczenia w Active Directory - notatka analityka SOC

Wspólny mianownik wszystkich tych ataków: zdobycie haseł/hashy kont domenowych. Cztery pierwsze celują w Kerberos i konta użytkowników, dwa ostatnie (DCSync, NTDS.dit) to kradzież całej bazy haseł domeny. Typowa ścieżka atakującego: Kerberoasting/AS-REP -> LSASS dump -> (gdy ma DA) DCSync lub NTDS.dit.

---

## 1. Kerberoasting (T1558.003)

**Co to:** atakujący prosi DC o bilet serwisowy (TGS) dla konta z SPN. DC szyfruje bilet hashem hasła tego konta serwisowego. Atakujący zabiera bilet i łamie go offline. Słabe hasło = odzyskane w kilka minut. **Wystarczy zwykłe konto domenowe.**

**Dlaczego działa:** każdy user domenowy może poprosić o bilet do dowolnego SPN, a DC nie sprawdza, czy faktycznie będzie z usługi korzystał. Konta serwisowe często mają słabe hasła i wysokie uprawnienia (np. SQL jako Domain Admin).

**Sygnał:** Event **4769** (TGS requested). Narzędzia (Rubeus, GetUserSPNs.py) obniżają szyfrowanie do **RC4 (0x17)**, bo łamie się je szybciej, a domena domyślnie używa AES-256 (0x12).

**Kluczowe pola 4769:** `Service_Name` (który SPN atakowany), `Ticket_Encryption_Type` (0x17 = sygnał), `Account_Name` (kto prosi = przejęte konto), `Client_Address` (IP atakującego, często w formacie `::ffff:10.5.90.1`, prawdziwe IP jest po `::ffff:`).

**Filtr - wykrywa pojedyncze żądania RC4 do kont serwisowych:**
```spl
index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```
*(wykluczamy konta komputerów `*$` i `krbtgt`, bo generują masę normalnego ruchu)*

**Filtr - agregacja do triażu (ile kont zaatakowanych, kto, skąd):**
```spl
index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| stats dc(Service_Name) as targeted_services count by Account_Name, Client_Address
```

**Filtr - detekcja po wolumenie (łapie też Kerberoasting po AES):**
```spl
index=task2 EventCode=4769 Service_Name!="*$" Service_Name!="krbtgt"
| bin _time span=5m
| stats dc(Service_Name) as unique_spns count by Account_Name, Client_Address, _time
| where unique_spns > 5
```
*Jedno konto prosi o bilety do >5 różnych SPN w 5 minut = wzorzec Kerberoastingu. Próg 5 dostrój do swojej sieci. Ważne, bo narzędzie Orpheus potrafi Kerberoastować po AES i omija filtr `0x17`.*

**Triaż:** sprawdź uprawnienia zaatakowanych kont serwisowych. Jeśli któreś jest w Domain Admins - to nie zwykły alert, tylko potencjalne przejęcie domeny.

---

## 2. AS-REP Roasting (T1558.004)

**Co to:** celuje w konta **użytkowników z wyłączoną pre-autentykacją** (flaga `DONT_REQUIRE_PREAUTH`). DC wydaje TGT bez sprawdzenia hasła, a odpowiedź (AS-REP) jest zaszyfrowana hashem hasła konta -> łamane offline. **Nie trzeba mieć żadnego konta domenowego, wystarczy znać nazwę użytkownika.**

**Dlaczego istnieje:** stare aplikacje (ERP, payroll) czasem nie działają z pre-autentykacją, admin ją wyłącza i zapomina.

**Sygnał:** Event **4768** (TGT requested) z **`Pre_Authentication_Type=0`** (normalnie = 2, albo 15 dla certyfikatów) + zwykle RC4 (0x17).

**Kluczowe rozróżnienie:** atakujący chce tylko hash, więc **nie ma żadnej aktywności następczej**. Legalny użytkownik: 4768 -> 4769 -> 4624 (pełny łańcuch). AS-REP Roasting: 4768 i cisza (brak 4769 i 4624).

**Filtr - przegląd wszystkich TGT (baseline):**
```spl
index=task3 EventCode=4768
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
| sort _time
```

**Filtr - izolacja anomalii:**
```spl
index=task3 EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
```

**Filtr - sprawdzenie braku aktywności następczej (potwierdzenie):**
```spl
index=task3 (EventCode=4624 OR EventCode=4769)
| search Account_Name="{ACCOUNT_NAME}"
| table _time, EventCode, Account_Name, Client_Address
```
*Zero wyników = TGT pobrany tylko po to, by złamać hash offline. Nie jest to dowód w 100%, ale w połączeniu z `Pre_Auth=0` i RC4 bardzo mocno wskazuje na atak.*

**Kerberoasting vs AS-REP - szybka ściąga:**

| | Kerberoasting | AS-REP Roasting |
|---|---|---|
| Event | 4769 | 4768 |
| Cel | konta serwisowe z SPN | konta userów z wyłączoną pre-auth |
| Wymóg | dowolne konto domenowe | tylko znajomość nazwy usera |
| Sygnał | `Ticket_Encryption_Type=0x17` | `Pre_Authentication_Type=0` |

---

## 3. LSASS Dumping (T1003.001)

**Co to:** kradzież poświadczeń z pamięci procesu **LSASS** na endpoincie (nie na DC). LSASS trzyma dane każdego zalogowanego usera: hashe NTLM, bilety Kerberos (TGT/TGS), hasła jawnym tekstem (gdy WDigest włączony), cached credentials. Zrzut = poświadczenia od razu, bez łamania. Jeśli na maszynie była aktywna sesja Domain Admina (DA) -> atakujący przejmuje konto DA.

**Sygnał:** Sysmon **Event 10** (ProcessAccess), `TargetImage = lsass.exe`. **UWAGA: domyślny config Sysmona tego NIE loguje** - trzeba jawnej reguły ProcessAccess na lsass.

**Kluczowe pola:** `SourceImage` (ścieżka procesu - najważniejsze!), `SourceUser` (SYSTEM normalny, konto domenowe = przejęte), `GrantedAccess` (maska uprawnień hex), `CallTrace` (metoda dumpu).

**GrantedAccess (maska = suma uprawnień):**
- `0x0010` PROCESS_VM_READ = czytanie pamięci **(to jest ten ważny bit)**
- `0x1010` = kojarzone z **Mimikatz**
- `0x1FFFFF` (ALL_ACCESS) = **ProcDump, comsvcs.dll, Task Manager**

**CallTrace (łańcuch DLL):**
- Znane DLL (`dbgcore.dll`, `dbghelp.dll`) = MiniDump API = ProcDump/comsvcs (LOLBin, legalne narzędzie użyte złośliwie).
- **`UNKNOWN(...)`** (offsety bez DLL) = **wstrzyknięty kod** = Cobalt Strike, Meterpreter.

**Co jest normalne** (ale tylko z `C:\Windows\System32\`): `csrss.exe` (0x1000/0x1400), `WerFault.exe` (0x1000), `svchost.exe` (0x1010), agenci AV/EDR.

**ZASADA:** filtruj po **pełnej ścieżce, nie nazwie**. Atakujący nazwie swój plik `svchost.exe` i wrzuci do `C:\Temp\`. Nazwa legalna, ścieżka zdradza. Ścieżka spoza `System32` = podejrzane niezależnie od nazwy.

**Filtr - baseline, wszystko co dotyka LSASS:**
```spl
index=task4 EventCode=10 TargetImage="*\\lsass.exe"
| stats count by SourceImage, GrantedAccess
```

**Filtr - detale podejrzanego procesu:**
```spl
index=task4 EventCode=10 TargetImage="*\\lsass.exe" SourceImage={SUSPICIOUS_PROCESS}
| table _time, SourceImage, SourceUser, GrantedAccess, CallTrace
```
*CallTrace mówi jaka metoda (MiniDump vs injection), SourceUser mówi które konto jest przejęte.*

**Inne magazyny haseł:** SAM (tylko konta lokalne), cached credentials (DCC2, wolne do łamania, nie do PtH), NTDS.dit (cała domena, tylko na DC).

---

## 4. DCSync (T1003.006)

**Co to:** atakujący **udaje kontroler domeny** i przez protokół replikacji **DRSUAPI** prosi prawdziwy DC o hashe haseł. Zdalnie, bez dotykania dysku DC, bez shadow copy. Może pobrać hash dowolnego konta, w tym **krbtgt** (-> Golden Ticket -> pełna kontrola domeny).

**Wymóg:** uprawnienia replikacji. Mają je domyślnie Domain Admins, Enterprise Admins, konta DC. Czasem zdobywane przez ACL abuse (WriteDACL) bez wchodzenia do DA.

**GUID-y uprawnień (najważniejszy pierwszy):**
- `1131f6ad-...` = **DS-Replication-Get-Changes-All** (to pozwala ciągnąć hasła, główny wskaźnik)
- `1131f6aa-...` = DS-Replication-Get-Changes
- `89e95b76-...` = Get-Changes-In-Filtered-Set

**Sygnał:** Event **4662** (operacja na obiekcie), `Access_Mask=0x100` (Control Access), GUID replikacji w surowych danych, **konto nie kończące się na `$`**.

**Normalne vs podejrzane:** DC-to-DC replikacja jest normalna. Różnica to źródło: konto komputera `THM-DC$` = OK, konto usera (bez `$`) = DCSync.

**UWAGA konfiguracja:** 4662 dla DCSync wymaga (1) włączonego "Audit Directory Service Access" w GPO ORAZ (2) SACL na partycji domeny. Domyślnie ani jedno, ani drugie. Bez tego DCSync jest niewidoczny - to jedna z najczęstszych luk w realnych sieciach.

**Filtr - konto niemaszynowe robiące replikację:**
```spl
index=task5 EventCode=4662 "1131f6ad" user!="*$"
| table _time, user, Access_Mask, Properties
| sort _time
```
*GUID `1131f6ad` szukamy jako słowo kluczowe (keyword) w surowym logu, bo Splunk nie wyciąga go do osobnego pola, parsuje tylko jako "Control Access".*

**Filtr - pobranie Logon_ID do korelacji (4662 nie ma pola source IP):**
```spl
index=task5 EventCode=4662 Access_Mask=0x100 user={COMPROMISED_USER} "1131f6ad"
| table _time, host, user, Logon_ID
```

**Filtr - korelacja Logon_ID z 4624, żeby znaleźć source IP:**
```spl
index=task5 EventCode=4624 Logon_ID={LOGON_ID}
| table _time, host, user, Source_Network_Address, Logon_Type
```
*Technika: 4662 (co się stało) -> po wspólnym `Logon_ID` -> 4624 (skąd przyszło = `Source_Network_Address`).*

**Uwaga do filtra `user!="*$"`:** zakłada, że atak idzie z konta ludzkiego. Zaawansowany atakujący z hashem konta maszynowego zrobi DCSync z konta `$` i ten filtr go schowa. W dojrzałych środowiskach monitoruj wszystkie konta robiące replikację i baseline'uj, które maszyny normalnie replikują.

---

## 5. NTDS.dit Extraction (T1003.003)

**Co to:** starsza, głośniejsza metoda. `NTDS.dit` (`C:\Windows\NTDS\ntds.dit`) to baza AD z hashami wszystkich kont domeny. Windows blokuje plik podczas pracy AD, więc atakujący obchodzi blokadę na 2 sposoby. Do odszyfrowania hashy potrzebny też hive **SYSTEM**.

**Metoda 1 - vssadmin (shadow copy):**
```
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\...\Windows\System32\config\SYSTEM C:\temp\SYSTEM
vssadmin delete shadows /shadow={id} /quiet
```

**Metoda 2 - ntdsutil IFM (legalne narzędzie do promocji DC, nadużyte):**
```
ntdsutil "ac i ntds" "ifm" "create full C:\temp" q q
```

Obie wymagają uprawnień na DC (vssadmin - lokalny admin, ntdsutil - DA). Efekt ten sam: offline kopia bazy, parsowana `secretsdump.py`/NTDSDumpEx -> wszystkie hashe.

**Sygnał:** Sysmon **Event 1** (Process Creation, pełna linia komend) lub Security **4688** z command-line logging. Plus Sysmon **Event 11** (File Creation) gdy `ntds.dit` zapisany w nietypowym miejscu.

**Filtr - wykonanie ntdsutil:**
```spl
index=task6 EventCode=1 Image="*\ntdsutil.exe"
| table _time, host, User, ParentImage, Image, CommandLine
```

**Filtr - potwierdzenie zapisu pliku ntds.dit:**
```spl
index=task6 EventCode=11 TargetFilename="*ntds.dit" Image="*\\ntdsutil.exe"
| table _time, Image, TargetFilename
```

**Filtr - utworzenie shadow copy:**
```spl
index=task6 EventCode=1 Image="*\vssadmin.exe" CommandLine="*create shadow*"
| table _time, host, User, ParentImage, Image, CommandLine
```
*Sam shadow copy ma legalne zastosowania (backup) - nie potwierdza kradzieży. Potwierdza to dopiero kolejny krok.*

**Filtr - kopiowanie wrażliwych plików z shadow copy (to potwierdza atak):**
```spl
index=task6 EventCode=1 CommandLine="*HarddiskVolumeShadowCopy*" (CommandLine="*ntds*" OR CommandLine="*SYSTEM*")
| table _time, host, User, ParentImage, Image, CommandLine
```

---

## DCSync vs NTDS.dit - ściąga

| Cecha | DCSync | NTDS.dit Extraction |
|---|---|---|
| Metoda | zdalna replikacja (DRSUAPI) | lokalna kopia pliku (shadow copy / IFM) |
| Dostęp | prawa replikacji (DA domyślnie) | lokalny admin na DC |
| Logi | Event 4662 (Directory Service Access) | Sysmon 1 (Process) + 11 (File Creation) |
| Sieć | ruch replikacji z IP spoza DC | brak (operacja lokalna) |
| Głośność | **niska** (miesza się z replikacją) | **wysoka** (shadow copy, zapisy plików) |

---

## Ściąga Event ID (do zapamiętania)

| Event ID | Znaczenie | Atak |
|---|---|---|
| 4768 | TGT requested | AS-REP Roasting (`Pre_Auth=0`) |
| 4769 | TGS requested | Kerberoasting (`Enc_Type=0x17`) |
| 4624 | Udane logowanie | korelacja source IP |
| 4662 | Operacja na obiekcie AD | DCSync (`0x100` + GUID `1131f6ad`, konto bez `$`) |
| Sysmon 10 | ProcessAccess | LSASS dump (`TargetImage=lsass.exe`) |
| Sysmon 1 / 4688 | Process Creation | NTDS.dit (ntdsutil / vssadmin) |
| Sysmon 11 | File Creation | NTDS.dit (zapis `ntds.dit`) |

**Grupy zagrożeń używające tych technik:** BlackSuit, Akira (Kerberoasting + AS-REP), APT29/SolarWinds i Scattered Spider (DCSync). Narzędzia: Rubeus, Impacket (GetUserSPNs.py, secretsdump.py), Mimikatz, ProcDump.
