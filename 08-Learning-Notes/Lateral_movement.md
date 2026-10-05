# Lateral Movement - notatka analityka SOC

Po przejęciu pierwszej maszyny atakujący rusza w głąb sieci do celu (DC, baza danych, plik z danymi). Zawsze ten sam wzorzec: **uwierzytelnij się do zdalnej maszyny skradzionymi poświadczeniami -> wykonaj coś na niej** (authenticate-then-execute). Zmienia się tylko technika. Zanim zacznie się ruch, atakujący robi **discovery** - mapuje domenę, żeby wiedzieć gdzie iść.

**Model source/destination (klucz do całej notatki):** każde zdalne połączenie zostawia ślady na DWÓCH maszynach.
- **Source** (skąd atak wyszedł): widać JAKIE poświadczenia użyto i JAKI cel wybrano. Sygnał: **Event 4648**, Sysmon 1 (`net.exe`, `mstsc.exe`, `PsExec.exe`).
- **Destination** (gdzie wylądował): widać ŻE ktoś się połączył i CO zrobił. Sygnał: **Event 4624**, 5140/5145, 7045.

Tylko destination = wiemy że atak był, nie wiemy skąd. Tylko source = znamy intencję, nie wiemy czy się udało. Potrzebujemy obu.

**Co to za eventy (szybkie wyjaśnienie):**
- **4624** - udane logowanie na destination. Pole `Logon_Type` mówi JAK ktoś wszedł (3=SMB/PsExec, 10=RDP). Podstawowy event każdego zdalnego połączenia.
- **4648** - logowanie z jawnie podanymi poświadczeniami (Explicit Credentials), na source. Odpala gdy proces używa INNEGO konta niż zalogowany user (np. `net use /user:...`, `runas`). Pokazuje kto siedział przy klawiaturze + jakie obce konto podstawił.
- **5140** - dostęp do udziału sieciowego (share). Loguje KTÓRY share dotknięto (np. `ADMIN$`, `C$`), z jakiego IP i jakim kontem. Sercem detekcji SMB.
- **5145** - szczegółowy dostęp do share. To samo co 5140, ale idzie głębiej: loguje KONKRETNE pliki/obiekty dotknięte przez share (pole `Relative_Target_Name`). Przy PsExec pokazuje nazwy named pipe'ów.
- **7045** - instalacja nowego serwisu Windows na destination. **Sygnatura PsExec** (domyślnie serwis `PSEXESVC`). Odpala niezależnie od nazwy serwisu.

> Uwaga: 5140 i 5145 wymagają włączonego audytu "Audit File Share" / "Audit Detailed File Share" w GPO - bez tego nie ma tych logów mimo że aktywność była.

---

## Logon Type - pierwsza rzecz do sprawdzenia

Na destination Windows loguje **Event 4624**, a pole `Logon_Type` mówi JAK ktoś się połączył. To rozdziela techniki:

| Logon_Type | Znaczenie | Protokół | Co mówi |
|---|---|---|---|
| **3** | Network logon | SMB, PsExec | zdalny dostęp bez sesji interaktywnej |
| **7** | Unlock/Reconnect | RDP | wznowienie sesji / odblokowanie |
| **10** | RemoteInteractive | RDP | pełna sesja pulpitu |

- **Type 10 = zawsze RDP** (proste).
- **Type 3 = SMB albo PsExec** - oba dają Type 3, więc potrzeba dodatkowych artefaktów żeby je rozróżnić (patrz niżej).
- **Type 7 z zdalnym IP (nie 127.0.0.1) = RDP reconnect**, nie fizyczne odblokowanie. Filtrując tylko `Logon_Type=10` przegapisz wznowienia sesji.

**Event 4648 (Explicit Credentials):** odpala się na SOURCE, gdy proces używa INNYCH poświadczeń niż zalogowany user (np. `net use ... /user:luke.sullivan` uruchomione przez `liam.patel`). Loguje konto oryginalne, konto alternatywne i cel. **UWAGA:** nie odpala się dla Pass-the-Hash / Pass-the-Ticket / Kerberos SSO - bo tam poświadczenia są reużywane z cache, nie podawane jawnie.

**Normalne vs podejrzane = kontekst** (te same Event ID generuje admin i atakujący): źródło (workstation IT vs marketingu), konto (admin vs HR user grzebiący w admin shares), czas (godziny pracy vs 2 w nocy w sobotę), wzorzec (jeden serwer vs szybkie skoki po wielu).

---

## 0. Discovery (rozpoznanie przed ruchem)

**Co to:** po wejściu do sieci atakujący nie wie co w niej jest. Odpala wbudowane komendy, żeby zmapować konta domenowe, grupy, trusty i maszyny. **Żadna z nich nie wymaga uprawnień admina** - AD domyślnie daje odczyt każdemu uwierzytelnionemu userowi. To "living off the land" (LOTL): natywne komendy nie ruszają antywirusa.

**Najczęstsze komendy:**
- `nltest /dclist` - lista kontrolerów domeny; `/domain_trusts` - zaufane domeny do pivotu.
- `net user /domain` - wszystkie konta domenowe; `net group "Domain Admins" /domain` - członkowie Domain Admins (kluczowe cele).
- `net view` - maszyny widoczne w sieci.
- PowerShell `Get-ADUser` - userzy, `Get-ADGroupMember` - skład grupy, `Get-ADComputer` - konta komputerów.
- Narzędzia third-party: `adfind.exe` (Conti, FIN7), `dsquery` - surowe zapytania LDAP do AD.

**Sygnał:** Sysmon **Event 1** (process create, komenda w linii poleceń) oraz PowerShell **Event 4104** (Script Block Logging - łapie cmdlety nawet gdy odpalane interaktywnie w jednej sesji, odporny na base64).

**Filtr - komendy discovery (cmd/net):**
```spl
index=win EventCode=1
| search CommandLine IN ("*nltest*", "*net * user*", "*net * group*", "*net * view*", "*net * localgroup*")
| table _time, host, User, Image, CommandLine, ParentImage
| sort _time
```
*Wykrywa klasyczne komendy rozpoznania. Discovery na workstation, który normalnie tego nie robi, w wąskim oknie czasowym = mocny sygnał.*

**Filtr - discovery przez PowerShell:**
```spl
index=win EventCode=4104
| search Message IN ("*Get-ADUser*", "*Get-ADGroupMember*", "*Get-ADComputer*")
| table _time, Message
| sort _time
```
*Pole `Message` zawiera cały blok skryptu z cmdletem i parametrami. 4104 łapie to, czego Sysmon 1 nie złapie - pojedyncze cmdlety wewnątrz jednej sesji PowerShell.*

---

## Co to jest SMB

**SMB (Server Message Block)** - protokół Windows do współdzielenia plików, drukarek i zdalnego zarządzania, działa na **porcie 445**. Najpopularniejszy i **najgłośniejszy** kanał lateral movement: mapowanie dysków sieciowych, otwieranie dokumentów, GPO, agenci backupu - wszystko to SMB. Masa legalnego ruchu = atakujący się w nim chowa.

**Admin Shares** - ukryte udziały administracyjne tworzone automatycznie przez Windows przy starcie:
- **C$** - root dysku systemowego (D$, E$ analogicznie).
- **ADMIN$** - wskazuje na `%SystemRoot%` (zwykle `C:\Windows`).
- **IPC$** - logiczny udział do komunikacji między procesami (named pipes), potrzebny do zdalnych RPC.

**Zwykli użytkownicy NIE używają admin shares.** Korzystają z nazwanych udziałów (`Marketing`, `IT`). Dostęp do ADMIN$/C$ = albo admin robi maintenance, albo atakujący rusza lateralnie.

---

## 1. SMB Admin Shares (T1021.002)

**Co to:** atakujący uwierzytelnia się skradzionymi poświadczeniami do admin share (`net use \\target\c$ /user:...`), kopiuje malware, czasem tworzy zdalny serwis żeby go odpalić. Sam dostęp do share kopiuje pliki, ale **nic nie wykonuje** (do wykonania służy PsExec - niżej).

**Sygnał:** na destination **Event 5140** (A network share object was accessed) + **Event 4624** (logon, Type 3). Na source **Event 4648** + Sysmon 1 (`net use` w linii komend).

**Filtr - dostęp do ADMIN$/C$ (destination):**
```spl
index=win EventCode=5140 Share_Name IN ("*\\ADMIN$\*", "*\\C$\*")
| table _time, host, Source_Address, user, Share_Name
| sort _time
```
*5140 daje wszystko w jednym evencie: `host` (co zaatakowano), `Source_Address` (skąd), `user` (jakie konto), `Share_Name` (który udział). Jedno IP sięgające ADMIN$ na wielu serwerach = mocny wskaźnik ruchu lateralnego.*

**Filtr - baseline usera (czy to naprawdę podejrzane):**
```spl
index=win EventCode=5140 user={USER_ACCOUNT}
| table _time, Source_Address, Share_Name, host
| sort _time
```
*Porównujemy z normą. IT admin łączący się z udziału IT ze swojej stacji = OK. Ten sam user sięgający nagle wielu ADMIN$ z obcej maszyny marketingu = kradzież poświadczeń.*

**Filtr - mapowanie IP na hostname (konto maszynowe):**
```spl
index=win EventCode=4624 Source_Network_Address={SOURCE_IP} user=*$
| stats count by user, Source_Network_Address
| sort -count
```
*Każdy komputer w AD uwierzytelnia się kontem maszynowym kończącym się na `$` o nazwie = hostname. Mamy IP, chcemy nazwę maszyny, żeby pivotować dalej. User kończący się na `$` zdradza hostname - odrzuć `$` i masz nazwę.*

**Filtr - komendy na source:**
```spl
index=win EventCode=1 host={SOURCE_HOST} CommandLine="*ADMIN$*"
| table _time, User, Image, CommandLine
| sort _time
```
*Teraz widać kto siedział przy klawiaturze (`User`) i jakich skradzionych poświadczeń użył (w `CommandLine` po `/user:`). Dwa różne konta = klasyczne nadużycie poświadczeń.*

**UWAGA konfiguracja:** 5140/5145 wymagają włączonego "Audit File Share" / "Audit Detailed File Share" w GPO. Zero wyników nie znaczy że nic nie było - może audyt wyłączony. Frameworki C2 (Cobalt Strike, Metasploit) mają wbudowane moduły SMB bez `net.exe` -> brak Sysmon 1 na source, ale 4648 i 5140 nadal odpalą.

---

## Co to jest PsExec

**PsExec** - legalne narzędzie Sysinternals (Microsoft) do uruchamiania komend na zdalnych maszynach. Admini używają go codziennie do patchowania, skryptów, troubleshootingu. Łączy **dostęp do ADMIN$ przez SMB** z **instalacją serwisu Windows** - i to pozwala WYKONAĆ kod zdalnie (czego sam SMB nie robi). Z perspektywy protokołu wygląda identycznie jak normalny ruch SMB; różni go tylko kontekst (jakie konto, z jakiej maszyny, kiedy).

**Jak PsExec działa pod spodem** (zostawia bardzo konkretny ślad):
1. Łączy się z **ADMIN$** celu przez SMB.
2. Kopiuje binarkę serwisu **PSEXESVC.exe** do `C:\Windows`.
3. Tworzy i uruchamia nowy serwis -> **Event 7045** (sygnatura PsExec).
4. Serwis tworzy **named pipes** (stdin/stdout/stderr) -> **Sysmon Event 17**.
5. Serwis wykonuje komendę atakującego.
6. Po sesji - usuwa serwis i czyści binarkę.

Domyślnie komenda leci jako user uwierzytelniający; z flagą **`-s`** serwis działa jako **LocalSystem (SYSTEM)**.

---

## 2. PsExec (T1569.002)

**Sygnał główny:** **Event 7045** (A New Service Was Installed) na destination - to odróżnia PsExec od zwykłego SMB.

**Filtr - instalacja serwisu (destination, sygnatura):**
```spl
index=win EventCode=7045
| table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Service_Account
| sort _time
```
*Domyślnie `Service_Name=PSEXESVC`, `Service_File_Name=C:\Windows\PSEXESVC.exe`. `Service_Account` mówi pod jakim kontem leci serwis (LocalSystem = użyto `-s`).*

**Filtr - jakie komendy odpalono przez PsExec:**
```spl
index=win EventCode=1 host={DESTINATION_HOST} ParentImage="*PSEXESVC*"
| table _time, host, User, ParentImage, Image, CommandLine
| sort _time
```
*PSEXESVC.exe jest rodzicem (`ParentImage`) wszystkich zdalnie odpalonych komend. Filtrując po nim widzimy dokładnie co atakujący wykonał na zdalnej maszynie.*

**Filtr - named pipes (Sysmon 17):**
```spl
index=win EventCode=17 Image="*PSEXESVC*"
| table _time, host, Image, PipeName
| sort _time
```
*Pipe'y mają nazwy `\PSEXESVC-<hostname>-<pid>-stdin/stdout/stderr`. Nazwa pipe'a zawiera hostname SOURCE - zdradza z jakiej maszyny atakujący operuje. Wzorzec nazw zostaje nawet po zmianie nazwy binarki.*

**Filtr - dostęp do plików/pipe'ów przez share (Event 5145):**
```spl
index=win EventCode=5145 host={DESTINATION_HOST} Relative_Target_Name="*PSEXE*"
| table _time, user, Source_Address, Share_Name, Relative_Target_Name
| sort _time
```
*5145 loguje konkretne obiekty dotknięte przez share (`Relative_Target_Name`). Dla PsExec to kopalnia: widać usera, source IP i nazwy pipe'ów zawierające hostname atakującego.*

**Filtr - PsExec na source:**
```spl
index=win EventCode=1 host={SOURCE_HOST} Image="*PsExec*"
| table _time, host, User, Image, CommandLine
| sort _time
```
*`CommandLine` pokazuje jaki cel wskazano i jaką komendę puszczono zdalnie. Korelacja source + destination = pełny obraz.*

**Hunting za przemianowanym PsExec:** atakujący wiedzą, że szukamy `PSEXESVC` po nazwie. Flaga `-r` zmienia nazwę serwisu; Impacket/Cobalt Strike generują losowe. Ale **Event 7045 odpala niezależnie od nazwy.** Szukaj wzorca: nowy serwis z `Service_Type = "user mode service"` + `Service_Start_Type = "demand start"`. Nazwa i binarka się zmienią, sygnatura user-mode + demand-start zostaje.

---

## Co to jest RDP

**RDP (Remote Desktop Protocol)** - protokół Windows dający **pełny interaktywny pulpit** zdalnej maszyny (klient: `mstsc.exe`). W odróżnieniu od SMB/PsExec nie zostawia unikalnej sygnatury typu instalacji serwisu - dlatego RDP rzadko hunt-ujemy bezpośrednio, częściej znajdujemy go jako kanał dostawy PO tym, jak coś innego wzbudzi alert.

**Główny artefakt:** **Event 4624 z `Logon_Type=10`** (RemoteInteractive) na destination - konto, source IP, czas. Type 10 od razu odróżnia RDP od SMB/PsExec (które dają Type 3).

**NLA (Network Level Authentication)** - domyślnie włączone. User uwierzytelnia się na poziomie sieci ZANIM powstanie sesja RDP -> generuje krótki **Type 3 tuż przed Type 10** z tego samego IP. To prolog NLA, nie osobne połączenie SMB.

**Normalne vs podejrzane (kierunek połączenia):** Workstation -> Server = normalne (admin IT). Workstation -> Workstation = rzadkie. **Server -> Server = podejrzane** (serwery same z siebie nie inicjują RDP; ktoś siedzi w sesji i pivotuje).

---

## 3. RDP (T1021.001)

**Scenariusz śledztwa (od alertu do źródła):** zwykle nie zaczynamy od logów RDP (za głośne), tylko od alertu - np. komendy discovery na DC. Potem cofamy się przez `LogonId`.

**Filtr - komendy discovery na DC (start):**
```spl
index=win EventCode=1 host=THM-DC
| search CommandLine IN ("*nltest*", "*net * user*", "*net * group*", "*net * view*")
| table _time, host, User, Image, CommandLine, LogonId
| sort _time
```
*`LogonId` mówi do której sesji należą te komendy - to klucz do cofnięcia się.*

**Filtr - jak powstała ta sesja (korelacja LogonId -> 4624):**
```spl
index=win EventCode=4624 host=THM-DC Logon_ID={LOGON_ID}
| table _time, user, Logon_Type, Source_Network_Address, Logon_ID
```
*`Logon_Type=10` = atakujący doszedł do DC przez RDP. `Source_Network_Address` = skąd się połączył.*

**Filtr - mapowanie source IP na hostname:**
```spl
index=win EventCode=4624 Source_Network_Address={SOURCE_IP} user=*$
| stats count by user, Source_Network_Address
| sort -count
```
*Ta sama technika konta maszynowego `$` co przy SMB. Daje nazwę maszyny pośredniej.*

**Filtr - dowód wychodzącego RDP na source (mstsc.exe):**
```spl
index=win EventCode=1 host={SOURCE_SERVER} Image="*mstsc.exe*"
| table _time, User, Image, CommandLine, LogonId
| sort _time
```
*`mstsc.exe` (klient RDP) uruchamia się na maszynie inicjującej połączenie. Potwierdza wychodzące RDP w stronę DC.*

**Filtr - jak atakujący dostał się na maszynę pośrednią (kolejny hop):**
```spl
index=win EventCode=4624 host={SOURCE_SERVER} Logon_ID={LOGON_ID}
| table _time, user, Logon_Type, Source_Network_Address, Logon_ID
```
*Widać kolejne logowanie RDP, ale z innego usera i innego IP.*

**RDP chaining:** atakujący zaczyna na workstation, przez RDP wchodzi na serwer, a z tej sesji otwiera KOLEJNE RDP do DC - często bardziej uprzywilejowanym kontem. Każdy hop to RDP, ale source IP zmienia się na każdym skoku (połączenie wychodzi z maszyny pośredniej, nie z oryginalnej). Pivot przez maszyny pośrednie do celów typu DC. **UWAGA:** reconnect przydziela nowy `Logon_ID` mimo że sesja RDP trwa - korelacja po `Logon_ID` może się urwać na granicy disconnect/reconnect.

---

## Ściąga Event ID (do zapamiętania)

| Event ID | Znaczenie | Technika / sygnał |
|---|---|---|
| 4624 | Udane logowanie (destination) | Logon_Type **3**=SMB/PsExec, **7**=RDP reconnect, **10**=RDP |
| 4648 | Explicit Credentials (source) | kto + jakie konto alternatywne + cel (nie łapie PtH/PtT) |
| 5140 | Dostęp do share (destination) | SMB admin shares (`ADMIN$`, `C$`) |
| 5145 | Detailed File Share (destination) | PsExec (`Relative_Target_Name=*PSEXE*`, nazwy pipe'ów) |
| 7045 | Instalacja serwisu (destination) | **sygnatura PsExec** (`PSEXESVC`; renamed: user-mode + demand-start) |
| Sysmon 1 / 4688 | Process Creation | discovery, `net use`, `PsExec.exe`, `mstsc.exe` |
| Sysmon 17 | Pipe Created (destination) | named pipes PsExec (`PSEXESVC-<host>-<pid>-std*`) |
| 4104 | PowerShell Script Block | discovery przez cmdlety (`Get-AD*`) |

## Model source vs destination - ściąga

| | Source (skąd) | Destination (gdzie) |
|---|---|---|
| Co widać | jakie poświadczenia, jaki cel | że ktoś wszedł, co zrobił |
| SMB | 4648, Sysmon 1 (`net use`) | 5140, 4624 (Type 3) |
| PsExec | Sysmon 1 (`PsExec.exe`) | 7045, Sysmon 17, 5145, 4624 (Type 3) |
| RDP | Sysmon 1 (`mstsc.exe`) | 4624 (Type 10) |

**Dlaczego lateral movement działa:** reużycie haseł kont lokalnych (LAPS temu zapobiega), współdzielone konta admin, zbyt szerokie członkostwa w grupach, zła segmentacja sieci, RDP włączone tam gdzie niepotrzebne. Jedno przejęte poświadczenie otwiera całą sieć.

**Grupy zagrożeń:** BlackSuit (RDP+PsExec+SMB), Wizard Spider/Ryuk/Conti (PsExec do deploymentu ransomware), Earth Kurma (admin shares), Volt Typhoon (LOTL discovery). Narzędzia: PsExec, Impacket (psexec.py), Cobalt Strike, adfind.exe.
