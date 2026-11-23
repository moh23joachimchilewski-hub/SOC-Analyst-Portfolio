# Analiza obrazu dysku Linux (Kali) w FTK Imager: lab CyberDefenders "Insider"

> Ćwiczenie szkoleniowe (publiczny lab CyberDefenders, dane fikcyjne). Notatka nie zawiera danych klientów. Nazwy plików, hostów i adresy pochodzą wyłącznie z materiału labu.

## 1. Kontekst

- **Zadanie:** przeanalizować obraz dysku maszyny z Linuksem (konto "Karen"), ustalić, jakich narzędzi używano, co zostało uruchomione i czy maszyna posłużyła do ataku na inną.
- **Taktyki z opisu labu:** Execution, Credential Access.
- **Narzędzie:** Exterro FTK Imager 8.3.1.6 (tylko odczyt, nic nie uruchamiam na hoście).
- **Materiał:** `FirstHack.ad1` (87 719 990 B, Custom Content Image), partycja ext4 `Horcrux.E01:Partition 5 [14304MB]`.
- **Przeglądanie:** File > Add Evidence Item > Image File. Podgląd plików w dolnym panelu (tekst/hex), hashe przez **Export File Hash List**.
- **Ważna obserwacja:** obraz AD1 zawiera tylko wybrane katalogi (`boot`, `root`, `var`). Nie ma katalogu `etc` ani `home`, więc część standardowych artefaktów (np. `/etc/os-release`) nie jest dostępna.

<img width="1198" height="1019" alt="Zrzut ekranu (1581)" src="https://github.com/user-attachments/assets/3c34bff4-8445-49da-93f0-ca32e568de6d" />

*Drzewo dowodów: dostępne tylko `boot`, `root`, `var`. Lista plików jest pusta, bo zaznaczony jest najwyższy węzeł.*

## 2. Szczegóły: gdzie szukałem, dlaczego tam i co mi nie wyszło

### Q1: dystrybucja
- **Pierwszy pomysł:** `/etc/os-release`. **Nie wyszło:** w drzewie nie ma katalogu `etc` (obraz zawiera tylko `boot`, `root`, `var`).
- **Co zadziałało:** `/boot/grub/grub.cfg`. Wpis `menuentry 'Kali GNU/Linux' --class kali` oraz linia `Loading Linux 4.13.0-kali1-amd64` jednoznacznie wskazują dystrybucję.
- **Dlaczego tam:** GRUB zapisuje nazwę systemu w menu startowym, a katalog `boot` był dostępny.

<img width="1920" height="1026" alt="Zrzut ekranu (1582)" src="https://github.com/user-attachments/assets/0673dc19-fbba-4798-965e-692633545a6c" />
*`/boot/grub/grub.cfg`: wpis menu startowego Kali GNU/Linux.*

### Q2: MD5 `access.log`
- **Gdzie:** `/var/log/apache2/`, plik `access.log` (rozmiar 0 KB).
- **Jak:** prawy przycisk na pliku, **Export File Hash List**. Powstał `md5.csv` (236 B) obok pliku obrazu, który odczytałem w PowerShellu.
- **Wniosek:** hash `d41d8cd98f00b204e9800998ecf8427e` to znany MD5 **pustego pliku**, co zgadza się z rozmiarem 0 KB. SHA-1 w CSV (`da39a3ee5e6b4b0d3255bfef95601890afd80709`) to analogicznie SHA-1 pustego wejścia.

<img width="1920" height="152" alt="Zrzut ekranu (1583)" src="https://github.com/user-attachments/assets/29b36f1e-8ba6-4d31-9276-e99b8de55130" />

*Folder z labu: `FirstHack.ad1`, `FirstHack.ad1.txt` i wygenerowany `md5.csv`.*

<img width="1920" height="285" alt="Zrzut ekranu (1600)" src="https://github.com/user-attachments/assets/c2188ec8-1fa6-45e0-b3f8-8dff0f2eb65a" />

*Zawartość `md5.csv`: MD5 i SHA-1 pliku `access.log`.*

### Q3: narzędzie do dumpowania poświadczeń
- **Gdzie:** `/root/Downloads`. Tam leży `mimikatz_trunk.zip` (845 749 B), utworzony 22.03.2019 03:04:08.
- **Błądzenie:** najpierw trafiłem na `/root/Desktop/mimikatz` (`mimikatz.exe`, `mimilib.dll`, `mimidrv.sys`), czyli **rozpakowane** narzędzie. Pytanie dotyczy jednak **pobranego pliku**, więc właściwa odpowiedź to archiwum z `Downloads`, a nie `mimikatz.exe`.
- **Bezpieczeństwo:** wszystko oglądałem tylko w FTK Imager. Plików nie eksportowałem i nie uruchamiałem.

<img width="1920" height="536" alt="Zrzut ekranu (1584)" src="https://github.com/user-attachments/assets/42bae967-32ad-4f6d-95dd-b72f4cf532c8" />

*`/root/Downloads`: archiwum `mimikatz_trunk.zip`.*

<img width="1920" height="318" alt="Zrzut ekranu (1588)" src="https://github.com/user-attachments/assets/bb038f80-a1de-44ec-ad97-6b9375d5de7b" />

*`/root/Desktop/mimikatz`: rozpakowane pliki narzędzia (kontekst, nie odpowiedź).*

### Q4 i Q5: `.bash_history`
- **Gdzie:** `/root/.bash_history` (1 435 B, ostatnia modyfikacja 22.03.2019 05:48:44). Kliknąć trzeba sam folder `root`, a nie jego podfoldery.
- **Błądzenie:** na początku klikałem w drzewie folder `.binwalk/magic` i widziałem tam tylko plik `binarch` (0 KB). To konfiguracja narzędzia, nie ślad użycia. Historia leży w katalogu `/root`, nie w podfolderze.
- **Q4:** polecenia `touch snky snky > /root/Desktop/SuperSecretFile.txt` i `cat snky snky > ...` wskazują ścieżkę. Na zrzucie `Desktop` widzę tylko folder `mimikatz` i plik `Checklist`, więc ścieżka wynika z historii poleceń, a nie z istniejącego pliku na dysku.
- **Q5:** linia `binwalk didyouthinkwedmakeiteasy.jpg`.

<img width="1920" height="542" alt="Zrzut ekranu (1586)" src="https://github.com/user-attachments/assets/fb064096-35d4-496a-b090-858cb8c180ff" />
*Lista plików w `/root` i początek `.bash_history` ze ścieżką `SuperSecretFile.txt`. Na liście widać też `irZLAohL.jpeg` (Q8).*

<img width="1920" height="220" alt="Zrzut ekranu (1587)" src="https://github.com/user-attachments/assets/373723ce-4892-4bb7-b4bf-5f70d9292e85" />
*Koniec `.bash_history`: polecenie `binwalk didyouthinkwedmakeiteasy.jpg`.*

<img width="1920" height="1080" alt="Zrzut ekranu (1585)" src="https://github.com/user-attachments/assets/44c817c4-9c07-469e-80ab-fcbc32bbb43d" />
*Przykład błądzenia: `.binwalk/magic` zawiera tylko konfigurację (`binarch`, 0 KB).*

### Q6: lista celów Karen
- **Gdzie:** `/root/Desktop/Checklist` (60 B).
- **Zawartość:** `Gain Bob's Trust`, `Learn how to hack`, `Profit`. Trzeci punkt to `Profit`.
- **Błądzenie:** najpierw miałem otwarty podfolder `Desktop/mimikatz`, gdzie widać było tylko pliki narzędzia. Plik z listą pojawił się dopiero po kliknięciu samego folderu `Desktop`.

<img width="1920" height="551" alt="Zrzut ekranu (1589)" src="https://github.com/user-attachments/assets/66eef48a-b43a-4a0c-962d-f677d30b3fe9" />
*`/root/Desktop`: folder `mimikatz` i plik `Checklist` z trzema punktami.*

### Q7: uruchomienia Apache
- **Gdzie:** `/var/log/apache2/`: `access.log`, `error.log`, `other_vhosts_access.log`, wszystkie po 0 KB.
- **Wniosek:** brak zapisów, więc odpowiedź `0`. To wniosek z **pustych logów**, a nie z wpisu o starcie usługi. Wiarygodność ogranicza fakt, że obraz zawiera tylko część katalogów.

<img width="1920" height="990" alt="Zrzut ekranu (1590)" src="https://github.com/user-attachments/assets/dbcf06dc-04d9-40aa-a1f8-5f87ab4e77e8" />
*`/var/log/apache2/`: wszystkie trzy logi mają 0 KB.*

### Q8: dowód ataku na inną maszynę
- **Gdzie:** `/root/`, plik `irZLAohL.jpeg` (130 859 B, utworzony 22.03.2019 05:39:18). Podpowiedź labu mówi o obrazie w katalogu root, który pokazuje wiersz poleceń z podwyższonymi uprawnieniami.
- **Błądzenie (ważne):** najpierw zakładałem, że chodzi o `didyouthinkwedmakeiteasy.jpg` z `Documents/myfirsthack`, bo ten plik występuje w historii z `binwalk`. To był błędny trop. Właściwy plik to obraz z **losową nazwą** leżący bezpośrednio w `/root`.
- **Drugi trop, który nie był odpowiedzią:** polecenia msfconsole (skan `db_nmap`, exploit Rejetto na `10.0.0.101`, próby `bypassuac`) świadczą o atakach, ale pytanie dotyczy konkretnego **pliku**.
- **Lekcja:** gdy pytanie podaje typ pliku (obraz) i katalog, najpierw przejrzeć listę plików w tym katalogu, a dopiero potem budować hipotezy z historii poleceń.

*Plik `irZLAohL.jpeg` widać na liście plików na zrzucie `07_bash_history_supersecretfile.png` (sekcja Q4 i Q5).*

### Q9: taunting w skrypcie
- **Gdzie:** `/root/Documents/myfirsthack/`. W folderze są `bob.txt`, `firstscript`, `firstscript_fixed`, `hellworld.sh`, `didyouthinkwedmakeiteasy.jpg`.
- **Wskazanie:** `firstscript_fixed` zawiera m.in. `echo "Heck yeah! I can write bash too Young"`. Nazwisko eksperta to `Young`.
- **Wcześniej:** `firstscript` zawiera tylko `pwd`, `ip route | grep default`, `netstat | grep 80`, więc nie jest to właściwy plik.

<img width="1920" height="1080" alt="Zrzut ekranu (1591)" src="https://github.com/user-attachments/assets/b7289428-08e1-4e11-a234-e0b0cf6884f2" />

*`/root/Documents/myfirsthack/`: lista plików i treść `firstscript` (zwykłe polecenia diagnostyczne).*

<img width="1920" height="582" alt="Zrzut ekranu (1592)" src="https://github.com/user-attachments/assets/c1a5bd03-f234-4249-9d6a-110a2ce7b64f" />
*`firstscript_fixed`: ostatnia linia `echo` z nazwiskiem eksperta.*

### Q10: `su` o 11:26
- **Gdzie:** `/var/log/auth.log` (191 845 B). Po kliknięciu samego folderu `log` plik widać na liście plików.
- **Wpisy:** `Mar 20 11:26:22 KarenHacker su[4060]: Successful su for postgres by root` i kolejne `su[4074]`, `su[4081]`, `su[4094]`, `su[4101]` w ciągu około sekundy. Poprzedza je zadanie `CRON` o 11:25:01.
- **Interpretacja:** `root` wielokrotnie przełączał się na konto `postgres`. Odpowiedź platformy to `postgres`. Hipoteza (niezweryfikowana): ma to związek z uruchomieniem bazy PostgreSQL dla Metasploita (`systemctl start postgresql`, `msfdb init` w historii).
- **Uwaga:** log nie zawiera roku. Rok 2019 wnioskuję z metadanych plików.

<img width="1920" height="968" alt="Zrzut ekranu (1593)" src="https://github.com/user-attachments/assets/1e11b101-44c2-4c0d-bbda-80ceb1fc3549" />
*`/var/log/auth.log`: seria `su` z `root` na `postgres` o 11:26:22.*

### Q11: katalog roboczy z historii
Prześledziłem kolejne `cd` od początku sesji (start w `/root`):

1. `cd Documents/`, `cd myfirsthack/` → `/root/Documents/myfirsthack`
2. `cd ..` → `/root/Documents`; `cd..` (literówka, błąd); `cd ..` → `/root`
3. `cd /var/log/` → `/var/log`; `cd ..` → `/var`; `cd ~` → `/root`
4. `cd ..` → `/`; `cd home/` → `/home`; `cd /root` → `/root`
5. `cd ../root/Documents/myfirsthack/../../Desktop/` → `/root/Desktop`
6. `cd ../Documents/myfirsthack/` → **`/root/Documents/myfirsthack`**

Po tym `cd` do `exit` nie ma kolejnej zmiany katalogu. Polecenia `touch keys.txt` i `pwd` po `exit` należą do kolejnej sesji.

## 3. IOC (z obrazu, wszystko z laboratorium)

| Typ | Wartość |
|---|---|
| Nazwa hosta w logach | `KarenHacker` |
| Narzędzie (archiwum) | `/root/Downloads/mimikatz_trunk.zip` (845 749 B) |
| Narzędzie (rozpakowane) | `/root/Desktop/mimikatz/mimikatz.exe` (927 384 B), `mimilib.dll` (46 232 B), `mimidrv.sys` (36 088 B) |
| Plik z historii | `/root/Desktop/SuperSecretFile.txt` (ścieżka z historii poleceń) |
| Plik pomocniczy | `/root/Desktop/Checklist` (60 B) |
| Obraz-dowód | `/root/irZLAohL.jpeg` (130 859 B) |
| Plik z `binwalk` | `/root/Documents/myfirsthack/didyouthinkwedmakeiteasy.jpg` (1 865 B) |
| Hash (pusty plik) | `access.log` MD5 `d41d8cd98f00b204e9800998ecf8427e`, SHA-1 `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| Cel w historii msfconsole | `10.0.0.101` (adres prywatny z labu) |
| Moduły Metasploit | `exploit/windows/http/rejetto_hfs_exec`, `exploit/windows/smb/ms17_010_eternalblue`, `exploit/windows/local/bypassuac_fodhelper` |
| Workspace Metasploit | `Bob` |
| Aktywność `su` | `root` → `postgres`, 20 Mar, 11:26:22 do 11:26:23 |

## 4. Mapowanie na MITRE ATT&CK (orientacyjne)

- **T1003** OS Credential Dumping: Mimikatz.
- **T1548.002** Bypass User Account Control: próby `bypassuac` w historii msfconsole.
- **T1190** Exploit Public-Facing Application: Rejetto HFS w historii msfconsole.
- **T1046** Network Service Discovery: `db_nmap`.
- **T1059.004** Unix Shell: skrypty `.sh` i polecenia z historii.

## 5. Wnioski i lekcje

1. Zaczynać od historii poleceń w katalogu domowym i listy plików w `/root`, a nie od dalekich podfolderów.
2. Kliknięcie samego folderu pokazuje jego pliki. Kliknięcie podfolderu zmienia widok i łatwo zgubić trop (przykład: `.binwalk/magic`).
3. Warto znać hashe pustego wejścia: MD5 `d41d8cd98f00b204e9800998ecf8427e` i SHA-1 `da39a3ee5e6b4b0d3255bfef95601890afd80709`. Pozwalają od razu rozpoznać pusty plik.
4. Pytania o "pobrany plik" i "narzędzie" mogą mieć inną odpowiedź (archiwum vs rozpakowany plik).
5. Hipotezy z historii poleceń sprawdzać na plikach: historia pokazuje, co wpisano, a nie co się udało.

## 6. Potwierdzenie wyników

<img width="1001" height="579" alt="Zrzut ekranu (1594)" src="https://github.com/user-attachments/assets/2904c3c5-3d81-4276-81f7-06686ffac3d5" />
<img width="980" height="687" alt="Zrzut ekranu (1595)" src="https://github.com/user-attachments/assets/7478128b-374d-492b-af76-94a92867ed67" />
<img width="970" height="527" alt="Zrzut ekranu (1596)" src="https://github.com/user-attachments/assets/e86e2322-e277-42e3-a8d7-44e21ba29ff9" />
<img width="989" height="180" alt="Zrzut ekranu (1597)" src="https://github.com/user-attachments/assets/38e4a1eb-566f-4e3c-a937-49430b8323e2" />
