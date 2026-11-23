# Linux: co gdzie leży (ściąga do analizy artefaktów)

> Notatka własna do nauki (DFIR / SOC). Przydatna przy analizie obrazów dysków i logów. Ścieżki dotyczą typowych dystrybucji Debian/Ubuntu/Kali, a w razie różnic podaję odpowiedniki z RHEL/CentOS.

## Szybka ściąga

| Co chcę znaleźć | Gdzie szukać |
|---|---|
| Nazwa i wersja systemu | `/etc/os-release`, `/etc/lsb-release`, `/etc/issue`; awaryjnie `/boot/grub/grub.cfg` |
| Loginy (lista kont) | `/etc/passwd` |
| Hashe haseł | `/etc/shadow` (tylko root) |
| Grupy i uprawnienia sudo | `/etc/group`, `/etc/sudoers`, `/etc/sudoers.d/` |
| Logi logowań, `su`, `sudo`, SSH | `/var/log/auth.log` (Debian/Ubuntu/Kali) lub `/var/log/secure` (RHEL/CentOS) |
| Ogólne logi systemowe | `/var/log/syslog` lub `/var/log/messages` |
| Logi serwera WWW | `/var/log/apache2/` lub `/var/log/nginx/` (`access.log`, `error.log`) |
| Zainstalowane pakiety | `/var/log/dpkg.log`, `/var/log/apt/history.log` |
| Historia logowań | `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` (polecenia `last`, `lastb`, `lastlog`) |
| Historia poleceń użytkownika | `~/.bash_history` lub `~/.zsh_history` |
| Klucze SSH | `~/.ssh/` (`authorized_keys`, `id_rsa`, `known_hosts`) |
| Zadania cykliczne (trwałość) | `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/` |
| Aplikacje i polecenia | `/bin`, `/usr/bin`, `/sbin`, `/usr/sbin` |
| Programy doinstalowane ręcznie | `/opt`, `/usr/local` |
| Pliki tymczasowe | `/tmp`, `/var/tmp` |
| Strony WWW | `/var/www` |
| Jądro i bootloader | `/boot` |
| Procesy i sprzęt "na żywo" | `/proc`, `/sys`; urządzenia w `/dev` |

## Opis katalogów

- **`/etc`**: konfiguracja systemu i usług. Tu są konta (`passwd`), hashe haseł (`shadow`), nazwa systemu (`os-release`), DNS (`resolv.conf`), nazwy hostów (`hosts`) i zadania cykliczne (`crontab`).
- **`/var/log`**: logi systemu i usług. Podstawa każdej analizy po incydencie.
- **`/home/<użytkownik>`** i **`/root`**: katalogi domowe. Zawierają historię poleceń, klucze SSH, pobrane pliki (`Downloads`), dokumenty i konfiguracje programów (pliki z kropką na początku).
- **`/bin`, `/usr/bin`, `/sbin`, `/usr/sbin`**: programy i polecenia systemu.
- **`/opt`, `/usr/local`**: oprogramowanie instalowane poza menedżerem pakietów (częste miejsce narzędzi atakującego).
- **`/tmp`, `/var/tmp`**: pliki tymczasowe, zwykle zapisywalne dla wszystkich użytkowników, dlatego często wykorzystywane przez malware.
- **`/boot`**: jądro i bootloader.
- **`/proc`, `/sys`, `/dev`**: katalogi wirtualne z danymi o procesach, sprzęcie i urządzeniach (nie są zwykłymi plikami na dysku).
- **`/var/www`**: domyślny katalog stron WWW. Przy atakach na aplikacje webowe szukam tu webshelli.

## Jak to wykorzystać w analizie

1. Zacznij od **tożsamości systemu** (`/etc/os-release`) i **kont** (`/etc/passwd`).
2. Sprawdź **historię poleceń** w katalogu domowym podejrzanego użytkownika.
3. Przejrzyj **`/var/log/auth.log`**: logowania, `su`, `sudo`, SSH.
4. Poszukaj **podejrzanych plików** w `/tmp`, `/var/tmp`, `/opt` i `Downloads`.
5. Sprawdź **mechanizmy trwałości**: cron, klucze SSH (`authorized_keys`), usługi.
6. Przy serwerze WWW przejrzyj `/var/log/apache2/` lub `/var/log/nginx/` oraz `/var/www`.

## Uwagi

- Obraz dysku może zawierać tylko część katalogów (w labie FTK Imager z AD1 brakowało `etc` i `home`), więc warto znać **zamienniki**, np. nazwę systemu z `/boot/grub/grub.cfg`.
- Pusty plik ma MD5 `d41d8cd98f00b204e9800998ecf8427e`, co pomaga od razu rozpoznać pusty log.
- `/etc/passwd` nie zawiera haseł, tylko listę kont. Hashe są w `/etc/shadow`.
