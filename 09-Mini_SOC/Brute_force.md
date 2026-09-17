# Analiza zdarzeń — Attack-Host (Mini-SOC Home Lab)

## Środowisko

Maszyna wirtualna **Attack-Host** utworzona w Oracle VM VirtualBox, z zainstalowanym systemem **Ubuntu 22.04**, podłączona do izolowanej sieci laboratoryjnej (VirtualBox Host-Only Adapter, `192.168.56.0/24`), pełniąca rolę atakującego w środowisku Mini-SOC.

Adresacja: `192.168.56.102`

### Instalacja narzędzi ofensywnych

```bash
sudo apt update
sudo apt install -y hydra hping3
```

Poniżej udokumentowano scenariusz ataków przeprowadzonej z tej maszyny w stronę Wazuh Server (`192.168.56.101`), wraz z analizą 5W, wskaźnikami kompromitacji (IOC) i mapowaniem na MITRE ATT&CK.

---

## Zdarzenie 1 — Brute Force Login (SSH)

### Opis

Z maszyny Attack-Host przeprowadzono atak słownikowy (brute force) na usługę SSH działającą na Wazuh Server, próbując odgadnąć hasło użytkownika systemowego `pendragon` przy użyciu listy haseł rockyou.txt.

### Komenda wykonana

```bash
hydra -l pendragon -P ~/rockyou.txt ssh://192.168.56.101 -t 16
```

### 5W

| | |
|---|---|
| **Who (kto)** | Atakujący z maszyny Attack-Host, atakowane konto: `pendragon` |
| **What (co)** | Wielokrotne, automatyczne próby logowania SSH z różnymi hasłami ze słownika rockyou.txt |
| **When (kiedy)** | 2026-09-13 11:26:09 UTC |
| **Where (gdzie)** | Usługa SSH na Wazuh Server (192.168.56.101), źródło ataku: Attack-Host (192.168.56.102) |
| **Why (dlaczego)** | Symulacja ataku brute force w celu uzyskania nieautoryzowanego dostępu do systemu poprzez odgadnięcie hasła |

### IOC (Indicators of Compromise)

- **Narzędzie:** Hydra (The Hacker Choice) v9.2
- **Lista haseł:** rockyou.txt
- **Adres źródłowy ataku:** 192.168.56.102
- **Atakowane konto:** pendragon
- **Usługa docelowa:** SSH (port 22)
- **Liczba wątków (threads):** 16
- **Wzorzec w logach:** wielokrotne wpisy `authentication failure` w krótkim odstępie czasu (ten sam znacznik czasu, różne PID procesów `sshd`)

### Źródło detekcji

- `/var/log/auth.log` na Wazuh Server (PAM/sshd authentication failure)
- Wbudowana reguła Wazuh (SID 5716 — nieudane logowanie)
- Własna reguła Wazuh `100014` (agregacja 5 nieudanych logowań w oknie 60 sekund)

### MITRE ATT&CK

- **T1110** — Brute Force

### Surowy log (auth.log)

```
Sep 13 11:26:09 wazuhservertest sshd[3559]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1 user=pendragon
Sep 13 11:26:09 wazuhservertest sshd[3558]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1 user=pendragon
Sep 13 11:26:09 wazuhservertest sshd[3550]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1 user=pendragon
Sep 13 11:26:09 wazuhservertest sshd[3549]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1 user=pendragon
Sep 13 11:26:09 wazuhservertest sshd[3548]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1 user=pendragon
Sep 13 11:26:09 wazuhservertest sshd[3547]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1 user=pendragon
Sep 13 11:26:09 wazuhservertest sshd[3551]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.56.1 user=pendragon
```
<img width="1920" height="963" alt="image" src="https://github.com/user-attachments/assets/aa14e9b4-d6af-4376-9804-d241bc7667bb" />
<img width="1920" height="952" alt="image" src="https://github.com/user-attachments/assets/4ae895ff-6b6e-4c1d-b3e7-08b6df680bf1" />

---


## Podsumowanie

| Zdarzenie | Narzędzie | Źródło detekcji | Reguła | MITRE ATT&CK |
|---|---|---|---|---|
| Brute Force SSH | Hydra | auth.log + Wazuh | SID 5716, własna 100014 | T1110 |
