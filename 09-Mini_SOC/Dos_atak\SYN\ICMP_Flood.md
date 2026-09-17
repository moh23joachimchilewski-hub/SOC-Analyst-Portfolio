# Analiza zdarzeń — Attack-Host (Mini-SOC Home Lab)

## Środowisko

Maszyna wirtualna **Attack-Host** utworzona w Oracle VM VirtualBox, z zainstalowanym systemem **Ubuntu 22.04**, podłączona do izolowanej sieci laboratoryjnej (VirtualBox Host-Only Adapter, `192.168.56.0/24`), pełniąca rolę atakującego w środowisku Mini-SOC.

Adresacja: `192.168.56.102`

### Instalacja narzędzi ofensywnych

```bash
sudo apt update
sudo apt install -y hydra hping3
```

Poniżej udokumentowano scenariusz ataków przeprowadzonych z tej maszyny w stronę Wazuh Server (`192.168.56.101`), wraz z analizą 5W, wskaźnikami kompromitacji (IOC) i mapowaniem na MITRE ATT&CK.

---



## Zdarzenie 2 — DoS / Flood Attack (hping3)

### Opis

Z Attack-Host wygenerowano intensywny ruch sieciowy w stronę Wazuh Server w celu zasymulowania ataku typu DoS, opartego o wysyłanie pakietów SYN bez dokończenia ACK (TCP handshake) oraz zalanie żądaniami ICMP (ping flood).

### Komendy wykonane

```bash
sudo hping3 -S -p 80 --flood 192.168.56.101
sudo hping3 --icmp --flood 192.168.56.101
```

### 5W

| | |
|---|---|
| **Who (kto)** | Atakujący z maszyny Attack-Host |
| **What (co)** | Wysłanie dużej liczby pakietów TCP SYN (bez dokończenia handshake) oraz pakietów ICMP Echo Request w krótkim czasie |
| **When (kiedy)** | Sesja ataku przeprowadzona z Attack-Host w trakcie testów Mini-SOC |
| **Where (gdzie)** | Wazuh Server (192.168.56.101), interfejs sieciowy Host-Only |
| **Why (dlaczego)** | Symulacja ataku DoS mającego na celu wyczerpanie zasobów systemu docelowego / zakłócenie dostępności usługi |

### IOC (Indicators of Compromise)

- **Narzędzie:** hping3
- **Adres źródłowy ataku:** 192.168.56.102
- **Adres docelowy:** 192.168.56.101
- **Typ ruchu 1:** TCP SYN, port docelowy 80, tryb flood (bez oczekiwania na odpowiedź)
- **Typ ruchu 2:** ICMP Echo Request (ping), tryb flood
- **Charakterystyka:** setki/tysiące pakietów wysłanych w bardzo krótkim odstępie czasu z jednego adresu źródłowego

### Źródło detekcji

- Snort IDS (nasłuch na interfejsie Host-Only Wazuh Servera), log: `/var/log/snort/snort.alert.fast`
- Wbudowane reguły community Snort (np. BAD-TRAFFIC)
- Własne reguły Snort oparte o próg (threshold):
  - `1000001` — SYN Flood (≥20 pakietów SYN w 5 sekund z jednego źródła)
  - `1000002` — ICMP Flood (≥30 pakietów ICMP w 5 sekund z jednego źródła)
- Integracja Snort → Wazuh (format `snort-fast`), alerty widoczne w dashboardzie Wazuh (grupa `snort`)

### MITRE ATT&CK

- **T1498** — Network Denial of Service

---
<img width="800" height="472" alt="image" src="https://github.com/user-attachments/assets/c0ec322d-afab-4245-8b80-6b3bf52948ea" />
<img width="800" height="263" alt="image" src="https://github.com/user-attachments/assets/7fd3b0bf-ed3b-4473-b6b2-ad7e2b0b681c" />
<img width="1920" height="960" alt="image" src="https://github.com/user-attachments/assets/fb99331a-c584-46f9-9292-fdb7ecf6ce36" />



## Podsumowanie

| Zdarzenie | Narzędzie | Źródło detekcji | Reguła | MITRE ATT&CK |
|---|---|---|---|---|
| SYN Flood | hping3 | Snort | własna 1000001 | T1498 |
| ICMP Flood | hping3 | Snort | własna 1000002 | T1498 |


---

