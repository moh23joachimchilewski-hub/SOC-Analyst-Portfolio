# Konfiguracja — Wazuh Server + Snort IDS

## Środowisko

Wazuh Server wdrożony na maszynie wirtualnej **Wazuh-Server_test** (Ubuntu 22.04, Oracle VM VirtualBox), podłączonej do izolowanej sieci laboratoryjnej (VirtualBox Host-Only Adapter). Na tej samej maszynie zainstalowano również **Snort IDS**, zintegrowany z Wazuh w celu przesyłania alertów sieciowych do centralnego dashboardu.

Adresacja: `192.168.56.101`

---

## 2.1 Wazuh

### Konfiguracja sieci

Po pierwszym uruchomieniu maszyny interfejs sieciowy (Host-Only) wymagał ręcznego podniesienia i przypisania adresu IP:

```bash
sudo ip link set enp0s8 up
sudo dhclient enp0s8
ip a show enp0s8
```

Wynik: `192.168.56.101`

### Instalacja (manager + indexer + dashboard)

Instalacja przeprowadzona przy użyciu oficjalnego skryptu Wazuh (tryb all-in-one):

```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

### Weryfikacja usług

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

Wszystkie trzy usługi (manager, indexer, dashboard) zostały uruchomione poprawnie w statusie `active (running)`.
<img width="800" height="142" alt="image" src="https://github.com/user-attachments/assets/e3b1fd45-d235-48f1-80f5-879edc3d1817" />
<img width="800" height="147" alt="image" src="https://github.com/user-attachments/assets/22edec1b-f6fd-47ea-a675-c457fcdcb2ff" />
<img width="795" height="172" alt="VirtualBox_Wazuh-Server_test_14_09_2026_13_58_06" src="https://github.com/user-attachments/assets/ae456fd2-ed9f-4258-962c-784abb7629ac" />




### Dodanie zbierania logów SSH (auth.log)

Domyślna konfiguracja managera nie obejmowała pliku `/var/log/auth.log`, wymaganego do wykrywania prób ataków brute force na SSH. Dodano ręcznie w `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
```

Po edycji zrestartowano managera:

```bash
sudo systemctl restart wazuh-manager
```

---

## 2.2 Snort IDS

### Instalacja

Snort zainstalowany na tej samej maszynie co Wazuh Server:

```bash
sudo apt update
sudo apt install -y snort
```

### Konfiguracja sieci monitorowanej

W trakcie instalacji ustawiono zakres sieci domowej (HOME_NET) zgodny z siecią laboratoryjną:

```
ipvar HOME_NET 192.168.56.0/24
```

### Zapisywanie alertów

Snort skonfigurowano do zapisywania alertów w formacie fast do pliku:

```
/var/log/snort/snort.alert.fast
```

### Własne reguły detekcyjne

W pliku `/etc/snort/rules/local.rules` dodano dwie własne reguły wykrywające ataki typu DoS (SYN Flood oraz ICMP Flood) w oparciu o próg (threshold) liczby pakietów w krótkim oknie czasowym.

<img width="800" height="201" alt="image" src="https://github.com/user-attachments/assets/91cbbcf9-078f-4d89-8e66-8514ae98ac46" />


### Integracja Snort → Wazuh

Aby alerty Snorta trafiały do dashboardu Wazuh, dodano w `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>snort-fast</log_format>
  <location>/var/log/snort/snort.alert.fast</location>
</localfile>
```
<img width="800" height="600" alt="VirtualBox_Wazuh-Server_test_14_09_2026_14_21_06" src="https://github.com/user-attachments/assets/335ded04-88c4-4d6f-9500-1d94fb432885" />


Po edycji zrestartowano managera:

```bash
sudo systemctl restart wazuh-manager
```
<img width="800" height="600" alt="VirtualBox_Wazuh-Server_test_14_09_2026_14_23_42" src="https://github.com/user-attachments/assets/5c019add-964d-49a8-a7f0-be0ba48bc3ca" />

---

