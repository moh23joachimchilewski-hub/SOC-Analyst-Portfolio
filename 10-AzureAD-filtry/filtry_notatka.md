# Notatka: Splunk - logi Entra ID (Azure AD) i Microsoft 365

> **Źródło:** notatki z TryHackMe (filtry z labu) + uzupełnienia oznaczone jako *(dodane)*
> **Cel:** szybkie wykrywanie password spray / brute force, ataków na MFA i sesję (fatigue, SIM swap, AiTM, impossible travel), przejęcia konta i działań po przejęciu (zmiany w koncie, reguły poczty)

---

## 1. Pięć źródeł logów

| sourcetype | Co zawiera | Kluczowe pola |
|---|---|---|
| `azure:aad:signin` | **Logowania** (udane i nieudane) | `userPrincipalName`, `ipAddress`, `appDisplayName`, `status.errorCode`, `status.failureReason`, `location.countryOrRegion`, `conditionalAccessStatus` |
| `azure:aad:audit` | **Zmiany w katalogu** (konta, role, hasła, MFA, aplikacje) | `activityDisplayName`, `result`, `initiatedBy.user.userPrincipalName`, `initiatedBy.app.displayName`, `targetResources{}.userPrincipalName` |
| `o365:management:activity` | **Aktywność w M365** (poczta, SharePoint, OneDrive) | `Operation`, `UserId`, `ClientIP` / `ClientIPAddress`, `Workload`, `ObjectId` |
| `azure:aad:identity_protection:riskdetection` | **Wykrycia ryzyka** (impossible travel, anonimowe IP itd.) | `riskEventType`, `riskLevel`, `userPrincipalName`, `ipAddress`, `activity` |
| `azure:aad:identity_protection:risky_user` | **Użytkownicy oznaczeni jako ryzykowni** | `riskLevel`, `riskState`, `riskDetail`, `userPrincipalName` |

Dobra kolejność analizy: **signin** (kto i skąd się logował) -> **identity_protection** (czy Microsoft oznaczył ryzyko) -> **audit** (co zmieniono w koncie) -> **o365** (co zrobiono w poczcie i plikach).

---

## 2. Kody błędów logowania (`status.errorCode`)

| Kod | Znaczenie | Co może oznaczać |
|---|---|---|
| `0` | Sukces | - |
| `50126` | Zły login lub hasło | brute force / spray |
| `50053` | Konto zablokowane (zbyt wiele nieudanych prób) | trwa atak na hasło |
| `50074` | Wymagane MFA, nie zostało podane | **hasło mogło być poprawne**, brakuje drugiego składnika |
| `50055` | Hasło wygasło | zwykle zdarzenie administracyjne |

*(dodane, zweryfikuj w dokumentacji Microsoft)*: `50076` (MFA wymagane przez politykę), `50034` (użytkownik nie istnieje), `50057` (konto wyłączone), `53003` (zablokowane przez Conditional Access).

**Ważne:** `50074` / `50076` po serii `50126` to sygnał, że atakujący trafił w hasło, ale zatrzymało go MFA. To jest wyższy priorytet niż sam zły login.

---

## 3. Filtry: logowania (`azure:aad:signin`)

### 3.1 Lista wszystkich nieudanych logowań (per użytkownik)

```spl
index="scenario" sourcetype="azure:aad:signin" "status.errorCode"!=0
| stats count as event_count values(ipAddress) as ip_addresses
  values(appDisplayName) as applications values(status.errorCode) as errorCodes by userPrincipalName
| sort - event_count
| table applications, userPrincipalName, ip_addresses, errorCodes, event_count
```

- **Wykrywa:** brute force na jedno konto (dużo `event_count`, mało IP) oraz ślady spray (wiele kont z podobnym `ip_addresses`).
- **MITRE:** T1110.001 (Password Guessing), T1110.003 (Password Spraying).
- **Patrz na:** `errorCodes` (czy są `50053`/`50074`), liczbę różnych IP.

### 3.2 Udane logowania z podejrzanego IP

```spl
index=scenario sourcetype="azure:aad:signin" "status.errorCode"=0 ipAddress="<ADD-IP-HERE>"
| stats values(ipAddress) as ip_addresses values(appDisplayName) as applications by userPrincipalName
| table applications, userPrincipalName, ip_addresses
```

- **Wykrywa:** które konta **faktycznie zostały przejęte** po ataku z danego IP.
- **MITRE:** T1078.004 (Valid Accounts: Cloud Accounts).
- **Użycie:** wpisz IP atakującego znalezione w 3.1 lub 3.4. Wynik niepusty = konto przejęte, eskalacja.

### 3.3 Nieudane logowania z danymi o kraju i powodzie

```spl
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion, status.errorCode, status.failureReason
| sort - _time
```

- **Wykrywa:** oś czasu nieudanych prób, kraj źródłowy, powód błędu.
- **Patrz na:** nietypowy kraj, nagłą zmianę `appDisplayName`, kolejność błędów w czasie.

### 3.4 Password spray: ile kont atakuje jedno IP

```spl
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| stats dc(userPrincipalName) as targeted_accounts, count as failures by ipAddress
| sort - failures
```

- **Wykrywa:** **password spray** (jedno IP, wiele różnych kont, po kilka prób na konto) i credential stuffing.
- **MITRE:** T1110.003, T1110.004.
- **Jak czytać:** wysokie `targeted_accounts` przy niskim `failures / targeted_accounts` = spray. Niskie `targeted_accounts` i wysokie `failures` = brute force na jedno konto.

---

### 3.5 Udane logowania konkretnego użytkownika

```spl
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"=0
| where userPrincipalName="<TARGET_USER>"
| stats count by userPrincipalName, status.errorCode, ipAddress
| sort status.errorCode
```

- **Użycie:** z jakich IP logowało się przejęte lub podejrzane konto. Nowe, nieznane IP = trop.

### 3.6 Udane logowania z konkretnego IP

```spl
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"=0
| where ipAddress="<SUSPICIOUS_IP>"
| stats count by userPrincipalName, status.errorCode
| sort status.errorCode
```

- **Użycie:** wariant 3.2 z liczbą logowań. Pokazuje, które konta zalogowały się z IP atakującego i ile razy.
- W 3.5 i 3.6 `status.errorCode` w `stats ... by` jest zawsze `0` (bo filtrujesz po `=0`), więc to pole i sortowanie po nim niczego nie wnoszą. Można je pominąć.

---

## 4. Filtry: zmiany w katalogu (`azure:aad:audit`)

### 4.1 Zmiany dotyczące konkretnego użytkownika

```spl
index=scenario sourcetype="azure:aad:audit" targetResources{}.userPrincipalName="<ADD-USER-EMAIL>"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName', 'initiatedBy.app.displayName')
| sort - _time
| table _time, initiator, activityDisplayName, result, targetResources{}.userPrincipalName
```

- **Wykrywa:** co zrobiono z kontem ofiary po przejęciu: reset hasła, **dodanie metody MFA**, zmiana roli.
- **MITRE:** T1098 (Account Manipulation), T1098.005 (Device Registration), T1098.003 (Additional Cloud Roles), T1556.006 (modyfikacja MFA).
- **Patrz na:** kto jest `initiator` (czy to sam użytkownik, admin, czy aplikacja) i na `activityDisplayName`.
- `coalesce(...)` bierze pierwsze niepuste pole, bo zmianę może wykonać użytkownik **albo** aplikacja.

### 4.2 Zmiany wykonane przez konkretnego użytkownika

```spl
index=scenario sourcetype="azure:aad:audit" initiatedBy.user.userPrincipalName="<ADD-USER-EMAIL>"
| sort - _time
| table _time, initiatedBy.user.userPrincipalName, activityDisplayName, result, targetResources{}.userPrincipalName
```

- **Wykrywa:** co zrobiło **przejęte konto** (szczególnie administratorskie): tworzenie kont, nadawanie ról, zgody dla aplikacji.
- **MITRE:** T1136.003 (Create Cloud Account), T1098.003.

---

## 5. Filtry: aktywność M365 (`o365:management:activity`)

### 5.1 Wszystkie zdarzenia (żeby poznać strukturę)

```spl
index="scenario" sourcetype="o365:management:activity"
```

Pola wspólne dla każdego typu zdarzenia:

| Pole | Znaczenie |
|---|---|
| `Operation` | Akcja (np. `New-InboxRule`, `FileAccessed`, `Send`) |
| `UserId` | Konto wykonujące akcję (zwykle e-mail) |
| `ClientIP` / `ClientIPAddress` | Źródłowe IP. **Czasem to IP Microsoftu**, więc sprawdź rejestratora adresu |
| `Workload` | Usługa (Exchange, SharePoint, OneDrive) |
| `ObjectId` | Cel akcji (skrzynka, ścieżka pliku) |

### 5.2 Wszystkie akcje użytkownika

```spl
index="scenario" sourcetype="o365:management:activity" UserId="<ADD-USER-EMAIL>"
| sort - _time
| eval sourceIP=coalesce('ClientIP', 'ClientIPAddress')
| table _time, Operation, UserId, sourceIP, Workload, ObjectId
```

- **Wykrywa:** działania po przejęciu konta: **reguły skrzynki**, przekierowania poczty, masowy dostęp do plików, wysyłka wiadomości.
- **MITRE:** T1114.003 (Email Forwarding Rule), T1564.008 (Email Hiding Rules), T1530 (Data from Cloud Storage).
- **Patrz na:** `Operation` = `New-InboxRule`, `Set-Mailbox` (przekierowanie), `FileAccessed`/`FileDownloaded` w dużej liczbie; `sourceIP` inne niż zwykle użytkownika.
- `coalesce` jest potrzebne, bo różne typy zdarzeń używają innej nazwy pola z IP.

---

## 6. Zasady dostępu warunkowego (CAP) w logach logowań

Każde zdarzenie logowania ma pole `appliedConditionalAccessPolicies`, które pokazuje, **które polityki oceniono i jaki był wynik** każdej z nich.

```js
appDisplayName: "One Outlook Web"
appliedConditionalAccessPolicies: [
  {
    displayName: "Require MFA"          // polityka
    enforcedGrantControls: ["Block"]
    result: "notApplied"                // wynik
  }
]
```

| `result` | Znaczenie |
|---|---|
| `success` | Warunki polityki spełnione, wymagane kontrole zaliczone |
| `failure` | Polityka zablokowała logowanie albo wymagana kontrola nie została spełniona |
| `notApplied` | Warunki polityki nie zostały spełnione albo użytkownik/aplikacja jest poza zakresem |
| `reportOnly` | Tryb audytu: polityka **by zadziałała**, ale nie została wymuszona |

### 6.1 Logowania zablokowane przez konkretne polityki

```spl
index="task-3" sourcetype="azure:aad:signin" conditionalAccessStatus=failure
| spath output=policies path=appliedConditionalAccessPolicies{}
| mvexpand policies
| spath input=policies output=policy_result path=result
| spath input=policies output=policy_name path=displayName
| where policy_result="failure"
| stats values(policy_name) as FailedPolicies by _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus
| eval FailedPolicies=mvjoin(FailedPolicies, ", ")
| table _time, appDisplayName, userDisplayName, ipAddress, conditionalAccessStatus, FailedPolicies
| sort - _time
```

- **Wykrywa:** próby logowania, które zatrzymała polityka (np. blokada kraju, wymóg MFA). Pokazuje też, **która** polityka zadziałała.
- **Jak działa:** `spath` wyciąga pole zagnieżdżone, `mvexpand` rozbija listę polityk na osobne wiersze, `where` zostawia tylko te z wynikiem `failure`, a `stats ... values()` skleja nazwy z powrotem na jedno zdarzenie.
- **Użycie:** jeśli atak się nie udał, tu zobaczysz dlaczego. Ciągłe `notApplied` dla ważnej polityki przy udanych logowaniach = luka w zakresie polityki.

---

## 7. Ryzyko (Identity Protection)

| | Sign-in risk | User risk |
|---|---|---|
| Co ocenia | podejrzaność **jednej próby logowania** | prawdopodobieństwo, że **konto zostało przejęte** |
| Kiedy | w czasie rzeczywistym, na każde logowanie | narasta w czasie, na podstawie historii konta |
| Przykłady | anonimowe IP (Tor, VPN, proxy), **impossible travel**, nowe urządzenie/lokalizacja/ASN | wyciek hasła, wiele ryzykownych logowań bez naprawy, podejrzana aktywność M365 (np. dziwne reguły skrzynki) |

*(dodane)* Funkcje Identity Protection wymagają zwykle licencji Entra ID P2. Jeśli klient jej nie ma, sourcetype `identity_protection:*` może być pusty.

### 7.1 Logowania o wysokim ryzyku

```spl
index="task-3" sourcetype="azure:aad:signin"
| where riskLevelDuringSignIn="high"
| table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion, riskLevelDuringSignIn, riskLevelAggregated
| sort - _time
```

### 7.2 Wszystkie wykrycia ryzyka

```spl
index="task-3" sourcetype="azure:aad:identity_protection:riskdetection"
```

### 7.3 Wykrycia związane z anonimowymi IP

```spl
index="task-3" sourcetype="azure:aad:identity_protection:riskdetection"
| where riskEventType="anonymizedIPAddress"
| table _time, userPrincipalName, activity, ipAddress, location.countryOrRegion, riskLevel, riskEventType
| sort - _time
```

- **Wykrywa:** logowania przez Tor, VPN, proxy. Często maskuje atakującego (T1090).
- **Uwaga:** anonimowe IP bywa też u legalnych użytkowników (VPN firmowy lub prywatny), więc sprawdź kontekst.

### 7.4 Użytkownicy oznaczeni jako ryzykowni

```spl
index="task-3" sourcetype="azure:aad:identity_protection:risky_user"
| table _time, userPrincipalName, riskLevel, riskState, riskDetail
| sort - _time
```

- **Patrz na:** `riskState` (czy nadal `atRisk`, czy już `remediated`/`dismissed`).

---

## 8. Ataki na MFA i sesję

### 8.1 MFA Fatigue (prompt bombing) - T1621

Atakujący ma poprawne hasło i wysyła wiele prób logowania pod rząd. Każda generuje push w Authenticatorze, a celem jest zmęczenie użytkownika, aż któryś zatwierdzi. To atak socjotechniczny, a nie techniczny.

**Jak wygląda w logach:**
- dużo promptów MFA na jedno konto w krótkim czasie,
- powtarzające się kody `50074`, `50076`, `500121`,
- jeśli użytkownik zatwierdzi, to potem pojawia się kod `0`.

Microsoft częściowo to ograniczył przez **number matching** (użytkownik wpisuje liczbę z ekranu logowania) i dodatkowy kontekst (lokalizacja, nazwa aplikacji).

```spl
index="task-4" sourcetype="azure:aad:signin" (status.errorCode=50074 OR status.errorCode=50076 OR status.errorCode=500121)
| stats count as mfa_failures values(status.errorCode) as errorCodes values(status.failureReason) as failureReasons by userPrincipalName, ipAddress
| sort - mfa_failures
```

- **Wykrywa:** konta z dużą liczbą nieudanych MFA z jednego IP. Wysokie `mfa_failures` = podejrzenie fatigue.
- **Następny krok:** sprawdź, czy po serii błędów jest **udane logowanie** (3.5) z tego samego IP. Jeśli tak, atak się udał.
- *(dodane)* Żeby zobaczyć „serię w krótkim czasie", dodaj podział na okna czasowe (`bin _time span=10m`) przed `stats`.

### 8.2 SIM swapping (SMS jako MFA)

Atakujący przekonuje operatora do przeniesienia numeru ofiary na swoją kartę SIM i odbiera kody SMS. Zagrożenie dla organizacji, które nadal używają SMS jako drugiego składnika. Zaradzenie: odejść od SMS.

**W logach:**
- udane logowanie z **nietypowego urządzenia lub przeglądarki**,
- udane logowanie z **nietypowej lokalizacji**.

### 8.3 AiTM (Adversary-in-the-Middle) phishing - T1557, T1539

Atakujący stawia reverse proxy między ofiarą a prawdziwą stroną logowania Microsoftu. Ofiara loguje się normalnie, łącznie z MFA, a proxy **kradnie token sesji**. Atakujący odtwarza go na swoim komputerze i obchodzi MFA, bo uwierzytelnienie już się odbyło.

**W logach:**
- logowanie udane **bez nowego promptu MFA** (token już zawiera dowód MFA),
- IP i lokalizacja **inne** niż przy pierwotnym uwierzytelnieniu,
- Conditional Access pokazuje sesję jako zgodną, bo polityka została spełniona, tylko nie przez tę osobę.

Z perspektywy Entra ID wszystko wygląda dobrze. Jedyną anomalią jest **geografia i IP**, więc analityk musi połączyć dwa osobne logowania.

### 8.4 Impossible travel

Konto loguje się z dwóch odległych miejsc w czasie, który to wyklucza (np. São Paulo 09:00, Moskwa 09:45). Jedno z logowań raczej nie pochodzi od właściwego użytkownika. Identity Protection oznacza to jako `impossibleTravel`, ale **nie ufaj ślepo** tym alertom (bywają fałszywe, np. przez VPN).

```spl
index="task-4" sourcetype="azure:aad:signin" status.errorCode=0
| table _time, userPrincipalName, ipAddress, location.countryOrRegion, conditionalAccessStatus
| sort - _time
```

- W notatce z labu to zapytanie nie ma filtra użytkownika. Dodaj `userPrincipalName="<USER>"`, żeby ręcznie porównać kraje i czasy dla jednego konta.

```spl
index="task-4" sourcetype="azure:aad:identity_protection:riskdetection"
| where riskEventType="impossibleTravel"
| table _time, userPrincipalName, activity, ipAddress, location.countryOrRegion, riskLevel, riskEventType
| sort - _time
```

---

## 9. Działania po przejęciu konta (`azure:aad:audit`)

Trzy pola odpowiadają na główne pytania w analizie:
- `activityDisplayName` - **co** zmieniono,
- `initiatedBy` - **kto** to zrobił (użytkownik lub aplikacja),
- `targetResources` - **czego** dotyczyła zmiana i jakie są szczegóły.

### 9.1 Nadanie roli (eskalacja uprawnień) - T1098.003

Najprostsza droga do wyższych uprawnień: nadać rolę przejętemu kontu albo nowemu kontu atakującego. Typowe cele:

| Rola | Co daje |
|---|---|
| Global Administrator | pełna kontrola nad tenantem |
| Exchange Administrator | dostęp do wszystkich skrzynek |
| User Administrator | resetowanie haseł i modyfikacja kont |
| Application Administrator | zarządzanie rejestracjami aplikacji i zgodami |

```spl
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add member to role"
| table _time, activityDisplayName, initiatedBy.user.userPrincipalName, targetResources{}.userPrincipalName, targetResources{}.modifiedProperties{}.newValue
| sort - _time
```

- **Patrz na:** `newValue` (jaka rola), kto nadał (`initiatedBy`), kto dostał.

### 9.2 Konta-backdoory (persistence) - T1136.003

Nowe konto administratora utworzone poza normalnym procesem HR/IT to klasyczny mechanizm trwałości. Atakujący zakłada je, nadaje rolę i używa jako zapasowego dostępu, gdyby przejęte konto zostało naprawione.

```spl
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="Add user"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| eval userCreated='targetResources{}.userPrincipalName'
| table _time, activityDisplayName, initiator, userCreated
```

- **Patrz na:** czy konto utworzył ktoś, kto zwykle tego nie robi; nietypowa nazwa lub pora; czy zaraz potem dostało rolę (9.1).

### 9.3 Dodanie własnej metody MFA - T1098.005, T1556.006

```spl
index="task-5" sourcetype="azure:aad:audit" activityDisplayName="User started security info registration" loggedByService="Authentication Methods" operationType="Add"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| table _time, activityDisplayName, initiator, initiatedBy.user.ipAddress, additionalDetails{}.value
```

- **Wykrywa:** próby zarejestrowania nowego urządzenia/metody MFA. Po przejęciu konta atakujący dodaje własną, żeby zachować dostęp.
- **Patrz na:** IP w `initiatedBy.user.ipAddress` (czy to IP użytkownika), czas względem podejrzanego logowania.

### 9.4 Zgody dla aplikacji (illicit consent grant) - T1528

```spl
index="main" sourcetype="azure:aad:audit"
activityDisplayName="Consent to application"
| eval initiator=coalesce('initiatedBy.user.userPrincipalName','initiatedBy.app.displayName')
| eval appName='targetResources{}.displayName'
| eval permissionsGranted='targetResources{}.modifiedProperties{}.newValue'
| table _time, initiator, appName, permissionsGranted
| sort - _time
```

- **Wykrywa:** udzielenie aplikacji uprawnień do danych (pocztę, pliki). Atakujący może użyć takiej aplikacji jako dostępu, który **przeżyje reset hasła**.
- **Patrz na:** nieznane nazwy aplikacji, szerokie uprawnienia (`Mail.Read`, `Files.ReadWrite.All`, `offline_access`).

---

## 10. Ściąga: atak -> sygnał w logach

| Atak | Sygnał | Filtr |
|---|---|---|
| Password spray | jedno IP, wiele kont, kod `50126` | 3.4 |
| Brute force | jedno konto, dużo błędów | 3.1 |
| Przejęcie konta | udane logowanie z IP atakującego | 3.2 / 3.6 |
| MFA fatigue | wiele `50074`/`50076`/`500121`, potem `0` | 8.1 + 3.5 |
| SIM swap | udane logowanie z nowego urządzenia/lokalizacji | 3.5 |
| AiTM | udane logowanie bez MFA z innego IP/kraju | 3.5 + 8.4 |
| Impossible travel | dwa kraje w niemożliwym czasie | 8.4 |
| Eskalacja uprawnień | `Add member to role` | 9.1 |
| Backdoor | `Add user` + rola | 9.2 |
| Trwałość przez MFA | `User started security info registration` | 9.3 |
| Nadużycie zgód | `Consent to application` | 9.4 |
| Działania w poczcie | `New-InboxRule`, przekierowania | 5.2 |

---

## 11. Przepływ analizy (cały atak w 5 krokach)

1. **3.4** - które IP atakuje wiele kont (spray)? Przy atakach na MFA dodatkowo **8.1** (wiele błędów `50074`/`50076`/`500121`).
2. **3.2 / 3.6** - czy któreś konto zalogowało się z tego IP **udanie**? (`errorCode=0`)
3. **Weryfikacja logowania:** czy było MFA i skąd? (**3.5**, **8.4** - kraje i czasy), czy Identity Protection oznaczył ryzyko (**7.1**, **7.3**), co zrobiły polityki dostępu warunkowego (**6.1**). To rozróżnia przejęcie konta, SIM swap i AiTM.
4. **4.1 / 4.2 / 9.1-9.4** - co zmieniono w tym koncie i co ono zmieniło (MFA, role, nowe konta, zgody aplikacji)?
5. **5.2** - co zrobiono w poczcie i plikach (reguły, przekierowania, pobrania)?

Wynik na kroku 2 jest punktem decyzji: bez udanego logowania to nieudany atak (zablokować IP, monitorować), z udanym to incydent (reset hasła, unieważnienie sesji, sprawdzenie kroków 3-5).

---
