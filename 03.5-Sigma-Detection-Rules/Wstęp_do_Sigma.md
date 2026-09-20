# Sigma Rules

Repozytorium z regułami Sigma, które tworzę i rozwijam podczas nauki detekcji zagrożeń oraz w ramach kursu SOC L2.

## Co tu znajdziesz

- **Autorskie reguły** — pisane od zera na podstawie własnej analizy technik ataków (MITRE ATT&CK), logów lub konkretnych scenariuszy.
- **Reguły przerabiane na kursie SOC L2** — bazowane na publicznych źródłach (m.in. [SigmaHQ](https://github.com/SigmaHQ/sigma)), rozbierane na czynniki pierwsze i modyfikowane w ramach ćwiczeń (redukcja false positives, dodawanie filtrów, zmiana logiki warunków itp.).

## Cel repozytorium

- Utrwalanie wiedzy o budowie reguł Sigma (`logsource`, `detection`, `condition`, filtry).
- Ćwiczenie pisania reguł pod kątem realnych źródeł logów (Sysmon, Windows Event ID, process creation itd.).
- Budowanie własnego portfolio jako dowód praktycznych umiejętności w detekcji (threat detection / SOC analyst).
