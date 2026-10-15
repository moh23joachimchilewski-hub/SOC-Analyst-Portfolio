# Notatka: Sysmon EID 17/18, named pipe

**Named pipe** = kanał komunikacji między procesami (IPC), ścieżka `\\.\pipe\nazwa`. Działa też zdalnie przez SMB (445).

| EID | Znaczenie |
|---|---|
| **17** | Pipe utworzony (serwer) |
| **18** | Pipe podłączony (klient) |

Pola: `PipeName`, `Image`, `ProcessGuid`, `User`.

## Podejrzane nazwy pipe

| Wzorzec | Narzędzie |
|---|---|
| `\msagent_*` | Cobalt Strike (SMB beacon) |
| `\postex_*`, `\postex_ssh_*` | Cobalt Strike (post-exploitation) |
| `\MSSE-*-server` | Cobalt Strike (starsze profile) |
| `\status_*`, `\mojo.*` z dziwnym procesem | Cobalt Strike (malleable profile) |
| `\PSEXESVC` | PsExec (zdalne wykonanie) |
| `\paexec*`, `\remcom*`, `\csexec*` | klony PsExec |
| `\isapi_http`, `\isapi_dg`, `\sdlrpc`, `\ahexec` | RAT-y / malware |
| `\lsadump`, `\cachedump`, `\wceservicepipe` | kradzież haseł |

Nazwy w C2 da się zmienić, więc brak wzorca nie oznacza, że jest czysto.

## Jak oceniać

1. **Image:** `Temp`, `AppData`, `ProgramData`, interpreter (`powershell`, `rundll32`) lub losowa nazwa = podejrzane. Podpisany `System32` = zwykle OK.
2. **Nazwa:** porównać z tabelą wyżej.
3. **EID 18:** kto się łączy, czy z innego hosta (SMB).
4. **Kontekst:** EID 1 (nowy proces), 7045 (usługa), 4624 typ 3 lub 10 chwilę wcześniej.
5. Zrobić baseline pipe'ów dla hosta.

**MITRE:** T1021.002 (SMB/Admin Shares), T1569.002 (Service Execution), T1055 (Process Injection).
