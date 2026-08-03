# Network Traffic Analysis — ICMP & DNS Covert Tunneling

> **Tool:** Wireshark
> **Detection Type:** Command & Control / Data Exfiltration (Protocol Tunneling)
> **Severity:** Critical
> **MITRE ATT&CK:** T1572, T1071.004, T1132, T1048

This report covers two related but distinct anomalous traffic patterns identified during PCAP triage: an SSH session tunneled inside ICMP Echo packets, and a DNS-based covert channel consistent with the `dnscat` tool.

---

## Part 1 — ICMP Tunneling (SSH-over-ICMP)

### 5W Analysis

| Question | Answer |
|---|---|
| **Who** | Client: `192.168.154.131` → Server: `192.168.154.132` |
| **What** | An SSH session tunneled inside ICMP Echo Request/Reply packets, bypassing standard TCP/22 monitoring |
| **When** | Sustained periodic ICMP traffic beginning at capture start (`T+0.000432s`), continuing at ~1-second intervals |
| **Where** | ICMP protocol (network layer), disguising an inner TCP/22 (SSH) session |
| **Why** | Consistent with an attacker establishing a covert command channel or remote access tunnel that evades filtering focused on standard SSH (TCP/22) traffic |

---

### Detection Logic (Wireshark Display Filters)

**Initial broad filter — isolate ICMP traffic:**
```
icmp
```

**Narrow to anomalously large ICMP packets (standard ping payload is far smaller):**
```
icmp and data.len > 64
```

---

### Investigation

**Step 1 — Baseline anomaly (packet list level).**
Filtering on `icmp` alone immediately shows a sustained stream of Echo Request packets from `192.168.154.131` to `192.168.154.132` at regular ~1-second intervals, all sharing:
- **Identifier:** fixed at `0xfeff` (BE) / `0xfffe` (LE) — never varies
- **Sequence number:** fixed at `0/0` — never increments

Standard OS ping utilities increment the sequence number on every request and typically vary the identifier per process. A **constant identifier and sequence across an entire session** is not normal ping behavior — it is characteristic of tooling that repurposes these fields as session/state markers rather than using them for their RFC 792 purpose.

**Step 2 — Payload size anomaly.**
Applying `icmp and data.len > 64` reveals that many of these "ping" packets carry payloads far larger than a standard 32–64 byte ICMP Echo (up to **1075 bytes total frame length / 1033 bytes of ICMP data** observed, e.g. packet #242). This volume of data has no legitimate purpose in a diagnostic ping and strongly suggests the ICMP data field is being used to carry an encapsulated payload.

**Step 3 — Payload content: confirming SSH.**
Inspecting the raw bytes of the oversized ICMP data field reveals a **fully-formed, nested IP packet**:

```
ICMP Data (offset 0x002a onward):
45 00 03 4c 39 6c 40 00 40 06 e7 7f 0a 5f 01 01 0a 5f 01 02 ...
└┬┘          └┬┘          └┬┘  └┬┘          └───┬───┘ └───┬───┘
 │            │            │    │               │          │
 IPv4/IHL   Total Len   Flags  Proto=6(TCP)   Src: 10.95.1.1  Dst: 10.95.1.2
```

Immediately followed by a TCP header:
```
c8 8b 00 16 31 7d 53 ca 0e 1b bf cb 80 18 ...
└┬┘  └┬┘
 │    └── Dst Port: 0x0016 = 22 (SSH)
 └────── Src Port: 0xc88b = 51339
```

And immediately after the TCP header, the payload contains **plaintext ASCII matching an SSH2 `KEXINIT` (Key Exchange Init) message** — the algorithm-negotiation list every SSH connection sends at the start of a handshake:

```
diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,
diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 ...
ssh-rsa,ssh-dss ...
aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,... ...
hmac-md5,hmac-sha1,umac-64@openssh.com,... ...
none,zlib@openssh.com,zlib
```

This sequence — key exchange algorithms, host key types (`ssh-rsa`/`ssh-dss`), cipher suites, MAC algorithms, and compression options — is **unique and unmistakable to the SSH2 protocol handshake**. There is no other protocol that produces this exact string set. This is the direct, conclusive evidence that the tunneled traffic is SSH.

**Conclusion:** the client at `192.168.154.131` is running a full SSH session between an inner virtual network (`10.95.1.1` ↔ `10.95.1.2`, TCP/22) encapsulated inside ICMP Echo Request packets exchanged between `192.168.154.131` and `192.168.154.132`. This is a classic ICMP tunneling pattern (tools such as `ptunnel`/`icmptunnel` operate this way), used to bypass network controls that only inspect/restrict standard TCP/22 traffic.

---

### Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Outer tunnel endpoint (client) | 192.168.154.131 |
| Outer tunnel endpoint (server) | 192.168.154.132 |
| Inner tunnel IP (client) | 10.95.1.1 |
| Inner tunnel IP (server) | 10.95.1.2 |
| Inner protocol / port | TCP/22 (SSH) |
| Fixed ICMP Identifier | 0xfeff |
| Fixed ICMP Sequence | 0 |

---

## Part 2 — DNS Tunneling (dnscat)

### 5W Analysis

| Question | Answer |
|---|---|
| **Who** | Client: `192.168.253.1` → Server: `192.168.253.128` |
| **What** | DNS queries using `dnscat`-style hex-encoded subdomains, rotating across MX, TXT, and CNAME record types, ultimately routed to a confirmed external C2 domain |
| **When** | High-frequency DNS queries at sub-second intervals (multiple exchanges per second) |
| **Where** | DNS protocol (UDP/53) |
| **Why** | Consistent with a DNS-based covert channel / C2, commonly used to exfiltrate data or issue commands while blending into normal, rarely-inspected DNS traffic |

---

### Detection Logic (Wireshark Display Filters)

**Initial broad filter:**
```
dns
```

**Combined filter — tool signature + anomalous query length (used in this investigation):**
```
dns contains "dnscat" and dns.qry.name.len > 15
```

---

### Investigation

**Step 1 — Tool signature identification.**
Filtering with `dns contains "dnscat" and dns.qry.name.len > 15` returns a dense, rapid sequence of DNS queries and responses between `192.168.253.1` and `192.168.253.128`. The literal string `dnscat` appearing as a query subdomain label is a direct tool signature — `dnscat`/`dnscat2` is a widely-known DNS-based C2/tunneling tool.

**Step 2 — Encoded payload in subdomain.**
A representative query:
```
Name: dnscat.3b80015aaf45c2a02977230080b68d0ea3
Type: MX (15)
Name Length: 41
Label Count: 2
```

The subdomain segment (`3b80015aaf45c2a02977230080b68d0ea3`) is a hex-encoded string, not a real hostname — this is the classic dnscat pattern of encoding session/data content into subdomain labels rather than sending a genuine domain lookup.

**Step 3 — Record type rotation.**
Across the capture, queries cycle through **MX**, **TXT**, and **CNAME** record types for structurally similar encoded subdomains. Legitimate lookups for a single service don't typically rotate record types like this — dnscat/dnscat2 deliberately varies query types to maximize channel bandwidth and resilience against filtering of any single record type.

**Step 4 — C2 domain confirmed directly in packet payload.**
A separate query packet (raw hex) shows the full query name in cleartext ASCII:

```
Hex offset 0x0120: 09 64 61 74 61 65 78 66 69 6c 03 63 6f 6d 00
ASCII:              . d  a  t  a  e  x  f  i  l  .  c  o  m
```

The `09` and `03` bytes preceding `dataexfil` and `com` are DNS label-length prefixes (9 characters, then 3 characters) — standard DNS message encoding, confirming the parsed FQDN. The full query name for this packet:

```
F2BB01B0DEBCBAF89BF5CA00565428D725AE39601439DCB67A5541091207088.
EB7730F5386AC290C34C080380E7CDA6D8B3BB889759A720B004EF8E863C5A5.
1A6D6D296DA9A36F35F807B63C17698CA1973302AD72B3A151705B22B9A62B7.
E9BD4A82EBFD63ABB64A098F2564D3910D6EBCAAA.
dataexfil.com
```

This confirms **`dataexfil[.]com`** as the parent domain receiving the tunneled traffic. Each of the four long hex-encoded labels (up to 63 characters — the DNS label length maximum) represents a chunk of encoded data/session payload, consistent with dnscat2's session/data encoding scheme, which splits larger payloads across multiple labels within a single query due to DNS label-length limits (RFC 1035, 63 bytes per label).

---

### Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Client | 192.168.253.1 |
| Server / resolver | 192.168.253.128 |
| Tool signature | `dnscat` (subdomain label) |
| C2 / exfiltration domain | dataexfil[.]com |
| Query types abused | MX, TXT, CNAME |
| Example encoded subdomain (session marker) | 3b80015aaf45c2a02977230080b68d0ea3 |
| Example encoded subdomain (data payload, TXT query) | F2BB01B0DEBCBAF89BF5CA00565428D725AE39601439DCB67A5541091207088 |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|---|---|---|
| Command and Control | T1572 | Protocol Tunneling — SSH session encapsulated inside ICMP Echo packets |
| Command and Control | T1071.004 | Application Layer Protocol: DNS — dnscat covert channel over standard DNS queries |
| Command and Control / Exfiltration | T1132 | Data Encoding — hex-encoded payload embedded in DNS subdomain labels |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol — data moved via ICMP/DNS rather than a standard, monitored channel |

---

## Analyst Notes & Caveats

- **ICMP checksum anomalies noted but not treated as a primary indicator.** Several ICMP packets in the capture show `Checksum: 0x0000 incorrect`. While this can indicate raw/custom-crafted packets (consistent with a tunneling tool), it is also commonly caused by checksum offloading (the NIC calculates the checksum at send time, after the packet was already captured) — a frequent, benign artifact in packet captures. This was **not** relied upon as standalone evidence; the definitive finding is the embedded SSH KEXINIT payload documented above.
- **"No response seen" labels on ICMP requests are a byproduct of the fixed identifier/sequence, not necessarily true packet loss.** Wireshark matches ICMP request/reply pairs using the identifier and sequence number; since both are held constant throughout the session, Wireshark's matching heuristic frequently fails to pair requests with replies even when a reply may have occurred. This should not be read as literal network non-responsiveness.

---

## Recommendations

- Block/alert on ICMP packets with payload sizes exceeding standard ping thresholds (e.g. >64 bytes) at the network perimeter.
- Alert on ICMP sessions with static (non-incrementing) identifier/sequence values sustained over many packets.
- Alert on DNS queries containing the literal string `dnscat`, and more generally on unusually long query names (`dns.qry.name.len > 15`) excluding mDNS.
- Block or sinkhole the domain `dataexfil[.]com` at the DNS resolver / firewall level.
- Consider DNS query-type-rotation (single client cycling through MX/TXT/CNAME for structurally similar names) as a standalone detection heuristic.
- Review firewall/IDS rules to ensure ICMP and DNS are not implicitly trusted as "low-risk" protocols exempt from deep packet inspection.

---

## Conclusion

This investigation identified two independent covert channel techniques within the reviewed packet captures. The first is an SSH session fully encapsulated inside ICMP Echo Request packets between `192.168.154.131` and `192.168.154.132`, confirmed conclusively by the presence of an embedded IPv4/TCP header (destination port 22) followed by a plaintext SSH2 KEXINIT algorithm-negotiation string inside the oversized ICMP payload. The second is a DNS-based tunnel consistent with the `dnscat` tool, in which session and data payloads are hex-encoded into subdomain labels and rotated across MX, TXT, and CNAME queries, ultimately routed to the external domain `dataexfil[.]com` — confirmed directly from the raw packet bytes of a captured query.

Both techniques share a common purpose: abusing protocols (ICMP, DNS) that are frequently under-inspected or implicitly trusted by network security controls, in order to establish command-and-control channels or exfiltrate data while evading detection focused on conventional TCP-based traffic.
