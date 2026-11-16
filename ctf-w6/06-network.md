# Network

Evidence: `ctf_fire_dns.pcap` — a DNS capture. Parsed with scapy, keeping every query
(`qr == 0`): time, src, dst, `qname`.

```python
from scapy.all import rdpcap, DNS, DNSQR, IP
for p in rdpcap("ctf_fire_dns.pcap"):
    if p.haslayer(DNSQR) and p[DNS].qr == 0:
        print(p.time, p[IP].src, p[IP].dst, p[DNSQR].qname)
```

Victim is `10.50.0.69`; among the Microsoft noise one look-alike domain stands out:
**`cdn-hamilton-sync.test`**. Its sub-domains are `<id>.b.` (beacon keep-alive, ~165) and
`<data>.x.` (exfil, 16).

## DNS resolver (50)
Every query's destination is `10.50.0.10` — the configured resolver (the DC). Answer: `████`.

## Beacon domain (50)
The C2 / callback domain: `cdn-hamilton-sync.test`. Answer: `████`.

## Beacon interval (100)
Timestamps of the `.b` keep-alive queries are ~600 s apart → **10 minutes** (matches the task's
`RepetitionInterval`). *Format gotcha: it wanted `10 minutes`, not `600`/`600 seconds`.*
Answer: `████`.

## Victim ID (100)
Constant label on the beacon channel: `7f3a9c` (`7f3a9c.b.cdn-hamilton-sync.test`). Answer: `████`.

## Reconstruct exfil (150)
The 16 `.x.` queries each carry a Base32 chunk in their first label. Concatenated in time order
and Base32-decoded, they rebuild a **supplier-payments CSV** (IBANs, amounts, suppliers) with the
flag embedded in a comment line:
```python
data = "".join(first_label for t, first_label in sorted(exfil_queries)).upper()
base64.b32decode(data + "=" * ((-len(data)) % 8)).decode()
# -> CSV … # HAM{████}
```
Answer: `HAM{████}`.

## Correlate PID (150)
Correlate the pcap beacon with the host's **Sysmon EID 22** (which records `ProcessId` per DNS
query). The beacon traffic ties to PowerShell **PID 3568** (the first beacon run). Answer: `████`.
*(Note: the exfil burst came from a later run, PID 3640 — "beacon traffic" keys on the first
beacon PID.)*
