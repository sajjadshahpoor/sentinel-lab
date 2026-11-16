# CTF W6 — Blue-team forensics (Hamilton, "the fire")

My write-ups for the Week-6 forensics CTF: a business-email-compromise that turned into a
PowerShell implant, a DNS beacon, data exfiltration and scheduled-task persistence on the
workstation of **Lucie Martens** (`lmartens`, host `HAM-FIN-WKS07` = `10.50.0.69`).

> **Flags withheld.** The literal `HAM{…}` values are redacted (`HAM{████}`) while the CTF is
> live (closes **2026-11-20**), so this repo never hands out a flag during the event. The method
> and evidence are complete; I fill the values back in once it closes.

## The incident, end to end
1. **Phishing (BEC).** The supplier `verhaegen-packaging.test` is impersonated by a look-alike
   domain `verhaegen-packaging**s**.test` (extra "s"). A message in the real `PO-88214` thread
   asks to change the IBAN (SPF **fail**). A separate phish spoofs `accounts@hamilton.corp`
   from `secure-paymentdesk.test` (SPF softfail).
2. **Delivery.** A ZIP `INV-2026-1147.zip` is downloaded from the look-alike domain
   (Mark-of-the-Web proves the origin URL).
3. **Execution & persistence.** `powershell.exe` (spawned by the Task Scheduler via
   `svchost.exe`) drops `synchelper.ps1`, adds a `Run` key, and registers a scheduled task
   `\Microsoft\Windows\SyncHelper\Refresh`.
4. **C2 beacon.** Every 10 minutes the task runs `Resolve-DnsName <id>.b.cdn-hamilton-sync.test`
   — DNS-based beaconing to a CDN look-alike domain, victim id `7f3a9c`.
5. **Exfiltration.** Customer/supplier payment data is base32-encoded and tunnelled out over
   16 data-carrying DNS queries on a `.x` sub-channel.
6. **Noise.** A parallel domain-auth attack sprays `helpdesk` on the DC, and a Kerberoast-style
   discovery requests service tickets for `lmartens`.

## Evidence used (read-only)
| Evidence | Used for |
|---|---|
| `maildir.zip` (22 `.eml`) | Email |
| `stage2.b64.txt` | Encoding |
| `DN-5583_verhaegen.pdf` | OSINT |
| `*_tir.evtx` (Sysmon / PowerShell / TaskScheduler / Security / Security_DC01) | Logs, Hunt |
| `ctf_fire_dns.pcap` | Network |
| `MFT_ctf_post_tir.raw`, `POWERSHELL.EXE-*.pf`, `zone_identifier.txt` | Disk |
| `ctf_post_tir_*.mem` | Memory |

## Toolkit
Linux (WSL/Ubuntu) + Python venv: `python-evtx` (`evtx_dump`), `scapy`, `pypdf`, plus CyberChef
logic reimplemented in Python (base64/base32/rot13/gzip/XOR). Windows side for the compressed
Prefetch (`RtlDecompressBufferEx`). No commercial tooling.

## Index
- [01 — Warm-up](01-warmup.md)
- [02 — Email](02-email.md)
- [03 — Encoding](03-encoding.md)
- [04 — OSINT](04-osint.md)
- [05 — Logs](05-logs.md)
- [06 — Network](06-network.md)
- [07 — Disk](07-disk.md)
- [08 — Hunt](08-hunt.md)
- [09 — Memory](09-memory.md)
