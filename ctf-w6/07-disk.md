# Disk

Evidence: `zone_identifier.txt` (NTFS Zone.Identifier ADS), `MFT_ctf_post_tir.raw` ($MFT),
`POWERSHELL.EXE-*.pf` (Prefetch).

## Run value (50)
From the dropper's registry write (PowerShell EID 4104 / Sysmon): the persistence `Run` value the
attacker added is named **`OneDriveSyncHelper`** (masquerading as OneDrive), pointing at the
dropped stage-2 script. Answer: `████`.

## Stage 2 path (100)
The dropped second-stage script:
`C:\Users\lmartens\AppData\Roaming\Microsoft\SyncHelper\synchelper.ps1`. Answer: `████`.

## ZIP origin URL (100)
Evidence: `zone_identifier.txt` — the Mark-of-the-Web of the downloaded ZIP.
```
[ZoneTransfer]
ZoneId=3
HostUrl=https://verhaegen-packagings.test/invoices/INV-2026-1147.zip
ReferrerUrl=https://verhaegen-packagings.test/
```
The `HostUrl` is the origin (the same look-alike domain as the phishing email). Answer: `████`.

## PowerShell execution count (150)
Evidence: `POWERSHELL.EXE-CA1AE517.pf`. Win10 Prefetch is **MAM/Xpress-Huffman compressed**, so I
decompressed it first with the Windows API `RtlDecompressBufferEx` (format 4), then read the
file-information block.

```python
import ctypes, struct
data = open(pf, "rb").read()               # starts b"MAM\x04"
usize = struct.unpack("<I", data[4:8])[0]
# RtlGetCompressionWorkSpaceSize + RtlDecompressBufferEx(format=4) -> dec
# version == 30 (Win10), executable name "POWERSHELL.EXE", 8 last-run FILETIMEs at 0x80..0xC0
```
**Gotcha:** the standard v30 run-count offset (`0xD0`) read `0` here — this synthetic prefetch
stores the run count at **`0xC8` = 32**. (PECmd / the Python libs read `0xD0` and would report 0,
so I dumped the file-info block by hand to find the real field.) The host's logs independently
show 169 powershell executions, but the challenge wants the Prefetch field value. Answer: `████`.

## Timestomping check (150)
Evidence: `MFT_ctf_post_tir.raw`. For the persistence folder
`Users\lmartens\AppData\Roaming\Microsoft\SyncHelper`, compare `$STANDARD_INFORMATION` vs
`$FILE_NAME` creation times. I wrote a minimal $MFT parser (1024-byte FILE records, attributes
`0x10` and `0x30`, timestamps as FILETIME; parent-ref walk to resolve the full path and
distinguish the AppData folder from the Task-Scheduler `SyncHelper` task file).

Both timestamps **match** → no timestomping → submit the creation time (UTC, `YYYY-MM-DD HH:MM:SS`,
= `████`).
