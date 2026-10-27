# Case file — RDP brute-force intrusion on WKS-L65

**Analyst:** Sajjad · **Workstation:** `WKS-L65.hamilton.corp` · **Date of incident:** 2026-10-13
**Source of evidence:** Microsoft Sentinel (`SecurityEvent`), workspace `log-sentinel-lab`, plus the local Security log.
All times UTC (local = UTC+2).

## Summary

On 13 October 2026 at 08:12 UTC, an attacker on another machine on the lab network (**10.50.0.100**, host **WKSTN-07**) guessed the password of the local account **`helpdesk`** on my workstation in five quick attempts, logged in over **Remote Desktop**, and ran **one command** that wrote a proof file to the account's Desktop. The login was visible in my SIEM with default logging; the command only became visible after a **process-creation audit policy** was enabled by GPO.

## Answers

| Question | Answer | Evidence |
|---|---|---|
| Which account was used? | **`helpdesk`** (local account on WKS-L65) | 4625 ×5 then 4624 for `TargetUserName == "helpdesk"` |
| Where did the connection come from? | **10.50.0.100** (workstation name `WKSTN-07`) | `IpAddress` and `WorkstationName` on 4625/4624 |
| What kind of attack? | **Brute force / password guessing** (MITRE T1110.001) | 5 failures in 0.3 s, then a success 2 s later |
| What did the attacker run? | `"C:\Windows\System32\cmd.exe" /c echo HAM{…}> %USERPROFILE%\Desktop\flag.txt` | 4688 at 08:13:25 |
| Proof left behind | `C:\Users\helpdesk\Desktop\flag.txt` | File on disk |

## Timeline

| Time (UTC) | Event | Detail | MITRE ATT&CK |
|---|---|---|---|
| 08:06:28 | 4647 | I signed out of WKS-L65 (attack window starts) | — |
| 08:08:27 | 4719 ×10 | Audit policy changed (GPO): **Process Creation** enabled, with command line | — |
| 08:08:27 → | 4688 | Process-creation events start appearing in the SIEM | — |
| **08:12:57.7 – 08:12:58.1** | **4625 ×5** | Failed logons for `helpdesk`, LogonType 3, from 10.50.0.100 / WKSTN-07 | **T1110.001** Brute Force: Password Guessing |
| **08:13:00** | **4624** | Successful logon `helpdesk`, LogonType 3 (RDP Network Level Authentication) | **T1078.003** Valid Accounts: Local Accounts |
| **08:13:01** | **4624** | LogonType **10**: RDP desktop session opened | **T1021.001** Remote Services: Remote Desktop Protocol |
| 08:13:03 – 08:13:14 | 4688 | First-logon noise: `rdpinit`, `runonce`, Edge and OneDrive setup | — |
| **08:13:25** | **4688** | `cmd.exe /c echo HAM{…}> %USERPROFILE%\Desktop\flag.txt`, parent `rdpinit.exe` | **T1059.003** Command and Scripting Interpreter: Windows Command Shell |
| 09:26 | 4624 | I signed back in (attack window ends) | — |

## How I separated the attacker from myself

Before hunting, I played attacker on my own machine (Part 1) with the lab account `labuser`:

| Time (UTC) | Event | From |
|---|---|---|
| 07:24:15 – 07:24:40 | 4625 ×3 (type 3) | 10.50.0.1 / SAJJAD |
| 07:24:59 | 4624 ×2 (type 3) | 10.50.0.1 / SAJJAD |
| 07:25:01 | 4624 (type 10) | 10.50.0.1 |

My own activity always comes from the gateway **10.50.0.1** with workstation name **SAJJAD** (my laptop). The intrusion came from **10.50.0.100 / WKSTN-07**: a different account from a different machine. One RDP login produces several 4624 events (type 3, then 10), so I counted it as one login.

The speed of the failures matters: my three manual wrong passwords took **25 seconds**; the attacker's five took **0.3 seconds**. That is a tool, not a person typing.

## The gap: before and after the logging policy

| | Before (default logging) | After (process-creation GPO) |
|---|---|---|
| Failed logons (4625) | ✅ Visible | ✅ Visible |
| Successful logon, account, source IP (4624) | ✅ Visible | ✅ Visible |
| **What the attacker ran** | ❌ **Invisible**: no 4688; my own `whoami` as labuser left no trace | ✅ **4688 with full command line** |

**Why:** Windows records *who logged in* by default, but *which programs started* only if "Audit Process Creation" is on, and *with which arguments* only if "Include command line in process creation events" is also on. Default logging tells you the door was opened, not what was taken.

## Detection I would want next time

> Alert when one source IP produces **5 or more failed logons (4625) for the same account within 1 minute**, followed by a **successful logon (4624) for that account from the same IP**.

```kql
let window = 1m;
let failures = SecurityEvent
    | where EventID == 4625
    | summarize Failures = count(), FirstFail = min(TimeGenerated), LastFail = max(TimeGenerated)
        by TargetUserName, IpAddress, bin(TimeGenerated, window)
    | where Failures >= 5;
failures
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | project SuccessTime = TimeGenerated, TargetUserName, IpAddress, LogonType
  ) on TargetUserName, IpAddress
| where SuccessTime between (LastFail .. LastFail + 5m)
| project TargetUserName, IpAddress, Failures, FirstFail, SuccessTime, LogonType
```

## For a non-technical manager

Someone on our network guessed a weak password for a support account and logged into an employee's computer remotely. Because that account could log in from anywhere, they could have read files, installed malware or used the computer to attack others. We saw the break-in because our monitoring records logins; we only saw what they did because we turned on extra logging, so that setting should stay on everywhere.

## Recommendations

1. **Strong, unique password** for `helpdesk`, or disable the account if it is not needed.
2. **Account lockout policy** (e.g. lock after 5 failures for 15 minutes) to stop guessing.
3. **Restrict RDP** to the accounts and source addresses that need it.
4. **Keep process-creation auditing with command line** on all workstations, and collect it in Sentinel.
5. **Turn the detection above into a Sentinel analytics rule.**
