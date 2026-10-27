# Mission 1 — Baseline: what "normal" looks like

Taken on **2026-10-08** before any of the investigated changes. Two halves: the SIEM's view (events) and the machine's view (state). The scripts are in [`../scripts`](../scripts).

## SIEM baseline (24 h up to 2026-10-08 ~20:56 UTC)

**Health:** 1,438 heartbeats from `WKS-L65.hamilton.corp` (about one per minute).

**Security event types**

| EventID | Meaning | Count | Notes |
|---|---|---|---|
| 4624 | Successful logon | 394 | Mostly SYSTEM (type 5) |
| 4672 | Admin rights at logon | 390 | Paired with SYSTEM logons |
| 4799 | Local group membership read | 335 | Windows/services checking groups |
| 4634 | Logoff | 47 | |
| 4648 | Logon with explicit credentials | 7 | My RDP sessions / scheduled tasks |
| 4798 | A user's groups were read | 1 | |

**Seen zero times:** 4625 (failed logon), 4720 (user created), 4732 (added to group), 4740 (lockout), 4724 (password reset), 1102 (log cleared). Any of these later is worth investigating.

**Who logs on**

| Account | LogonType | From | Count |
|---|---|---|---|
| NT AUTHORITY\SYSTEM | 5 | – | 349 |
| WKS-L65$ | 3 | ::1 / – | 35 |
| HAMILTON\sajjad | 3, 7 | 10.50.0.1 | 13 |

`helpdesk`, `labuser`, `becode` and `Administrator` never logged on.

**Volume:** usually **25–45 security events per hour**. Busier hours (05:00, **09:00 = 209**, 13:00, 20:00 UTC) matched my own work, except 09:00, which turned out to be the hypervisor dropping files (see [`detection.md`](detection.md)).

**Chain A (System/Application):** very quiet, only Error/Warning events (TPM-WMI 1796, VSS 8194, SPP 8198, DCOM 10016).

## Machine baseline (2026-10-08 22:59 local)

Saved to `C:\baseline\` with [`scripts/baseline-snapshot.ps1`](../scripts/baseline-snapshot.ps1).

**Local users:** Administrator (disabled), becode, helpdesk, labuser (enabled), DefaultAccount, Guest, WDAGUtilityAccount (disabled).

**Local Administrators:** `HAMILTON\Domain Admins`, `HAMILTON\sajjad`, `WKS-L65\Administrator`, `WKS-L65\becode`.

**Non-Microsoft scheduled tasks:** `azcmagent` (Arc agent), Edge update tasks, OneDrive tasks for three user SIDs.

**Audit policy highlights**

| Subcategory | Setting | Consequence |
|---|---|---|
| Logon | Success and Failure | 4624 / 4625 ✅ |
| Account Lockout | Success | 4740 ✅ |
| User Account Management | Success | 4720, 4722, 4724, 4726, 4738 ✅ |
| Security Group Management | Success | 4732 ✅ |
| Audit Policy Change | Success | 4719 ✅ |
| **Process Creation** | **No Auditing** | **4688 ❌, commands invisible** |
| Other Object Access | No Auditing | Scheduled task creation (4698) ❌ |
| File System / Registry | No Auditing | ❌ |

## Why the baseline mattered

- The **09:00 UTC spike** was the first clue for the file-drop investigation.
- The **account list** let me spot `svc_backup` (and that it had since been removed).
- The **audit policy** told me in advance which attacks the SIEM would and would not see. Process creation being off is exactly the gap Mission 2 exploits.
