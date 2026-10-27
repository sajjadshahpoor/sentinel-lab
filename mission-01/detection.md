# Detection — changes I did not make

Three changes appeared on my seat that I did not make. For each: what happened, how I know, where the evidence lives, and whether my SIEM could see it.

## 1. Two files appeared on my Desktop (2026-10-08)

**What:** `IDENTITY_IN_HAMILTON.md` and `CTFD_CREDENTIALS.txt` appeared in `C:\Users\Public\Desktop`.

**How I found it**

1. My baseline showed an unusual spike at **09:00 UTC on Oct 8**: 209 security events, while a normal hour has 25–45.
2. The file is on the **Public** Desktop, created **11:13:10 local (09:13:10 UTC)**, owner `BUILTIN\Administrators`. That is what you get when SYSTEM creates a file.
3. In Sentinel, there was **no network or RDP logon** (no 4624 type 3/10) by any other account in that window, only SYSTEM service logons and a burst of 4799 events from `C:\Program Files\Qemu-ga\qemu-ga.exe`.
4. On the workstation, the **Application log, provider `qemu-ga`, Event ID 1** shows every action.

**Timeline (local time)**

| Time | QEMU guest agent action |
|---|---|
| 11:05:48 | `guest-fsfreeze`: the hypervisor froze the disk (likely a snapshot) → burst of 4799 + VSS error 8194 |
| 11:13:10 | `guest-file-open C:\Users\Public\Desktop\IDENTITY_IN_HAMILTON.md, mode: wb` |
| 11:13:11 | `guest-file-open C:\Users\Public\Desktop\CTFD_CREDENTIALS.txt, mode: wb` |
| 11:13:12 | `guest-exec` encoded PowerShell: removed inheritance, allowed only `HAMILTON\sajjad`, SYSTEM, Administrators |
| 11:13:16 | `guest-exec` encoded PowerShell: verified size, SHA-256, owner, permissions |
| 11:15:36 | `guest-exec` encoded PowerShell: collected computer/account DN, DC, GPOs, local admins (`net1.exe` seen as 4799 at 11:15:40) |

I decoded the `-EncodedCommand` values (Base64, UTF-16LE) to read the scripts.

**Conclusion:** the lab operator wrote the files **from the hypervisor**, through the QEMU Guest Agent running inside the VM as SYSTEM. No password, no logon event.

**SIEM:** ❌ The actions were in the Application log at **Information** level; `dcr-windowsevents` collects only Error/Warning. Only side effects (4799 from `qemu-ga.exe`, VSS 8194) reached Sentinel.

## 2. A hidden admin account: `svc_backup` (2026-10-09)

**What:** a local account `svc_backup` ("Backup service account") was created and added to **Administrators**, then later removed. It was no longer in `Get-LocalUser` when I checked, but the SIEM remembered it.

**Evidence (SecurityEvent, all by `HAMILTON\WKS-L65$` = SYSTEM, within 0.1 s → a script)**

| Time (UTC) | Event | Meaning |
|---|---|---|
| 12:30:49.403 | **4720** | `WKS-L65\svc_backup` created |
| 12:30:49.407 | 4722 | Account enabled |
| 12:30:49.407 | 4738 ×2 | Account properties changed |
| 12:30:49.438 | 4724 | Password set |
| 12:30:49.486 | **4732** | Added to `BUILTIN\Administrators` |

The Application log (`qemu-ga`) confirms the source: a `guest-exec` at 14:30:47 local ran `New-LocalUser svc_backup … -PasswordNeverExpires` with a random password, then `Add-LocalGroupMember -Group 'Administrators' -Member 'svc_backup'`. A check script at 14:32:20 verified that 4720 and 4732 had been logged.

**Why it matters:** a new admin account with a harmless-looking "service" name is a classic persistence technique (MITRE **T1136.001 Create Account: Local Account**, **T1098 Account Manipulation**).

**SIEM:** ✅ Both 4720 and 4732 are in `SecurityEvent`. The SIEM copy survives even if the local log is cleared or the account is deleted.

## 3. My own domain account changed (2026-10-09)

**What:** `HAMILTON\sajjad` was added to the domain group **L65-Project-Readers**. The group was later deleted during cleanup.

**What I checked (12–13 Oct):** `net user sajjad /domain`, LDAP `memberOf`, and `whoami /groups` after a fresh logon → only **Domain Users**. These were correct for the current state, but the change was already gone.

**Where the evidence lives:** **DC01's Security log** (4728/4756 member added, 4730/4758 group deleted). The change was made in Active Directory, not on my workstation.

**SIEM:** ❌ I only collect WKS-L65. Domain controller logs are not in my workspace.

## Summary

| # | Change | Where the evidence lives | SIEM saw it? |
|---|---|---|---|
| 1 | Files dropped via QEMU guest agent | WKS-L65 Application log (Information) | ❌ Side effects only |
| 2 | `svc_backup` created + made admin | WKS-L65 Security log → `SecurityEvent` | ✅ 4720, 4732 |
| 3 | My account added to a domain group | DC01 Security log | ❌ Not collected |

**What this says about my SIEM:** it sees one machine and one well-collected log (Security, *Common*). It misses anything on another machine (DC01), anything at Information level in Application/System, and anything not audited. An empty result never means "it didn't happen". First ask: *which machine would record this, in which log, at which level, and do I collect it?*
