# My seat in hamilton.corp

Before noticing anything wrong on a machine, you need to know what normal looks like. Everything below was found from my own workstation, logged in with my own account.

## Know your seat

| Question | Answer | How I know | Source |
|---|---|---|---|
| Workstation full name | `WKS-L65.hamilton.corp` | `"$env:COMPUTERNAME.$env:USERDNSDOMAIN"` | Workstation |
| My account | `HAMILTON\sajjad`, SID ending `-1158` | `whoami /all` | Domain |
| Who checks my password | `DC01` (KDC, PDC, GC, DNS, time server) | `$env:LOGONSERVER`, `nltest /dsgetdc:hamilton.corp` | Domain |
| DC01 address | `10.50.0.10` | `nltest`, `Resolve-DnsName DC01.hamilton.corp` | Domain |
| Workstation's place in AD | `OU=L65,OU=Learners,DC=hamilton,DC=corp` | `gpresult /r /scope computer` | Domain |
| My account's OU | `Accounts` | `gpresult /r` | Domain |
| GPO applied to my workstation | `Default Domain Policy` (user side: none) | `gpresult /r /scope computer` | Domain |
| Domain group in my local Administrators | `Domain Admins` | `Get-LocalGroupMember Administrators` | Workstation |

**In my own words:** the workstation knows its own name and who is in its local groups. Everything about identity (who I am, where my account and computer live, which rules apply) comes from the domain, held by DC01. The two meet in the local Administrators group: a local group that contains domain identities. Whoever controls those domain accounts controls my workstation.

**Rights:** I am a local admin on WKS-L65, but because of UAC my normal session runs at Medium integrity ("Group used for deny only"). I only get admin rights with *Run as administrator*.

## Baseline (2026-10-08, 22:59 local)

**Local accounts**

| Account | Enabled | Notes |
|---|---|---|
| Administrator | No | Built-in |
| becode | Yes | Local admin |
| helpdesk | Yes | Not an admin |
| labuser | Yes | Not an admin |
| DefaultAccount, Guest, WDAGUtilityAccount | No | System accounts |

**Local Administrators:** `HAMILTON\Domain Admins`, `HAMILTON\sajjad`, `WKS-L65\Administrator`, `WKS-L65\becode`.

**Normal SIEM activity (24 h):** about 25–45 security events per hour, mostly SYSTEM service logons (4624 type 5), 4672 and 4799. My own logons come from the lab gateway `10.50.0.1`, workstation name `SAJJAD` (my laptop): LogonType 3 then 7/10. Zero failed logons (4625), zero account or group changes.

## What Windows records (audit policy at baseline)

| Recorded | Not recorded |
|---|---|
| Logon success/failure (4624/4625), special logon (4672), lockout (4740) | **Process creation (4688)** |
| User account management (4720, 4722, 4724, 4726, 4738) | File system and registry access |
| Security group management (4732…) | Scheduled task creation (4698) |
| Audit policy change (4719) | Credential validation |
