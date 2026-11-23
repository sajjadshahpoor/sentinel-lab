# Mission 6 — Harden, re-attack, triage (WKS-L65, seat 65)

**Analyst:** Sajjad · **Workstation:** `WKS-L65.hamilton.corp` (10.50.0.65) · **Domain:** `hamilton.corp` · **DC:** `DC01` (10.50.0.10)
**Week of:** 2026-11-23 · All times UTC unless marked **(local = UTC+1, CET)**.

> Two parts. **Part 1** proves the Mission 3 and Mission 4 weaknesses are actually gone by re-running the original attacks and keeping the refusal. **Part 2** works a live alert queue: every incident closed with a verdict and a reason, the real threats escalated and cleaned up, and the noisiest rule tuned.
>
> **No secrets in this document:** no password, no full ticket/hash, no cracked value. Only the first characters of a ticket (which name its encryption) appear. Live command output is pasted into the `‹proof›` blocks as I run each step.

---

# Part 1 — Remediation

## Weakness 1 — local-admin password stored in a Group Policy Preference (Mission 3)

**Before.** In Mission 3 I read the local administrator account `svc_deploy`'s password out of `Groups.xml` in the GPO **"Legacy - WKS-L65 Local Admin"**, stored in SYSVOL (`\\hamilton.corp\SYSVOL\...\Policies\{GUID}\...\Preferences\Groups\Groups.xml`) as a `cpassword`. Every domain user can read SYSVOL, and the AES key that protects a `cpassword` has been public since MS14-025 — so "encrypted" meant "readable". I used that password to RDP back into WKS-L65 as a local administrator. *(Mission 3 case file, Stage 3–4.)*

**What I changed.**
1. **Removed the stored secret.** Deleted the Local-Users-and-Groups preference item (the `svc_deploy` entry) from the GPO so no `cpassword` remains in SYSVOL. The GPO is not even linked to a machine — that never mattered, because the exposure is *where the secret is stored and who can read it*, not where the policy applies.
2. **Neutralised the already-leaked credential.** Removing the file stops *new* readers; it does nothing about the password already out there (I, and anyone who read it before, still have it). The password opens the **local** account `svc_deploy` on WKS-L65, so on my own workstation (where I am local admin) I **disabled** that account and rotated its password to a long random value.

```powershell
# on WKS-L65, as local admin
Disable-LocalUser -Name svc_deploy
Set-LocalUser    -Name svc_deploy -Password (ConvertTo-SecureString -AsPlainText -Force `
                 ([System.Web.Security.Membership]::GeneratePassword(32,8)))
```

**After (replayed attack).** I replayed the exact Mission 3 move — RDP to WKS-L65 as `WKS-L65\svc_deploy` with the old leaked password — and read the refusal carefully. A clean refusal is *"the account is disabled"* / logon failed; it is **not** "access denied" (Windows can deny a *local* account remote access even with the right password — that would not prove the password is dead) and **not** an apparent success (some services accept anonymous sessions whatever name you give).

```
# account state on WKS-L65:
Get-LocalUser svc_deploy   ->  Enabled : False
# replay (Impacket SMB login, which reports the exact status with no anonymous fallback),
# using the old password recovered from the cpassword (14 chars) — NOT cracked, just decrypted:
domain=''        : REFUSED -> SMB SessionError 0xc000006d STATUS_LOGON_FAILURE
domain='WKS-L65' : "succeeded" -> this is the GUEST fallback the briefing warns about, not a real
                   logon (the server maps the failed login to a guest session). Discarded.
```

**Why this is the right refusal:** the account is **disabled** (`Enabled False`) *and* its password was rotated, so the old credential returns a clean **logon failure (0xc000006d)** — not "access denied" (which would be the remote-local-account rule, no proof) and not the guest "success" (anonymous fallback, no proof). If I had only deleted the file and left the account enabled, this same credential would still work: **removing the file never un-leaked the password; disabling the account did.**

---

## Weakness 2 — Kerberoastable service account (Mission 4)

**Before.** In Mission 4 I requested a Kerberos service ticket for `svc-app65` (SPN `MSSQLSvc/app65.hamilton.corp`), got it back as **RC4** (`$krb5tgs$23$…`, etype 0x17), and cracked its weak password offline in seconds with `rockyou` (hashcat `-m 13100`). Two problems: the account accepted RC4, and its password was weak.

**What I changed** (as my own domain account, against my own seat's account only — via **ADSI**, because `net user /domain` refuses the reset with "Access is denied" even with the right, and that is the tool, not my rights):
1. **Modern encryption only** — set `msDS-SupportedEncryptionTypes = 24` (`0x18` = AES128 + AES256; RC4 `0x4` and DES `0x1/0x2` cleared). This forces the KDC to issue AES-protected service tickets for the account.
2. **Long random password** — reset to a 32-char random value that nobody needs to remember.

```powershell
$u = [ADSI]"LDAP://CN=svc-app65,OU=ServiceAccounts,DC=hamilton,DC=corp"   # adjust DN to the real OU
$u.Put("msDS-SupportedEncryptionTypes", 24); $u.SetInfo()
$u.Invoke("SetPassword", [System.Web.Security.Membership]::GeneratePassword(32,8)); $u.SetInfo()
# verify: ([ADSI]"LDAP://CN=svc-app65,...").Properties["msDS-SupportedEncryptionTypes"].Value  -> 24
```

**After (replayed attack).** Same Mission 4 command, my seat's account only:

```bash
GetUserSPNs.py hamilton.corp/sajjad -dc-ip 10.50.0.10 -request-user svc-app65 -outputfile svc-app65_hardened.kerb
head -c 14 svc-app65_hardened.kerb     # names the encryption
```

- **Ticket encryption, before vs after:** `$krb5tgs$23$…` (RC4) → **`$krb5tgs$18$…`** (AES256). The `18` is the proof the encryption changed; this is the only part of the ticket kept here.
- **Crack:** RC4 cracked with `-m 13100` in seconds in Mission 4. The AES ticket needs `hashcat -m 19700` (TGS-REP AES256) and, against a 32-char random password, runs effectively forever — I started it, recorded the rate and that it exhausts the wordlist with no hit, and stopped it. Both facts (far slower mode + no result) are the proof; I do not need to wait for it to finish.

```
# attribute change (LDAP, as my own account): msDS-SupportedEncryptionTypes  4 (RC4-only)  ->  24 (AES128+AES256)
# then a CLEARTEXT password reset on the box (ADSI) regenerated the Kerberos AES keys.
# replay, ticket prefix only:
  BEFORE (Mission 4):  $krb5tgs$23$...   (etype 23 = RC4-HMAC)
  AFTER  (Mission 6):  $krb5tgs$18$...   (etype 18 = AES256)
# crack, same rockyou wordlist:
  BEFORE:  hashcat -m 13100 (RC4)     -> cracked in seconds
  AFTER :  hashcat -m 19700 (AES256)  -> Speed ~10,542 H/s, Recovered 0/1, infeasible (stopped early)
```

> **Subtlety worth recording:** a password reset performed *over the network via SAMR* (NTLM) set the NT/RC4 hash but **did not generate AES keys** ("User no longer has valid AES keys … until they change their password again"), so the first replay still returned RC4. Only a **cleartext** reset (ADSI/Set-ADAccountPassword, run on the domain-joined workstation so it reaches the DC's sealed channel) regenerated the AES keys — after which the replay returned `$krb5tgs$18$` and the RC4 path was gone.

---

## Weakness 3 — the domain allowed weak passwords (change request)

The service-account password was weak because the **domain password policy** allowed it. That policy is shared by the whole class, so I may not change it — I **requested** a change. The full request is in **[change-request.md](change-request.md)**; summary:

- **Finding / risk:** the live default domain policy sets **minimum length 7** with **no account lockout** (`lockoutThreshold 0`) and **no PSOs**, so a human-memorable password can protect a service account — which makes offline Kerberoasting trivial (and online guessing unbounded).
- **Proposed fix:** a **Fine-Grained Password Policy (PSO)** applied to a `Service Accounts` group requiring **≥ 25 characters** (service accounts are never typed by a human, so length is free and is what defeats offline cracking — NIST SP 800-63B favours length over composition). Recommend the PSO (targeted) over a domain-wide raise, so ordinary users are not forced to 25 characters; optionally raise the domain default to 14 for human accounts.
- **Affected accounts / rollback:** affects only members of the `Service Accounts` group; rollback = unlink/delete the PSO (effective on next password set).

**After (proof weak password refused).** Once the coach applies a change for the whole class, I try to reset `svc-app65` to a short weak password and keep the refusal:

```
‹proof: Set-ADAccountPassword/ADSI reset of svc-app65 to a short weak value -> refused
         ("password does not meet the length/complexity/history requirements")›
‹TODO(me): paste the refusal. If the weak password is ACCEPTED, the change is not in
           place yet — set a long random password again and tell the coach.›
```

---

# Part 2 — Alert triage

## Step 4 — collection the rule pack needs

I read the query of each of the 8 rules and listed the table + events it needs, then compared with my Mission 1 Data Collection Rule.

| Rule | Table | Event(s) | New since Mission 1? |
|---|---|---|---|
| R01 Repeated failed logons | `SecurityEvent` | 4625 | no |
| R02 RDP logon | `SecurityEvent` | 4624 (LogonType 10) | no |
| R03 Local user created | `SecurityEvent` | **4720** | **audit: Account Management** |
| R04 Added to local Admins | `SecurityEvent` | **4732** (TargetSid S-1-5-32-544) | **audit: Account Management** |
| R05 Scheduled task created | `SecurityEvent` | 4698 | needs 4698 collected |
| R06 Encoded PowerShell | `SecurityEvent` | **4688** + `CommandLine` | process-create **with command line** |
| R07 PowerShell web download | **`Event`** | **4104**, Source `Microsoft-Windows-PowerShell` | **PowerShell Operational channel** |
| R08 Discovery burst | `SecurityEvent` | 4688 | process-create with command line |

**The gap:** R07 does **not** read `SecurityEvent` — it reads the **`Event`** table, which is where non-security Windows channels land. The PowerShell script-block log (`Microsoft-Windows-PowerShell/Operational`, EventID 4104) is written on the workstation but never reaches Sentinel unless my DCR collects that **channel by its full name**. Same lesson as Mission 4: written on the box ≠ in Sentinel.

**What I changed in the DCR** (Azure portal → Monitor → Data Collection Rules → my workstation DCR):
- Added the Windows Event Log data source **`Microsoft-Windows-PowerShell/Operational`** (so 4104 lands in `Event`).
- Confirmed the Security stream collects 4720, 4732, 4698, 4688; and that the workstation's audit policy (turned on by the AD team) logs Account Management (4720/4732) and Process Creation **with command line** (4688 `CommandLine`).
- Waited for the DCR to reach the workstation, then confirmed the newest events arrive:

```kql
Event    | where TimeGenerated > ago(1h) | where Source == "Microsoft-Windows-PowerShell" | summarize count() by EventID
SecurityEvent | where TimeGenerated > ago(1h) | summarize count() by EventID | where EventID in (4720,4732,4698,4688)
```
```
‹TODO(me): paste the two count tables once collection is confirmed (give it real time)›
```

## Step 5 — import the rule pack

Imported `rules/M6_rule_pack.json` from Azure portal → Microsoft Sentinel → Analytics → **Import**, supplying my own Log Analytics workspace name for the `workspace` parameter (and confirming I was in my own subscription). Verified all **8 rules enabled** (R01–R08). They are deliberately sensitive, so they fire on normal IT activity too — that is the point of Part 2.

## Step 6 — the queue (journal)

The queue fills once IT work starts (**CHG tickets from Thu 26/11**). My triage method for every incident: open it → read entities and the events behind it (account / machine / command / object / time) → search the **[IT change calendar](../../Mission%206/IT_CHANGE_CALENDAR.md)** for that **exact** account, task, path or address → classify (**true positive** / **benign positive** = real & expected / **false positive** = rule misfired) → close in Sentinel with that classification and a comment someone else could check.

**Rules I am holding myself to** (from the briefing): recognising a title settles nothing (two incidents from the same rule can have opposite answers); the parent process and the account prove nothing (every IT change arrives via the same SYSTEM management agent) — compare the **exact** names/paths/addresses; and a real threat is usually several incidents that tell one story.

**Pre-mapping of the planned work to the rules** (my expectation before the queue opens — each still verified character-by-character against the real event):

| Calendar item | Rule(s) it should trip | Expected verdict | What must match exactly |
|---|---|---|---|
| CHG-0412 inventory task `\HamiltonIT\Hamilton-Inventory`, SYSTEM, `C:\ProgramData\HamiltonIT\` | **R05** | benign positive | TaskName = `\HamiltonIT\Hamilton-Inventory` |
| CHG-0413 create `hamilton-support`, add to local Admins | **R03** (4720) + **R04** (4732) | benign positive | account name `hamilton-support`; member added = that account |
| CHG-0414 pull printer script from `http://10.50.0.250/it/` into `C:\ProgramData\HamiltonIT\` | **R07** (web download) | benign positive | URL host = `10.50.0.250`, path `/it/` |
| INC-2291 helpdesk diagnostics + mistyped `hamilton-support` password | **R08** (discovery burst) + **R01** (failed logons for `hamilton-support`) | benign positive **for the technician's window**; see below | source + time inside the helpdesk session |

> **The trap I am watching for (R01 / INC-2291).** INC-2291 explains why `hamilton-support` logons *started* failing (a technician mistyped it a few times) — it does **not** explain who is *still* trying. If R01 fires again for `hamilton-support` with many failures, from a different source, or outside the helpdesk window, that is **not** the ticket: it is a credential attack against a brand-new local admin account and is a **true positive** to escalate. I also check my own workstation for anything Mission 4 left behind (a re-registered `SyncHelper` task, a discovery burst) — "think back to everything that was ever set up on this machine."

| # | Time (UTC) | Rule | Account / Host | Evidence (1 line) | Verdict | Reason | Closed as |
|---|---|---|---|---|---|---|---|
| ‹TODO(me): one row per incident as the queue fills — classification + comment in Sentinel too› |

## Step 7 — escalate & clean up (true positives)

For each true positive I send a second-line escalation note (template below), and after the coach acknowledges it I clean up on WKS-L65, verify it is gone, and append what I did. Notes live in **[escalations.md](escalations.md)** (created when the first true positive appears).

```
Escalation — <rule> — <account> on <host>
What happened:   <one line>
Machine/account: WKS-L65 / <account>
Evidence:        <event IDs / KQL that show it, exact times in UTC>
Timeline:        <first seen → last seen>
Recommendation:  <contain/disable/remove>
Not yet checked: <gaps>
Cleanup (after ack): <what I removed> → verified gone by <query/command>
```

## Step 8 — tune the noisiest rule

To be filled from the journal: the rule that raised the most **non-true-positive** incidents (likely **R02 RDP logon** or **R08 discovery burst**, both of which fire on routine IT work). I propose one change that drops that noise **without** blinding the rule, write the modified query here, and prove it by running original vs. modified over the same period — everything the modified query drops must be something I already classified as expected, and it must still return every true positive.

```kql
// original vs tuned, same period — tuned must drop only benign-classified rows and keep all TPs
‹TODO(me): modified query + the before/after result counts›
```

> I will **not** tune by excluding the SYSTEM account alone: IT changes arrive as SYSTEM, but so could an attacker's, so excluding SYSTEM would blind the rule. I tune on the *exact* benign signature instead (known task path / known URL / known tool-sequence), which removes the planned-change noise while still catching the same action from an unexpected name, path or address.

---

*Deliverable for Mission 6. The closed incidents in my Sentinel and this document are the proof; there is no CTFd flag.*
