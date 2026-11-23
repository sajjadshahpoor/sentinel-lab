# Mission 6 — runbook (exact steps I ran)

Seat 65. Part 1 from WKS-L65 signed in as myself (domain account `sajjad`), local admin on the box.
Attack replays from my laptop over Tailscale (WSL), as in Missions 3–4. Part 2 in my own Sentinel.
No live secrets are pasted into the deliverable — only ticket prefixes and refusals.

> Rights for this mission cover my seat only: the "Legacy - WKS-L65 Local Admin" GPO, `svc-app65`,
> and local admin on WKS-L65. If a tool ever touches another seat, stop and tell the coach.

---

## Block 1 — remove the GPP password + kill the leaked credential

**1a. Remove the stored secret from the GPO** (either method):
- *GUI (RSAT/GPMC):* `gpmc.msc` → edit **Legacy - WKS-L65 Local Admin** → Computer (or User) Config →
  Preferences → Control Panel/Windows Settings → **Local Users and Groups** → delete the `svc_deploy`
  item (the one carrying the password). This rewrites the preference without a `cpassword`.
- *File (if I can write SYSVOL for my GPO):* delete the `Groups.xml` under that GPO's
  `...\Preferences\Groups\` in `\\hamilton.corp\SYSVOL\hamilton.corp\Policies\{GUID}\`.
- Confirm no `cpassword` remains:
  ```powershell
  Select-String -Path "\\hamilton.corp\SYSVOL\hamilton.corp\Policies\*\*\Preferences\Groups\Groups.xml" -Pattern cpassword
  # -> no matches for my GPO
  ```

**1b. Neutralise the already-leaked local account** (on WKS-L65, local admin):
```powershell
Get-LocalUser svc_deploy                       # before: Enabled True
Disable-LocalUser -Name svc_deploy
Add-Type -AssemblyName System.Web
Set-LocalUser -Name svc_deploy -Password (ConvertTo-SecureString -AsPlainText -Force `
              ([System.Web.Security.Membership]::GeneratePassword(32,8)))
Get-LocalUser svc_deploy                       # after: Enabled False
```

**1c. Replay the Mission 3 attack (must now fail with the *right* refusal):**
```bash
# from the laptop (WSL) — old leaked password; expect a DISABLED/logon-failed refusal, not "access denied"
xfreerdp /u:svc_deploy /d:WKS-L65 /p:'<old-leaked-password>' /v:10.50.0.65 /cert:ignore
```
Keep the exact error. Cross-check on the box: `Security` log 4625 for `svc_deploy` with **SubStatus
0xC0000072** (account disabled) = valid proof. "Access is denied" alone is **not** proof (remote
local-account restriction); an apparent success is **not** proof (anonymous fallback).

---

## Block 2 — harden the roasted service account + replay

Find the account DN, then set AES-only + long random password via **ADSI** (not `net user /domain`).
```powershell
# DN
([ADSISearcher]"(sAMAccountName=svc-app65)").FindOne().Path   # -> LDAP://CN=svc-app65,OU=...,DC=hamilton,DC=corp
$u = [ADSI]"LDAP://CN=svc-app65,OU=...,DC=hamilton,DC=corp"

# modern encryption only: 24 = 0x18 = AES128 + AES256 (RC4/DES cleared)
$u.Put("msDS-SupportedEncryptionTypes", 24); $u.SetInfo()
$u.Properties["msDS-SupportedEncryptionTypes"].Value          # verify -> 24

# long random password (nobody memorises it)
Add-Type -AssemblyName System.Web
$u.Invoke("SetPassword", [System.Web.Security.Membership]::GeneratePassword(32,8)); $u.SetInfo()
```
*(RSAT alternative: `Set-ADUser svc-app65 -Replace @{"msDS-SupportedEncryptionTypes"=24}` and
`Set-ADAccountPassword svc-app65 -Reset`.)*

**Replay (my seat only) and compare encryption:**
```bash
GetUserSPNs.py hamilton.corp/sajjad -dc-ip 10.50.0.10 -request-user svc-app65 -outputfile svc-app65_hardened.kerb
head -c 14 svc-app65_hardened.kerb          # BEFORE: $krb5tgs$23$  (RC4)   AFTER: $krb5tgs$18$  (AES256)

# crack now needs the AES mode and is effectively infeasible; capture ONE status line, no cracked value
hashcat -m 19700 svc-app65_hardened.kerb "$HOME/rockyou.txt" --runtime=120 --status --status-timer=30
# record: mode 19700 vs 13100 before, the H/s rate, and "Exhausted"/stopped with no hit. Do not wait for it.
rm -f svc-app65_hardened.kerb               # don't leave the ticket on disk
```

---

## Block 3 — password-policy change request

Read the current policy (allowed), then send `change-request.md` to the coach:
```powershell
Get-ADDefaultDomainPasswordPolicy
Get-ADFineGrainedPasswordPolicy -Filter *   # any existing PSOs
```
After the coach applies the class-wide change, prove a weak password is refused:
```powershell
# expect: "The password does not meet the length/complexity/history requirements of the domain"
Set-ADAccountPassword svc-app65 -Reset -NewPassword (ConvertTo-SecureString "Weak1" -AsPlainText -Force)
# if it is ACCEPTED, the change is not live yet -> set a long random password again and tell the coach.
```

---

## Block 4 — Sentinel collection (do BEFORE importing rules)

Azure portal → **Monitor → Data Collection Rules →** my workstation DCR → **Data sources → Windows Event Logs**:
- Add channel **`Microsoft-Windows-PowerShell/Operational`** (feeds the `Event` table → needed by **R07**).
- Ensure the Security stream carries **4720, 4732, 4698, 4688** (4688 with command line). The AD team
  already enabled the audit policy on the workstation (Account Management + Process Creation w/ cmdline).

Give the DCR time to reach the box, then confirm the new events arrive:
```kql
Event
| where TimeGenerated > ago(2h) and Source == "Microsoft-Windows-PowerShell"
| summarize count() by EventID            // expect 4104 (and 4103)

SecurityEvent
| where TimeGenerated > ago(2h) and Computer has "WKS-L65"
| summarize count() by EventID
| where EventID in (4720,4732,4698,4688)
```

## Block 5 — import rules
Azure portal → Microsoft Sentinel (my workspace) → **Analytics → Import** → `rules/M6_rule_pack.json` →
set the `workspace` parameter to **my own Log Analytics workspace name** (confirm I'm in my own
subscription). Verify **R01–R08 all Enabled**.

## Blocks 6–8 — triage (from 26/11)
Work the Incidents queue against `IT_CHANGE_CALENDAR.md`; record each in the journal table in
`case-file.md`; escalate true positives (`escalations.md`); tune the noisiest rule (Step 8). See the
pre-mapping and traps in `case-file.md` (CHG-0412→R05, CHG-0413→R03+R04, CHG-0414→R07, INC-2291→R08/R01,
and the "who is still trying" R01 true-positive trap).
