# Change request — strengthen password requirements for service accounts

**Requested by:** Sajjad (seat 65) · **Date:** 2026-11-23 · **Owner to approve/apply:** domain / policy owner (coach)
**Type:** standard change to Active Directory password requirements · **Scope:** `hamilton.corp`

## 1. What I found
During Mission 4 I recovered the password of my seat's service account `svc-app65` by offline
Kerberoasting: I requested its Kerberos service ticket as any domain user may, then cracked it in
**seconds** with a public wordlist (`rockyou`). The crack was trivial because the password was
short and human-memorable — which the **domain password policy permits today**. The same is true
for every `svc-appNN` service account in the domain.

## 2. Risk (two sentences)
Any domain user can request a service account's ticket and crack a weak password offline, silently,
then authenticate as that account. Weak passwords on service accounts therefore turn a normal,
un-alarmed Kerberos request into full credential theft of a privileged, non-interactive account.

## 3. Current state (read-only, allowed)
Current effective policy (Default Domain Policy — to be confirmed against the live value):

```
Minimum password length:   7      (allows human-memorable, crackable secrets)
Complexity:                Enabled
Max/Min password age:      <current>
Lockout:                   <current>
```
`‹TODO(me): paste the live output of  Get-ADDefaultDomainPasswordPolicy  (and any existing PSOs)›`

## 4. Proposed change (exact values, with justification)
Service accounts are **never typed by a human**, so length is free and is exactly what defeats
offline cracking; composition rules add little against an offline attacker (NIST SP 800-63B
prioritises length over complexity). I propose a **Fine-Grained Password Policy (PSO)** targeted at
service accounts, rather than raising the rule for everyone:

| Setting | Proposed | Why |
|---|---|---|
| **Min length (service accounts)** | **≥ 25 characters** (PSO on a `Service Accounts` group) | 25+ random chars make offline Kerberoast cracking infeasible; no human types it, so no usability cost |
| Complexity (service accounts) | Enabled | defence in depth; cost is zero for generated passwords |
| Max password age (service accounts) | ≤ 180 days, or managed rotation (gMSA) | bounds exposure of any leaked secret |
| **Min length (all human users)** *(optional, lower priority)* | **14 characters** on the default domain policy | modest raise; aligns with current baseline guidance |
| PSO precedence | lowest number (applies first) | ensures the service-account PSO wins over the default |

**Even better (note, not required now):** migrate `svc-appNN` accounts to **group Managed Service
Accounts (gMSA)** — 120-character machine-managed passwords, rotated automatically, AES-only. That
removes the crackable secret entirely and is the real long-term fix; the PSO is the immediate step.

## 5. Who is affected and how
- **Service accounts** (members of the `Service Accounts` group): next password set must be ≥ 25
  chars. Each seat owner resets their own `svc-appNN` to a long random value (Mission 6, block 1) —
  no human-login impact, because these accounts are not logged into interactively.
- **Human users** (only if the optional 14-char domain change is accepted): their *next* password
  change must meet the new minimum. No forced reset; existing passwords keep working until change.
- A PSO (recommended) means ordinary users feel **nothing** — the stricter rule hits service
  accounts only.

## 6. Rollback
- **PSO:** unlink it from the `Service Accounts` group or delete it (`Remove-ADFineGrainedPasswordPolicy`).
  Existing long passwords keep working; only the *next* reset reverts to the default rule. No outage.
- **Default-domain change (if applied):** revert the minimum length in the Default Domain Policy GPO
  and run `gpupdate` on the DCs. Reversible, no account lockout caused by the change itself.

## 7. Verification after apply
Once applied for the class, I will attempt to reset `svc-app65` to a short weak password; the
expected result is a refusal ("password does not meet the minimum length requirements"). I keep
that refusal as proof. If the weak password is accepted, the change is not yet in place — I set a
long random password again and report back.

**Requested action:** apply the Service-Accounts PSO (≥ 25 chars) domain-wide and confirm the
target group; notify seat owners to rotate their `svc-appNN` accounts.
