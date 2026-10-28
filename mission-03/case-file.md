# Case file — Mission 3: locked out and back in on WKS-L65

**Analyst:** Sajjad · **Workstation:** `WKS-L65.hamilton.corp` (seat 65) · **Domain:** `hamilton.corp`
**Attack machine:** my own laptop, over Tailscale · **Date:** 2026-10-28
**Evidence:** Microsoft Sentinel (workspace from Missions 1–2), the `SecurityEvent` table, plus the actions I took from my laptop. All times UTC (local = UTC+2).

> This mission was run the other way round from Mission 2: I ran the intrusion, end to end, against my own workstation, then reconstructed the part of it my own monitoring could see.

---

## 1. Executive summary — for a manager

I was locked out of my own workstation: my account was disabled so Remote Desktop would no longer let me in. Instead of a password, I used three weaknesses that were already present on the machine and the domain — an anonymous file share that handed out a working account, a domain password stored in a way that anyone can reverse, and a local administrator account whose password came from that same reversible store — to get back onto my own computer with full rights. Once back in, I found a file an intruder had left staging a copy of employee records (names, work emails, departments and salaries) ready to be taken off the machine. The single most important risk this exposed is that **a stranger with no account could reach a working administrator password on this workstation in minutes**, and that a set of **personal employee data was collected and left ready to exfiltrate** — a reportable data breach.

---

## 2. Technical narrative — for a technician

- **Stage 1 — seeing what was still exposed.** Interactive logon to the workstation was refused (my account was disabled), so I stopped trying to log in and instead asked the machine what it still offered to the network. Only two services answered from outside: Remote Desktop (3389), which rejected me, and SMB file sharing (445), which did not require me to prove who I was. I concluded the way back in ran through SMB, not RDP. *How I knew it worked:* the service inventory returned 445 open and anonymously reachable while every RDP logon attempt failed.

- **Stage 2 — getting a first foothold.** SMB let me connect as a guest with no credentials. One non-default share (`Public`) held a single file that had been left lying in the open; reading it gave me the username and password of a low-privilege **domain training account**. *How I knew it worked:* the recovered account authenticated to the domain controller where guest and my own disabled account were both refused.

- **Stage 3 — finding the real key.** That small account was enough to read **SYSVOL**, the share every domain machine reads to get its Group Policy. There I found a Group Policy Preferences file that sets the password of a local administrator account (`svc_deploy`) on each workstation. The password is stored as a `cpassword` — encrypted, but with a key that was **published for anyone to read**, so "encrypted" here does not mean "protected." I decrypted my own seat's value and recovered the local administrator password. *How I knew it worked:* the decrypted value was a well-formed password, and the matching value for another seat decrypted to an equally well-formed password, confirming the key and method.

- **Stage 4 — walking back in.** With a local administrator credential in hand, I opened Remote Desktop to my own workstation as that account. The client first balked at the security negotiation; forcing the RDP security mode let the connection through. I landed on my own desktop with administrator rights. *How I knew it worked:* the credential authenticated as `WKS-L65\svc_deploy` (a wrong password was refused), and the interactive session opened on WKS-L65.

- **Stage 5 — taking my proof and seeing what they were after.** On the desktop were three things that did not belong there together: a **proof file** (my evidence I made the whole way), a **monitoring-access file** with a new login for my Sentinel, and a **`staging\` folder** holding `employees.csv` — a set of employee records an intruder had gathered and marked ready to carry off. I took the proof, recovered and immediately rotated the monitoring login, and recorded exactly what the staged data was. *How I knew it worked:* all three files were present on the workstation's Public desktop; the CSV carried an explicit exfiltration marker.

---

## 3. MITRE ATT&CK mapping

| Stage | Tactic | Technique (ID + name) | What I did | Where I can prove it |
|---|---|---|---|---|
| lockout (context) | Impact | **T1531** Account Access Removal | My domain account was disabled, so interactive logon failed | My Sentinel: `SecurityEvent` 4625 for `sajjad`, and the "account disabled" logon failures (see `queries.kql` Q1) |
| 1 — exposure | Discovery | **T1046** Network Service Discovery | Port/service scan of WKS-L65 → only 445 + 3389 exposed | Reconstructed from my own actions (scan ran from my laptop; not on the workstation) |
| 2 — foothold | Discovery + Credential Access | **T1135** Network Share Discovery, then **T1552.001** Unsecured Credentials: Credentials In Files | Anonymous SMB → read `Public\account-access.txt` → low-priv domain account | My Sentinel: anonymous/guest access to the `Public` share on WKS-L65 (file-share access events, `queries.kql` Q2) |
| 3 — the key | Credential Access | **T1552.006** Unsecured Credentials: Group Policy Preferences | Read `Groups.xml` in SYSVOL, decrypted the `cpassword` with the published key | Reconstructed from my own actions (SYSVOL lives on DC01, not on my workstation, so my SIEM cannot see it) |
| 4 — reprise | Lateral Movement + Defense Evasion | **T1021.001** Remote Services: RDP, with **T1078.003** Valid Accounts: Local Accounts | RDP back into WKS-L65 as the recovered local admin `svc_deploy` | My Sentinel: 4624 LogonType 10 for `svc_deploy` from my laptop (`queries.kql` Q3) |
| 5 — proof + staged data | Collection | **T1005** Data from Local System, **T1074.001** Local Data Staging | Found employee records staged in `C:\Users\Public\Desktop\staging\employees.csv` | The file on the workstation (collected); staging itself reconstructed from my own actions |

---

## 4. Control gaps & remediation

| Weakness exploited | Why it worked | Missing control + fix | ISO 27001 Annex A | NIS2 / CyFun |
|---|---|---|---|---|
| Anonymous/guest SMB access to a workstation share | Guest sessions were allowed to connect and read a share | Disable guest/anonymous SMB; require authentication; remove non-essential shares from endpoints | A.5.15 Access control; A.8.3 Information access restriction | Access control & authentication (CyFun **PR.AC**); NIS2 Art. 21 "basic cyber hygiene / access control" |
| A working credential left in a readable file on the share | Account name + password stored in plain text in `account-access.txt` | Never store credentials in files; use a secrets manager; delete any such file and rotate the account | A.5.17 Authentication information; A.8.3 | PR.AC / PR.DS; NIS2 Art. 21 access control |
| Domain password stored as a reversible GPP `cpassword` in SYSVOL | GPP encrypts with a key Microsoft published (MS14-025); any domain user can read SYSVOL and reverse it | Apply MS14-025 (KB2962486); remove all GPP `cpassword` from SYSVOL; never set passwords via GPP; use **LAPS** for local-admin passwords | A.8.24 Use of cryptography; A.5.17; A.8.8 Management of technical vulnerabilities | Vulnerability management (CyFun **ID.RA / PR.IP**); NIS2 Art. 21 vulnerability handling & patching |
| Same local-admin account (`svc_deploy`) pushed to workstations with a recoverable password | One recovered password = local admin on the seat (and the pattern repeats per seat) | **LAPS** (unique, rotated, non-reversible local-admin passwords); remove shared local admins | A.8.5 Secure authentication; A.5.16 Identity management | PR.AC; NIS2 Art. 21 access control |
| RDP exposed and usable by a local account | 3389 reachable network-wide; a local admin could open an interactive session | Restrict RDP to required sources/accounts; enforce NLA + **MFA**; network-segment management access | A.8.3; A.8.20 Network security | PR.AC / PR.PT; NIS2 Art. 21 network security & MFA |
| Employee data collected and staged for exfiltration | No monitoring/blocking of sensitive data being copied and gathered on an endpoint | **DLP** + egress monitoring; data minimization; encrypt-at-rest + least-privilege on HR data | A.8.12 Data leakage prevention; A.5.34 Privacy & PII; A.5.33 Protection of records | Data security (CyFun **PR.DS**); NIS2 Art. 21 incident handling & business-continuity |

---

## 5. Data breach assessment

- **What was exposed.** A copy of **employee records** was staged on the workstation in `staging\employees.csv`: each row held an employee ID, full name, work email address, department and **salary**. In the recovered sample this was a small set of records, but the content type is HR personal data including remuneration, explicitly tagged as an exfiltration set.

- **Severity.** This is personal data about identifiable individuals, combined with **salary** (sensitive financial information). If it left the organisation it could enable identity fraud, targeted phishing/social engineering against named staff, and real harm to individuals' privacy and finances. Because it names people and pairs them with pay, the impact is high relative to the record count.

- **Notification duty under NIS2.** As a significant incident this triggers staged reporting to the national CSIRT / competent authority: an **early warning within 24 hours** of becoming aware, a **full incident notification within 72 hours** (assessment, severity, indicators), and a **final report within one month**. Affected recipients must be informed where appropriate.

- **Obligations under GDPR.** Personal data was involved, so this is a personal-data breach. The controller must **notify the supervisory authority within 72 hours** of becoming aware (Art. 33) unless the breach is unlikely to result in risk, and must **inform the affected individuals without undue delay** where the breach is likely to result in a high risk to their rights and freedoms (Art. 34). The event must be recorded in the internal breach register regardless.

- **Missing control.** There was nothing to stop sensitive data being gathered on an endpoint and prepared for exit: no **data-loss-prevention / egress controls**, no data minimization, and no least-privilege or encryption around the HR dataset. Fix: classify and restrict HR data at source, deploy DLP and egress monitoring, and alert on bulk collection/staging of sensitive files on endpoints (A.8.12; CyFun PR.DS).

---

## 6. Stretch — alternative route (optional)

_Not completed. The main chain (anonymous SMB → leaked training account → GPP `cpassword` in SYSVOL → local-admin RDP) was the route used. A second, independent route was not pursued._

---

## Appendix — rotation and clean-up performed

- Rotated the recovered **monitoring/Sentinel login** on first sign-in (it had been left in a readable file, so it was compromised by definition).
- Flagged for remediation: the `Public\account-access.txt` credential file, the GPP `cpassword` entries in SYSVOL, and the staged `employees.csv`.
- Credentials used during the mission (my own workstation and the recovered local admin) should be rotated by the owner as part of closing the incident.
