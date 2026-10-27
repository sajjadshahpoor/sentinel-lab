# Microsoft Sentinel SIEM Lab — Windows workstation monitoring and intrusion hunting

Hands-on blue-team project from the BeCode cybersecurity track. I connected a Windows 10 domain workstation (`WKS-L65`, domain `hamilton.corp`) to **Microsoft Sentinel**, mapped what "normal" looks like on it, investigated three changes I did not make, and reconstructed an **RDP brute-force intrusion** from my own SIEM.

## Repository

```
sentinel-lab/
├── mission-01/                 Build the monitoring, learn the ground, catch what I didn't do
│   ├── README.md
│   ├── runbook.md              Azure Arc + Log Analytics + 2 data collection rules, issues & fixes
│   ├── verification.md         Event Viewer vs SIEM, heartbeat & clock check, normal logon pattern
│   ├── kql-practice.md         KQL practice on Microsoft's demo workspace
│   ├── identity-in-hamilton.md My seat: account, workstation, DC, OUs, GPOs, local admins
│   ├── baseline.md             What normal looks like (SIEM + machine state)
│   ├── detection.md            Three changes I did not make, and where the evidence lives
│   └── queries.kql
├── mission-02/                 My first intrusion
│   ├── README.md
│   ├── case-file.md            Timeline, MITRE ATT&CK mapping, before/after logging, detection rule
│   └── queries.kql
└── scripts/
    ├── baseline-snapshot.ps1   Read-only snapshot of users, admins, tasks, services, audit policy
    ├── compare-snapshot.ps1    Before/after diff of two snapshots
    └── qemu-ga-activity.ps1    Lists QEMU guest-agent actions and decodes encoded PowerShell
```

## Environment

| Component | Value |
|---|---|
| Workstation | `WKS-L65.hamilton.corp`, Windows 10 22H2, VM on a QEMU/KVM hypervisor |
| Domain controller | `DC01.hamilton.corp` (10.50.0.10) |
| SIEM | Microsoft Sentinel on Log Analytics workspace `log-sentinel-lab` |
| Cloud | Azure for Students, region Germany West Central (EU) |
| Collection | Azure Monitor Agent via Azure Arc; `dcr-windowsevents` → `Event` (Application, System), `dcr-securityevents` → `SecurityEvent` (Security, *Common*) |

## Highlights

| | Finding | How |
|---|---|---|
| 🔍 | Files dropped on my Desktop **from the hypervisor**, with no logon at all | Hourly volume spike → file owner → `qemu-ga` Application log → decoded `-EncodedCommand` |
| 🔍 | Hidden local admin `svc_backup` created and later deleted | 4720 + 4732 in `SecurityEvent` (the SIEM remembered what the machine no longer showed) |
| 🔍 | My domain account added to a group on the DC, then cleaned up | Evidence only on DC01, outside my SIEM |
| 🚨 | RDP brute force: `helpdesk` from 10.50.0.100, 5 failures in 0.3 s then success | 4625 → 4624 type 3 → type 10 |
| 🚨 | Attacker's command line recovered after enabling process-creation auditing | 4688 with `CommandLine`, parent `rdpinit.exe` |

## MITRE ATT&CK techniques observed

| ID | Technique | Where |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Mission 2 |
| T1078.003 | Valid Accounts: Local Accounts | Mission 2 |
| T1021.001 | Remote Services: Remote Desktop Protocol | Mission 2 |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Mission 2 |
| T1136.001 | Create Account: Local Account | Mission 1 (`svc_backup`) |
| T1098 | Account Manipulation (added to Administrators) | Mission 1 (`svc_backup`) |

## Skills practised

Microsoft Sentinel · Log Analytics · KQL · Azure Arc · Azure Monitor Agent · Data Collection Rules · Azure Policy · Windows Security auditing (4624, 4625, 4688, 4719, 4720, 4732…) · Event Viewer · Active Directory (OUs, GPOs, domain vs local accounts) · PowerShell for forensics · MITRE ATT&CK mapping · writing a case file

## Key lessons

1. **A SIEM only sees what you send it.** The decisive evidence of two incidents was on the machine (Application log at Information level) or on the domain controller, not in my workspace.
2. **"Not there now" does not mean "never happened".** A deleted account and a deleted group left no live trace; only logs remembered them.
3. **Default logging sees the login, not the action.** Without process-creation auditing, the attacker's command was invisible. One policy change made it visible.
4. **A baseline pays off.** A spike in hourly event volume was the first clue of the first investigation.

> Lab flags (`HAM{...}`) are redacted so other learners can still solve the challenges. No credentials or subscription identifiers are included.
