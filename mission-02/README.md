# Mission 2 — My first intrusion

**Goal:** an intrusion was run against my workstation during a given window. Reconstruct it from my own Sentinel: which account, from where, what kind of attack, and (after a logging policy change) which command.

## Files

| File | Content |
|---|---|
| [`case-file.md`](case-file.md) | The full case file: timeline, MITRE ATT&CK mapping, before/after logging, detection rule, recommendations |
| [`queries.kql`](queries.kql) | All Mission 2 queries, including the detection rule |

## How the mission ran

| Part | What I did | Result |
|---|---|---|
| 1. Make noise | RDP to my own machine as `.\labuser`: 3 wrong passwords, 1 right, `whoami`, sign out | 3 × 4625, then 4624 type 3 ×2 and type 10, from 10.50.0.1. **No trace of `whoami`** |
| 2. Hunt (Temps 1) | Searched 4625/4624 in the attack window (08:06–09:26 UTC, 13 Oct) | `helpdesk`, from **10.50.0.100 / WKSTN-07**, **brute force** (5 failures in 0.3 s → success) |
| 3. The gap | Tried to find the command with default logging | Impossible: no 4688, Process Creation not audited |
| 4. After the policy (Temps 2) | GPO enabled Process Creation + command line (4719 at 08:08 UTC); hunted 4688 | `cmd.exe /c echo HAM{…}> %USERPROFILE%\Desktop\flag.txt` at 08:13:25 UTC |

## Key takeaways

- **Shape before detail:** many failures close together, then a success from the same IP, is the signature of password guessing.
- **Speed tells human from tool:** my 3 manual attempts took 25 s; the attacker's 5 took 0.3 s.
- **Default logging sees the login, not the action.** One audit policy setting turned an invisible command into a full command line.
- **Separate yourself from the attacker:** know your own source IP, workstation name and account before you hunt.
