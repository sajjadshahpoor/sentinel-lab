# Hunt

Evidence: `Security_DC01_tir.evtx` — the **domain controller's** Security log. Parsed with
`python-evtx`, pulling the `<Data Name="…">` fields for the relevant event IDs.

## Targeted account (50)
EID 4625 (failed logon) on the DC. Two accounts fail, but the attack target (6 failures, all from
the victim host `10.50.0.69`) is **`helpdesk`** — the other (`sajjad`, 3 failures from
`10.50.0.1`) is unrelated lab noise. Answer: `████`.

```python
# EID 4625 -> Counter((TargetUserName, IpAddress))
#   helpdesk / 10.50.0.69 : 6
#   sajjad   / 10.50.0.1  : 3
```

## Source IP (100)
The source of those `helpdesk` failures: **`10.50.0.69`** (the compromised workstation
HAM-FIN-WKS07). Answer: `████`.

## Kerberos services (150)
EID 4769 (Kerberos service ticket requested) filtered to `lmartens`. During the discovery the
workstation requests service tickets to the domain controller — service name **`DC01$`** (the
LDAP/directory target), with a burst at 10:05 on 2026-11-12 after the beacon was live. (The other
tickets are to its own host `HAM-FIN-WKS07$` and a `krbtgt` TGT — the DC ticket is the discovery
tell.) Answer: `████`.
