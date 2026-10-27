# Mission 1 — Build the monitoring, learn the ground, catch what I didn't do

**Goal:** connect my domain workstation `WKS-L65` to Microsoft Sentinel, prove the data is live and trustworthy, map my place in `hamilton.corp`, and detect changes made to my seat by someone else.

## Files

| File | Content |
|---|---|
| [`runbook.md`](runbook.md) | How I built it: Azure Arc, Log Analytics, two DCRs, chain A vs chain B, issues and fixes |
| [`verification.md`](verification.md) | Event Viewer vs SIEM, heartbeat and clock check, my normal logon pattern |
| [`kql-practice.md`](kql-practice.md) | KQL practice on Microsoft's demo workspace |
| [`identity-in-hamilton.md`](identity-in-hamilton.md) | My seat: account, workstation, DC01, OUs, GPOs, local admins |
| [`baseline.md`](baseline.md) | What "normal" looks like, in the SIEM and on the machine |
| [`detection.md`](detection.md) | Three changes I did not make, where the evidence lives, and what my SIEM saw |
| [`queries.kql`](queries.kql) | All Mission 1 queries, each with a comment |

## Results at a glance

| Step | Result |
|---|---|
| Region | Germany West Central (from the *Allowed resource deployment regions* policy) |
| Workstation onboarded | `WKS-L65` connected via Azure Arc on 2026-10-07 |
| Data live | Heartbeat every minute, ~1 min ingestion delay |
| Security log | Collected once, through the Sentinel connector → `SecurityEvent` |
| Detection 1 | Files dropped on the Desktop by the hypervisor's QEMU guest agent (no logon at all) |
| Detection 2 | Hidden local admin `svc_backup` created and later removed: caught by 4720 + 4732 |
| Detection 3 | My domain account added to `L65-Project-Readers` on DC01: invisible to my SIEM |

## What I learned

- A SIEM cannot see the past: collection starts when the rule starts.
- One RDP login produces several 4624 events (type 3, then 7/10); read **New Logon**, not Subject.
- The decisive evidence of two of my three detections was **outside my SIEM** (Application log at Information level; the domain controller).
- An empty result is a question, not an answer: which machine would have recorded it, in which log, and do I collect it?
