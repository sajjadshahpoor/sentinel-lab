# Runbook — Connecting a Windows workstation to Microsoft Sentinel

**Date:** 2026-10-07 / 2026-10-08
**Subscription:** Azure for Students
**Region:** Germany West Central (`germanywestcentral`)

## Resources

| Type | Name |
|---|---|
| Resource group | `rg-sentinel-lab` |
| Log Analytics workspace | `log-sentinel-lab` |
| Data collection rule A (Azure Monitor) | `dcr-windowsevents` |
| Data collection rule B (Sentinel connector) | `dcr-securityevents` |
| Arc-enabled machine | `WKS-L65` |

```
                          ┌─ Rule A: dcr-windowsevents  ──→ table Event          (Application + System)
WKS-L65 ── agent (AMA) ───┤
                          └─ Rule B: dcr-securityevents ──→ table SecurityEvent  (Security log, "Common")
```

## Steps

1. **Find the allowed region.** Portal → Policy → Assignments → *Allowed resource deployment regions* → parameter `listOfAllowedLocations`:
   `belgiumcentral, germanywestcentral, norwayeast, francecentral, spaincentral`.
   Chose **germanywestcentral** (EU region, available for every resource I needed).
2. **Create the resource group** `rg-sentinel-lab` in Germany West Central.
3. **Create the Log Analytics workspace** `log-sentinel-lab` in the same resource group and region.
4. **Generate the Azure Arc onboarding script**: Azure Arc → Machines → Add a single server → resource group `rg-sentinel-lab`, region `germanywestcentral`, authentication by device code.
5. **Run the script on WKS-L65** in PowerShell as Administrator. It starts with
   `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`, which allows the script to run in this window only. The machine-wide policy is unchanged.
6. **Sign in** at `https://login.microsoft.com/device` with the code shown in PowerShell.
7. **Result** (2026-10-07, ~14:45 local): `Machine connectée à Azure`. WKS-L65 shows **Connected** in Azure Arc → Machines.
8. **Create rule A** `dcr-windowsevents` (Azure Monitor → Data Collection Rules) → source WKS-L65 → Windows Event Logs → destination `log-sentinel-lab`.
9. **Wait for the first heartbeat** (15–30 min), then verify with `Heartbeat` (see `queries.kql`).
10. **Install the Sentinel solution** *Windows Security Events* (Sentinel → Content hub).
11. **Create rule B** from Data connectors → *Windows Security Events via AMA* (not the deprecated legacy connector) → `dcr-securityevents`, resource WKS-L65, events **Common**.
12. **Remove the duplicate.** In `dcr-windowsevents`, untick Security (Audit success + Audit failure) and keep Application and System. Security events now come only through rule B.
13. **Verify.** The connector shows *Connected*, `SecurityEvent` receives new rows, and `Event` no longer receives new Security rows.

## Issues and fixes

| Problem (exact message) | Cause | Fix |
|---|---|---|
| Policy → Assignments showed *"No policies found in the given scope."* | The page was not scoped to the student subscription | Opened Policy from the Azure for Students subscription |
| Device-code sign-in failed on the first attempt | Code expired or mistyped | Second attempt with a new code succeeded |
| `VERBOSE: Error The operation has timed out. checking if we are in Azure` | The installer checks whether it runs on an Azure VM; WKS-L65 is not one | None needed: normal for Arc machines |
| `WARNING ... missing some OS info` | The agent could not read some OS details | None needed: onboarding succeeded |
| `SecurityEvent` empty after creating the Arc machine | Rule A sends to `Event`, not `SecurityEvent` | Created rule B through the Sentinel connector |
| KQL: *Query could not be parsed at '!'* when using `!has_any` | `!has_any` is not valid KQL | Use `where not(Column has_any (...))` |

## Chain A vs chain B

| | Chain A: `dcr-windowsevents` → `Event` | Chain B: `dcr-securityevents` → `SecurityEvent` |
|---|---|---|
| Set up in | Azure Monitor (works without Sentinel) | Sentinel (Windows Security Events solution) |
| Can collect | Any Windows log (Application, System, Security…) | Security log only |
| How events are chosen | By log and level (XPath for advanced filters) | Ready-made sets: All / Common / Minimal / Custom |
| Data shape | One text field per event (`RenderedDescription`), parse it yourself | Already split into columns (`Account`, `LogonType`, `IpAddress`…) |
| Sentinel rules and workbooks | Mostly not written for it | Written for it |
| Used by | IT operations | Security teams / SOC |
| I use it for | **Application + System** | **Security** |

**Why I kept only chain B for the Security log:** Sentinel's detections, workbooks and hunting queries are built on `SecurityEvent`, and its columns make logons easy to query. Collecting the same events twice means two places to search, results that can drift apart, and paying for every event twice.

## Known gaps in this setup

- `dcr-windowsevents` collects Application/System at **Error and Warning** only. Information-level events, such as the QEMU guest agent's actions, never reach the SIEM.
- Only **WKS-L65** is collected. Domain-level changes are recorded on **DC01**, which is not in my workspace.
- Until the Mission 2 GPO, **Process Creation (4688) was not audited**, so commands were invisible.
