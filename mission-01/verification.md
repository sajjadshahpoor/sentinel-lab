# Mission 1 — Verifying the monitoring

After building the pipeline (see [`runbook.md`](runbook.md)), I checked that it works and that the SIEM tells the same story as the machine.

## 1. Reading a Windows event at the source (Event Viewer)

Path on WKS-L65: Event Viewer → Windows Logs → Security → *Filter Current Log* → Event ID `4624`.

**Trap 1: the first 4624 I opened was not me.**

| Field | Value | Meaning |
|---|---|---|
| New Logon → Account | `SYSTEM` | Windows itself |
| Logon Type | 5 | A service started |
| Process | `services.exe` | The service manager |

**Fix:** an XML filter for logon types 10 and 7 only:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624)]]
      and
      *[EventData[(Data[@Name='LogonType']='10' or Data[@Name='LogonType']='7')]]
    </Select>
  </Query>
</QueryList>
```

**My logon (EventRecordID 36367)**

| Field | Value |
|---|---|
| Time | 2026-10-07 16:15:17 UTC (18:15:17 local) |
| Account (New Logon, `TargetUserName`) | `HAMILTON\sajjad` |
| Logon Type | **7**: reconnected to an existing RDP session |
| Source network address | Not recorded (`-`): normal for type 7 |
| Process | `lsass.exe` |
| Computer | `WKS-L65.hamilton.corp` |

> **Subject vs New Logon:** Subject (`WKS-L65$`) is who *reported* the logon. New Logon is who actually logged on.
> `SystemTime` ends in **Z** = UTC. Event Viewer's General tab shows local time.

## 2. Is the machine talking to me? (Step 5)

| Question | Query | Result |
|---|---|---|
| Is my machine sending data? | `Heartbeat \| summarize max(TimeGenerated) by Computer` | `WKS-L65.hamilton.corp`, last seen 18:40:20 UTC: **alive** |
| Is it current, or is the clock wrong? | `ingestion_time() - TimeGenerated` | **~1 min 10 s** delay on every heartbeat (first one 3 min 49 s) → clock correct, data current |
| What am I collecting? | `Event \| summarize count() by EventLevelName` | 151 events, all Information (Security log via chain A) |
| Who logged on? | `Event` 4624 + `RenderedDescription has "sajjad"` | Mostly SYSTEM type 5; my logons buried in one text field |

**Why the delay check matters:** a source that looks silent may just have a wrong clock. A small, positive, stable delay means the machine speaks in the present.

**Finding: the SIEM does not see the past.** My first collected event was at 16:33:57 UTC, while my Event Viewer logon was at 16:15:17 UTC. Events written before collection started stay on the machine, so I reconnected via RDP to create a new logon the SIEM could see.

**Answer to "what is my machine telling me, and how do I know it is current?"**
WKS-L65 sends a heartbeat every minute, and the delay between `TimeGenerated` and `ingestion_time()` is about one minute, so it speaks in the present and its clock is right. It sends Security events such as 4624; in chain A the account and logon type are hidden inside `RenderedDescription`.

## 3. The SOC way: SecurityEvent (Step 5b)

- Sentinel → Content hub → **Windows Security Events** installed.
- Data connector **Windows Security Events via AMA**: status **Connected**, last log 48 s ago, last data received 2026-10-08 07:19:47, **380 SecurityEvents on 2026-10-07**.
- Query 5 returns the same logons as query 4, but with `Account`, `LogonType` and `IpAddress` as columns.
- Security removed from `dcr-windowsevents`. From then on, new Security events arrive only in `SecurityEvent`.

**One RDP connection = several 4624 in the same second:** LogonType **3** first (Network Level Authentication checks the password), then **7** (reconnect) or **10** (new session). `IpAddress` is **10.50.0.1**, the lab gateway, not my laptop; my laptop's name (`SAJJAD`) appears in `WorkstationName`.

## 4. My normal logon pattern

| LogonType | IpAddress | WorkstationName | Meaning |
|---|---|---|---|
| 3 | 10.50.0.1 | SAJJAD | My laptop authenticating through the gateway |
| 7 or 10 | 10.50.0.1 | WKS-L65 | My RDP session opening (reconnect / new) |
| 3 only, no 7/10 | 10.50.0.1 | SAJJAD | RDP started but no session opened (2026-10-10 06:51 UTC, checked: my laptop) |

Anything outside this pattern (another IP, another workstation name, another account) deserves a look.
