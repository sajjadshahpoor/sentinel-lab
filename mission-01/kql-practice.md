# Mission 1 — KQL practice on Microsoft's demo workspace

While waiting for my first heartbeat, I practised KQL on the Log Analytics demo workspace (`https://aka.ms/LADemo`), in **KQL mode**, time range **Last 7 days**. It contains web-application monitoring data, not security events (`SecurityEvent` is empty), but the language and operators are the same.

## Questions and answers

| # | Question | Answer |
|---|---|---|
| 1 | Which tables contain data, and how much? | 13 tables. Largest: **AppMetrics (3,679,347 rows)**, then AppDependencies (843,470), AppPerformanceCounters (568,407), AppTraces (418,026), AppRequests (386,377) |
| 2 | How many requests failed? | **203,187 of 386,377 (~53%)** |
| 3 | Top 5 failing pages | GET Customers/Details (53,294), Function2 (40,334), GET /** (10,132), GET Employees/Create (8,960), GET / (6,253) |
| 4 | Most frequent exception types | System.InvalidOperationException (80,687), System.NullReferenceException (53,375), System.Web.HttpException (9,674), java.lang.OutOfMemoryError (2,016) |
| 5 | Requests per hour (time chart) | Baseline ~1,000–3,000/h, with short **1-hour spikes up to ~13,000/h** on Oct 1, 3, 5 and 6 (UTC). No daily pattern |

**Observations**

- The top two pages cause ~46% of all failures; the top two exception types ~92% of all exceptions.
- `System.*` (.NET) and `java.*` / `org.*` (Java) exceptions mean the workspace monitors more than one application.
- Short bursts far above the normal level are exactly what you hunt for in a SIEM (e.g. a spike of failed logons).
- Looking at 11 rows of the hourly data suggested peaks at 7 AM and 3 PM; the full 7-day chart showed that was wrong. **Look at the whole series before concluding.**

## Queries

```kql
// 1. Tables and row counts
search *
| summarize Rows = count() by $table
| order by Rows desc

// 2. Failed requests
AppRequests
| where Success == false
| count

// 3. Top 5 failing pages
AppRequests
| where Success == false
| summarize Failures = count() by Name
| top 5 by Failures

// 4. Most frequent exception types
AppExceptions
| summarize Count = count() by ExceptionType
| order by Count desc

// 5. Requests per hour
AppRequests
| summarize Requests = count() by bin(TimeGenerated, 1h)
| render timechart
```

## Operators learned

| Operator | What it does |
|---|---|
| `where` | Keep only matching rows |
| `summarize … count() by X` | Count rows per value of X |
| `top N by` / `order by` | Keep the N highest / sort |
| `project` | Choose columns |
| `bin(TimeGenerated, 1h)` | Group timestamps into 1-hour buckets |
| `render timechart` | Draw the result as a line chart |
| `not(X has_any (...))` | Exclude a list of values (`!has_any` does not exist) |

## Issues

| Problem | Fix |
|---|---|
| Results area empty after choosing the time range | Write a query and click **Run** |
| Query 5 showed a table, not a chart | Open the **Chart** tab |
