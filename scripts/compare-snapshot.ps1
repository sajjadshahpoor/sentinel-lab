<#
.SYNOPSIS
  Compares two snapshots made with baseline-snapshot.ps1.
.DESCRIPTION
  "=>" = present only in the later snapshot (new); "<=" = only in the baseline (removed).
  Note: something added AND removed between the two snapshots will not show here,
  check the event logs / SIEM for that (e.g. 4720 then 4726).
#>
param(
  [string]$Before = "C:\baseline",
  [string]$After  = "C:\after"
)

foreach ($f in "users", "admins", "tasks", "services", "startup", "auditpol") {
  "=== $f ==="
  Compare-Object (Get-Content "$Before\$f.txt") (Get-Content "$After\$f.txt")
}
