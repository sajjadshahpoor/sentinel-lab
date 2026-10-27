<#
.SYNOPSIS
  Saves a snapshot of the workstation's security-relevant state (read-only).
.DESCRIPTION
  Run in PowerShell as Administrator. Writes text files to the folder given
  in -Path (default C:\baseline). Run once as a baseline, later again with
  -Path C:\after, then use compare-snapshot.ps1.
#>
param([string]$Path = "C:\baseline")

New-Item -ItemType Directory -Force -Path $Path | Out-Null

Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description |
  Out-File "$Path\users.txt"
Get-LocalGroupMember Administrators | Select-Object Name, PrincipalSource |
  Out-File "$Path\admins.txt"
Get-ScheduledTask | Where-Object TaskPath -notlike "\Microsoft\*" |
  Select-Object TaskName, TaskPath, State | Out-File "$Path\tasks.txt"
Get-Service | Where-Object Status -eq Running | Select-Object Name, DisplayName |
  Sort-Object Name | Out-File "$Path\services.txt"
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location |
  Out-File "$Path\startup.txt"
Get-Process | Select-Object Name, Id, Path | Sort-Object Name |
  Out-File "$Path\processes.txt"
auditpol /get /category:* | Out-File "$Path\auditpol.txt"

Get-ChildItem $Path
