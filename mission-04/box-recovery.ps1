# Mission 4 — run ON your workstation (RDP in), PowerShell.
# Recovers the two impact flags (staged data + persistence) and the SPN for the recon flag.
# Read-only enumeration — it inspects, it does not change anything.

Write-Host "==================== #28 RECON: the service account's SPN ====================" -ForegroundColor Cyan
# A Kerberoastable service account advertises its service via a servicePrincipalName (SPN).
# List every SPN in the domain; the service account from Sentinel will be in here.
setspn -Q */* 2>&1 | Select-String -NotMatch "CN=Computers|GC/|RestrictedKrbHost|ForestDnsZones|DomainDnsZones"
# If you already know the account name from Sentinel, read just its SPN:
# setspn -L <service-account>
# The SPN looks like  serviceclass/host:port  (e.g. MSSQLSvc/...) -> the "serviceclass" is the service type.

Write-Host "`n==================== #29 DATA STAGED: the collected file ====================" -ForegroundColor Cyan
# Look for something gathered and set aside where it does not belong, written recently.
$cut = (Get-Date).AddDays(-14)
$roots = @("C:\Users\Public","C:\ProgramData","C:\Temp","C:\Windows\Temp","$env:TEMP","C:\Users")
foreach ($r in $roots) {
    if (Test-Path $r) {
        Get-ChildItem -Path $r -Recurse -File -ErrorAction SilentlyContinue -Include *.zip,*.7z,*.rar,*.csv,*.cab,*.tar,*.gz |
            Where-Object { $_.LastWriteTime -gt $cut } |
            Select-Object FullName, Length, LastWriteTime
    }
} | Sort-Object LastWriteTime -Descending | Format-Table -Auto
Write-Host "--- Once you spot the staged file, read it (the flag/proof is inside or in its name): ---"
Write-Host '    Get-Content "<path-to-staged-file>" | Select-Object -First 20'
Write-Host '    # (for a .zip) : Expand-Archive "<path>" -DestinationPath "$env:TEMP\m4" ; Get-ChildItem "$env:TEMP\m4" -Recurse'

Write-Host "`n==================== #30 PERSISTENCE: the rogue scheduled task ====================" -ForegroundColor Cyan
# A task that runs on its own, that is not Microsoft's.
Get-ScheduledTask |
    Where-Object { $_.TaskPath -notlike "\Microsoft\*" -and $_.Author -notlike "Microsoft*" } |
    Select-Object TaskName, TaskPath, State, Author | Format-Table -Auto
Write-Host "--- Inspect the suspicious one to see WHAT it runs (the flag is usually here): ---"
Write-Host '    $t = Get-ScheduledTask -TaskName "<task-name>"'
Write-Host '    $t.Actions | Format-List Execute, Arguments, WorkingDirectory'
Write-Host '    Export-ScheduledTask -TaskName "<task-name>"   # full XML, incl. the command/script it runs'
Write-Host '    # if it runs a script file, read it:  Get-Content "<script-path>"'
