<#
.SYNOPSIS
  Lists what the hypervisor did inside the VM through the QEMU guest agent,
  and decodes any -EncodedCommand PowerShell it ran.
.DESCRIPTION
  qemu-ga writes its actions to the Application log (provider "qemu-ga",
  Event ID 1, Information level). Run as Administrator.
.EXAMPLE
  .\qemu-ga-activity.ps1 -Start '2026-10-08 11:00' -End '2026-10-08 11:30'
#>
param(
  [datetime]$Start = (Get-Date).AddDays(-7),
  [datetime]$End   = (Get-Date)
)

Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'qemu-ga'; StartTime = $Start; EndTime = $End } -ErrorAction SilentlyContinue |
  Where-Object Message -match 'guest-exec called|guest-file-open called' |
  Sort-Object TimeCreated |
  ForEach-Object {
    $decoded = $null
    if ($_.Message -match '-EncodedCommand\s+([A-Za-z0-9+/=]+)') {
      $decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]))
    }
    [pscustomobject]@{
      Time    = $_.TimeCreated
      Action  = ($_.Message -split ':')[0]
      Message = $_.Message
      Decoded = $decoded
    }
  } | Format-List
