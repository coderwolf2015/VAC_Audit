# PreInstall-Baseline.ps1
# Generic pre-install baseline capture for the VAC audit VM.
# Public-safe script: writes all machine-specific output only to the local VM.

[CmdletBinding()]
param(
    [string]$Root = 'C:\VAC-Audit'
)

$ErrorActionPreference = 'Continue'

# Require an elevated PowerShell session.
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this script from an Administrator PowerShell session.'
    exit 1
}

$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Base  = Join-Path $Root ("PreInstall-{0}" -f $Stamp)
New-Item -ItemType Directory -Path $Base -Force | Out-Null

Write-Host "VAC pre-install baseline capture"
Write-Host "Output: $Base"
Write-Host ''

# Boundary timestamp and basic OS information.
Get-Date | Out-File (Join-Path $Base 'Timestamp.txt')
Get-ComputerInfo | Out-File (Join-Path $Base 'ComputerInfo.txt')

# Processes.
Get-CimInstance Win32_Process |
    Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
    Sort-Object Name,ProcessId |
    Export-Csv (Join-Path $Base 'Processes.csv') -NoTypeInformation

# Services and kernel/system drivers.
Get-CimInstance Win32_SystemDriver |
    Sort-Object Name |
    Export-Csv (Join-Path $Base 'SystemDrivers.csv') -NoTypeInformation

Get-CimInstance Win32_Service |
    Sort-Object Name |
    Export-Csv (Join-Path $Base 'Services.csv') -NoTypeInformation

# PnP signed drivers and driver store.
Get-CimInstance Win32_PnPSignedDriver |
    Sort-Object DeviceName |
    Export-Csv (Join-Path $Base 'PnPSignedDrivers.csv') -NoTypeInformation

pnputil /enum-drivers | Out-File (Join-Path $Base 'DriverStore.txt')

# Current network state.
Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Sort-Object OwningProcess,LocalPort |
    Export-Csv (Join-Path $Base 'TCPConnections.csv') -NoTypeInformation

Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
    Sort-Object OwningProcess,LocalPort |
    Export-Csv (Join-Path $Base 'UDPEndpoints.csv') -NoTypeInformation

ipconfig /all | Out-File (Join-Path $Base 'IPConfig.txt')
route print   | Out-File (Join-Path $Base 'Routes.txt')
arp -a        | Out-File (Join-Path $Base 'ARP.txt')

# Startup and persistence-related state.
Get-CimInstance Win32_StartupCommand |
    Sort-Object Name |
    Export-Csv (Join-Path $Base 'StartupCommands.csv') -NoTypeInformation

Get-ScheduledTask |
    Sort-Object TaskPath,TaskName |
    Export-Csv (Join-Path $Base 'ScheduledTasks.csv') -NoTypeInformation

# Firewall and audit configuration.
Get-NetFirewallRule |
    Sort-Object DisplayName |
    Export-Csv (Join-Path $Base 'FirewallRules.csv') -NoTypeInformation

auditpol /get /category:* | Out-File (Join-Path $Base 'AuditPolicy.txt')
wevtutil gl Security       | Out-File (Join-Path $Base 'SecurityLogConfig.txt')

# Power state relevant to the unattended soak.
powercfg /getactivescheme | Out-File (Join-Path $Base 'PowerScheme.txt')
powercfg /query SCHEME_CURRENT SUB_SLEEP | Out-File (Join-Path $Base 'PowerScheme.txt') -Append

# VAC audit rules, separated for quick validation.
Get-NetFirewallRule -DisplayName 'VAC Audit - *' -ErrorAction SilentlyContinue |
    Select-Object DisplayName,Enabled,Direction,Action |
    Sort-Object DisplayName |
    Export-Csv (Join-Path $Base 'VAC-Audit-Rules.csv') -NoTypeInformation

# Write a compact manifest with file sizes and hashes for the captured baseline.
$ManifestPath = Join-Path $Base 'Manifest-SHA256.csv'
Get-ChildItem -Path $Base -File |
    Where-Object { $_.FullName -ne $ManifestPath } |
    Sort-Object Name |
    ForEach-Object {
        $hash = Get-FileHash -Algorithm SHA256 -Path $_.FullName
        [pscustomobject]@{
            Name   = $_.Name
            Length = $_.Length
            SHA256 = $hash.Hash
        }
    } |
    Export-Csv $ManifestPath -NoTypeInformation

Write-Host ''
Write-Host 'Capture complete.'
Write-Host "Baseline directory: $Base"
Write-Host ''
Get-ChildItem -Path $Base -File |
    Select-Object Name,Length |
    Sort-Object Name |
    Format-Table -AutoSize

Write-Host ''
Write-Host 'PASS checkpoint: expected capture files exist and non-empty files have plausible sizes.'
Write-Host 'Do not upload the generated baseline directory to this public repository.'
