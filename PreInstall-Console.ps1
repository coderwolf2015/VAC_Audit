# PreInstall-Console.ps1
# VAC audit pre-install console check.
# This script is designed to be COPIED AND PASTED into PowerShell.
# It creates no files, directories, transcripts, or exports.
# All output stays in the current PowerShell window.

& {
    $ErrorActionPreference = 'SilentlyContinue'

    function Write-Section([string]$Name) {
        Write-Host ''
        Write-Host ('=' * 72)
        Write-Host $Name
        Write-Host ('=' * 72)
    }

    function Write-Check([string]$Label, [bool]$Passed, [string]$Detail) {
        $state = if ($Passed) { 'PASS' } else { 'REVIEW' }
        Write-Host ('[{0}] {1} - {2}' -f $state, $Label, $Detail)
    }

    Write-Section 'VAC AUDIT - PRE-INSTALL CONSOLE CHECK'
    Write-Host ('Timestamp: {0:o}' -f (Get-Date))
    Write-Host ('Computer:  {0}' -f $env:COMPUTERNAME)

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Check 'Elevated PowerShell' $isAdmin $(if ($isAdmin) { 'Administrator token present' } else { 'Not elevated; reopen PowerShell as Administrator before continuing' })
    if (-not $isAdmin) {
        Write-Host ''
        Write-Host 'STOP: This check was not run because the PowerShell session is not elevated.'
        return
    }

    Write-Section 'CLEAN-ROOM PROCESSES'
    $edge = Get-Process msedge -ErrorAction SilentlyContinue
    $oneDrive = Get-Process OneDrive -ErrorAction SilentlyContinue
    Write-Check 'Microsoft Edge not running' (-not $edge) $(if ($edge) { "Found $($edge.Count) Edge process(es)" } else { 'No Edge process found' })
    Write-Check 'OneDrive not running' (-not $oneDrive) $(if ($oneDrive) { "Found $($oneDrive.Count) OneDrive process(es)" } else { 'No OneDrive process found' })

    Write-Section 'EXISTING VAC / MUZYCHENKO ARTIFACTS'
    $rx = '(?i)Virtual Audio Cable|vrtaucbl|Muzychenko'

    $vacProc = Get-CimInstance Win32_Process | Where-Object { $_.Name -match $rx -or $_.ExecutablePath -match $rx -or $_.CommandLine -match $rx }
    $vacSvc  = Get-CimInstance Win32_Service | Where-Object { $_.Name -match $rx -or $_.DisplayName -match $rx -or $_.PathName -match $rx }
    $vacDrv  = Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match $rx -or $_.DisplayName -match $rx -or $_.PathName -match $rx }
    $vacPnp  = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -match $rx -or $_.DriverProviderName -match $rx -or $_.InfName -match $rx }

    Write-Check 'VAC-related processes absent' (-not $vacProc) $(if ($vacProc) { "Found $($vacProc.Count) matching process(es)" } else { 'None found' })
    Write-Check 'VAC-related services absent'  (-not $vacSvc)  $(if ($vacSvc)  { "Found $($vacSvc.Count) matching service(s)" } else { 'None found' })
    Write-Check 'VAC-related system drivers absent' (-not $vacDrv) $(if ($vacDrv) { "Found $($vacDrv.Count) matching driver(s)" } else { 'None found' })
    Write-Check 'VAC-related PnP signed drivers absent' (-not $vacPnp) $(if ($vacPnp) { "Found $($vacPnp.Count) matching PnP driver(s)" } else { 'None found' })

    if ($vacProc) { $vacProc | Select-Object ProcessId,Name,ExecutablePath | Format-Table -AutoSize }
    if ($vacSvc)  { $vacSvc  | Select-Object Name,DisplayName,State,StartMode,PathName | Format-Table -AutoSize }
    if ($vacDrv)  { $vacDrv  | Select-Object Name,DisplayName,State,StartMode,PathName | Format-Table -AutoSize }
    if ($vacPnp)  { $vacPnp  | Select-Object DeviceName,DriverProviderName,DriverVersion,InfName | Format-Table -AutoSize }

    Write-Section 'VAC AUDIT FIREWALL RULES'
    $rules = Get-NetFirewallRule -DisplayName 'VAC Audit - *' | Sort-Object DisplayName
    if ($rules) {
        $rules | Select-Object DisplayName,Enabled,Direction,Action | Format-Table -AutoSize
        $expected = @(
            'VAC Audit - DNS TCP',
            'VAC Audit - DNS UDP',
            'VAC Audit - HTTP',
            'VAC Audit - HTTPS TCP',
            'VAC Audit - QUIC',
            'VAC Audit - DoT'
        )
        foreach ($name in $expected) {
            $r = $rules | Where-Object DisplayName -eq $name
            Write-Check $name ($null -ne $r) $(if ($r) { "Present; Enabled=$($r.Enabled); Direction=$($r.Direction); Action=$($r.Action)" } else { 'Missing' })
        }
    }
    else {
        Write-Check 'VAC Audit firewall rules' $false 'No VAC Audit rules found'
    }

    Write-Section 'WFP FAILURE AUDITING'
    auditpol /get /subcategory:'Filtering Platform Connection'
    auditpol /get /subcategory:'Filtering Platform Packet Drop'

    Write-Section 'SECURITY LOG CONFIGURATION'
    wevtutil gl Security | Select-String 'maxSize:|retention:|autoBackup:'

    Write-Section 'FIREWALL TEXT LOG CONFIGURATION'
    Get-NetFirewallProfile | Select-Object Name,Enabled,LogFileName,LogMaxSizeKilobytes,LogAllowed,LogBlocked | Format-Table -AutoSize

    Write-Section 'POWER - ACTIVE SCHEME / SLEEP'
    powercfg /getactivescheme
    powercfg /query SCHEME_CURRENT SUB_SLEEP

    Write-Section 'CURRENT EXTERNAL TCP CONNECTIONS'
    $tcp = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -notin @('127.0.0.1','::1') }

    if ($tcp) {
        $tcp | ForEach-Object {
            $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Process       = $p.ProcessName
                PID           = $_.OwningProcess
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort    = $_.RemotePort
            }
        } | Sort-Object Process,PID,RemoteAddress,RemotePort | Format-Table -AutoSize
    }
    else {
        Write-Host 'No established external TCP connections found.'
    }

    Write-Section 'FINAL CHECKPOINT'
    $vacAbsent = (-not $vacProc) -and (-not $vacSvc) -and (-not $vacDrv) -and (-not $vacPnp)
    $cleanProc = (-not $edge) -and (-not $oneDrive)
    Write-Check 'No pre-existing VAC artifacts' $vacAbsent $(if ($vacAbsent) { 'Baseline is clean for VAC-specific artifacts' } else { 'Investigate matching artifacts before installation' })
    Write-Check 'Browser/cloud-noise processes absent' $cleanProc $(if ($cleanProc) { 'Edge and OneDrive absent' } else { 'Close/stop remaining process(es) before formal baseline' })

    Write-Host ''
    Write-Host 'NO FILES OR DIRECTORIES WERE CREATED BY THIS CHECK.'
}
