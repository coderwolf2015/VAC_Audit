# Soak-Review-Console.ps1
# Paste into an elevated Windows PowerShell window.
# Read-only review: creates no files/directories and changes no settings.
# The review window is frozen so browser/network activity used to retrieve this
# script after 2026-09-10 13:25 does not contaminate the soak analysis.

& {
    $ErrorActionPreference = 'SilentlyContinue'
    $Start = [datetime]'2026-09-05 14:00:00'
    $End   = [datetime]'2026-09-10 13:25:00'

    function Banner($s) { Write-Host "`n=== $s ===" -ForegroundColor Cyan }
    function Pass($s)   { Write-Host "[PASS] $s" -ForegroundColor Green }
    function Review($s) { Write-Host "[REVIEW] $s" -ForegroundColor Yellow }
    function Fail($s)   { Write-Host "[FAIL] $s" -ForegroundColor Red }

    Banner 'VAC SOAK REVIEW - READ ONLY'
    Write-Host ('Frozen window : {0}  through  {1}' -f $Start,$End)
    Write-Host ('Window length  : {0:N2} days' -f (($End-$Start).TotalDays))
    Write-Host 'No files or directories will be created by this block.'

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'Not elevated. Re-run in Administrator PowerShell.'
        return
    }
    Pass 'Elevated PowerShell'

    Banner 'HOST CONTINUITY'
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Host ('Last boot      : {0}' -f $os.LastBootUpTime)
    if ($os.LastBootUpTime -le $Start) { Pass 'No reboot occurred after soak start' }
    else { Review 'System boot time is inside the soak window' }

    Banner 'VAC DRIVER / CONTROL STATE'
    $vacDrv = Get-CimInstance Win32_SystemDriver | Where-Object {
        $_.Name -match '(?i)vrtaucbl|virtual.*audio.*cable' -or $_.PathName -match '(?i)vrtaucbl'
    }
    if ($vacDrv) {
        $vacDrv | Select-Object Name,State,StartMode,PathName | Format-Table -AutoSize
        Pass 'VAC system driver is present'
    } else { Fail 'VAC system driver not found' }

    $vacProc = Get-CimInstance Win32_Process | Where-Object {
        $_.Name -match '(?i)^(vcctlpan|audiorepeater|audiorepeater_ks)\.exe$'
    }
    if ($vacProc) {
        $vacProc | Select-Object ProcessId,Name,ExecutablePath | Format-Table -AutoSize
    } else { Write-Host 'No VAC user-mode utility is currently running.' }

    Banner 'CONTAINMENT RULES - CURRENT STATE'
    $expected = @(
        'VAC Audit - DNS TCP','VAC Audit - DNS UDP','VAC Audit - HTTP',
        'VAC Audit - HTTPS TCP','VAC Audit - QUIC','VAC Audit - DoT'
    )
    $rules = foreach ($n in $expected) { Get-NetFirewallRule -DisplayName $n }
    $rules | Select-Object DisplayName,Enabled,Direction,Action | Format-Table -AutoSize
    $bad = @($rules | Where-Object { $_.Enabled -ne 'True' -or $_.Direction -ne 'Outbound' -or $_.Action -ne 'Block' })
    if ($rules.Count -eq 6 -and $bad.Count -eq 0) { Pass 'All six containment rules are still enabled/outbound/block' }
    else { Fail 'One or more containment rules are missing or no longer enabled/outbound/block' }

    Banner 'AUDIT LOG COVERAGE'
    $oldestActive = Get-WinEvent -LogName Security -Oldest -MaxEvents 1
    $newestActive = Get-WinEvent -LogName Security -MaxEvents 1
    Write-Host ('Active Security oldest : {0}' -f $oldestActive.TimeCreated)
    Write-Host ('Active Security newest : {0}' -f $newestActive.TimeCreated)

    $archiveDir = Join-Path $env:SystemRoot 'System32\winevt\Logs'
    $archives = @(Get-ChildItem $archiveDir -Filter 'Archive-Security-*.evtx' -File)
    Write-Host ('Archived Security logs : {0}' -f $archives.Count)
    if ($oldestActive.TimeCreated -le $Start) { Pass 'Active Security log alone reaches soak start' }
    elseif ($archives.Count -gt 0) { Review 'Active log does not reach soak start; archived Security logs will also be queried' }
    else { Fail 'Security event coverage does not reach soak start and no Security archives were found' }

    Banner 'WFP BLOCK EVENTS (5152 / 5157)'
    $events = New-Object System.Collections.Generic.List[object]

    function Add-WfpEvents($evs) {
        foreach ($e in $evs) {
            try {
                [xml]$x = $e.ToXml()
                $d = @{}
                foreach ($node in $x.Event.EventData.Data) { $d[[string]$node.Name] = [string]$node.'#text' }
                $events.Add([pscustomobject]@{
                    Time        = $e.TimeCreated
                    Id          = $e.Id
                    Application = $d['Application']
                    Protocol    = $d['Protocol']
                    DestAddress = $d['DestAddress']
                    DestPort    = $d['DestPort']
                    Direction   = $d['Direction']
                })
            } catch {}
        }
    }

    $activeEvs = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5152,5157; StartTime=$Start; EndTime=$End}
    Add-WfpEvents $activeEvs

    if ($oldestActive.TimeCreated -gt $Start -and $archives.Count -gt 0) {
        foreach ($a in $archives) {
            $ae = Get-WinEvent -FilterHashtable @{Path=$a.FullName; Id=5152,5157; StartTime=$Start; EndTime=$End}
            Add-WfpEvents $ae
        }
    }

    # De-duplicate conservatively in case an archive overlaps the active log.
    $events = @($events | Sort-Object Time,Id,Application,Protocol,DestAddress,DestPort -Unique)
    Write-Host ('Total WFP block events in frozen window: {0}' -f $events.Count)

    if ($events.Count -gt 0) {
        Write-Host "`nTop blocked applications:"
        $events | Group-Object Application | Sort-Object Count -Descending | Select-Object -First 15 Count,Name | Format-Table -AutoSize

        Write-Host "Top blocked protocol/port pairs:"
        $events | ForEach-Object {
            [pscustomobject]@{ Protocol=$_.Protocol; DestPort=$_.DestPort }
        } | Group-Object Protocol,DestPort | Sort-Object Count -Descending | Select-Object -First 15 Count,Name | Format-Table -AutoSize

        Write-Host "Top blocked destinations:"
        $events | ForEach-Object {
            [pscustomobject]@{ DestAddress=$_.DestAddress; DestPort=$_.DestPort; Protocol=$_.Protocol }
        } | Group-Object DestAddress,DestPort,Protocol | Sort-Object Count -Descending | Select-Object -First 15 Count,Name | Format-Table -AutoSize
    }

    $vacPattern = '(?i)(\\vcctlpan\.exe$|\\audiorepeater\.exe$|\\audiorepeater_ks\.exe$|\\setup64\.exe$|\\vrtaucbl\.sys$|virtual audio cable|muzychenko)'
    $vacEvents = @($events | Where-Object { $_.Application -match $vacPattern })

    Banner 'VAC-ATTRIBUTED NETWORK ATTEMPTS'
    if ($vacEvents.Count -eq 0) {
        Pass 'No WFP block event in the frozen soak window is attributed to a VAC executable/driver name'
    } else {
        Review ("Found {0} VAC-attributed blocked WFP event(s)" -f $vacEvents.Count)
        $vacEvents | Select-Object Time,Id,Application,Protocol,DestAddress,DestPort | Sort-Object Time | Format-Table -AutoSize
    }

    Banner 'FIREWALL TEXT LOG CORROBORATION'
    $fw = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
    $fwFiles = @($fw,($fw + '.old')) | Where-Object { Test-Path $_ }
    Write-Host ('Firewall log files available: {0}' -f $fwFiles.Count)
    $targetDrops = New-Object System.Collections.Generic.List[object]
    foreach ($f in $fwFiles) {
        Get-Content $f | Where-Object { $_ -and $_[0] -ne '#' -and $_ -match '\sDROP\s' } | ForEach-Object {
            $p = $_ -split '\s+'
            if ($p.Count -ge 8) {
                $dt = $null
                if ([datetime]::TryParseExact(($p[0]+' '+$p[1]),'yyyy-MM-dd HH:mm:ss',$null,[Globalization.DateTimeStyles]::None,[ref]$dt)) {
                    if ($dt -ge $Start -and $dt -le $End -and $p[7] -in @('53','80','443','853')) {
                        $targetDrops.Add([pscustomobject]@{Time=$dt;Protocol=$p[3];Source=$p[4];Destination=$p[5];DestPort=$p[7]})
                    }
                }
            }
        }
    }
    Write-Host ('DROP records to audited standard ports in frozen window: {0}' -f $targetDrops.Count)
    if ($targetDrops.Count -gt 0) {
        $targetDrops | Group-Object Protocol,DestPort | Sort-Object Count -Descending | Select-Object Count,Name | Format-Table -AutoSize
    }

    Banner 'FINAL SOAK CHECKPOINT'
    if ($rules.Count -eq 6 -and $bad.Count -eq 0 -and $vacDrv -and $vacEvents.Count -eq 0) {
        Pass 'Current evidence is consistent with VAC remaining installed/contained with no VAC-attributed conventional network attempt observed.'
    } else {
        Review 'One or more items require inspection above before drawing a conclusion.'
    }
    Write-Host 'Important: this does not rule out exotic/raw kernel networking outside ordinary WFP attribution.'
    Write-Host 'No settings were changed and no files/directories were created.'
}
