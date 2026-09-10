# VAC soak evidence capture + checkpointed analysis
# Creates ONE root directory containing all preserved logs, metadata, hashes, and reports.
# Intended for post-test use after the frozen observation window has ended.
# Run from elevated Windows PowerShell.

$ErrorActionPreference = 'Stop'

# ---------------------------
# Frozen observation window
# ---------------------------
$SoakStart = Get-Date '2026-09-05 14:00:00'
$SoakEnd   = Get-Date '2026-09-10 13:25:00'

# Everything created by this script stays below this one root.
$Root = 'C:\VAC_Audit_Evidence_20260910_1325'
$Raw  = Join-Path $Root 'RawLogs'
$Rpt  = Join-Path $Root 'Reports'
$Meta = Join-Path $Root 'Metadata'

Write-Host '=== VAC SOAK EVIDENCE CAPTURE + CHECKPOINTED ANALYSIS ===' -ForegroundColor Cyan
Write-Host "Frozen window : $SoakStart through $SoakEnd"
Write-Host "Evidence root : $Root"
Write-Host

# ---------------------------
# Elevation gate
# ---------------------------
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $IsAdmin) {
    Write-Host '[FAIL] Run this in Administrator PowerShell.' -ForegroundColor Red
    return
}
Write-Host '[PASS] Elevated PowerShell' -ForegroundColor Green

# ---------------------------
# Root directory creation
# ---------------------------
New-Item -ItemType Directory -Force -Path $Root,$Raw,$Rpt,$Meta | Out-Null

@"
VAC soak evidence package
Frozen observation start: $($SoakStart.ToString('o'))
Frozen observation end  : $($SoakEnd.ToString('o'))
Capture time             : $((Get-Date).ToString('o'))
Computer name            : $env:COMPUTERNAME
OS                       : $((Get-CimInstance Win32_OperatingSystem).Caption)
Last boot                 : $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('o'))

IMPORTANT:
- Only events inside the frozen observation window are valid soak evidence.
- Activity after the firewall rules were disabled is intentionally excluded by timestamp.
- The RawLogs directory is the preserved source evidence.
"@ | Set-Content -Encoding UTF8 (Join-Path $Root 'README.txt')

# ---------------------------
# Capture current system state
# ---------------------------
Write-Host '\n=== CAPTURE CURRENT STATE ===' -ForegroundColor Cyan

Get-CimInstance Win32_SystemDriver |
    Where-Object { $_.Name -match 'VirtualAudioCable|vrtaucbl|VAC' -or $_.PathName -match 'vrtaucbl|Virtual Audio Cable' } |
    Select-Object Name,State,StartMode,PathName |
    Format-List | Out-String -Width 4096 |
    Set-Content -Encoding UTF8 (Join-Path $Meta 'VAC-SystemDriver.txt')

Get-CimInstance Win32_PnPSignedDriver |
    Where-Object { $_.DeviceName -match 'Virtual Audio Cable|VAC' -or $_.DriverName -match 'vrtaucbl' } |
    Select-Object DeviceName,DeviceID,Manufacturer,DriverProviderName,DriverVersion,DriverDate,InfName,DriverName,IsSigned,Signer |
    Format-List | Out-String -Width 4096 |
    Set-Content -Encoding UTF8 (Join-Path $Meta 'VAC-PnPSignedDriver.txt')

Get-NetFirewallRule -DisplayName 'VAC Audit - *' -ErrorAction SilentlyContinue |
    Select-Object DisplayName,Enabled,Direction,Action,Profile |
    Sort-Object DisplayName |
    Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Meta 'VAC-FirewallRules-Current.csv')

(auditpol /get /subcategory:'Filtering Platform Connection','Filtering Platform Packet Drop') |
    Set-Content -Encoding UTF8 (Join-Path $Meta 'WFP-AuditPolicy.txt')

(wevtutil gl Security) |
    Set-Content -Encoding UTF8 (Join-Path $Meta 'Security-Log-Configuration.txt')

powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE |
    Set-Content -Encoding UTF8 (Join-Path $Meta 'Power-Sleep.txt')
powercfg /query SCHEME_CURRENT SUB_SLEEP HIBERNATEIDLE |
    Set-Content -Encoding UTF8 (Join-Path $Meta 'Power-Hibernate.txt')

Write-Host '[PASS] Current state captured' -ForegroundColor Green

# ---------------------------
# Preserve raw logs FIRST
# ---------------------------
Write-Host '\n=== PRESERVE RAW LOGS ===' -ForegroundColor Cyan

$ActiveSecurity = Join-Path $Raw 'Security-Active.evtx'
Write-Host 'Exporting active Security log...'
& wevtutil epl Security $ActiveSecurity /ow:true
Write-Host '[PASS] Active Security log exported' -ForegroundColor Green

$EvtDir = Join-Path $env:SystemRoot 'System32\winevt\Logs'
$ArchiveFiles = Get-ChildItem -LiteralPath $EvtDir -Filter 'Archive-Security-*.evtx' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime

$ArchiveMap = @()
$i = 0
foreach ($f in $ArchiveFiles) {
    $i++
    $dst = Join-Path $Raw ("Security-Archive-{0:D2}.evtx" -f $i)
    Write-Host "Copying archived Security log $i of $($ArchiveFiles.Count): $($f.Name)"
    Copy-Item -LiteralPath $f.FullName -Destination $dst -Force
    $ArchiveMap += [pscustomobject]@{
        Index = $i
        OriginalName = $f.Name
        OriginalPath = $f.FullName
        OriginalLastWriteTime = $f.LastWriteTime
        PreservedName = Split-Path $dst -Leaf
    }
    Write-Host "[CHECKPOINT] Preserved archive $i" -ForegroundColor Yellow
}
$ArchiveMap | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Meta 'Security-Archive-Map.csv')

$FirewallLog = Join-Path $env:SystemRoot 'System32\LogFiles\Firewall\pfirewall.log'
if (Test-Path -LiteralPath $FirewallLog) {
    Copy-Item -LiteralPath $FirewallLog -Destination (Join-Path $Raw 'pfirewall.log') -Force
    Write-Host '[PASS] Firewall text log preserved' -ForegroundColor Green
} else {
    '[MISSING] pfirewall.log not found at expected path' |
        Set-Content -Encoding UTF8 (Join-Path $Meta 'FirewallLog-Missing.txt')
    Write-Host '[REVIEW] Firewall text log not found' -ForegroundColor Yellow
}

# ---------------------------
# Inventory + hashes of preserved evidence
# ---------------------------
Write-Host '\n=== HASH PRESERVED EVIDENCE ===' -ForegroundColor Cyan
$RawFiles = Get-ChildItem -LiteralPath $Raw -File | Sort-Object Name
$HashRows = foreach ($f in $RawFiles) {
    $h = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256
    [pscustomobject]@{
        Name = $f.Name
        Length = $f.Length
        LastWriteTime = $f.LastWriteTime
        SHA256 = $h.Hash
    }
}
$HashRows | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root 'SHA256SUMS.csv')
$HashRows | Format-Table -AutoSize | Out-String -Width 4096 |
    Set-Content -Encoding UTF8 (Join-Path $Root 'SHA256SUMS.txt')
Write-Host "[PASS] Hashed $($HashRows.Count) preserved raw files" -ForegroundColor Green

# ---------------------------
# Helpers for WFP parsing
# ---------------------------
function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
    $xml = [xml]$Event.ToXml()
    $map = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $name = [string]$d.Name
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $map[$name] = [string]$d.'#text'
    }
    return $map
}

function Convert-WfpEvent {
    param(
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event,
        [string]$SourceLog
    )
    $d = Get-EventDataMap $Event
    [pscustomobject]@{
        TimeCreated        = $Event.TimeCreated
        EventID            = $Event.Id
        SourceLog          = $SourceLog
        ProcessID          = $d['ProcessID']
        Application        = $d['Application']
        Direction          = $d['Direction']
        SourceAddress      = $d['SourceAddress']
        SourcePort         = $d['SourcePort']
        DestAddress        = $d['DestAddress']
        DestPort           = $d['DestPort']
        Protocol           = $d['Protocol']
        FilterRTID         = $d['FilterRTID']
        LayerName          = $d['LayerName']
        LayerRTID          = $d['LayerRTID']
        RemoteMachineID    = $d['RemoteMachineID']
        RemoteUserID       = $d['RemoteUserID']
    }
}

# ---------------------------
# Analyze each Security EVTX independently
# ---------------------------
Write-Host '\n=== CHECKPOINTED WFP ANALYSIS (5152 / 5157) ===' -ForegroundColor Cyan
$SecurityLogs = Get-ChildItem -LiteralPath $Raw -Filter 'Security-*.evtx' | Sort-Object Name
$AllCsv = @()
$CoverageRows = @()

$logIndex = 0
foreach ($log in $SecurityLogs) {
    $logIndex++
    Write-Host "\n[$logIndex/$($SecurityLogs.Count)] $($log.Name)" -ForegroundColor Cyan

    # Coverage query is intentionally separate and checkpointed.
    try {
        $oldest = Get-WinEvent -Path $log.FullName -Oldest -MaxEvents 1 -ErrorAction Stop
        $newest = Get-WinEvent -Path $log.FullName -MaxEvents 1 -ErrorAction Stop
        $CoverageRows += [pscustomobject]@{
            Log = $log.Name
            Oldest = $oldest.TimeCreated
            Newest = $newest.TimeCreated
        }
        Write-Host "Coverage: $($oldest.TimeCreated)  ->  $($newest.TimeCreated)"
    } catch {
        $CoverageRows += [pscustomobject]@{
            Log = $log.Name
            Oldest = $null
            Newest = $null
        }
        Write-Host "[REVIEW] Could not determine coverage: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    $outCsv = Join-Path $Rpt ("WFP-{0}.csv" -f ([IO.Path]::GetFileNameWithoutExtension($log.Name)))
    try {
        Write-Host 'Querying only IDs 5152/5157 inside frozen time window...'
        $events = Get-WinEvent -FilterHashtable @{
            Path      = $log.FullName
            Id        = 5152,5157
            StartTime = $SoakStart
            EndTime   = $SoakEnd
        } -ErrorAction Stop

        $count = 0
        foreach ($evt in $events) {
            $row = Convert-WfpEvent -Event $evt -SourceLog $log.Name
            $row | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $outCsv
            $count++
        }

        if ($count -eq 0) {
            # Keep an explicit checkpoint even when no rows exist.
            'No 5152/5157 events found in frozen window.' |
                Set-Content -Encoding UTF8 (Join-Path $Rpt ("WFP-{0}-EMPTY.txt" -f ([IO.Path]::GetFileNameWithoutExtension($log.Name))))
        } else {
            $AllCsv += $outCsv
        }

        Write-Host "[CHECKPOINT] $($log.Name): $count matching WFP events written" -ForegroundColor Yellow
    } catch {
        $errFile = Join-Path $Rpt ("WFP-{0}-ERROR.txt" -f ([IO.Path]::GetFileNameWithoutExtension($log.Name)))
        $_ | Out-String | Set-Content -Encoding UTF8 $errFile
        Write-Host "[REVIEW] Query failed for $($log.Name); error saved, continuing." -ForegroundColor Yellow
    }
}

$CoverageRows | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Rpt 'Security-Log-Coverage.csv')

# ---------------------------
# Merge checkpoint CSVs
# ---------------------------
Write-Host '\n=== MERGE WFP CHECKPOINTS ===' -ForegroundColor Cyan
$WfpCsvFiles = Get-ChildItem -LiteralPath $Rpt -Filter 'WFP-Security-*.csv' -ErrorAction SilentlyContinue | Sort-Object Name
$MergedCsv = Join-Path $Rpt 'WFP-All-5152-5157-FrozenWindow.csv'

if ($WfpCsvFiles.Count -gt 0) {
    $merged = foreach ($f in $WfpCsvFiles) {
        Import-Csv -LiteralPath $f.FullName
    }
    $merged | Export-Csv -NoTypeInformation -Encoding UTF8 $MergedCsv
    Write-Host "[PASS] Merged $($merged.Count) WFP events" -ForegroundColor Green
} else {
    $merged = @()
    'No WFP checkpoint CSV files contained matching events.' |
        Set-Content -Encoding UTF8 (Join-Path $Rpt 'WFP-All-EMPTY.txt')
    Write-Host '[REVIEW] No matching WFP events found in preserved Security logs' -ForegroundColor Yellow
}

# ---------------------------
# WFP summaries
# ---------------------------
if ($merged.Count -gt 0) {
    Write-Host '\n=== WFP SUMMARIES ===' -ForegroundColor Cyan

    $merged |
        Group-Object Application |
        Sort-Object Count -Descending |
        Select-Object Count,Name |
        Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Rpt 'WFP-Summary-ByApplication.csv')

    $merged |
        Group-Object DestPort |
        Sort-Object Count -Descending |
        Select-Object Count,Name |
        Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Rpt 'WFP-Summary-ByDestinationPort.csv')

    $merged |
        Group-Object DestAddress |
        Sort-Object Count -Descending |
        Select-Object Count,Name |
        Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Rpt 'WFP-Summary-ByDestinationAddress.csv')

    $merged |
        Group-Object Protocol |
        Sort-Object Count -Descending |
        Select-Object Count,Name |
        Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Rpt 'WFP-Summary-ByProtocol.csv')

    $VacPattern = '(?i)virtual audio cable|vrtaucbl|vcctlpan|audiorepeater|setup64|muzychenko|vac\\|\\vac\b'
    $VacHits = $merged | Where-Object {
        $_.Application -match $VacPattern -or
        $_.SourceLog   -match $VacPattern
    }

    $VacHits | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Rpt 'WFP-VAC-Attributed-Hits.csv')

    if ($VacHits.Count -eq 0) {
        '[PASS] No WFP 5152/5157 event in the frozen window was attributed by Application field to a VAC/Muzychenko executable name.' |
            Set-Content -Encoding UTF8 (Join-Path $Rpt 'WFP-VAC-Assessment.txt')
        Write-Host '[PASS] No VAC-attributed WFP hits by executable/application name' -ForegroundColor Green
    } else {
        "[REVIEW] VAC-attributed WFP hits found: $($VacHits.Count)" |
            Set-Content -Encoding UTF8 (Join-Path $Rpt 'WFP-VAC-Assessment.txt')
        Write-Host "[REVIEW] VAC-attributed WFP hits found: $($VacHits.Count)" -ForegroundColor Yellow
    }
}

# ---------------------------
# Analyze preserved firewall text log
# ---------------------------
Write-Host '\n=== FIREWALL TEXT LOG ANALYSIS ===' -ForegroundColor Cyan
$PreservedFw = Join-Path $Raw 'pfirewall.log'
if (Test-Path -LiteralPath $PreservedFw) {
    $fwOut = Join-Path $Rpt 'pfirewall-FrozenWindow.log'
    $fwRows = New-Object System.Collections.Generic.List[string]

    foreach ($line in Get-Content -LiteralPath $PreservedFw) {
        if ($line -match '^#') { continue }
        if ($line -match '^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+') {
            try {
                $ts = [datetime]::ParseExact(
                    "$($Matches[1]) $($Matches[2])",
                    'yyyy-MM-dd HH:mm:ss',
                    [Globalization.CultureInfo]::InvariantCulture
                )
                if ($ts -ge $SoakStart -and $ts -le $SoakEnd) {
                    $fwRows.Add($line)
                }
            } catch {}
        }
    }

    $fwRows | Set-Content -Encoding UTF8 $fwOut
    Write-Host "[CHECKPOINT] Firewall lines inside frozen window: $($fwRows.Count)" -ForegroundColor Yellow
} else {
    Write-Host '[REVIEW] No preserved pfirewall.log available' -ForegroundColor Yellow
}

# ---------------------------
# Final package inventory + hashes
# ---------------------------
Write-Host '\n=== FINAL PACKAGE MANIFEST ===' -ForegroundColor Cyan
$Manifest = Get-ChildItem -LiteralPath $Root -Recurse -File | Sort-Object FullName | ForEach-Object {
    [pscustomobject]@{
        RelativePath = $_.FullName.Substring($Root.Length).TrimStart('\')
        Length = $_.Length
        LastWriteTime = $_.LastWriteTime
        SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    }
}
$Manifest | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Root 'FINAL-MANIFEST-SHA256.csv')

Write-Host '\n=== COMPLETE ===' -ForegroundColor Cyan
Write-Host "Evidence package is entirely contained in:" -ForegroundColor White
Write-Host "  $Root" -ForegroundColor Green
Write-Host
Write-Host 'Copy that ONE directory off the VM before disposal.' -ForegroundColor Yellow
Write-Host 'Do not delete the VM until the copied directory has been opened and the manifest/hash files are present.' -ForegroundColor Yellow
