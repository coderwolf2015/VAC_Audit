# Analyze-VAC-Soak-Evidence.ps1
#
# Resumable OFF-BOX analyzer for a preserved VAC soak evidence package.
# This script is intentionally analysis-only:
#   - It NEVER queries the analysis PC's live Security log, firewall state, VAC driver, or power state.
#   - It reads only files already present below -EvidenceRoot.
#   - It writes only below -OutputRoot, which MUST be outside -EvidenceRoot.
#   - It processes Security EVTX files one at a time.
#   - Per-log WFP work uses atomic .partial -> final output and .done checkpoints.
#   - Re-running the same command automatically resumes completed work.
#
# Frozen VAC observation window:
#   2026-09-05 14:00:00 through 2026-09-10 13:25:00
#
# Normal use:
#   .\Analyze-VAC-Soak-Evidence.ps1 -EvidenceRoot 'D:\VAC_Audit_Evidence_20260910_1325'
#
# If interrupted, rebooted, PowerShell closes, etc., run THE SAME COMMAND again.
# Completed stages/logs are skipped automatically.
#
# Explicit restart points:
#   -Stage Preflight    Verify transferred source evidence hashes
#   -Stage Coverage     Read oldest/newest timestamps from each EVTX
#   -Stage WFP          Resume per-EVTX 5152/5157 extraction
#   -Stage Merge        Merge checkpoint CSVs and build summaries
#   -Stage Firewall     Analyze preserved pfirewall.log
#   -Stage Assessment   Build VAC-specific assessment
#   -Stage Finalize     Hash analysis products and write final completion marker
#
# To intentionally repeat one completed stage:
#   add -RedoStage.  This only replaces OUTPUT for that stage; source evidence is never altered.

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$EvidenceRoot,

    [string]$OutputRoot,

    [ValidateSet('All','Preflight','Coverage','WFP','Merge','Firewall','Assessment','Finalize')]
    [string]$Stage = 'All',

    [switch]$RedoStage
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$SoakStart = [datetime]'2026-09-05 14:00:00'
$SoakEnd   = [datetime]'2026-09-10 13:25:00'
$VacPattern = '(?i)virtual audio cable|vrtaucbl|vcctlpan|audiorepeater|setup64|muzychenko|\\vac\\|\\vac\b'
$TripwirePorts = @('53','80','443','853')

function Get-FullPath([string]$Path) {
    return [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path)
}

$EvidenceRoot = Get-FullPath $EvidenceRoot
if (-not $OutputRoot) {
    $parent = Split-Path -Parent $EvidenceRoot
    $leaf   = Split-Path -Leaf $EvidenceRoot
    $OutputRoot = Join-Path $parent ($leaf + '_Analysis')
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)

# Safety: output may not be the evidence root or a child of it.
$srcPrefix = $EvidenceRoot.TrimEnd('\') + '\'
$outPrefix = $OutputRoot.TrimEnd('\') + '\'
if (($OutputRoot.TrimEnd('\') -ieq $EvidenceRoot.TrimEnd('\')) -or $outPrefix.StartsWith($srcPrefix,[StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputRoot must be OUTSIDE EvidenceRoot. Source evidence will never be modified."
}

$Raw   = Join-Path $EvidenceRoot 'RawLogs'
$Meta  = Join-Path $EvidenceRoot 'Metadata'
$OutReports = Join-Path $OutputRoot 'Reports'
$State = Join-Path $OutputRoot 'State'
$WfpDir = Join-Path $OutReports 'WFP-PerLog'
$LogDir = Join-Path $OutputRoot 'RunLogs'

foreach ($d in @($OutputRoot,$OutReports,$State,$WfpDir,$LogDir)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

$RunLog = Join-Path $LogDir ("run-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
try { Start-Transcript -Path $RunLog -Append | Out-Null } catch { }

function Write-Step([string]$Text) { Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Write-Pass([string]$Text) { Write-Host "[PASS] $Text" -ForegroundColor Green }
function Write-Review([string]$Text) { Write-Host "[REVIEW] $Text" -ForegroundColor Yellow }
function Write-Checkpoint([string]$Text) { Write-Host "[CHECKPOINT] $Text" -ForegroundColor Yellow }

function Stage-Marker([string]$Name) { Join-Path $State ("STAGE-{0}.done" -f $Name) }
function Test-StageDone([string]$Name) { Test-Path -LiteralPath (Stage-Marker $Name) }
function Mark-StageDone([string]$Name,[string]$Detail='') {
    @(
        "Stage=$Name"
        "Completed=$((Get-Date).ToString('o'))"
        "Detail=$Detail"
    ) | Set-Content -Encoding UTF8 -LiteralPath (Stage-Marker $Name)
}
function Should-RunStage([string]$Name) {
    if ($Stage -ne 'All' -and $Stage -ne $Name) { return $false }
    if ($RedoStage -and $Stage -eq $Name) { return $true }
    return -not (Test-StageDone $Name)
}

function Assert-StageDone([string]$Name) {
    if (-not (Test-StageDone $Name)) {
        throw "Stage '$Name' is required first. Run with -Stage $Name, or use -Stage All."
    }
}

function Get-EventDataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
    $xml = [xml]$Event.ToXml()
    $map = @{}
    foreach ($d in $xml.Event.EventData.Data) {
        $name = [string]$d.Name
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            $map[$name] = [string]$d.'#text'
        }
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
        TimeCreated     = if ($Event.TimeCreated) { $Event.TimeCreated.ToString('o') } else { '' }
        EventID         = $Event.Id
        SourceLog       = $SourceLog
        RecordId        = $Event.RecordId
        ProcessID       = $d['ProcessID']
        Application     = $d['Application']
        Direction       = $d['Direction']
        SourceAddress   = $d['SourceAddress']
        SourcePort      = $d['SourcePort']
        DestAddress     = $d['DestAddress']
        DestPort        = $d['DestPort']
        Protocol        = $d['Protocol']
        FilterRTID      = $d['FilterRTID']
        LayerName       = $d['LayerName']
        LayerRTID       = $d['LayerRTID']
        RemoteMachineID = $d['RemoteMachineID']
        RemoteUserID    = $d['RemoteUserID']
    }
}

function Remove-StageOutputs([string]$Name) {
    # Only analysis outputs are touched. EvidenceRoot is never touched.
    switch ($Name) {
        'Preflight' {
            Remove-Item -LiteralPath (Join-Path $OutReports 'Transfer-Hash-Verification.csv') -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Join-Path $OutReports 'Source-Inventory.csv') -Force -ErrorAction SilentlyContinue
        }
        'Coverage' {
            Remove-Item -LiteralPath (Join-Path $OutReports 'Security-Log-Coverage.csv') -Force -ErrorAction SilentlyContinue
        }
        'WFP' {
            Get-ChildItem -LiteralPath $WfpDir -File -ErrorAction SilentlyContinue | Remove-Item -Force
        }
        'Merge' {
            Get-ChildItem -LiteralPath $OutReports -File -Filter 'WFP-*' -ErrorAction SilentlyContinue |
                Where-Object { $_.DirectoryName -ne $WfpDir } | Remove-Item -Force
        }
        'Firewall' {
            Get-ChildItem -LiteralPath $OutReports -File -Filter 'Firewall-*' -ErrorAction SilentlyContinue | Remove-Item -Force
        }
        'Assessment' {
            Remove-Item -LiteralPath (Join-Path $OutReports 'VAC-Final-Assessment.txt') -Force -ErrorAction SilentlyContinue
        }
        'Finalize' {
            Remove-Item -LiteralPath (Join-Path $OutputRoot 'ANALYSIS-MANIFEST-SHA256.csv') -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath (Join-Path $OutputRoot 'ANALYSIS-COMPLETE.marker') -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath (Stage-Marker $Name) -Force -ErrorAction SilentlyContinue
}

Write-Host '=== VAC OFF-BOX RESUMABLE SOAK ANALYZER ===' -ForegroundColor Cyan
Write-Host "Evidence root : $EvidenceRoot"
Write-Host "Output root   : $OutputRoot"
Write-Host "Frozen window : $($SoakStart.ToString('o')) through $($SoakEnd.ToString('o'))"
Write-Host "Requested     : $Stage"
Write-Host

if (-not (Test-Path -LiteralPath $Raw -PathType Container)) {
    throw "RawLogs directory not found: $Raw"
}

if ($RedoStage -and $Stage -eq 'All') {
    throw '-RedoStage requires one explicit -Stage value, not All.'
}
if ($RedoStage) { Remove-StageOutputs $Stage }

# -----------------------------------------------------------------------------
# STAGE 1: PREFLIGHT / SOURCE HASH VERIFICATION
# -----------------------------------------------------------------------------
if (Should-RunStage 'Preflight') {
    Write-Step 'STAGE 1 - PREFLIGHT / SOURCE INTEGRITY'

    $manifestPath = Join-Path $EvidenceRoot 'TRANSFER-SHA256.csv'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        throw "TRANSFER-SHA256.csv not found in EvidenceRoot. Refusing to mark preflight complete."
    }

    $manifest = Import-Csv -LiteralPath $manifestPath
    $verifyPath = Join-Path $OutReports 'Transfer-Hash-Verification.csv'
    $verifyPartial = $verifyPath + '.partial'
    Remove-Item -LiteralPath $verifyPartial -Force -ErrorAction SilentlyContinue

    $bad = 0
    $i = 0
    $rows = foreach ($entry in $manifest) {
        $i++
        $file = Join-Path $EvidenceRoot $entry.Path
        Write-Progress -Activity 'Verifying transferred evidence SHA-256' -Status "$i / $($manifest.Count): $($entry.Path)" -PercentComplete (($i / [math]::Max(1,$manifest.Count))*100)
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            $bad++
            [pscustomobject]@{Path=$entry.Path;Status='MISSING';Expected=$entry.SHA256;Actual='';LengthExpected=$entry.Length;LengthActual=''}
            continue
        }
        $item = Get-Item -LiteralPath $file
        $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        $status = if ($actual -eq $entry.SHA256 -and ([string]$item.Length -eq [string]$entry.Length)) {'PASS'} else {'FAIL'}
        if ($status -ne 'PASS') { $bad++ }
        [pscustomobject]@{Path=$entry.Path;Status=$status;Expected=$entry.SHA256;Actual=$actual;LengthExpected=$entry.Length;LengthActual=$item.Length}
    }
    Write-Progress -Activity 'Verifying transferred evidence SHA-256' -Completed
    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $verifyPartial
    Move-Item -LiteralPath $verifyPartial -Destination $verifyPath -Force

    Get-ChildItem -LiteralPath $EvidenceRoot -File -Recurse |
        Select-Object @{n='RelativePath';e={$_.FullName.Substring($EvidenceRoot.Length).TrimStart('\')}},Length,LastWriteTimeUtc |
        Sort-Object RelativePath |
        Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'Source-Inventory.csv')

    if ($bad -ne 0) { throw "Source integrity verification FAILED for $bad manifest entries." }
    Mark-StageDone 'Preflight' "Verified $($manifest.Count) source files against TRANSFER-SHA256.csv"
    Write-Pass "All $($manifest.Count) transferred source files match source SHA-256 manifest"
} elseif ($Stage -eq 'All') {
    Write-Pass 'Stage 1 already complete - skipped'
}

if ($Stage -eq 'Preflight') { try { Stop-Transcript | Out-Null } catch {}; return }

# -----------------------------------------------------------------------------
# STAGE 2: EVTX COVERAGE
# -----------------------------------------------------------------------------
if (Should-RunStage 'Coverage') {
    Assert-StageDone 'Preflight'
    Write-Step 'STAGE 2 - SECURITY EVTX COVERAGE'
    $logs = @(Get-ChildItem -LiteralPath $Raw -File -Filter 'Security-*.evtx' | Sort-Object Name)
    if ($logs.Count -eq 0) { throw 'No Security-*.evtx files found in RawLogs.' }

    $coverage = foreach ($log in $logs) {
        Write-Host "Reading coverage: $($log.Name)"
        try {
            $oldest = Get-WinEvent -Path $log.FullName -Oldest -MaxEvents 1 -ErrorAction Stop
            $newest = Get-WinEvent -Path $log.FullName -MaxEvents 1 -ErrorAction Stop
            [pscustomobject]@{Log=$log.Name;Length=$log.Length;Oldest=$oldest.TimeCreated;Newest=$newest.TimeCreated;Status='PASS';Error=''}
        } catch {
            [pscustomobject]@{Log=$log.Name;Length=$log.Length;Oldest=$null;Newest=$null;Status='REVIEW';Error=$_.Exception.Message}
        }
    }
    $coverage | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'Security-Log-Coverage.csv')
    Mark-StageDone 'Coverage' "Coverage recorded for $($logs.Count) EVTX files"
    Write-Checkpoint "Coverage complete for $($logs.Count) EVTX files"
} elseif ($Stage -eq 'All') {
    Write-Pass 'Stage 2 already complete - skipped'
}

if ($Stage -eq 'Coverage') { try { Stop-Transcript | Out-Null } catch {}; return }

# -----------------------------------------------------------------------------
# STAGE 3: PER-EVTX WFP EXTRACTION
# -----------------------------------------------------------------------------
if (Should-RunStage 'WFP') {
    Assert-StageDone 'Preflight'
    Write-Step 'STAGE 3 - RESUMABLE PER-EVTX WFP EXTRACTION (5152 / 5157)'
    $logs = @(Get-ChildItem -LiteralPath $Raw -File -Filter 'Security-*.evtx' | Sort-Object Name)
    if ($logs.Count -eq 0) { throw 'No Security-*.evtx files found in RawLogs.' }

    $index = 0
    foreach ($log in $logs) {
        $index++
        $base = [IO.Path]::GetFileNameWithoutExtension($log.Name)
        $done = Join-Path $WfpDir ($base + '.done')
        $csv = Join-Path $WfpDir ($base + '.csv')
        $empty = Join-Path $WfpDir ($base + '.empty')
        $partial = $csv + '.partial'

        if (Test-Path -LiteralPath $done) {
            Write-Pass "[$index/$($logs.Count)] $($log.Name) already complete - skipped"
            continue
        }

        # Any partial file is from an interrupted attempt and is safe to discard.
        Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $empty -Force -ErrorAction SilentlyContinue

        Write-Host "`n[$index/$($logs.Count)] Processing $($log.Name) ($([math]::Round($log.Length/1GB,2)) GB)" -ForegroundColor Cyan
        $count = 0
        $sw = [Diagnostics.Stopwatch]::StartNew()

        try {
            Get-WinEvent -FilterHashtable @{Path=$log.FullName;Id=5152,5157;StartTime=$SoakStart;EndTime=$SoakEnd} -ErrorAction Stop |
                ForEach-Object {
                    $count++
                    if (($count % 10000) -eq 0) {
                        Write-Host "  ... $count WFP events converted ($([math]::Round($sw.Elapsed.TotalMinutes,1)) min)"
                    }
                    Convert-WfpEvent -Event $_ -SourceLog $log.Name
                } |
                Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $partial

            if ($count -gt 0) {
                Move-Item -LiteralPath $partial -Destination $csv -Force
            } else {
                Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
                "No 5152/5157 events in frozen window." | Set-Content -Encoding UTF8 -LiteralPath $empty
            }

            @(
                "Log=$($log.Name)"
                "Completed=$((Get-Date).ToString('o'))"
                "Events=$count"
                "ElapsedSeconds=$([math]::Round($sw.Elapsed.TotalSeconds,3))"
            ) | Set-Content -Encoding UTF8 -LiteralPath $done
            $sw.Stop()
            Write-Checkpoint "$($log.Name): $count events; $([math]::Round($sw.Elapsed.TotalMinutes,2)) min"
        } catch {
            $sw.Stop()
            Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
            $_ | Out-String | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $WfpDir ($base + '.error.txt'))
            Write-Review "$($log.Name) failed after $([math]::Round($sw.Elapsed.TotalMinutes,2)) min. No .done marker written; next run retries this log."
            throw
        }
    }

    $remaining = @(Get-ChildItem -LiteralPath $Raw -File -Filter 'Security-*.evtx' | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $WfpDir (([IO.Path]::GetFileNameWithoutExtension($_.Name)) + '.done')))
    })
    if ($remaining.Count -eq 0) {
        Mark-StageDone 'WFP' "All $($logs.Count) Security EVTX files checkpointed"
        Write-Pass 'All per-log WFP extraction checkpoints complete'
    } else {
        throw "$($remaining.Count) Security EVTX logs remain incomplete."
    }
} elseif ($Stage -eq 'All') {
    Write-Pass 'Stage 3 already complete - skipped'
}

if ($Stage -eq 'WFP') { try { Stop-Transcript | Out-Null } catch {}; return }

# -----------------------------------------------------------------------------
# STAGE 4: MERGE + SUMMARIES
# -----------------------------------------------------------------------------
if (Should-RunStage 'Merge') {
    Assert-StageDone 'WFP'
    Write-Step 'STAGE 4 - MERGE WFP CHECKPOINTS + SUMMARIES'
    $csvFiles = @(Get-ChildItem -LiteralPath $WfpDir -File -Filter 'Security-*.csv' | Sort-Object Name)
    $mergedPath = Join-Path $OutReports 'WFP-All-5152-5157-FrozenWindow.csv'
    $mergedPartial = $mergedPath + '.partial'
    Remove-Item -LiteralPath $mergedPartial -Force -ErrorAction SilentlyContinue

    if ($csvFiles.Count -gt 0) {
        $first = $true
        foreach ($f in $csvFiles) {
            Write-Host "Merging $($f.Name)"
            if ($first) {
                Import-Csv -LiteralPath $f.FullName | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $mergedPartial
                $first = $false
            } else {
                Import-Csv -LiteralPath $f.FullName | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -LiteralPath $mergedPartial
            }
        }
        Move-Item -LiteralPath $mergedPartial -Destination $mergedPath -Force

        # Summaries are produced one at a time. These can consume RAM, but only the already-filtered WFP rows, not 4 GB of EVTX.
        $merged = Import-Csv -LiteralPath $mergedPath
        $merged | Group-Object Application | Sort-Object Count -Descending | Select-Object Count,Name |
            Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'WFP-Summary-ByApplication.csv')
        $merged | Group-Object DestPort | Sort-Object Count -Descending | Select-Object Count,Name |
            Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'WFP-Summary-ByDestinationPort.csv')
        $merged | Group-Object DestAddress | Sort-Object Count -Descending | Select-Object Count,Name |
            Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'WFP-Summary-ByDestinationAddress.csv')
        $merged | Group-Object Protocol | Sort-Object Count -Descending | Select-Object Count,Name |
            Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'WFP-Summary-ByProtocol.csv')

        $merged | Where-Object { $TripwirePorts -contains [string]$_.DestPort } |
            Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'WFP-Tripwire-Port-Hits.csv')
        $merged | Where-Object { $_.Application -match $VacPattern } |
            Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'WFP-VAC-Attributed-Hits.csv')

        Write-Pass "Merged $($merged.Count) filtered WFP events from $($csvFiles.Count) checkpoint files"
        Remove-Variable merged -ErrorAction SilentlyContinue
        [GC]::Collect()
    } else {
        'No WFP events were extracted from any Security EVTX in the frozen window.' |
            Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'WFP-All-EMPTY.txt')
        Write-Review 'No per-log WFP CSVs contained events'
    }

    Mark-StageDone 'Merge' "Merged $($csvFiles.Count) per-log WFP CSV files"
} elseif ($Stage -eq 'All') {
    Write-Pass 'Stage 4 already complete - skipped'
}

if ($Stage -eq 'Merge') { try { Stop-Transcript | Out-Null } catch {}; return }

# -----------------------------------------------------------------------------
# STAGE 5: PRESERVED FIREWALL TEXT LOG
# -----------------------------------------------------------------------------
if (Should-RunStage 'Firewall') {
    Assert-StageDone 'Preflight'
    Write-Step 'STAGE 5 - FIREWALL TEXT LOG'
    $fw = Join-Path $Raw 'pfirewall.log'
    $fwOut = Join-Path $OutReports 'Firewall-FrozenWindow.csv'
    $fwPartial = $fwOut + '.partial'
    Remove-Item -LiteralPath $fwPartial -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path -LiteralPath $fw)) {
        'pfirewall.log was not present in preserved RawLogs.' | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'Firewall-MISSING.txt')
        Write-Review 'Preserved pfirewall.log is missing'
    } else {
        $fields = $null
        $count = 0
        $writerRows = New-Object System.Collections.Generic.List[object]
        # Firewall logs are much smaller than Security EVTX (configured ~32 MB), so line streaming is sufficient.
        foreach ($line in [IO.File]::ReadLines($fw)) {
            if ($line.StartsWith('#Fields:')) {
                $fields = @($line.Substring(8).Trim() -split '\s+')
                continue
            }
            if ($line.StartsWith('#') -or [string]::IsNullOrWhiteSpace($line) -or -not $fields) { continue }
            $parts = @($line -split '\s+')
            if ($parts.Count -lt 2) { continue }
            try {
                $when = [datetime]::ParseExact(($parts[0] + ' ' + $parts[1]),'yyyy-MM-dd HH:mm:ss',[Globalization.CultureInfo]::InvariantCulture)
            } catch { continue }
            if ($when -lt $SoakStart -or $when -gt $SoakEnd) { continue }

            $obj = [ordered]@{ TimeCreated=$when.ToString('o') }
            for ($j=0; $j -lt $fields.Count; $j++) {
                $obj[$fields[$j]] = if ($j -lt $parts.Count) { $parts[$j] } else { '' }
            }
            $writerRows.Add([pscustomobject]$obj)
            $count++
        }

        if ($count -gt 0) {
            $writerRows | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $fwPartial
            Move-Item -LiteralPath $fwPartial -Destination $fwOut -Force
            $writerRows | Where-Object {
                ($_.PSObject.Properties['dst-port'] -and $TripwirePorts -contains [string]$_.'dst-port')
            } | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'Firewall-Tripwire-Port-Hits.csv')
            $writerRows | Where-Object {
                ($_.PSObject.Properties['path'] -and [string]$_.'path' -match $VacPattern)
            } | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'Firewall-VAC-Attributed-Hits.csv')
            Write-Pass "Parsed $count firewall records inside frozen window"
        } else {
            'No firewall text-log records found inside frozen window.' | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'Firewall-FrozenWindow-EMPTY.txt')
            Write-Review 'No firewall text-log records inside frozen window'
        }
    }

    Mark-StageDone 'Firewall' 'Preserved firewall log analysis complete'
} elseif ($Stage -eq 'All') {
    Write-Pass 'Stage 5 already complete - skipped'
}

if ($Stage -eq 'Firewall') { try { Stop-Transcript | Out-Null } catch {}; return }

# -----------------------------------------------------------------------------
# STAGE 6: ASSESSMENT
# -----------------------------------------------------------------------------
if (Should-RunStage 'Assessment') {
    Assert-StageDone 'WFP'
    Assert-StageDone 'Merge'
    Write-Step 'STAGE 6 - VAC NETWORK ASSESSMENT'

    $wfpVacFile = Join-Path $OutReports 'WFP-VAC-Attributed-Hits.csv'
    $fwVacFile  = Join-Path $OutReports 'Firewall-VAC-Attributed-Hits.csv'
    $wfpVacCount = if (Test-Path -LiteralPath $wfpVacFile) { @(Import-Csv -LiteralPath $wfpVacFile).Count } else { 0 }
    $fwVacCount  = if (Test-Path -LiteralPath $fwVacFile)  { @(Import-Csv -LiteralPath $fwVacFile).Count } else { 0 }

    $status = if (($wfpVacCount + $fwVacCount) -eq 0) { 'PASS' } else { 'REVIEW' }
    $assessment = @"
VAC soak network assessment
Generated             : $((Get-Date).ToString('o'))
Frozen window         : $($SoakStart.ToString('o')) through $($SoakEnd.ToString('o'))
Source evidence root  : $EvidenceRoot
WFP VAC-attributed    : $wfpVacCount
Firewall VAC-attributed: $fwVacCount
Assessment            : $status

Interpretation:
- PASS means no preserved WFP 5152/5157 event or firewall-text-log record in the frozen window was attributed by application/path to a VAC/Muzychenko executable name.
- REVIEW means one or more such records require inspection.
- This is evidence about conventional Windows networking paths observed by WFP/Windows Firewall. It is not a mathematical proof against a malicious kernel driver using an exotic/raw NIC path.
- Static analysis of vrtaucbl.sys should be considered separately when making the final product judgment.
"@
    $assessment | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $OutReports 'VAC-Final-Assessment.txt')
    Mark-StageDone 'Assessment' "Assessment=$status; WFP=$wfpVacCount; Firewall=$fwVacCount"
    if ($status -eq 'PASS') { Write-Pass "No VAC-attributed conventional network events found (WFP=$wfpVacCount, Firewall=$fwVacCount)" }
    else { Write-Review "VAC-attributed events require inspection (WFP=$wfpVacCount, Firewall=$fwVacCount)" }
} elseif ($Stage -eq 'All') {
    Write-Pass 'Stage 6 already complete - skipped'
}

if ($Stage -eq 'Assessment') { try { Stop-Transcript | Out-Null } catch {}; return }

# -----------------------------------------------------------------------------
# STAGE 7: FINALIZE / HASH ANALYSIS OUTPUT
# -----------------------------------------------------------------------------
if (Should-RunStage 'Finalize') {
    Assert-StageDone 'Preflight'
    Assert-StageDone 'WFP'
    Assert-StageDone 'Merge'
    Assert-StageDone 'Assessment'
    Write-Step 'STAGE 7 - FINALIZE ANALYSIS PACKAGE'

    $manifestOut = Join-Path $OutputRoot 'ANALYSIS-MANIFEST-SHA256.csv'
    $completeMarker = Join-Path $OutputRoot 'ANALYSIS-COMPLETE.marker'
    Remove-Item -LiteralPath $manifestOut,$completeMarker -Force -ErrorAction SilentlyContinue

    $files = @(Get-ChildItem -LiteralPath $OutputRoot -File -Recurse |
        Where-Object { $_.FullName -ne $manifestOut -and $_.FullName -ne $completeMarker } |
        Sort-Object FullName)
    $n = 0
    $hashRows = foreach ($f in $files) {
        $n++
        Write-Progress -Activity 'Hashing analysis products' -Status "$n / $($files.Count): $($f.Name)" -PercentComplete (($n/[math]::Max(1,$files.Count))*100)
        [pscustomobject]@{
            RelativePath = $f.FullName.Substring($OutputRoot.Length).TrimStart('\')
            Length = $f.Length
            SHA256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
        }
    }
    Write-Progress -Activity 'Hashing analysis products' -Completed
    $hashRows | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $manifestOut
    Mark-StageDone 'Finalize' "Hashed $($hashRows.Count) analysis files"

    @(
        'VAC OFF-BOX ANALYSIS COMPLETE'
        "Completed=$((Get-Date).ToString('o'))"
        "EvidenceRoot=$EvidenceRoot"
        "OutputRoot=$OutputRoot"
        "FrozenStart=$($SoakStart.ToString('o'))"
        "FrozenEnd=$($SoakEnd.ToString('o'))"
        "Manifest=$manifestOut"
    ) | Set-Content -Encoding UTF8 -LiteralPath $completeMarker

    Write-Pass "Analysis finalized. Completion marker: $completeMarker"
} elseif ($Stage -eq 'All') {
    Write-Pass 'Stage 7 already complete - skipped'
}

Write-Host "`n=== COMPLETE / SAFE STOP POINT ===" -ForegroundColor Green
Write-Host "Output: $OutputRoot"
Write-Host 'If this machine reboots or PowerShell exits unexpectedly, run the same command again; completed checkpoints will be skipped.'
try { Stop-Transcript | Out-Null } catch { }
