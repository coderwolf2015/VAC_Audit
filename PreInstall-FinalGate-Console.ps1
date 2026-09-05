# PreInstall-FinalGate-Console.ps1
# Paste directly into an elevated PowerShell window.
# No files/directories are created. All results remain in the console.

$ErrorActionPreference = 'Continue'

Write-Host ('=' * 72)
Write-Host 'VAC AUDIT - PRE-INSTALL FINAL GATE'
Write-Host ('=' * 72)
Write-Host ('Timestamp: {0}' -f (Get-Date -Format o))
Write-Host ''

# Elevation check without exiting the host shell.
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host '[REVIEW] Not elevated. Reopen PowerShell as Administrator.'
    return
}
Write-Host '[PASS] Elevated PowerShell'
Write-Host ''

# Locate VAC setup and driver in the extracted package.
$searchRoots = @(
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop"
)

$setup = $null
$driver = $null

foreach ($root in $searchRoots) {
    if (-not $setup -and (Test-Path $root)) {
        $setup = Get-ChildItem -Path $root -Filter 'setup64.exe' -File -Recurse -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    if (-not $driver -and (Test-Path $root)) {
        $driver = Get-ChildItem -Path $root -Filter 'vrtaucbl.sys' -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '[\\/]x64[\\/]' } |
            Select-Object -First 1
    }
}

Write-Host ('=' * 72)
Write-Host 'AUTHENTICODE CHECKS'
Write-Host ('=' * 72)

$gateOk = $true

if ($setup) {
    $sigSetup = Get-AuthenticodeSignature -FilePath $setup.FullName
    [pscustomobject]@{
        File   = $setup.FullName
        Status = $sigSetup.Status
        Signer = if ($sigSetup.SignerCertificate) { $sigSetup.SignerCertificate.Subject } else { '<none>' }
    } | Format-List
    if ($sigSetup.Status -ne 'Valid') {
        Write-Host '[REVIEW] setup64.exe signature is not Valid.'
        $gateOk = $false
    } else {
        Write-Host '[PASS] setup64.exe signature Valid'
    }
} else {
    Write-Host '[REVIEW] setup64.exe not found under Downloads/Desktop.'
    $gateOk = $false
}

Write-Host ''

if ($driver) {
    $sigDriver = Get-AuthenticodeSignature -FilePath $driver.FullName
    [pscustomobject]@{
        File   = $driver.FullName
        Status = $sigDriver.Status
        Signer = if ($sigDriver.SignerCertificate) { $sigDriver.SignerCertificate.Subject } else { '<none>' }
    } | Format-List
    if ($sigDriver.Status -ne 'Valid') {
        Write-Host '[REVIEW] x64\vrtaucbl.sys signature is not Valid.'
        $gateOk = $false
    } else {
        Write-Host '[PASS] x64\vrtaucbl.sys signature Valid'
    }
} else {
    Write-Host '[REVIEW] x64\vrtaucbl.sys not found under Downloads/Desktop.'
    $gateOk = $false
}

Write-Host ''
Write-Host ('=' * 72)
Write-Host 'ENABLE VAC AUDIT CONTAINMENT'
Write-Host ('=' * 72)

Get-NetFirewallRule -DisplayName 'VAC Audit - *' -ErrorAction SilentlyContinue | Enable-NetFirewallRule

$rules = Get-NetFirewallRule -DisplayName 'VAC Audit - *' -ErrorAction SilentlyContinue |
    Select-Object DisplayName,Enabled,Direction,Action |
    Sort-Object DisplayName

$rules | Format-Table -AutoSize

$expected = @(
    'VAC Audit - DNS TCP',
    'VAC Audit - DNS UDP',
    'VAC Audit - HTTP',
    'VAC Audit - HTTPS TCP',
    'VAC Audit - QUIC',
    'VAC Audit - DoT'
)

foreach ($name in $expected) {
    $r = $rules | Where-Object DisplayName -EQ $name
    if (-not $r) {
        Write-Host "[REVIEW] Missing rule: $name"
        $gateOk = $false
    } elseif ($r.Enabled -ne 'True' -and $r.Enabled -ne $true) {
        Write-Host "[REVIEW] Rule not enabled: $name"
        $gateOk = $false
    } elseif ($r.Direction -ne 'Outbound' -or $r.Action -ne 'Block') {
        Write-Host "[REVIEW] Rule not Outbound/Block: $name"
        $gateOk = $false
    } else {
        Write-Host "[PASS] $name enabled / outbound / block"
    }
}

Write-Host ''
Write-Host ('=' * 72)
Write-Host 'FINAL RESULT'
Write-Host ('=' * 72)
if ($gateOk) {
    Write-Host '[PASS] PRE-INSTALL FINAL GATE COMPLETE'
    Write-Host 'You may now launch setup64.exe manually.'
} else {
    Write-Host '[REVIEW] FINAL GATE NOT CLEAN - DO NOT INSTALL YET'
}
Write-Host ''
Write-Host 'No files or directories were created by this check.'
