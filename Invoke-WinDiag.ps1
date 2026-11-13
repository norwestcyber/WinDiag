#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the WinDiag toolkit: Windows Update health, compromise indicators, and an Edge/Copilot
    review, then correlates them to answer "is this a real problem, or an attacker?"

.DESCRIPTION
    Read-only. Produces one combined HTML/JSON/CSV report plus correlation notes.

    The correlation is the point of running both: a broken update on its own is
    usually environmental. A broken update PLUS weakened antivirus, new persistence
    or rogue accounts is the classic pattern of malware protecting itself.

    Exit codes (for scripting/RMM use):
      0 = no significant issues     1 = environmental problems only
      2 = suspicious, investigate   3 = compromise indicators found

.PARAMETER Mode          All (default), Update, Compromise, or EdgeCopilot.
.PARAMETER DeepScan      Also run DISM /ScanHealth and SFC /VERIFYONLY (slow).
.PARAMETER CollectLogs   Also export event logs, CBS.log, WindowsUpdate.log etc. into a zip for an investigator.
.PARAMETER Elevate       Relaunch as Administrator if not already elevated.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-WinDiag.ps1 -Elevate
.EXAMPLE
    .\Invoke-WinDiag.ps1 -DeepScan -CollectLogs -OutputDir D:\Cases\PC42
#>
[CmdletBinding()]
param(
    [ValidateSet('All', 'Update', 'Compromise', 'EdgeCopilot')][string]$Mode = 'All',
    [string]$OutputDir = '',
    [int]$Days = 30,
    [int]$UpdateHistoryDays = 90,
    [switch]$DeepScan,
    [switch]$SkipNetwork,
    [switch]$SkipFileScan,
    [switch]$CollectLogs,
    [switch]$Elevate,
    [switch]$Quiet,
    [switch]$NoOpen
)

. (Join-Path $PSScriptRoot 'Common.ps1')
if (-not $OutputDir) { $OutputDir = Get-DefaultOutputDir }
$script:WDQuiet = [bool]$Quiet

if ($Elevate -and -not (Test-IsAdmin)) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"", '-Mode', $Mode, '-OutputDir', "`"$OutputDir`"", '-Days', $Days, '-UpdateHistoryDays', $UpdateHistoryDays)
    foreach ($s in 'DeepScan', 'SkipNetwork', 'SkipFileScan', 'CollectLogs', 'Quiet', 'NoOpen') { if ((Get-Variable $s -ValueOnly)) { $argList += "-$s" } }
    $exe = (Get-Process -Id $PID).Path
    Start-Process -FilePath $exe -ArgumentList $argList -Verb RunAs
    return
}

$started = Get-Date
$stamp = $started.ToString('yyyyMMdd-HHmmss')
$caseDir = Join-Path $OutputDir "WinDiag-$env:COMPUTERNAME-$stamp"
New-Item -ItemType Directory -Path $caseDir -Force | Out-Null

Write-Host ''
Write-Host 'WinDiag - Windows Update & compromise triage (read-only)' -ForegroundColor White
Write-Host "Output: $caseDir" -ForegroundColor DarkGray
if (-not (Test-IsAdmin)) { Write-Host 'WARNING: not elevated. Re-run with -Elevate (or as Administrator) for complete results.' -ForegroundColor Yellow }

function Select-Findings { process { if ($_ -and $_.PSObject.Properties['Classification'] -and $_.PSObject.Properties['Tags']) { $_ } } }
function Select-Inventory { process { if ($_ -and $_.PSObject.Properties['InventoryName']) { $_ } } }

$wu = @(); $comp = @(); $inventory = @()
if ($Mode -in 'All', 'Update') {
    Write-Host "`n=== Part 1: Windows Update health ===" -ForegroundColor White
    $out = @(& (Join-Path $PSScriptRoot 'Test-WindowsUpdateHealth.ps1') -NoReport -PassThru -Quiet:$Quiet -Days $UpdateHistoryDays -DeepScan:$DeepScan -SkipNetwork:$SkipNetwork)
    $wu = @($out | Select-Findings); $inventory += @($out | Select-Inventory)
}
if ($Mode -in 'All', 'Compromise') {
    Write-Host "`n=== Part 2: Compromise indicators ===" -ForegroundColor White
    $out = @(& (Join-Path $PSScriptRoot 'Test-CompromiseIndicators.ps1') -NoReport -PassThru -Quiet:$Quiet -Days $Days -SkipFileScan:$SkipFileScan -SkipNetwork:$SkipNetwork)
    $comp = @($out | Select-Findings); $inventory += @($out | Select-Inventory)
}
if ($Mode -in 'All', 'EdgeCopilot') {
    Write-Host "`n=== Part 3: Edge and Copilot ===" -ForegroundColor White
    # Browser findings are compromise indicators too, so they feed the same correlation
    $out = @(& (Join-Path $PSScriptRoot 'Test-EdgeCopilot.ps1') -NoReport -PassThru -Quiet:$Quiet -Days $Days -SkipCodeScan:$SkipFileScan)
    $comp += @($out | Select-Findings); $inventory += @($out | Select-Inventory)
}

# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------
function Test-Tag($f, [string]$tag) { return (",$($f.Tags)," -like "*,$tag,*") }
$strongCls = 'Suspicious', 'Malicious'
$wuTamper   = @($wu | Where-Object { (Test-Tag $_ 'WU-Tamper') -and $_.Classification -in $strongCls -and $SeverityRank[$_.Severity] -ge 2 })
$wuEnv      = @($wu | Where-Object { $_.Classification -eq 'Benign' -and $SeverityRank[$_.Severity] -ge 2 })
$wuFail     = @($wu | Where-Object { (Test-Tag $_ 'WU-Failure') -and $SeverityRank[$_.Severity] -ge 2 })
$tweak      = @($wu + $comp | Where-Object { Test-Tag $_ 'TweakTool' })
$defTamper  = @($comp | Where-Object { (Test-Tag $_ 'Defender-Tamper') -and $_.Classification -in $strongCls -and $SeverityRank[$_.Severity] -ge 2 })
$compStrong = @($comp | Where-Object { $_.Classification -eq 'Malicious' -and $SeverityRank[$_.Severity] -ge 3 })
$compSus    = @($comp | Where-Object { $_.Classification -eq 'Suspicious' -and $SeverityRank[$_.Severity] -ge 3 -and -not (Test-Tag $_ 'Defender-Tamper') })
$detections = @($comp | Where-Object { Test-Tag $_ 'Detection' })
$staleSigs  = @($comp | Where-Object { $_.Title -like 'Defender signatures are*' })

$notes = New-Object System.Collections.Generic.List[string]
$cat = 'Correlation'
$script:WDQuiet = $true

if ($Mode -eq 'All') {
    if ($wuTamper.Count -and ($defTamper.Count -or $compStrong.Count)) {
        $notes.Add("Update tampering ($($wuTamper.Count)) occurs together with antivirus tampering ($($defTamper.Count)) and/or strong compromise indicators ($($compStrong.Count)). Malware blocks updates and antivirus to protect itself, so this combination should be treated as a compromise until proven otherwise.")
        Add-Finding -Category $cat -Title 'Update blocking + antivirus/compromise indicators: the self-protection pattern of malware' -Severity Critical -Classification Malicious `
            -Detail 'Blocked updates alone are usually a tool or admin choice; together with weakened Defender or persistence, the likeliest explanation is an intruder.' `
            -Recommendation 'Disconnect from the network, preserve this report (and -CollectLogs output), change passwords from a different device, then clean or reimage.' -Tags 'Correlation'
    } elseif ($wuTamper.Count -and $tweak.Count -and -not $compSus.Count) {
        $notes.Add("Updates are deliberately blocked, and an update-blocking/debloat tool is present. With no other strong compromise indicators, the tool is the most likely cause. Confirm that someone remembers running it and that the change dates (Event 7040 evidence) match.")
        Add-Finding -Category $cat -Title 'Update blocking is most likely caused by a tweak/debloat tool, not malware' -Severity Medium -Classification Suspicious `
            -Detail 'Verify the timing. If nobody ran the tool, treat it as malicious.' -Recommendation 'Undo the tool''s update settings using the tool itself, then retry Windows Update.' -Tags 'Correlation'
    } elseif ($wuTamper.Count -and $compSus.Count) {
        $notes.Add("Updates are deliberately blocked and there are other suspicious (not yet conclusive) findings ($($compSus.Count)). Investigate those first: they decide whether the update blocking was an attacker.")
        Add-Finding -Category $cat -Title 'Update blocking alongside other suspicious activity' -Severity High -Classification Suspicious -Tags 'Correlation'
    } elseif ($wuTamper.Count) {
        $notes.Add('Updates are deliberately blocked, but nothing else on the machine looks compromised and no tweak tool was found. Most often an admin, a family member or an old guide did this by hand. Confirm who before re-enabling.')
        Add-Finding -Category $cat -Title 'Updates are blocked deliberately, with no other compromise indicators' -Severity Medium -Classification Suspicious -Tags 'Correlation'
    } elseif (($wuEnv.Count -or $wuFail.Count) -and -not $compStrong.Count -and -not $compSus.Count -and -not $defTamper.Count) {
        $notes.Add('Windows Update problems match ordinary causes and the compromise sweep found nothing strong. This looks like a genuine update problem, not an attack. Repair it the normal way (see the Benign findings).')
        Add-Finding -Category $cat -Title 'Update problems are environmental; no sign an attacker caused them' -Severity Low -Classification Benign -Tags 'Correlation'
    } elseif ($compStrong.Count -or $compSus.Count) {
        $notes.Add('Windows Update itself is not being blocked, but the compromise sweep found suspicious or malicious items. Not every intruder bothers to block updates.')
        Add-Finding -Category $cat -Title 'Compromise indicators present even though updates are not blocked' -Severity High -Classification Suspicious -Tags 'Correlation'
    } else {
        $notes.Add('No update tampering and no strong compromise indicators were found.')
    }
    if ($staleSigs.Count -and ($wuFail.Count -or $wuTamper.Count -or $wuEnv.Count)) {
        $notes.Add('Defender signatures are stale AND Windows Update is failing. They share the same delivery path, so the same root cause (blocked endpoints, disabled services, network) likely explains both.')
    }
    if ($detections.Count -and $wuTamper.Count) {
        $notes.Add('Defender has detected threats during the same period updates were tampered with. Compare the detection times with the Event 7040 service-change times; matching dates strongly suggest the malware made the changes.')
    }
}
$notes.Add('Every check in this toolkit is read-only; nothing on this machine was changed.')
if (-not (Test-IsAdmin)) { $notes.Add('The scan was NOT elevated; event logs, Defender exclusions, WMI, BITS and DISM checks were skipped. Results are incomplete.') }

$corr = @(Get-Findings)
$script:WDQuiet = [bool]$Quiet
$all = @($corr + $wu + $comp)
$verdict = Get-WinDiagVerdict $all
$sys = Get-SystemInfoSummary
$paths = Export-WinDiagReport -Findings $all -OutputDir $caseDir -BaseName 'WinDiag-Report' -Title "WinDiag triage - $env:COMPUTERNAME" -Notes $notes.ToArray() -SystemInfo $sys -Verdict $verdict -Inventory $inventory

# ---------------------------------------------------------------------------
# Optional evidence collection (copies/exports only)
# ---------------------------------------------------------------------------
if ($CollectLogs) {
    Write-Host "`n=== Collecting logs for investigation ===" -ForegroundColor White
    $ev = Join-Path $caseDir 'evidence'
    New-Item -ItemType Directory -Path $ev -Force | Out-Null
    $logs = 'System', 'Application', 'Security', 'Setup', 'Microsoft-Windows-WindowsUpdateClient/Operational', 'Microsoft-Windows-Windows Defender/Operational',
            'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell', 'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
            'Microsoft-Windows-Bits-Client/Operational', 'Microsoft-Windows-Sysmon/Operational'
    foreach ($l in $logs) {
        $file = Join-Path $ev (($l -replace '[\\/ ]', '_') + '.evtx')
        & "$env:SystemRoot\System32\wevtutil.exe" epl $l $file 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Host "  exported $l" -ForegroundColor DarkGray }
    }
    foreach ($f in "$env:SystemRoot\Logs\CBS\CBS.log", "$env:SystemRoot\Logs\DISM\dism.log", "$env:SystemRoot\System32\drivers\etc\hosts", "$env:SystemRoot\WindowsUpdate.log") {
        if (Test-Path $f) { Copy-Item $f -Destination $ev -ErrorAction SilentlyContinue }
    }
    try { Get-WindowsUpdateLog -LogPath (Join-Path $ev 'WindowsUpdate-decoded.log') -ErrorAction Stop *> $null; Write-Host '  decoded WindowsUpdate.log' -ForegroundColor DarkGray } catch {}
    & "$env:SystemRoot\System32\netsh.exe" winhttp show proxy > (Join-Path $ev 'winhttp-proxy.txt') 2>$null
    & "$env:SystemRoot\System32\ipconfig.exe" /all > (Join-Path $ev 'ipconfig.txt') 2>$null
    & "$env:SystemRoot\System32\netstat.exe" -anob > (Join-Path $ev 'netstat.txt') 2>$null
    & "$env:SystemRoot\System32\dsregcmd.exe" /status > (Join-Path $ev 'dsregcmd.txt') 2>$null
    & "$env:SystemRoot\System32\gpresult.exe" /H (Join-Path $ev 'gpresult.html') /F 2>$null | Out-Null
    & "$env:SystemRoot\System32\schtasks.exe" /query /fo CSV /v > (Join-Path $ev 'scheduled-tasks.csv') 2>$null
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate |
        Export-Csv (Join-Path $ev 'processes.csv') -NoTypeInformation -Encoding UTF8
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
        Export-Csv (Join-Path $ev 'services.csv') -NoTypeInformation -Encoding UTF8
    try { Get-MpPreference -ErrorAction Stop | Select-Object Exclusion* , Disable* | Format-List | Out-File (Join-Path $ev 'defender-preferences.txt') } catch {}
    $zip = "$caseDir.zip"
    try { Compress-Archive -Path "$caseDir\*" -DestinationPath $zip -Force -ErrorAction Stop; Write-Host "  evidence archive: $zip" -ForegroundColor Green }
    catch { Write-Host "  could not create zip: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# ---------------------------------------------------------------------------
Write-WinDiagSummary -Findings $all -Verdict $verdict
if ($notes.Count) {
    Write-Host "`nCorrelation:" -ForegroundColor White
    foreach ($n in $notes) { Write-Host "  - $n" }
}
Write-Host ("`nFinished in {0:n0}s. Report: {1}" -f ((Get-Date) - $started).TotalSeconds, $paths.Html) -ForegroundColor Green
if (-not $NoOpen -and [Environment]::UserInteractive) { try { Invoke-Item $paths.Html } catch {} }

$exitCode = switch ($verdict.Level) { 'Critical' { 3 } 'High' { 2 } 'Medium' { 2 } 'Low' { 1 } default { 0 } }
exit $exitCode
