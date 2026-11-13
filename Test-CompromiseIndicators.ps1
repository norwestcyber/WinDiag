#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only sweep for common indicators of compromise on a Windows machine.

.DESCRIPTION
    Looks for the traces attackers usually leave: weakened Defender, rogue accounts,
    cleared logs, brute-force or remote logons, persistence (Run keys, Winlogon, IFEO,
    LSA packages, services, drivers, scheduled tasks, WMI, BITS, startup folders,
    PowerShell profiles), suspicious processes and network connections, recently
    dropped unsigned executables, unexpected root certificates, weakened security
    settings, ransomware precursors and unexpected remote-access tools.

    Nothing is changed. Findings are scored and classified; the report explains why
    each one matters and what legitimate explanations exist.

    This is a triage tool, not a replacement for a full antivirus/EDR scan. A clean
    result means these common signals are absent, not that the machine is proven clean.

.PARAMETER Days          Event-log look-back window. Default 30.
.PARAMETER FileScanDays  How recent a dropped file must be to be listed. Default 14.
.PARAMETER SkipFileScan  Skip the user-writable folder sweep (fastest).
.PARAMETER SkipNetwork   Skip the live DNS tests (fake answers, certificate checks of sensitive sites).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Test-CompromiseIndicators.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputDir = '',
    [int]$Days = 30,
    [int]$FileScanDays = 14,
    [switch]$SkipFileScan,
    [switch]$SkipNetwork,
    [switch]$Quiet,
    [switch]$NoReport,
    [switch]$PassThru
)

. (Join-Path $PSScriptRoot 'Common.ps1')
if (-not $OutputDir) { $OutputDir = Get-DefaultOutputDir }
$script:WDQuiet = [bool]$Quiet
$ErrorActionPreference = 'Continue'
$since = (Get-Date).AddDays(-$Days)
$mgmt = Get-ManagementContext
$isAdmin = Test-IsAdmin

if (-not $Quiet) {
    Write-Host 'WinDiag - Compromise indicator sweep  (read-only)' -ForegroundColor White
    if (-not $isAdmin) { Write-Host 'Not elevated: event logs, other users, BITS and several checks will be skipped. Run as Administrator.' -ForegroundColor Yellow }
}

# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------
function Test-PrivateIP([string]$ip) {
    if (-not $ip -or $ip -in @('-', '::', '0.0.0.0', '::1')) { return $true }
    return ($ip -match '^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fc|fd|::ffff:(10|127|192\.168)\.)')
}

function Get-EventDataMap($e) {
    $map = @{}
    try { ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $map[$_.Name] = $_.'#text' } } catch {}
    return $map
}

function Test-WinDiagScriptPath([string]$Path) {
    <# True when a script block came from WinDiag's own files (this copy or another copy of the toolkit). #>
    if (-not $Path) { return $false }
    $leaf = [IO.Path]::GetFileName($Path)
    if ($leaf -notin @('Common.ps1', 'Invoke-WinDiag.ps1', 'Test-CompromiseIndicators.ps1', 'Test-WindowsUpdateHealth.ps1', 'Test-EdgeCopilot.ps1')) { return $false }
    $dir = Split-Path $Path -Parent
    return ($leaf -ne 'Common.ps1' -or $dir -eq $PSScriptRoot -or (Test-Path -LiteralPath (Join-Path $dir 'Test-CompromiseIndicators.ps1')))
}

function ConvertTo-ScriptBlockLog {
    <# Reassembles 4104 events into script blocks (long blocks are split over several events) and
       separates out the blocks this scan produces itself: WinDiag's own code (its detection patterns
       contain the very keywords Windows flags) and the CIM proxy modules PowerShell generates when
       cmdlets like Get-NetTCPConnection load. Without this, every run reports itself. #>
    param([object[]]$Events)
    $blocks = [ordered]@{}
    foreach ($e in $Events) {
        $m = Get-EventDataMap $e
        $id = if ($m.ScriptBlockId) { $m.ScriptBlockId } else { "rec$($e.RecordId)" }
        if (-not $blocks.Contains($id)) { $blocks[$id] = [pscustomobject]@{ Time = $e.TimeCreated; Path = [string]$m.Path; Parts = @{}; Text = '' } }
        $b = $blocks[$id]
        $b.Parts[[int]$m.MessageNumber] = [string]$m.ScriptBlockText
        if ($e.TimeCreated -lt $b.Time) { $b.Time = $e.TimeCreated }
        if (-not $b.Path -and $m.Path) { $b.Path = [string]$m.Path }
    }
    $kept = New-Object System.Collections.Generic.List[object]
    $self = New-Object System.Collections.Generic.List[string]
    $generated = 0
    foreach ($b in $blocks.Values) {
        $b.Text = ($b.Parts.Keys | Sort-Object | ForEach-Object { $b.Parts[$_] }) -join ''
        if (Test-WinDiagScriptPath $b.Path) { $self.Add($b.Path); continue }
        if (-not $b.Path -and $b.Text -match '__cmdletization_' -and $b.Text -match 'Microsoft\.PowerShell\.Cmdletization') { $generated++; continue }
        $kept.Add(($b | Select-Object Time, Path, Text))
    }
    [pscustomobject]@{ Blocks = $kept.ToArray(); SelfCount = $self.Count; SelfPaths = @($self | Select-Object -Unique); GeneratedCount = $generated }
}

function Measure-CommandRisk {
    <# Judges a command line: the exe, and for LOLBin hosts the file they load. #>
    param([string]$Command)
    $exe = Resolve-CommandPath $Command
    $sig = $null
    if ($exe -and $exe -notmatch '^(?i)(javascript|vbscript|https?):') { $sig = Get-FileSignatureInfo $exe }
    $payload = Get-HostedPayloadPath -CommandLine $Command -ExePath $exe
    $psig = $null
    $cr = @(Get-CommandLineRisk $Command)
    if ($payload -match '^(?i)(javascript|vbscript|https?):') { $cr += [pscustomobject]@{ Reason = 'Host loads remote/inline script'; Weight = 3 } }
    elseif ($payload) { $psig = Get-FileSignatureInfo $payload }
    $judgeSig = if ($psig) { $psig } else { $sig }
    $judgePath = if ($payload) { $payload } else { $exe }
    $isScript = $judgePath -match '(?i)\.(ps1|psm1|vbs|vbe|js|jse|wsf|hta|bat|cmd)$'
    $risk = Get-RiskSeverity -SigInfo $(if ($isScript) { $null } else { $judgeSig }) -CmdRisk $cr -UserWritable:(Test-UserWritablePath $judgePath)
    [pscustomobject]@{ Exe = $exe; Payload = $payload; Sig = $judgeSig; Risk = $risk }
}

function Add-RiskFinding {
    <# Adds a finding for a scored item when it is at least mildly unusual. #>
    param([string]$Category, [string]$What, [string]$Command, $Measure, [string]$Extra = '', [string[]]$Tags = @('Persistence'), [int]$MinScore = 2)
    if ($Measure.Risk.Score -lt $MinScore) { return $false }
    $ev = [ordered]@{ Item = $What; Command = $Command; ResolvedExe = $Measure.Exe; LoadedFile = $Measure.Payload; Reasons = $Measure.Risk.Reasons }
    if ($Measure.Sig) {
        $ev.Signature = $Measure.Sig.Status; $ev.Signer = $Measure.Sig.Signer; $ev.Company = $Measure.Sig.Company
        $ev.Created = $Measure.Sig.Created
        if ($Measure.Sig.Exists) { $ev.SHA256 = Get-Sha256 $Measure.Sig.Path }
    }
    Add-Finding -Category $Category -Title "$What" -Severity $Measure.Risk.Severity -Classification $Measure.Risk.Classification `
        -Detail ("$($Measure.Risk.Reasons). $Extra").Trim() -Evidence ([pscustomobject]$ev) `
        -Recommendation 'Identify what installed it. Look up the SHA256 on VirusTotal. If unknown, isolate the PC before removing it so evidence is preserved.' -Tags $Tags
    return $true
}

# ===========================================================================
Invoke-Check -Name 'Defender and antivirus status' -ScriptBlock {
    $c = 'Antivirus'
    $thirdParty = $mgmt.ThirdPartyAV
    $st = $null
    try { $st = Get-MpComputerStatus -ErrorAction Stop } catch {}
    $wdStart = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' 'Start'
    if (-not $st) {
        if ($thirdParty.Count) { Add-Finding -Category $c -Title "Defender not active; third-party AV registered: $($thirdParty -join ', ')" -Classification Info }
        elseif ($wdStart -eq 4) {
            Add-Finding -Category $c -Title 'Microsoft Defender service is disabled and no other antivirus is registered' -Severity Critical -Classification Malicious `
                -Detail 'Disabling the only antivirus is one of the first things malware does.' -Recommendation 'Run Microsoft Defender Offline or a bootable scanner from a clean machine.' -Tags 'Defender-Tamper'
        } else { Add-Finding -Category $c -Title 'Could not query Defender status' -Severity Low -Classification Ambiguous -Tags 'Defender-Tamper' }
    } else {
        $mode = if ($st.PSObject.Properties['AMRunningMode']) { $st.AMRunningMode } else { 'Normal' }
        $passive = $mode -match '(?i)passive|edr block'
        $ev = $st | Select-Object AMRunningMode, AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
                                  IoavProtectionEnabled, OnAccessProtectionEnabled, IsTamperProtected, AntivirusSignatureAge, AntivirusSignatureLastUpdated, QuickScanAge
        if ($thirdParty.Count -and ($passive -or -not $st.RealTimeProtectionEnabled)) {
            Add-Finding -Category $c -Title "Defender in $mode; primary AV: $($thirdParty -join ', ')" -Classification Info -Evidence $ev
        } else {
            $off = @()
            foreach ($p in 'AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled','BehaviorMonitorEnabled','IoavProtectionEnabled','OnAccessProtectionEnabled') {
                if ($st.PSObject.Properties[$p] -and -not $st.$p) { $off += $p }
            }
            if ($off.Count) {
                Add-Finding -Category $c -Title "Defender protection components are OFF: $($off -join ', ')" -Severity High -Classification Suspicious `
                    -Detail 'No other antivirus is registered to take over. Malware routinely disables real-time and behaviour monitoring.' -Evidence $ev `
                    -Recommendation 'Check the 5001/5007 events below for when this happened. Turn protection back on and run a full + offline scan.' -Tags 'Defender-Tamper'
            } else { Add-Finding -Category $c -Title 'Defender real-time, behaviour and download protection are on' -Classification OK -Evidence $ev }
            if ($st.PSObject.Properties['IsTamperProtected'] -and -not $st.IsTamperProtected) {
                Add-Finding -Category $c -Title 'Defender Tamper Protection is off' -Severity $(if ($mgmt.IsManaged) {'Low'} else {'Medium'}) -Classification Ambiguous `
                    -Detail 'On by default for home PCs. Off means a user, admin tool or malware switched it off, which then allows Defender settings to be changed silently.' -Tags 'Defender-Tamper'
            }
            if ($st.AntivirusSignatureAge -gt 7) {
                Add-Finding -Category $c -Title "Defender signatures are $($st.AntivirusSignatureAge) days old" -Severity Medium -Classification Ambiguous `
                    -Detail 'Signatures normally update several times a day. Stale signatures share causes with failing Windows Update (blocked endpoints, disabled services) - compare with that report.' -Tags 'Defender-Tamper','WU-Failure'
            }
        }
    }

    # Policy-based disabling
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $pv = [ordered]@{
        DisableAntiSpyware         = Get-RegValue $pol 'DisableAntiSpyware'
        DisableAntiVirus           = Get-RegValue $pol 'DisableAntiVirus'
        DisableRealtimeMonitoring  = Get-RegValue "$pol\Real-Time Protection" 'DisableRealtimeMonitoring'
        DisableBehaviorMonitoring  = Get-RegValue "$pol\Real-Time Protection" 'DisableBehaviorMonitoring'
        DisableIOAVProtection      = Get-RegValue "$pol\Real-Time Protection" 'DisableIOAVProtection'
        DisableOnAccessProtection  = Get-RegValue "$pol\Real-Time Protection" 'DisableOnAccessProtection'
        DisableScriptScanning      = Get-RegValue "$pol\Real-Time Protection" 'DisableScriptScanning'
        SpynetReporting            = Get-RegValue "$pol\Spynet" 'SpynetReporting'
        SubmitSamplesConsent       = Get-RegValue "$pol\Spynet" 'SubmitSamplesConsent'
    }
    $bad = @($pv.Keys | Where-Object { ($_ -like 'Disable*' -and $pv[$_] -eq 1) -or ($_ -eq 'SpynetReporting' -and $pv[$_] -eq 0) -or ($_ -eq 'SubmitSamplesConsent' -and $pv[$_] -eq 2) })
    if ($bad.Count) {
        Add-Finding -Category $c -Title "Defender is weakened by policy: $($bad -join ', ')" -Severity $(if ($mgmt.IsManaged -or $thirdParty.Count) {'Medium'} else {'High'}) -Classification Suspicious `
            -Detail 'These policies are a standard malware/ransomware step. Legit when an organization deploys another AV, or after running a debloat tool.' -Evidence ([pscustomobject]$pv) -Tags 'Defender-Tamper'
    }

    # Exclusions
    if ($st) {
        try {
            $pref = Get-MpPreference -ErrorAction Stop
            $ex = [ordered]@{ Paths = @($pref.ExclusionPath | Where-Object { $_ }); Processes = @($pref.ExclusionProcess | Where-Object { $_ })
                              Extensions = @($pref.ExclusionExtension | Where-Object { $_ }); IPs = @($pref.ExclusionIpAddress | Where-Object { $_ }) }
            $hidden = @($ex.Paths + $ex.Processes + $ex.Extensions | Where-Object { $_ -match 'N/A' })
            if ($hidden.Count) { Add-Finding -Category $c -Title 'Defender exclusions are hidden from this account (run elevated to read them)' -Classification Info }
            else {
                $broad = @()
                $broad += $ex.Paths | Where-Object { $_ -match '^(?i)([a-z]:\\?$|[a-z]:\\users\\?$|[a-z]:\\windows\\?$|[a-z]:\\programdata\\?$)' -or $_ -match '(?i)\\(appdata|temp|downloads|users\\public)(\\|$)' -or $_ -match '^(?i)%(temp|appdata|userprofile)%' }
                $broad += $ex.Extensions | Where-Object { $_ -match '^(?i)\.?(exe|dll|ps1|bat|cmd|vbs|js|scr|hta|msi|sys)$' }
                $broad += $ex.Processes | Where-Object { $_ -match '(?i)(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|svchost|explorer|msiexec)(\.exe)?$' }
                $all = @($ex.Paths + $ex.Processes + $ex.Extensions + $ex.IPs)
                if ($broad.Count) {
                    Add-Finding -Category $c -Title "Defender has $($broad.Count) dangerously broad exclusion(s)" -Severity High -Classification $(if ($mgmt.IsManaged) {'Suspicious'} else {'Malicious'}) `
                        -Detail 'Excluding whole drives, user-writable folders, script hosts or executable extensions lets malware run unscanned. Attackers add these right after gaining access.' `
                        -Evidence ([pscustomobject]$ex) -Recommendation 'Find out who added them (Defender event 5007). Remove them and run a full scan.' -Tags 'Defender-Tamper'
                } elseif ($all.Count) {
                    Add-Finding -Category $c -Title "Defender has $($all.Count) exclusion(s) (none overly broad)" -Severity Low -Classification Ambiguous -Evidence ([pscustomobject]$ex) `
                        -Detail 'Usually added for games, dev tools or backup software. Make sure you recognize each one.' -Tags 'Defender-Tamper'
                } else { Add-Finding -Category $c -Title 'No Defender exclusions' -Classification OK }
            }
        } catch {}
        # Detections
        try {
            $det = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt $since })
            if ($det.Count) {
                $threats = @{}; Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $threats[[string]$_.ThreatID] = $_ }
                $rows = $det | ForEach-Object {
                    $t = $threats[[string]$_.ThreatID]
                    [pscustomobject]@{ Time = $_.InitialDetectionTime; Threat = $(if ($t) { $t.ThreatName } else { $_.ThreatID }); Severity = $(if ($t) { $t.SeverityID } else { '' })
                                       Removed = $_.ActionSuccess; Resources = ($_.Resources -join '; '); Process = $_.ProcessName; User = $_.DomainUser }
                }
                $active = @($rows | Where-Object { -not $_.Removed })
                Add-Finding -Category $c -Title "Defender detected $($det.Count) threat(s) in the last $Days days ($($active.Count) not removed)" `
                    -Severity $(if ($active.Count) {'High'} else {'Medium'}) -Classification $(if ($active.Count) {'Malicious'} else {'Ambiguous'}) `
                    -Detail 'A remediated detection means something reached the disk. Check whether it was a one-off download or part of a wider infection (look for the same time window in other findings).' `
                    -Evidence ($rows | Format-List | Out-String -Width 300) -Tags 'Detection'
            } else { Add-Finding -Category $c -Title "No Defender detections in the last $Days days" -Classification OK }
        } catch {}
    }
    if ($isAdmin) {
        $dev = Get-RecentEvents @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 5001, 5010, 5012, 5007, 5013; StartTime = $since } 400
        $offEv = @($dev | Where-Object { $_.Id -in 5001, 5010, 5012 })
        $cfgEv = @($dev | Where-Object { $_.Id -eq 5007 -and $_.Message -match '(?i)(Exclusions\\|DisableRealtimeMonitoring|DisableAntiSpyware|DisableBehaviorMonitoring|DisableIOAV|TamperProtection)' })
        $tpEv  = @($dev | Where-Object { $_.Id -eq 5013 })
        if ($offEv.Count -or $cfgEv.Count) {
            Add-Finding -Category $c -Title "Defender was disabled or reconfigured $($offEv.Count + $cfgEv.Count) time(s) in the last $Days days" -Severity Medium -Classification Suspicious `
                -Detail 'Events 5001/5010/5012 = protection turned off; 5007 = exclusions or protection settings changed. Match the times against software you installed.' `
                -Evidence (($offEv + $cfgEv) | Select-Object -First 25 TimeCreated, Id, @{ n = 'Message'; e = { ($_.Message -split "`n" | Select-Object -First 6) -join ' ' } } | Format-List | Out-String -Width 400) -Tags 'Defender-Tamper'
        }
        if ($tpEv.Count) {
            Add-Finding -Category $c -Title "Tamper Protection blocked $($tpEv.Count) attempt(s) to change Defender" -Severity High -Classification Suspicious `
                -Detail 'Event 5013: something tried to weaken Defender and was stopped. Legit tools rarely do this; malware does it constantly.' `
                -Evidence ($tpEv | Select-Object -First 15 TimeCreated, Message | Format-List | Out-String -Width 400) -Tags 'Defender-Tamper'
        }
    }
}

# ===========================================================================
Invoke-Check -Name 'Local accounts' -ScriptBlock {
    $c = 'Accounts'
    $users = @(Get-LocalUser -ErrorAction SilentlyContinue)
    $admins = @()
    try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name }) }
    catch {
        $raw = & net.exe localgroup administrators 2>$null
        $admins = @($raw | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' })
    }
    $known = '^(DefaultAccount|WDAGUtilityAccount|defaultuser0|defaultuser100000)$'
    $hiddenKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    $hiddenUsers = @()
    $hk = Get-ItemProperty $hiddenKey -ErrorAction SilentlyContinue
    if ($hk) { $hiddenUsers = @($hk.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and $_.Value -eq 0 } | Select-Object -ExpandProperty Name) }

    $inv = $users | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, Description, SID,
        @{ n = 'IsAdmin'; e = { $n = $_.Name; [bool]($admins | Where-Object { $_ -match "\\$([regex]::Escape($n))$" -or $_ -eq $n }) } }
    Add-Finding -Category $c -Title "$($users.Count) local account(s), $($admins.Count) member(s) of Administrators" -Classification Info `
        -Evidence (($inv | Format-Table -AutoSize | Out-String -Width 300) + "`nAdministrators:`n" + ($admins -join "`n"))

    foreach ($u in $users) {
        if ($u.Name -match '\$$') {
            Add-Finding -Category $c -Title "Local account '$($u.Name)' ends in `$ (disguised as a computer account)" -Severity High -Classification Suspicious `
                -Detail 'Local users ending in $ are hidden from some listings. A known persistence trick.' -Tags 'Account'
        }
        if ($u.SID.Value -match '-501$' -and $u.Enabled) {
            Add-Finding -Category $c -Title 'The Guest account is enabled' -Severity Medium -Classification Suspicious -Detail 'Disabled by default. Attackers enable it for an easy way back in.' -Tags 'Account'
        }
        if ($u.Enabled -and -not $u.PasswordRequired -and ($inv | Where-Object { $_.Name -eq $u.Name }).IsAdmin) {
            Add-Finding -Category $c -Title "Administrator account '$($u.Name)' does not require a password" -Severity High -Classification Ambiguous -Tags 'Account'
        }
    }
    foreach ($h in $hiddenUsers) {
        if ($h -match $known) { continue }
        Add-Finding -Category $c -Title "Account '$h' is hidden from the sign-in screen" -Severity Medium -Classification Suspicious `
            -Detail 'SpecialAccounts\UserList hides an account. Some vendor/service accounts do this; attackers hide backdoor admin accounts the same way.' -Tags 'Account'
    }

    if ($isAdmin) {
        $ev = Get-RecentEvents @{ LogName = 'Security'; Id = 4720, 4732, 4728, 4724; StartTime = $since } 300
        $created = @($ev | Where-Object Id -eq 4720 | ForEach-Object { $m = Get-EventDataMap $_; [pscustomobject]@{ Time = $_.TimeCreated; Account = $m.TargetUserName; By = $m.SubjectUserName } })
        $toAdmin = @($ev | Where-Object { $_.Id -eq 4732 } | ForEach-Object { $m = Get-EventDataMap $_; if ($m.TargetSid -eq 'S-1-5-32-544') {
                        $mem = $m.MemberName; if (-not $mem -or $mem -eq '-') { try { $mem = (New-Object Security.Principal.SecurityIdentifier($m.MemberSid)).Translate([Security.Principal.NTAccount]).Value } catch { $mem = $m.MemberSid } }
                        [pscustomobject]@{ Time = $_.TimeCreated; Member = $mem; By = $m.SubjectUserName } } })
        if ($created.Count) {
            Add-Finding -Category $c -Title "$($created.Count) local account(s) created in the last $Days days" -Severity Medium -Classification Ambiguous `
                -Detail 'Confirm each was created on purpose.' -Evidence ($created | Format-Table -AutoSize | Out-String) -Tags 'Account'
        }
        if ($toAdmin.Count) {
            Add-Finding -Category $c -Title "$($toAdmin.Count) account(s) added to Administrators in the last $Days days" -Severity High -Classification Suspicious `
                -Detail 'Adding an account to the local Administrators group is a key attacker step. Verify each change.' -Evidence ($toAdmin | Format-Table -AutoSize | Out-String) -Tags 'Account'
        }
    }
}

# ===========================================================================
Invoke-Check -Name 'Event log evidence' -RequiresAdmin -ScriptBlock {
    $c = 'Event logs'
    # Other providers reuse these IDs (e.g. the smartcard reader driver logs System 104), so match the Eventlog provider only
    $cleared = @(Get-RecentEvents @{ LogName = 'Security'; ProviderName = 'Microsoft-Windows-Eventlog'; Id = 1102; StartTime = $since } 50) +
               @(Get-RecentEvents @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Eventlog'; Id = 104; StartTime = $since } 50)
    if ($cleared.Count) {
        $rows = $cleared | ForEach-Object {
            $lc = $null; try { $lc = ([xml]$_.ToXml()).Event.UserData.LogFileCleared } catch {}
            [pscustomobject]@{ TimeCreated = $_.TimeCreated; Id = $_.Id
                ClearedLog = $(if ($lc -and $lc.Channel) { $lc.Channel } else { $_.LogName })
                By = $(if ($lc -and $lc.SubjectUserName) { "$($lc.SubjectDomainName)\$($lc.SubjectUserName)" } else { '' }) } }
        $multi = @($cleared | Group-Object { $_.TimeCreated.ToString('yyyyMMddHH') } | Where-Object Count -ge 2).Count -gt 0
        Add-Finding -Category $c -Title "Event logs were cleared $($cleared.Count) time(s) in the last $Days days" -Severity High -Classification $(if ($multi) {'Malicious'} else {'Suspicious'}) `
            -Detail 'Clearing logs destroys evidence. Several logs cleared in the same hour is a strong sign of an intruder covering tracks; a single clear can be an admin or cleanup tool.' `
            -Evidence ($rows | Format-Table -AutoSize | Out-String) -Tags 'AntiForensics'
    } else { Add-Finding -Category $c -Title "No event log clears in the last $Days days" -Classification OK }

    $evSvc = Get-Service EventLog -ErrorAction SilentlyContinue
    if ($evSvc -and $evSvc.Status -ne 'Running') {
        Add-Finding -Category $c -Title 'The Windows Event Log service is not running' -Severity High -Classification Suspicious -Detail 'Stopping event logging blinds every other check.' -Tags 'AntiForensics'
    }
    try {
        $oldest = Get-WinEvent -LogName Security -MaxEvents 1 -Oldest -ErrorAction Stop
        $span = (Get-Date) - $oldest.TimeCreated
        if ($span.TotalHours -lt 48) {
            Add-Finding -Category $c -Title ("Security log only covers the last {0:n0} hours" -f $span.TotalHours) -Severity Low -Classification Ambiguous `
                -Detail 'A very short history means the log is tiny, was recently cleared, or the PC is new. It limits what can be checked.'
        }
    } catch {}

    # Failed logons / brute force
    $fails = Get-RecentEvents @{ LogName = 'Security'; Id = 4625; StartTime = $since } 5000
    if ($fails.Count) {
        $f = $fails | ForEach-Object { $m = Get-EventDataMap $_; [pscustomobject]@{ IP = $m.IpAddress; User = $m.TargetUserName; Type = $m.LogonType } }
        $byIp = $f | Group-Object IP | Sort-Object Count -Descending | Select-Object -First 10
        $ext = @($byIp | Where-Object { -not (Test-PrivateIP $_.Name) -and $_.Count -ge 20 })
        $local = @($byIp | Where-Object { (Test-PrivateIP $_.Name) -and $_.Count -ge 50 })
        $evTxt = ($byIp | ForEach-Object { '{0,-40} {1,6} failures  users: {2}' -f $_.Name, $_.Count, (($_.Group.User | Select-Object -Unique -First 6) -join ', ') }) -join "`n"
        if ($ext.Count) {
            Add-Finding -Category $c -Title "Brute-force logon attempts from $($ext.Count) internet address(es)" -Severity High -Classification Suspicious `
                -Detail 'Many failed logons from public IPs means a service (usually RDP or SMB) is exposed to the internet and being attacked.' -Evidence $evTxt `
                -Recommendation 'Close RDP/SMB to the internet (router port forwarding), use VPN, enable account lockout. Check successful logons below.' -Tags 'Logon'
        } elseif ($local.Count) {
            Add-Finding -Category $c -Title 'Many failed logons from local addresses' -Severity Medium -Classification Ambiguous `
                -Detail 'Often a mapped drive or app with an old password; can also be lateral movement from another infected machine.' -Evidence $evTxt -Tags 'Logon'
        } else { Add-Finding -Category $c -Title "$($fails.Count) failed logon(s), no brute-force pattern" -Classification Info -Evidence $evTxt }
    }

    # Successful remote logons from public IPs
    $ms = [int64]((Get-Date) - $since).TotalMilliseconds
    $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LogonType']='10']]"
    $ok = @(); try { $ok = @(Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 2000 -ErrorAction Stop) } catch {}
    $remote = @($ok | ForEach-Object { $m = Get-EventDataMap $_
                    if ($m.LogonType -eq '10' -and -not (Test-PrivateIP $m.IpAddress) -and $m.TargetUserName -notmatch '(\$$|^ANONYMOUS)') {
                        [pscustomobject]@{ Time = $_.TimeCreated; User = $m.TargetUserName; Type = $(if ($m.LogonType -eq '10') {'RDP'} else {'Network'}); IP = $m.IpAddress; Workstation = $m.WorkstationName } } })
    $rcm = Get-RecentEvents @{ LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id = 1149; StartTime = $since } 500
    $rdpExt = @($rcm | ForEach-Object {
                    $ip = $null; try { $ip = ([xml]$_.ToXml()).Event.UserData.EventXML.Param3 } catch {}
                    if ($ip -and -not (Test-PrivateIP $ip)) { [pscustomobject]@{ Time = $_.TimeCreated; User = ([xml]$_.ToXml()).Event.UserData.EventXML.Param1; Type = 'RDP auth'; IP = $ip } } })
    $all = @($remote + $rdpExt)
    if ($all.Count) {
        Add-Finding -Category $c -Title "$($all.Count) successful remote logon(s) from internet addresses" -Severity High -Classification Suspicious `
            -Detail 'Someone authenticated to this PC directly from the internet. Unless you use RDP from outside on purpose, treat as an intrusion.' `
            -Evidence ($all | Sort-Object Time -Descending | Select-Object -First 40 | Format-Table -AutoSize | Out-String -Width 300) -Tags 'Logon'
    }

    # New services (7045)
    $svc = Get-RecentEvents @{ LogName = 'System'; Id = 7045; StartTime = $since } 300
    $risky = @()
    foreach ($e in $svc) {
        $m = Get-EventDataMap $e
        $meas = Measure-CommandRisk $m.ImagePath
        if ($meas.Risk.Score -ge 2 -or $m.ImagePath -match '(?i)(cmd(\.exe)?\s+/c|powershell|%comspec%|\\\\127\.0\.0\.1\\|\\admin\$\\)') {
            $risky += [pscustomobject]@{ Time = $e.TimeCreated; Service = $m.ServiceName; Image = $m.ImagePath; Account = $m.AccountName; Reasons = $meas.Risk.Reasons }
        }
    }
    if ($risky.Count) {
        Add-Finding -Category $c -Title "$($risky.Count) suspicious service(s) installed in the last $Days days" -Severity High -Classification Suspicious `
            -Detail 'Services that run cmd/PowerShell or binaries from user folders are how PsExec-style lateral movement and many backdoors start.' -Evidence ($risky | Format-List | Out-String -Width 400) -Tags 'Persistence'
    } elseif ($svc.Count) {
        Add-Finding -Category $c -Title "$($svc.Count) service(s) installed in the last $Days days (none look risky)" -Classification Info `
            -Evidence ($svc | Select-Object -First 30 TimeCreated, @{ n = 'Service'; e = { (Get-EventDataMap $_).ServiceName } } | Format-Table -AutoSize | Out-String)
    }

    # PowerShell: Windows auto-logs suspicious script blocks at Warning level (4104)
    $psLog = ConvertTo-ScriptBlockLog (Get-RecentEvents @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Level = 3; StartTime = $since } 1500)
    $ps = @($psLog.Blocks)
    if ($ps.Count) {
        $samples = $ps | Select-Object -First 12 | ForEach-Object { $t = $_.Text
            "[$($_.Time)] $(if ($_.Path) { $_.Path } else { '(interactive / -Command / generated)' })`n" + $t.Substring(0, [Math]::Min(400, $t.Length)) + "`n" }
        Add-Finding -Category $c -Title "Windows flagged $($ps.Count) PowerShell script block(s) as suspicious" -Severity Medium -Classification Suspicious `
            -Detail 'PowerShell logs a Warning-level 4104 event when a script uses keywords common in attack tooling (reflection, obfuscation, AMSI bypass). Admin and developer scripts trigger it too, so read the samples.' `
            -Evidence ($samples -join "`n") -Tags 'Execution'
    } else { Add-Finding -Category $c -Title "No PowerShell script blocks flagged as suspicious in the last $Days days" -Classification OK }
    if ($psLog.SelfCount -or $psLog.GeneratedCount) {
        Add-Finding -Category $c -Title "Ignored $($psLog.SelfCount + $psLog.GeneratedCount) flagged script block(s) produced by this scan" -Classification Info `
            -Detail "$($psLog.SelfCount) from WinDiag's own scripts (its detection patterns contain the keywords Windows flags) and $($psLog.GeneratedCount) CIM proxy module(s) PowerShell generates itself when network/SMB/firewall cmdlets load." `
            -Evidence $(if ($psLog.SelfPaths.Count) { "WinDiag script paths:`n" + ($psLog.SelfPaths -join "`n") } else { $null })
    }
    $v2 = @(Get-RecentEvents @{ LogName = 'Windows PowerShell'; Id = 400; StartTime = $since } 500 | Where-Object { $_.Message -match 'EngineVersion=2\.' })
    if ($v2.Count) {
        Add-Finding -Category $c -Title "PowerShell 2.0 engine was used $($v2.Count) time(s)" -Severity Medium -Classification Suspicious `
            -Detail 'PowerShell 2.0 has no script-block logging or AMSI, so attackers downgrade to it to avoid detection. Very old software can also require it.' `
            -Evidence ($v2 | Select-Object -First 10 TimeCreated, @{ n = 'Host'; e = { if ($_.Message -match 'HostApplication=(.+)') { $Matches[1] } } } | Format-List | Out-String -Width 400) -Tags 'Execution'
    }
    $aud = Get-RecentEvents @{ LogName = 'Security'; Id = 4719; StartTime = $since } 50
    if ($aud.Count) {
        Add-Finding -Category $c -Title "Audit policy was changed $($aud.Count) time(s)" -Severity Low -Classification Ambiguous -Detail 'Turning off auditing hides later activity. Group Policy refreshes also log this.' -Tags 'AntiForensics'
    }
}

# ===========================================================================
Invoke-Check -Name 'Autostart registry locations' -ScriptBlock {
    $c = 'Persistence'
    $runPaths = @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                  'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                  'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices')
    $roots = @([pscustomobject]@{ User = 'HKLM (all users)'; Root = 'HKLM:' })
    $roots += Get-UserHives
    $inventory = New-Object System.Collections.Generic.List[object]
    $flagged = 0
    foreach ($r in $roots) {
        foreach ($rp in $runPaths) {
            $k = "$($r.Root)\$rp"
            $props = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            foreach ($p in $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' }) {
                $cmd = [string]$p.Value
                $meas = Measure-CommandRisk $cmd
                $inventory.Add([pscustomobject]@{ Scope = $r.User; Key = ($rp -split '\\')[-1]; Name = $p.Name; Command = $cmd; Signed = $(if ($meas.Sig) { $meas.Sig.Status } else { '' }); Signer = $(if ($meas.Sig) { $meas.Sig.Signer -replace ',.*$', '' } else { '' }) })
                if (Add-RiskFinding -Category $c -What "Autostart '$($p.Name)' ($($r.User) $(($rp -split '\\')[-1]))" -Command $cmd -Measure $meas) { $flagged++ }
            }
        }
        # Legacy Windows\Load / Run
        foreach ($n in 'Load', 'Run') {
            $v = Get-RegValue "$($r.Root)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" $n
            if ($v) {
                Add-Finding -Category $c -Title "Legacy autostart value Windows\$n is set for $($r.User)" -Severity Medium -Classification Suspicious `
                    -Detail 'This old autostart location is rarely used by legitimate software today.' -Evidence $v -Tags 'Persistence'
            }
        }
        $us = Get-RegValue "$($r.Root)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'Shell'
        if ($r.Root -ne 'HKLM:' -and $us) {
            Add-Finding -Category $c -Title "Per-user Winlogon Shell override for $($r.User)" -Severity High -Classification Suspicious -Evidence $us `
                -Detail 'Replaces Explorer for that user. Used by kiosk setups and by malware.' -Tags 'Persistence'
        }
        $scr = Get-RegValue "$($r.Root)\Control Panel\Desktop" 'SCRNSAVE.EXE'
        if ($scr -and ((Expand-WinPath $scr) -notmatch '(?i)^[a-z]:\\windows\\(system32|syswow64)\\[^\\]+\.scr$')) {
            $m = Measure-CommandRisk $scr
            Add-RiskFinding -Category $c -What "Screensaver for $($r.User) points outside System32: $scr" -Command $scr -Measure $m -MinScore 0 | Out-Null
        }
    }
    if ($inventory.Count) {
        Add-Finding -Category $c -Title "$($inventory.Count) Run/RunOnce autostart entr(ies) reviewed ($flagged flagged)" -Classification $(if ($flagged) {'Info'} else {'OK'}) `
            -Evidence ($inventory | Format-Table -AutoSize -Wrap | Out-String -Width 400)
    }

    # Winlogon
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $userinit = [string](Get-RegValue $wl 'Userinit'); $shell = [string](Get-RegValue $wl 'Shell')
    if ($userinit -and $userinit.Trim().TrimEnd(',') -notmatch '^(?i)[a-z]:\\windows\\system32\\userinit\.exe$') {
        Add-Finding -Category $c -Title 'Winlogon Userinit runs extra programs at every logon' -Severity High -Classification Malicious -Evidence $userinit `
            -Detail "Default is C:\Windows\system32\userinit.exe, . Anything appended runs for every user at sign-in." -Tags 'Persistence'
    }
    if ($shell -and $shell.Trim() -notmatch '^(?i)explorer\.exe$') {
        Add-Finding -Category $c -Title "Winlogon Shell is not explorer.exe: $shell" -Severity High -Classification Suspicious -Evidence $shell `
            -Detail 'Legit for kiosk/shell-replacement setups; otherwise a classic persistence method.' -Tags 'Persistence'
    }
    foreach ($n in 'Taskman', 'AppSetup', 'GinaDLL') {
        $v = Get-RegValue $wl $n
        if ($v) { Add-Finding -Category $c -Title "Unusual Winlogon value '$n' is set" -Severity Medium -Classification Suspicious -Evidence $v -Tags 'Persistence' }
    }
    $boot = @(Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'BootExecute')
    $bootExtra = @($boot | Where-Object { $_ -and $_ -notmatch '^(?i)autocheck autochk \*$' })
    if ($bootExtra.Count) {
        Add-Finding -Category $c -Title 'Extra programs run at boot via BootExecute' -Severity Medium -Classification Ambiguous -Evidence ($bootExtra -join "`n") `
            -Detail 'Runs before Windows starts. Some disk/AV tools use it; so do rootkits.' -Tags 'Persistence'
    }

    # IFEO debugger / SilentProcessExit
    $secTools = '(?i)^(msmpeng|mpcmdrun|msseces|nissrv|securityhealthservice|taskmgr|procexp|procexp64|autoruns|regedit|mmc|cmd|powershell|sethc|utilman|osk|magnify|narrator|displayswitch|atbroker|avp|ekrn|bdagent|mbam|savservice)\.exe$'
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
            $dbg = Get-RegValue $_.PSPath 'Debugger'
            $gf = Get-RegValue $_.PSPath 'GlobalFlag'
            $exe = $_.PSChildName
            if ($dbg) {
                $legit = ($exe -eq 'taskmgr.exe' -and $dbg -match '(?i)procexp') -or $dbg -match '(?i)vsjitdebugger|windbg'
                if (-not $legit) {
                    $sev = 'High'; $cls = 'Suspicious'
                    if ($exe -match $secTools -or $dbg -match '(?i)(cmd|powershell|rundll32|\\temp\\|\\appdata\\)') { $sev = 'Critical'; $cls = 'Malicious' }
                    Add-Finding -Category $c -Title "IFEO 'Debugger' hijacks $exe" -Severity $sev -Classification $cls -Evidence "Debugger = $dbg" `
                        -Detail 'Launching this program runs the "debugger" instead. Used to block security tools or to create a sign-in screen backdoor (sethc/utilman).' -Tags 'Persistence', 'Defender-Tamper'
                }
            }
            if ($gf -and ([int]$gf -band 0x200)) {
                $mon = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$exe" 'MonitorProcess'
                if ($mon) {
                    Add-Finding -Category $c -Title "SilentProcessExit launches a program whenever $exe exits" -Severity High -Classification Malicious -Evidence "MonitorProcess = $mon" `
                        -Detail 'A stealthy persistence technique with almost no legitimate use outside debugging.' -Tags 'Persistence'
                }
            }
        }
    }

    # AppInit / AppCert DLLs
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $ai = [string](Get-RegValue $k 'AppInit_DLLs'); $load = Get-RegValue $k 'LoadAppInit_DLLs'
        if ($ai.Trim() -and $load -eq 1) {
            Add-Finding -Category $c -Title 'AppInit_DLLs injects a DLL into every GUI process' -Severity High -Classification Suspicious -Evidence $ai `
                -Detail 'Deprecated mechanism; a few old utilities use it, but it is a well-known malware injection point.' -Tags 'Persistence'
        }
    }
    $acd = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue
    if ($acd) {
        $vals = $acd.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "$($_.Name) = $($_.Value)" }
        if ($vals) { Add-Finding -Category $c -Title 'AppCertDlls loads DLLs into processes that create processes' -Severity High -Classification Suspicious -Evidence ($vals -join "`n") -Tags 'Persistence' }
    }

    # LSA packages (credential theft / persistence)
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $knownPkgs = '^(?i)(msv1_0|scecli|rassfm|kerberos|schannel|wdigest|tspkg|pku2u|cloudap|negoexts|livessp|msoidssp|""|)$'
    foreach ($n in 'Authentication Packages', 'Notification Packages', 'Security Packages') {
        $vals = @(Get-RegValue $lsa $n) + @(Get-RegValue "$lsa\OSConfig" $n)
        foreach ($pkg in ($vals | Where-Object { $_ } | Select-Object -Unique)) {
            if ($pkg -match $knownPkgs) { continue }
            $dll = Join-Path "$env:SystemRoot\System32" ($pkg -replace '\.dll$', '') ; $dll = "$dll.dll"
            $sig = Get-FileSignatureInfo $dll
            $sev = 'High'; $cls = 'Suspicious'
            if ($sig.IsMicrosoft) { $sev = 'Low'; $cls = 'Ambiguous' } elseif (-not $sig.Exists -or $sig.Status -ne 'Valid') { $cls = 'Malicious' }
            Add-Finding -Category $c -Title "Unrecognized LSA $n entry: $pkg" -Severity $sev -Classification $cls -Evidence $sig `
                -Detail 'LSA packages load into lsass.exe and can see every password typed. Password filters from enterprise products are legitimate; unknown ones are a credential-theft technique.' -Tags 'Persistence', 'Credential'
        }
    }
    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -eq 1) {
        Add-Finding -Category $c -Title 'WDigest is set to keep plaintext passwords in memory' -Severity High -Classification Malicious `
            -Detail 'UseLogonCredential=1 is off by default since Windows 8.1. Attackers turn it on so tools like Mimikatz can read plaintext passwords.' -Tags 'Credential'
    }

    # Netsh helpers, print monitors
    $nh = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NetSh' -ErrorAction SilentlyContinue
    if ($nh) {
        foreach ($p in $nh.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
            $dll = Expand-WinPath ([string]$p.Value)
            if (-not [IO.Path]::IsPathRooted($dll)) { $dll = Join-Path "$env:SystemRoot\System32" $dll }
            $sig = Get-FileSignatureInfo $dll
            if (-not $sig.IsMicrosoft) {
                Add-Finding -Category $c -Title "Non-Microsoft netsh helper DLL: $($p.Value)" -Severity High -Classification Suspicious -Evidence $sig `
                    -Detail 'Netsh helper DLLs run whenever netsh.exe runs. Rare for legitimate software (some VPN clients).' -Tags 'Persistence'
            }
        }
    }
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue | ForEach-Object {
        $d = Get-RegValue $_.PSPath 'Driver'
        if ($d) {
            $dll = if ([IO.Path]::IsPathRooted($d)) { $d } else { Join-Path "$env:SystemRoot\System32" $d }
            $sig = Get-FileSignatureInfo $dll
            if ($sig.Exists -and $sig.Status -ne 'Valid') {
                Add-Finding -Category $c -Title "Unsigned print monitor DLL: $d ($($_.PSChildName))" -Severity Medium -Classification Suspicious -Evidence $sig `
                    -Detail 'Print monitors load into the spooler as SYSTEM.' -Tags 'Persistence'
            }
        }
    }

    # Accessibility binaries (sign-in screen backdoor)
    $cmdHash = Get-Sha256 "$env:SystemRoot\System32\cmd.exe"; $psHash = Get-Sha256 "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"; $exHash = Get-Sha256 "$env:SystemRoot\explorer.exe"
    foreach ($a in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe') {
        $p = Join-Path "$env:SystemRoot\System32" $a
        $sig = Get-FileSignatureInfo $p
        if (-not $sig.Exists) { continue }
        $h = Get-Sha256 $p
        $swapped = ($h -and $h -in @($cmdHash, $psHash, $exHash)) -or $sig.OriginalFilename -match '(?i)^(cmd|powershell|explorer|taskmgr)\.exe'
        if ($swapped -or -not $sig.IsMicrosoft) {
            Add-Finding -Category $c -Title "Accessibility tool $a has been replaced" -Severity Critical -Classification Malicious -Evidence $sig `
                -Detail 'Swapping sethc/utilman/osk for cmd.exe gives a SYSTEM command prompt at the sign-in screen without a password. A classic backdoor.' `
                -Recommendation 'Isolate the machine. This is almost never legitimate.' -Tags 'Persistence'
        }
    }
}

# ===========================================================================
Invoke-Check -Name 'Scheduled tasks' -ScriptBlock {
    $c = 'Persistence'
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    $nonMs = New-Object System.Collections.Generic.List[object]
    $flagged = 0
    foreach ($t in $tasks) {
        foreach ($a in @($t.Actions)) {
            $cmd = $null
            if ($a.CimClass.CimClassName -eq 'MSFT_TaskExecAction') {
                $exe = [string]$a.Execute
                if ($exe -and $exe -notmatch '^\s*"' -and $exe -match ' ') { $exe = '"' + $exe + '"' }
                $cmd = ("$exe $($a.Arguments)").Trim()
            } elseif ($a.CimClass.CimClassName -eq 'MSFT_TaskComHandlerAction' -and $a.ClassId) {
                $dll = Get-RegValue "Registry::HKEY_CLASSES_ROOT\CLSID\$($a.ClassId)\InprocServer32" '(default)'
                if ($dll) { $cmd = $dll }
            }
            if (-not $cmd) { continue }
            $meas = Measure-CommandRisk $cmd
            $isMsPath = $t.TaskPath -like '\Microsoft\*'
            # Microsoft-folder tasks are only interesting when their binary is not Microsoft-signed (attackers hide tasks there)
            if ($isMsPath -and $meas.Sig -and $meas.Sig.IsMicrosoft -and $meas.Risk.Score -lt 3) { continue }
            $runAs = [string]$t.Principal.UserId
            if (-not $isMsPath -or ($meas.Sig -and -not $meas.Sig.IsMicrosoft)) {
                $nonMs.Add([pscustomobject]@{ Task = "$($t.TaskPath)$($t.TaskName)"; State = [string]$t.State; RunAs = $runAs; Command = $cmd; Signer = $(if ($meas.Sig) { $meas.Sig.Signer -replace ',.*$', '' } else { '' }) })
            }
            $extra = "Task: $($t.TaskPath)$($t.TaskName). Runs as: $runAs. Author: $($t.Author)."
            if ($isMsPath -and $meas.Sig -and $meas.Sig.Exists -and -not $meas.Sig.IsMicrosoft) {
                $meas.Risk.Score += 2; $extra += ' Placed in the \Microsoft\ folder but the binary is not Microsoft-signed (a disguise technique).'
                $meas.Risk.Severity = 'High'; $meas.Risk.Classification = 'Suspicious'
            }
            if ($t.Settings.Hidden -and -not $isMsPath) { $extra += ' Task is marked hidden.' }
            if (Add-RiskFinding -Category $c -What "Scheduled task '$($t.TaskName)'" -Command $cmd -Measure $meas -Extra $extra) { $flagged++ }
        }
    }
    Add-Finding -Category $c -Title "$($tasks.Count) scheduled tasks reviewed, $($nonMs.Count) non-Microsoft ($flagged flagged)" -Classification $(if ($flagged) {'Info'} else {'OK'}) `
        -Evidence ($nonMs | Format-Table -AutoSize -Wrap | Out-String -Width 400)

    # Tasks with their security descriptor removed are invisible to schtasks/Task Scheduler (Tarrask technique)
    $hiddenTasks = @()
    try {   # a task key readable only by admins makes -Recurse throw despite SilentlyContinue
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and $p.PSObject.Properties['Id'] -and -not $p.PSObject.Properties['SD']) { $hiddenTasks += ($_.Name -replace '^.*\\Tree', '') }
        }
    } catch {
        if (-not $isAdmin) { Add-Finding -Category $c -Title 'Hidden-task (missing security descriptor) check is incomplete without elevation' -Classification Info }
    }
    if ($hiddenTasks.Count) {
        Add-Finding -Category $c -Title "$($hiddenTasks.Count) scheduled task(s) have no security descriptor (hidden from Task Scheduler)" -Severity High -Classification Malicious `
            -Evidence ($hiddenTasks -join "`n") -Detail 'Deleting a task''s SD value hides it from every normal tool while it keeps running (used by the Tarrask malware). Requires SYSTEM to do.' -Tags 'Persistence'
    }
}

# ===========================================================================
Invoke-Check -Name 'Services and drivers' -ScriptBlock {
    $c = 'Persistence'
    $svcs = @(Get-CimInstance Win32_Service -ErrorAction Stop)
    $flagged = 0
    $svcList = New-Object System.Collections.Generic.List[object]
    foreach ($s in $svcs) {
        $file = ''; $sig = $null; $flags = New-Object System.Collections.Generic.List[string]
        if ($s.PathName) {
            $meas = Measure-CommandRisk $s.PathName
            $file = $meas.Exe; $sig = $meas.Sig
            $extra = "Service: $($s.Name) ($($s.DisplayName)). Start: $($s.StartMode). State: $($s.State). Account: $($s.StartName)."
            $isSvchost = $meas.Exe -match '(?i)\\svchost\.exe$'
            if ($isSvchost -and $meas.Exe -notmatch '(?i)^[a-z]:\\windows\\(system32|syswow64)\\svchost\.exe$') {
                $meas.Risk.Score += 4; $meas.Risk.Severity = 'Critical'; $meas.Risk.Classification = 'Malicious'; $extra += ' svchost.exe outside System32 is a masquerade.'
                if (Add-RiskFinding -Category $c -What "Service '$($s.Name)'" -Command $s.PathName -Measure $meas -Extra $extra) { $flagged++; $flags.Add('svchost.exe outside System32 (masquerade)') }
            } elseif ($isSvchost) {
                # Shared services run inside svchost; the file that matters is the DLL it loads
                $dll = Expand-WinPath (Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" 'ServiceDll')
                if (-not $dll) { $dll = Expand-WinPath (Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)" 'ServiceDll') }
                if ($dll) {
                    $ds = Get-FileSignatureInfo $dll
                    $file = $dll; $sig = $ds
                    if ((Test-UserWritablePath $dll) -or ($ds.Exists -and $ds.Status -ne 'Valid')) {
                        Add-Finding -Category $c -Title "svchost service '$($s.Name)' loads a suspicious DLL" -Severity High -Classification $(if (Test-UserWritablePath $dll) {'Malicious'} else {'Suspicious'}) `
                            -Evidence $ds -Detail "$extra ServiceDll = $dll" -Tags 'Persistence'
                        $flagged++; $flags.Add('Loads a suspicious DLL')
                    }
                }
            } else {
                if (Add-RiskFinding -Category $c -What "Service '$($s.Name)'" -Command $s.PathName -Measure $meas -Extra $extra) { $flagged++; $flags.Add($meas.Risk.Reasons) }
                if ($s.PathName -notmatch '^\s*"' -and $s.PathName -match '^[a-zA-Z]:\\[^"]*\s[^"]*\.exe' -and $s.StartName -match '(?i)LocalSystem') {
                    Add-Finding -Category 'Security posture' -Title "Unquoted service path with spaces: $($s.Name)" -Severity Low -Classification Info -Evidence $s.PathName `
                        -Detail 'A privilege-escalation weakness (not an infection): a file planted at the first space could run as SYSTEM.'
                    $flags.Add('Unquoted path with spaces (privilege-escalation weakness)')
                }
            }
        }
        $signer = ''
        if ($sig -and -not $sig.Exists) { $signer = 'File missing' }
        elseif ($sig -and $sig.Status -eq 'Valid') { $signer = if ($sig.Signer -match '^CN="?([^",]+)') { $Matches[1] } else { $sig.Signer } }
        elseif ($sig) { $signer = [string]$sig.Status }
        $runAs = [string]$s.StartName
        if (-not $runAs -and $s.Name -match '_[0-9a-f]{4,}$') { $runAs = '(signed-in user)' }   # per-user service instances
        $svcList.Add([pscustomobject][ordered]@{
            'Name' = $s.Name; 'Display name' = $s.DisplayName; 'Status' = $s.State; 'Start type' = $s.StartMode; 'Runs as' = $runAs
            'PID' = $(if ($s.ProcessId) { $s.ProcessId } else { '' }); 'File path' = $file; 'Signer' = $signer; 'Command line' = $s.PathName; 'Flagged' = ($flags -join '; ')
        })
    }
    Add-Finding -Category $c -Title "$($svcs.Count) services reviewed ($flagged flagged)" -Classification $(if ($flagged) {'Info'} else {'OK'}) `
        -Detail 'Every service is listed in the Services table after the findings.'
    Add-Inventory -Name 'Services' -Rows @($svcList | Sort-Object Name) -FlagColumn 'Flagged' `
        -Description 'Every Windows service: status, start type, the account it runs as and its file. For shared services that run inside svchost.exe, "File path" is the DLL actually loaded. Highlighted rows have findings above. Kernel drivers are reviewed separately.'

    # Kernel drivers
    $byovd = '(?i)^(rtcore64|rtcore32|dbutil_2_3|dbutildrv2|gdrv|asrdrv10[1-6]?|asio|asio2|asio3|iqvw64e|mhyprot2?|kprocesshacker|zam64|zamguard64|aswarpot|truesight|winring0x64|winring0|cpuz1\d\d_x64|hw64|gmer64|procexp152|ene|amifldrv64|phymemx64|atillk64|speedfan|blackbonedrv10|nicm|nscm|elbycdio|capcom|rzpnk|viragt64|wnbios|piddrv64|lha|sandra)\.sys$'
    $drivers = @(Get-CimInstance Win32_SystemDriver -Filter "State='Running'" -ErrorAction SilentlyContinue)
    $unsigned = @(); $vuln = @(); $odd = @()
    foreach ($d in $drivers) {
        $p = Expand-WinPath $d.PathName
        if (-not $p) { continue }
        $sig = Get-FileSignatureInfo $p
        $leaf = [IO.Path]::GetFileName($p)
        if ($leaf -match $byovd) { $vuln += $sig }
        if ($sig.Exists -and $sig.Status -ne 'Valid') { $unsigned += $sig }
        if ($p -notmatch '(?i)^[a-z]:\\windows\\(system32|syswow64)\\(drivers|driverstore)\\' -and $p -notmatch '(?i)^[a-z]:\\program files' -and $p -notmatch '(?i)^[a-z]:\\windows\\system32\\[^\\]+\.sys$') { $odd += $sig }
    }
    if ($unsigned.Count) {
        Add-Finding -Category $c -Title "$($unsigned.Count) running kernel driver(s) without a valid signature" -Severity High -Classification Suspicious -Evidence ($unsigned | Select-Object Path, Status, Signer, Company | Format-Table -AutoSize | Out-String -Width 300) `
            -Detail 'Windows normally refuses unsigned drivers. One running means test-signing mode, a disabled integrity check, or a rootkit.' -Tags 'Rootkit'
    }
    if ($vuln.Count) {
        Add-Finding -Category $c -Title "$($vuln.Count) known-vulnerable kernel driver(s) loaded" -Severity Medium -Classification Ambiguous -Evidence ($vuln | Select-Object Path, Signer, Company, FileVersion | Format-Table -AutoSize | Out-String -Width 300) `
            -Detail 'These signed drivers are commonly bundled with hardware/RGB/fan/overclocking tools and anti-cheat, but attackers also load them ("bring your own vulnerable driver") to kill antivirus from the kernel.' `
            -Recommendation 'If you do not recognize the tool that installed it, investigate. Turn on Microsoft''s vulnerable driver blocklist (Windows Security > Device security > Core isolation).' -Tags 'Rootkit'
    }
    $oddBad = @($odd | Where-Object { $_.Status -ne 'Valid' }); $oddOk = @($odd | Where-Object { $_.Status -eq 'Valid' })
    if ($oddBad.Count) {
        Add-Finding -Category $c -Title "$($oddBad.Count) unsigned driver(s) loaded from unusual locations" -Severity High -Classification Suspicious -Evidence ($oddBad | Select-Object Path, Status, Signer | Format-Table -AutoSize | Out-String -Width 300) -Tags 'Rootkit'
    }
    if ($oddOk.Count) {
        Add-Finding -Category $c -Title "$($oddOk.Count) signed driver(s) loaded from outside the driver folders" -Severity Low -Classification Ambiguous `
            -Detail 'Some AV, anti-cheat and hardware tools load drivers from their own folders. Check that you recognize the signer.' -Evidence ($oddOk | Select-Object Path, Signer | Format-Table -AutoSize | Out-String -Width 300) -Tags 'Rootkit'
    }
    if (-not ($unsigned.Count + $vuln.Count + $oddBad.Count)) { Add-Finding -Category $c -Title "$($drivers.Count) running drivers: all signed, none known-vulnerable" -Classification OK }
}

# ===========================================================================
Invoke-Check -Name 'WMI event subscriptions' -RequiresAdmin -ScriptBlock {
    $c = 'Persistence'
    $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop)
    $filters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue)
    $bind = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)
    $risky = @($consumers | Where-Object { $_.CimClass.CimClassName -in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer' -and $_.Name -notmatch '^(?i)(BVTConsumer)$' })
    if ($risky.Count) {
        $ev = foreach ($r in $risky) {
            $payload = if ($r.CimClass.CimClassName -eq 'CommandLineEventConsumer') { "$($r.ExecutablePath) $($r.CommandLineTemplate)" } else { "$($r.ScriptFileName) $($r.ScriptText)" }
            $payload = $payload.Trim()
            [pscustomobject]@{ Type = $r.CimClass.CimClassName; Name = $r.Name; Runs = $payload.Substring(0, [Math]::Min(500, $payload.Length)) }
        }
        Add-Finding -Category $c -Title "$($risky.Count) WMI subscription(s) that run commands or scripts" -Severity High -Classification $(if (@($ev | Where-Object { @(Get-CommandLineRisk $_.Runs).Count }).Count) {'Malicious'} else {'Suspicious'}) `
            -Detail 'WMI subscriptions run code when an event fires (boot, logon, timer) and are invisible to most startup managers. A favourite of fileless malware; a few OEM and management tools use them.' `
            -Evidence (($ev | Format-List | Out-String -Width 400) + "`nFilters:`n" + (($filters | ForEach-Object { "$($_.Name): $($_.Query)" }) -join "`n")) -Tags 'Persistence'
    } else { Add-Finding -Category $c -Title "No command/script WMI subscriptions ($($consumers.Count) consumer(s), $($bind.Count) binding(s))" -Classification OK }
}

Invoke-Check -Name 'BITS jobs' -RequiresAdmin -ScriptBlock {
    $c = 'Persistence'
    $out = (& "$env:SystemRoot\System32\bitsadmin.exe" /list /allusers /verbose 2>$null) -join "`n"
    $jobs = $out -split '(?m)^GUID: ' | Where-Object { $_ -match 'DISPLAY:' }
    $notify = @($jobs | Where-Object { $_ -match '(?im)^NOTIFICATION COMMAND LINE:\s*(?!none)(\S.*)$' })
    $remote = @($jobs | Where-Object { $_ -match '(?i)https?://\d{1,3}(\.\d{1,3}){3}' -or $_ -match '(?i)\.(exe|dll|ps1|hta|vbs|scr)\b' })
    if ($notify.Count) {
        Add-Finding -Category $c -Title "$($notify.Count) BITS job(s) run a command when they finish" -Severity High -Classification Suspicious `
            -Detail 'A BITS notify command is a persistence trick that survives reboots and runs as the job owner. Very rare legitimately.' -Evidence ($notify -join "`n---`n") -Tags 'Persistence'
    }
    if ($remote.Count) {
        Add-Finding -Category $c -Title "$($remote.Count) BITS job(s) download executables or use raw IP addresses" -Severity Medium -Classification Ambiguous -Evidence ($remote -join "`n---`n") -Tags 'Persistence'
    }
    if (-not $notify.Count -and -not $remote.Count) { Add-Finding -Category $c -Title "$(@($jobs).Count) BITS job(s), none suspicious" -Classification OK }
}

Invoke-Check -Name 'Startup folders and PowerShell profiles' -ScriptBlock {
    $c = 'Persistence'
    $shell = New-Object -ComObject WScript.Shell
    $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    foreach ($p in Get-UserProfilePaths) { $folders += Join-Path $p 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
    $items = 0
    foreach ($f in $folders | Where-Object { Test-Path $_ -ErrorAction SilentlyContinue }) {
        foreach ($file in Get-ChildItem $f -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' }) {
            $items++
            $cmd = $file.FullName
            if ($file.Extension -eq '.lnk') { try { $l = $shell.CreateShortcut($file.FullName); $cmd = ("`"$($l.TargetPath)`" $($l.Arguments)").Trim() } catch {} }
            $meas = Measure-CommandRisk $cmd
            if ($file.Extension -match '(?i)\.(vbs|js|jse|wsf|hta|bat|cmd|ps1|exe|scr)$') { $meas.Risk.Score += 1 }
            if ($meas.Risk.Score -ge 2 -and $meas.Risk.Severity -eq 'Info') { $meas.Risk.Severity = 'Low'; $meas.Risk.Classification = 'Ambiguous' }
            Add-RiskFinding -Category $c -What "Startup item '$($file.Name)'" -Command $cmd -Measure $meas -Extra "Folder: $f. Created $($file.CreationTime)." | Out-Null
        }
    }
    Add-Finding -Category $c -Title "$items startup-folder item(s) reviewed" -Classification Info

    $profiles = @("$env:SystemRoot\System32\WindowsPowerShell\v1.0\profile.ps1", "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1")
    foreach ($p in Get-UserProfilePaths) {
        foreach ($sub in 'Documents\WindowsPowerShell', 'Documents\PowerShell', 'OneDrive\Documents\WindowsPowerShell', 'OneDrive\Documents\PowerShell') {
            $profiles += Join-Path $p "$sub\profile.ps1"; $profiles += Join-Path $p "$sub\Microsoft.PowerShell_profile.ps1"
        }
    }
    foreach ($pf in $profiles | Where-Object { Test-Path $_ -ErrorAction SilentlyContinue }) {
        $txt = Get-Content -LiteralPath $pf -Raw -ErrorAction SilentlyContinue
        $r = @(Get-CommandLineRisk $txt)
        $sev = 'Info'; $cls = 'Info'
        if (($r | Measure-Object Weight -Sum).Sum -ge 3) { $sev = 'High'; $cls = 'Suspicious' } elseif ($r.Count) { $sev = 'Low'; $cls = 'Ambiguous' }
        Add-Finding -Category $c -Title "PowerShell profile exists: $pf" -Severity $sev -Classification $cls -Detail "Runs every time PowerShell starts. $(($r | ForEach-Object Reason) -join '; ')" `
            -Evidence $txt.Substring(0, [Math]::Min(1500, $txt.Length)) -Tags 'Persistence'
    }
}

# ===========================================================================
Invoke-Check -Name 'Running processes' -ScriptBlock {
    $c = 'Processes'
    $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $byPid = @{}; foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
    $expected = @{
        'svchost.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\(system32|syswow64)\\'; Parent = 'services.exe' }
        'lsass.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\system32\\'; Parent = 'wininit.exe' }
        'services.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\system32\\'; Parent = 'wininit.exe' }
        'csrss.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\system32\\' }
        'smss.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\system32\\' }
        'wininit.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\system32\\' }
        'winlogon.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\system32\\' }
        'explorer.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\' }
        'taskhostw.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\system32\\' }
        'runtimebroker.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\system32\\' }
        'spoolsv.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\system32\\' }
        'dwm.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\system32\\' }
        'conhost.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\system32\\' }
        'dllhost.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\(system32|syswow64)\\' }
        'rundll32.exe' = @{ Dir = '^(?i)[a-z]:\\windows\\(system32|syswow64)\\' }
    }
    $lookalike = '^(?i)(svch0st|scvhost|svhost|svchosts|lsas|lsasss|isass|csrs|cssrs|expl0rer|explore|winlogin|smss32|services32|taskhost32|rundl132|spoolsvc)\.exe$'
    $docApps = '^(?i)(winword|excel|powerpnt|outlook|msaccess|mspub|onenote|acrord32|acrobat|foxitreader|wordpad)\.exe$'
    $shells = '^(?i)(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild|installutil|wmic)\.exe$'
    $flagged = 0
    $lsassCount = @($procs | Where-Object { $_.Name -eq 'lsass.exe' }).Count
    if ($lsassCount -gt 1) {
        Add-Finding -Category $c -Title "$lsassCount lsass.exe processes are running" -Severity Critical -Classification Malicious -Detail 'There should be exactly one. A second is a masquerade.' -Tags 'Execution'
    }
    foreach ($p in $procs) {
        if ([int]$p.ProcessId -eq $PID) { continue }
        # Some processes report a \\?\ long-path prefix (e.g. conhost.exe started by ConPTY)
        $name = [string]$p.Name; $path = ([string]$p.ExecutablePath) -replace '^\\\\\?\\', ''; $cl = [string]$p.CommandLine
        $parent = $byPid[[int]$p.ParentProcessId]; $parentName = if ($parent) { [string]$parent.Name } else { '' }
        $reasons = @(); $score = 0
        if ($name -match $lookalike) { $score += 4; $reasons += 'Name imitates a Windows process' }
        $exp = $expected[$name.ToLowerInvariant()]
        if ($exp -and $path -and $path -notmatch $exp.Dir) { $score += 5; $reasons += "System process name running from $path" }
        if ($exp -and $exp.Parent -and $parent -and $parentName -ne $exp.Parent -and $name -ne 'svchost.exe') { $score += 2; $reasons += "Unexpected parent $parentName" }
        if ($name -eq 'svchost.exe' -and $parent -and $parentName -notin @('services.exe', 'MsMpEng.exe', 'svchost.exe')) { $score += 3; $reasons += "svchost started by $parentName (should be services.exe)" }
        if ($name -match $shells -and $parentName -match $docApps) { $score += 4; $reasons += "$parentName started $name (typical of a malicious document)" }
        foreach ($r in @(Get-CommandLineRisk $cl)) { $score += $r.Weight; $reasons += $r.Reason }
        $sig = $null
        if ($path -and ((Test-UserWritablePath $path) -or $score -gt 0)) {
            $sig = Get-FileSignatureInfo $path
            if ($sig.Exists -and $sig.Status -ne 'Valid' -and (Test-UserWritablePath $path)) { $score += 3; $reasons += 'Unsigned program running from a user-writable folder' }
            elseif ($sig.Status -eq 'HashMismatch') { $score += 4; $reasons += 'Signature hash mismatch' }
        }
        if ($path -and -not (Test-Path -LiteralPath $path)) { $score += 2; $reasons += 'Executable file no longer exists on disk' }
        if ($score -lt 3) { continue }
        $flagged++
        $sev = if ($score -ge 6) { 'High' } elseif ($score -ge 4) { 'High' } else { 'Medium' }
        $cls = if ($score -ge 6) { 'Malicious' } else { 'Suspicious' }
        $ev = [ordered]@{ PID = $p.ProcessId; Name = $name; Path = $path; CommandLine = $cl; Parent = "$parentName ($($p.ParentProcessId))"; Started = $p.CreationDate }
        if ($sig) { $ev.Signature = $sig.Status; $ev.Signer = $sig.Signer; if ($sig.Exists) { $ev.SHA256 = Get-Sha256 $path } }
        Add-Finding -Category $c -Title "Suspicious process: $name (PID $($p.ProcessId))" -Severity $sev -Classification $cls -Detail ($reasons -join '; ') -Evidence ([pscustomobject]$ev) `
            -Recommendation 'Do not kill it yet if you plan to investigate; note the PID, path and hash, then disconnect the network.' -Tags 'Execution'
    }
    if (-not $flagged) { Add-Finding -Category $c -Title "$($procs.Count) running processes reviewed, none suspicious" -Classification OK }
    if (-not $isAdmin) { Add-Finding -Category $c -Title 'Paths of other users'' and system processes are hidden when not elevated' -Classification Info }
}

# ===========================================================================
if (-not $SkipFileScan) {
Invoke-Check -Name 'Unsigned DLLs' -ScriptBlock {
    $c = 'DLLs'
    # Never individually signed, by design: Store/system app packages (covered by the package signature, in
    # folders only Windows can write) and .NET native images (generated on this PC by ngen).
    $covered = '(?i)(^[a-z]:\\Program Files\\WindowsApps\\|^[a-z]:\\Windows\\SystemApps\\|\\assembly\\NativeImages_[^\\]+\\.+\.ni\.(dll|exe)$)'
    $sensitive = '^(?i)(lsass|winlogon|services|csrss|wininit|smss|svchost|spoolsv|explorer|MsMpEng|NisSrv|SecurityHealthService|MpDefenderCoreService|taskhostw|RuntimeBroker|dllhost|msedge|chrome|firefox|brave|opera|outlook|winword|excel|powerpnt|ms-teams|teams)$'
    $exeOf = @{}; Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $exeOf[[int]$_.ProcessId] = [string]$_.ExecutablePath }

    # DLL path -> processes that have it loaded
    $users = @{}
    function Add-ModuleUse([string]$Path, [string]$Proc, [int]$ProcId) {
        $k = ($Path -replace '^\\\\\?\\', '').ToLowerInvariant()
        if (-not $users.ContainsKey($k)) { $users[$k] = New-Object System.Collections.Generic.List[object] }
        if ($users[$k].Count -lt 25) { $users[$k].Add([pscustomobject]@{ Name = $Proc; PID = $ProcId; Exe = $exeOf[$ProcId] }) }
    }
    $read = 0; $unreadable = 0; $wow = New-Object System.Collections.Generic.List[int]
    foreach ($p in Get-Process) {
        if ($p.Id -in 0, 4) { continue }
        $mods = $null; try { $mods = @($p.Modules) } catch {}
        if (-not $mods) { $unreadable++; continue }
        $read++
        # From 64-bit PowerShell a 32-bit process shows only its WOW64 layer; those are re-read by 32-bit PowerShell below
        if ([Environment]::Is64BitProcess -and @($mods | Where-Object { $_.ModuleName -eq 'wow64.dll' }).Count) { $wow.Add($p.Id); continue }
        foreach ($m in $mods) { if ($m.FileName -and $m.FileName -notmatch '(?i)\.exe$') { Add-ModuleUse $m.FileName $p.ProcessName $p.Id } }
    }
    $ps32 = "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    if ($wow.Count -and (Test-Path $ps32)) {
        $list32 = @(& $ps32 -NoProfile -NonInteractive -Command {
            param($ids)
            foreach ($i in $ids) { $p = Get-Process -Id $i -ErrorAction SilentlyContinue; if (-not $p) { continue }
                try { foreach ($m in $p.Modules) { [pscustomobject]@{ PID = $i; Name = $p.ProcessName; File = $m.FileName } } } catch {} }
        } -args (, $wow.ToArray()))
        foreach ($r in $list32) {
            if (-not $r.File -or $r.File -match '(?i)\.exe$') { continue }
            # A 32-bit process reports System32 paths that Windows serves from SysWOW64, except for the
            # folders WOW64 does not redirect (DriverStore, catroot, drivers\etc...), so use whichever exists
            $f = [string]$r.File
            $wowPath = $f -replace '(?i)^([a-z]:\\windows)\\system32\\', '$1\SysWOW64\'
            if ($wowPath -ne $f -and (Test-Path -LiteralPath $wowPath -PathType Leaf)) { $f = $wowPath }
            Add-ModuleUse $f ([string]$r.Name) ([int]$r.PID)
        }
    }

    $rows = New-Object System.Collections.Generic.List[object]
    $flagged = 0; $checked = 0
    foreach ($path in $users.Keys) {
        if ($path -match $covered) { continue }
        $checked++
        $sig = Get-FileSignatureInfo $path
        if ($sig.Status -eq 'Valid') { continue }
        $procs = $users[$path].ToArray()   # @() on a generic List throws in Windows PowerShell 5.1
        $leaf = [IO.Path]::GetFileName($path)
        $inWin = $path -match '(?i)^[a-z]:\\windows\\'
        $score = 0; $reasons = New-Object System.Collections.Generic.List[string]
        if ($sig.Status -eq 'HashMismatch') { $score += 5; $reasons.Add('Its signature no longer matches the file (changed after signing)') }
        if (-not $sig.Exists) { $score += 2; $reasons.Add('The file is no longer on disk (deleted after loading, or never written there)') }
        if (Test-UserWritablePath $path) { $score += 2; $reasons.Add('Loaded from a user-writable folder') }
        if ($inWin) { $score += 2; $reasons.Add('Unsigned file in the Windows folder, where Windows'' own DLLs are all signed') }
        if (-not $inWin -and (Test-Path -LiteralPath (Join-Path "$env:SystemRoot\System32" $leaf))) {
            $score += 2; $reasons.Add("Has the name of a Windows DLL ($leaf) but loads from another folder: the classic DLL side-loading pattern (game mods such as ReShade do the same)")
        }
        if ($sig.Company -match '(?i)microsoft') { $score += 2; $reasons.Add('Claims to be from Microsoft but is not signed') }
        $lsass = @($procs | Where-Object { $_.Name -eq 'lsass' })
        $winHost = @($procs | Where-Object { $_.Exe -match '(?i)^[a-z]:\\windows\\' -and (Get-FileSignatureInfo $_.Exe).IsMicrosoft })
        $sensHost = @($procs | Where-Object { $_.Name -match $sensitive })
        if ($lsass.Count) { $score += 3; $reasons.Add('Loaded into lsass.exe, which holds every signed-in user''s credentials') }
        elseif ($winHost.Count) { $score += 2; $reasons.Add("Loaded by Windows' own programs ($(($winHost.Name | Select-Object -Unique -First 4) -join ', '))") }
        elseif ($sensHost.Count) { $score += 1; $reasons.Add("Loaded into $(($sensHost.Name | Select-Object -Unique -First 4) -join ', ')") }

        $loadedBy = ($procs | ForEach-Object { "$($_.Name) ($($_.PID))" } | Select-Object -First 8) -join ', '
        $rows.Add([pscustomobject][ordered]@{ 'File path' = $path; 'Signature' = $sig.Status; 'Company' = $sig.Company; 'Version' = $sig.FileVersion
                                              'Modified' = $sig.Modified; 'Loaded by' = $loadedBy; 'Flagged' = $(if ($score -ge 3) { $reasons -join '; ' } else { '' }) })
        if ($score -lt 3) { continue }
        $flagged++
        $sev = if ($score -ge 7) { 'High' } elseif ($score -ge 5) { 'High' } else { 'Medium' }
        $cls = if ($score -ge 7) { 'Malicious' } else { 'Suspicious' }
        $ev = [pscustomobject][ordered]@{ Path = $path; Signature = $sig.Status; Company = $sig.Company; OriginalFilename = $sig.OriginalFilename; Version = $sig.FileVersion
                                          Created = $sig.Created; Modified = $sig.Modified; SHA256 = $(if ($sig.Exists) { Get-Sha256 $path } else { '' })
                                          LoadedBy = (($procs | ForEach-Object { "$($_.Name) (PID $($_.PID)) $($_.Exe)" }) -join "`n") }
        Add-Finding -Category $c -Title "Unsigned DLL $leaf loaded by $(($procs.Name | Select-Object -Unique -First 3) -join ', ')" -Severity $sev -Classification $cls `
            -Detail (($reasons -join '; ') + '.') -Evidence $ev `
            -Recommendation 'Look up the SHA256 on VirusTotal and find which program installed the file. Malware hides inside trusted processes this way; do not delete it until you know what it is (note the PIDs, then isolate the PC).' -Tags 'Execution', 'Persistence'
    }

    # Per-user COM objects: a DLL registered under the user's own classes loads into any program that uses
    # that object, and one that overrides a system-wide registration is the "COM hijacking" persistence trick.
    $comChecked = 0
    foreach ($h in Get-UserHives) {
        $root = "Registry::HKEY_USERS\$($h.Sid)_Classes\CLSID"
        foreach ($k in Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) {
            $dll = Expand-WinPath ([string](Get-RegValue "$root\$($k.PSChildName)\InprocServer32" '(default)'))
            if (-not $dll) { continue }
            $dll = $dll.Trim('"')
            if (-not [IO.Path]::IsPathRooted($dll)) { $dll = Join-Path "$env:SystemRoot\System32" $dll }
            $comChecked++
            $sig = Get-FileSignatureInfo $dll
            $overrides = Test-Path -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$($k.PSChildName)\InprocServer32"
            $unsigned = $sig.Exists -and $sig.Status -ne 'Valid'
            if (-not ($unsigned -or ($overrides -and $sig.Exists -and -not $sig.IsMicrosoft))) { continue }
            $sev = 'Medium'; $cls = 'Suspicious'
            if ($unsigned -and $overrides) { $sev = 'High' } elseif (-not $unsigned) { $sev = 'Low'; $cls = 'Ambiguous' }
            $flagged++
            Add-Finding -Category $c -Title "Per-user COM object $($k.PSChildName) loads $(if ($unsigned) { 'an unsigned' } else { 'a non-Microsoft' }) DLL$(if ($overrides) { ', overriding the system-wide object' }) ($($h.User))" `
                -Severity $sev -Classification $cls -Evidence $sig `
                -Detail "Any program that uses this COM object loads $dll. $(if ($overrides) { 'Registering the same ID per user takes precedence over the Windows registration, a well-known way to run code inside Explorer and other trusted programs without admin rights.' } else { 'Per-user registrations are normal for apps installed per user (OneDrive, Teams), which are signed.' })" `
                -Recommendation 'Identify the software that registered it. If unknown, export and delete the per-user CLSID key after saving this report.' -Tags 'Persistence'
        }
    }

    $note = "$read process(es) read$(if ($wow.Count) { " (including $($wow.Count) 32-bit)" })$(if ($unreadable) { "; $unreadable could not be read$(if (-not $isAdmin) { ' (run elevated to include system and other users'' processes)' })" })."
    Add-Finding -Category $c -Title "$checked loaded DLL(s) checked: $($rows.Count) unsigned, $flagged flagged; $comChecked per-user COM DLL(s) checked" -Classification $(if ($flagged) { 'Info' } else { 'OK' }) `
        -Detail "$note Unsigned DLLs inside an app's own install folder are common and listed in the Unsigned DLLs table for reference. Store-app files and .NET native images are not individually signed by design and are skipped."
    Add-Inventory -Name 'Unsigned DLLs' -Rows @($rows | Sort-Object @{ e = { [bool]$_.Flagged }; Descending = $true }, 'File path') -FlagColumn 'Flagged' `
        -Description 'Every unsigned DLL currently loaded by a running process, and which processes have it. Highlighted rows have findings above.'
}
}

# ===========================================================================
Invoke-Check -Name 'Network connections' -ScriptBlock {
    $c = 'Network'
    $procs = @{}; Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
    $conns = @(Get-NetTCPConnection -ErrorAction Stop)
    $lol = '^(?i)(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|msbuild|installutil|regasm|regsvcs|wmic)\.exe$'
    $ratPorts = @(4444, 4445, 1337, 31337, 6666, 6667, 6668, 6669, 6697, 5552, 1604, 2404, 7777, 9999, 1177, 8848)
    $sus = @(); $table = @()
    foreach ($cn in $conns) {
        if ([int]$cn.OwningProcess -eq $PID) { continue }
        $p = $procs[[int]$cn.OwningProcess]
        $pn = if ($p) { [string]$p.Name } else { '?' }; $pp = if ($p) { [string]$p.ExecutablePath } else { '' }
        $row = [pscustomobject]@{ State = [string]$cn.State; Local = "$($cn.LocalAddress):$($cn.LocalPort)"; Remote = "$($cn.RemoteAddress):$($cn.RemotePort)"; PID = $cn.OwningProcess; Process = $pn; Path = $pp }
        if ($cn.State -eq 'Established' -or $cn.State -eq 'Listen') { $table += $row }
        $reasons = @()
        if ($cn.State -eq 'Established' -and -not (Test-PrivateIP ([string]$cn.RemoteAddress))) {
            if ($pn -match $lol) { $reasons += "$pn has an outbound internet connection (scripting/LOLBin hosts rarely need one)" }
            if ($cn.RemotePort -in $ratPorts) { $reasons += "Remote port $($cn.RemotePort) is commonly used by remote-access trojans" }
            if ($pp -and (Test-UserWritablePath $pp)) { $s = Get-FileSignatureInfo $pp; if ($s.Exists -and $s.Status -ne 'Valid') { $reasons += 'Unsigned program in a user-writable folder talking to the internet' } }
        }
        if ($cn.State -eq 'Listen' -and $cn.LocalAddress -in @('0.0.0.0', '::') -and $pp -and (Test-UserWritablePath $pp)) {
            $s = Get-FileSignatureInfo $pp
            if ($s.Exists -and $s.Status -ne 'Valid') { $reasons += "Unsigned program from a user-writable folder listening on all interfaces (port $($cn.LocalPort))" }
        }
        if ($reasons.Count) { $sus += [pscustomobject]@{ Connection = $row; Reasons = ($reasons -join '; ') } }
    }
    if ($sus.Count) {
        Add-Finding -Category $c -Title "$($sus.Count) suspicious network connection(s)" -Severity High -Classification Suspicious `
            -Evidence (($sus | ForEach-Object { "$($_.Reasons)`n  $($_.Connection.Process) (PID $($_.Connection.PID)) $($_.Connection.Local) -> $($_.Connection.Remote)  [$($_.Connection.Path)]" }) -join "`n") `
            -Detail 'Connections a backdoor or command-and-control channel would produce.' -Recommendation 'Look up the remote IPs (e.g. AbuseIPDB, VirusTotal). Disconnect the PC if they are unknown.' -Tags 'Network', 'C2'
    } else { Add-Finding -Category $c -Title "$(@($table | Where-Object State -eq 'Established').Count) established connections, none suspicious" -Classification OK }
    Add-Finding -Category $c -Title 'Connection and listener inventory' -Classification Info -Evidence ($table | Sort-Object State, Process | Format-Table -AutoSize | Out-String -Width 300)

    $pp = (& "$env:SystemRoot\System32\netsh.exe" interface portproxy show all 2>$null) -join "`n"
    if ($pp -match '\d+\.\d+\.\d+\.\d+|\*') {
        Add-Finding -Category $c -Title 'Port forwarding (netsh portproxy) rules are configured' -Severity High -Classification Suspicious -Evidence $pp `
            -Detail 'Portproxy turns this PC into a relay, used by attackers to tunnel into other machines or hide RDP. Some WSL/dev setups use it.' -Tags 'Network', 'C2'
    }
}

# ===========================================================================
# Name resolution: hosts files and DNS
# ===========================================================================
$localName = '^(?i)([^.]+|.+\.(local|lan|home|internal|intranet|corp|localdomain|localhost|test|example|invalid|home\.arpa|wsl|mshome\.net))$'
$securityDomains = '(?i)(^|\.)(virustotal\.com|malwarebytes\.(com|org)|kaspersky(-labs)?\.com|kaspersky\.[a-z.]+|eset\.(com|[a-z.]+)|bitdefender\.(com|net)|sophos\.com|avast\.com|avg\.com|norton\.com|symantec\.com|nortonlifelock\.com|gendigital\.com|mcafee\.com|trendmicro\.com|crowdstrike\.com|sentinelone\.(com|net)|f-secure\.com|withsecure\.com|webroot\.com|emsisoft\.com|hitmanpro\.com|drweb\.(com|ru)|avira\.com|pandasecurity\.com|zemana\.com|superantispyware\.com|hybrid-analysis\.com|any\.run|joesandbox\.com|abuse\.ch|wdcp\.microsoft\.com|wdcpalt\.microsoft\.com|definitionupdates\.microsoft\.com|smartscreen(-prod)?\.microsoft\.com|windowsupdate\.(com|microsoft\.com)|update\.microsoft\.com|download\.microsoft\.com|wd\.microsoft\.com|security\.microsoft\.com)$'
$sensitiveDomains = '(?i)(^|\.)(paypal\.com|stripe\.com|chase\.com|wellsfargo\.com|bankofamerica\.com|citi(bank)?\.com|capitalone\.com|usbank\.com|hsbc\.[a-z.]+|barclays\.[a-z.]+|santander\.[a-z.]+|rbc(royalbank)?\.com|td(bank|canadatrust)?\.com|scotiabank\.com|bmo\.com|cibc\.com|desjardins\.com|americanexpress\.com|visa\.com|mastercard\.com|interac\.ca|coinbase\.com|binance\.(com|us)|kraken\.com|crypto\.com|blockchain\.com|metamask\.io|ledger\.com|microsoft\.com|microsoftonline\.com|live\.com|outlook\.com|office\.com|office365\.com|google\.com|gmail\.com|youtube\.com|googleapis\.com|facebook\.com|instagram\.com|whatsapp\.(com|net)|twitter\.com|x\.com|apple\.com|icloud\.com|amazon\.[a-z.]+|ebay\.[a-z.]+|netflix\.com|steampowered\.com|steamcommunity\.com|discord\.com|telegram\.org|github\.com|dropbox\.com|yahoo\.com|bing\.com|linkedin\.com|roblox\.com|epicgames\.com)$'
$hostsNames = @{}   # names the hosts files define; the DNS check skips these because the hosts check already judged them

function Get-IpKind([string]$ip) {
    $a = $null
    if (-not [Net.IPAddress]::TryParse($ip, [ref]$a)) { return 'Invalid' }
    if ($ip -match '^(0\.0\.0\.0|127\.|::1?$|0:0:0:0:0:0:0:[01]$)') { return 'Block' }
    if (Test-PrivateIP $ip) { return 'Private' }
    return 'Public'
}

function Read-HostsEntries([string]$Path) {
    <# One object per hostname. Flags entries pushed off-screen by blank lines or long runs of
       spaces, a trick malware uses so the line is not seen when someone opens the file. #>
    $n = 0; $blank = 0
    foreach ($line in ([IO.File]::ReadAllText($Path) -split "`r?`n")) {
        $n++
        if ($line -match '^\s*$') { $blank++; continue }
        $padded = $blank -ge 40 -or $line -match '^[ \t]{80,}'
        $blank = 0
        $body = ($line -replace '#.*$', '').Trim()
        if (-not $body) { continue }
        $parts = @($body -split '\s+')
        if ($parts.Count -lt 2) { [pscustomobject]@{ Line = $n; IP = $parts[0]; Host = ''; Kind = 'Invalid'; Padded = $padded; NonAscii = $false }; continue }
        $kind = Get-IpKind $parts[0]
        foreach ($h in $parts[1..($parts.Count - 1)]) {
            [pscustomobject]@{ Line = $n; IP = $parts[0]; Host = $h.ToLowerInvariant().TrimEnd('.'); Kind = $kind; Padded = $padded; NonAscii = ($h -match '[^\x21-\x7E]') }
        }
    }
}

function Get-RegistrableDomain([string]$Name) {
    $labels = $Name.TrimEnd('.').ToLowerInvariant().Split('.')
    if ($labels.Count -lt 2) { return $Name }
    $n = 2
    if ($labels.Count -ge 3 -and $labels[-2] -match '^(co|com|net|org|gov|edu|ac|or|ne|go)$' -and $labels[-1].Length -eq 2) { $n = 3 }
    return ($labels[(-$n)..(-1)] -join '.')
}

function Get-Entropy([string]$s) {
    if (-not $s) { return 0 }
    $h = 0.0
    foreach ($g in ($s.ToCharArray() | Group-Object)) { $p = $g.Count / $s.Length; $h -= $p * [Math]::Log($p, 2) }
    return $h
}

function Format-HostsEntries($List) {
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($e in $List) { if ($out.Count -ge 60) { break }; $out.Add(('{0,-10} line {1,-6} {2,-40} {3}' -f $e.File, $e.Line, $e.IP, $e.Host)) }
    return ($out -join "`n")
}

Invoke-Check -Name 'Hosts file and other name-resolution files' -ScriptBlock {
    $c = 'Hosts file'
    $dbPath = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DataBasePath'
    $etc = Expand-WinPath $(if ($dbPath) { $dbPath } else { '%SystemRoot%\System32\drivers\etc' })
    if ($dbPath -and (Expand-WinPath $dbPath) -notmatch '(?i)\\system32\\drivers\\etc\\?$') {
        Add-Finding -Category $c -Title 'Windows reads its hosts file from a non-standard folder' -Severity Critical -Classification Malicious -Evidence "DataBasePath = $dbPath" `
            -Detail 'Malware moves the hosts file so anyone checking the usual one sees nothing. The redirected file is the one reviewed below.' -Tags 'Network', 'DNS'
    }
    $entries = New-Object System.Collections.Generic.List[object]
    $hostsInfo = ''
    foreach ($fn in 'hosts', 'hosts.ics') {    # hosts.ics is written by Internet Connection Sharing / Mobile hotspot
        $p = Join-Path $etc $fn
        if (-not (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) {
            if ($fn -eq 'hosts') { Add-Finding -Category $c -Title "No hosts file at $p" -Classification Info }
            continue
        }
        try { foreach ($e in Read-HostsEntries $p) { $e | Add-Member -NotePropertyName File -NotePropertyValue $fn; $entries.Add($e) } }
        catch { Add-Finding -Category $c -Title "Could not read $p" -Severity Low -Classification Ambiguous -Detail $_.Exception.Message -Tags 'DNS'; continue }
        if ($fn -ne 'hosts') { continue }

        $fi = Get-Item -LiteralPath $p -Force
        $hostsInfo = "Last modified $($fi.LastWriteTime)$(if ($fi.LastWriteTime -gt $since) { " (within the last $Days days)" }); $($fi.Length) bytes."
        $attr = @('ReadOnly', 'Hidden', 'System' | Where-Object { $fi.Attributes -band [IO.FileAttributes]$_ })
        if ($attr.Count) {
            Add-Finding -Category $c -Title "The hosts file is marked $($attr -join ', ')" -Severity Low -Classification Ambiguous -Evidence $hostsInfo `
                -Detail 'Malware sets these so its entries survive cleanup tools and stay out of sight; some ad-blocking tools set read-only too.' -Tags 'DNS'
        }
        try {
            $writeMask = [int64]([Security.AccessControl.FileSystemRights]'WriteData, AppendData, ChangePermissions, TakeOwnership') -bor 0x50000000   # + GENERIC_WRITE/GENERIC_ALL
            $trusted = 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'   # SYSTEM, Administrators, TrustedInstaller
            $broad = @(); $deny = @()
            foreach ($a in (Get-Acl -LiteralPath $p).Access) {
                $sid = [string]$a.IdentityReference; try { $sid = $a.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch {}
                if ($a.AccessControlType -eq 'Deny') { $deny += "$($a.IdentityReference): $($a.FileSystemRights)" }
                elseif (([int64]$a.FileSystemRights -band $writeMask) -and $sid -notin $trusted) { $broad += "$($a.IdentityReference): $($a.FileSystemRights)" }
            }
            if ($broad.Count) {
                Add-Finding -Category $c -Title 'Non-administrators can modify the hosts file' -Severity Medium -Classification Suspicious -Evidence ($broad -join "`n") `
                    -Detail 'Any program running as these accounts can redirect websites without admin rights. By default only SYSTEM and Administrators can write it.' -Tags 'DNS'
            }
            if ($deny.Count) {
                Add-Finding -Category $c -Title 'The hosts file has DENY permissions' -Severity Medium -Classification Suspicious -Evidence ($deny -join "`n") `
                    -Detail 'Deny entries stop security tools (and Windows) from repairing the file.' -Tags 'DNS'
            }
        } catch {}
    }
    foreach ($e in $entries) { if ($e.Host) { $hostsNames[$e.Host] = $e.IP } }

    $active   = @($entries | Where-Object { $_.Host -and $_.Host -notmatch $localName })
    $pharm    = @($active | Where-Object { $_.Kind -in 'Public', 'Private' -and $_.Host -match $sensitiveDomains })
    $secBlock = @($active | Where-Object { $_.Kind -eq 'Block' -and $_.Host -match $securityDomains })
    $redirect = @($active | Where-Object { $_.Kind -eq 'Public' -and $_.Host -notmatch $sensitiveDomains })
    $lanMap   = @($active | Where-Object { $_.Kind -eq 'Private' -and $_.Host -notmatch $sensitiveDomains })
    $blocks   = @($active | Where-Object { $_.Kind -eq 'Block' -and $_.Host -notmatch $securityDomains })
    $hidden   = @($entries | Where-Object { $_.Padded -and $_.Host -notmatch $localName })
    $odd      = @($entries | Where-Object { $_.NonAscii -or $_.Kind -eq 'Invalid' })
    $wpad     = @($entries | Where-Object { $_.Host -match '^wpad(\.|$)' -and $_.Kind -ne 'Block' })

    if ($pharm.Count) {
        Add-Finding -Category $c -Title "Hosts file sends $($pharm.Count) bank, email or major site name(s) to a different server" -Severity High -Classification $(if ($mgmt.IsManaged) { 'Suspicious' } else { 'Malicious' }) `
            -Detail 'This is "pharming": the browser shows the real address but talks to another server, which can phish passwords or serve malware. Legitimate only for a developer testing their own site.' `
            -Evidence (Format-HostsEntries $pharm) -Recommendation 'Do not sign in to these sites from this PC. Remove the lines (edit the file as Administrator), run ipconfig /flushdns, then change those passwords from another device.' -Tags 'Network', 'DNS'
    }
    if ($secBlock.Count) {
        Add-Finding -Category $c -Title "Hosts file blocks $($secBlock.Count) security or update site(s)" -Severity $(if ($mgmt.IsManaged) { 'Medium' } else { 'High' }) -Classification Suspicious `
            -Detail 'Malware blocks antivirus updates and scanning sites (VirusTotal, Malwarebytes, AV vendors) so it cannot be detected or removed. Privacy and ad-block lists rarely include these.' `
            -Evidence (Format-HostsEntries $secBlock) -Tags 'Network', 'DNS', 'Defender-Tamper'
    }
    if ($redirect.Count) {
        Add-Finding -Category $c -Title "Hosts file redirects $($redirect.Count) public name(s) to other internet servers" -Severity Medium -Classification Suspicious `
            -Detail 'Legitimate for testing a website before a DNS change, game or emulator servers, or getting around a block. Otherwise it is a hijack; look up who owns each address.' `
            -Evidence (Format-HostsEntries $redirect) -Tags 'Network', 'DNS'
    }
    if ($lanMap.Count) {
        Add-Finding -Category $c -Title "Hosts file maps $($lanMap.Count) public name(s) to local-network addresses" -Severity Low -Classification Ambiguous `
            -Detail 'Usual for home labs, NAS/Plex and development. Also used to send traffic through a rogue proxy on the local network.' -Evidence (Format-HostsEntries $lanMap) -Tags 'DNS'
    }
    if ($wpad.Count) {
        Add-Finding -Category $c -Title 'Hosts file defines a WPAD host' -Severity Medium -Classification Suspicious -Evidence (Format-HostsEntries $wpad) `
            -Detail 'WPAD hands this PC an automatic proxy configuration from that address, a classic way to intercept all web traffic.' -Tags 'Network', 'DNS'
    }
    if ($hidden.Count) {
        Add-Finding -Category $c -Title "$($hidden.Count) hosts entr(ies) are hidden by blank-line or space padding" -Severity Medium -Classification Suspicious -Evidence (Format-HostsEntries $hidden) `
            -Detail 'Entries placed after dozens of blank lines or a long run of spaces are off-screen when the file is opened in Notepad. Malware does this so its lines are not noticed.' -Tags 'DNS'
    }
    if ($odd.Count) {
        Add-Finding -Category $c -Title "$($odd.Count) hosts entr(ies) are malformed or use non-ASCII look-alike characters" -Severity Medium -Classification Suspicious -Evidence (Format-HostsEntries $odd) `
            -Detail 'Look-alike (homoglyph) characters make a line appear to cover a different site than it does; malformed lines can hide data.' -Tags 'DNS'
    }
    if ($blocks.Count -ge 200) {
        Add-Finding -Category $c -Title "Hosts file is an ad/tracker blocklist ($($blocks.Count) blocked names)" -Classification Info -Detail "Typical of ad-blocking or privacy lists. $hostsInfo" -Evidence (Format-HostsEntries $blocks)
    } elseif ($blocks.Count) {
        Add-Finding -Category $c -Title "Hosts file blocks $($blocks.Count) name(s)" -Classification Info -Detail "Usually ads, telemetry or a nuisance site. Make sure you recognize them. $hostsInfo" -Evidence (Format-HostsEntries $blocks)
    }
    if (-not $active.Count -and -not $hidden.Count -and -not $odd.Count) {
        Add-Finding -Category $c -Title 'Hosts files contain only local names' -Classification OK -Detail $hostsInfo -Evidence (Format-HostsEntries $entries)
    }

    # lmhosts: legacy NetBIOS name mappings; #INCLUDE can pull them from a network share
    $lm = Join-Path $etc 'lmhosts'
    if (Test-Path -LiteralPath $lm -ErrorAction SilentlyContinue) {
        $lines = @(Get-Content -LiteralPath $lm -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[^#\s]' -or $_ -match '^\s*#INCLUDE' })
        $inc = @($lines | Where-Object { $_ -match '(?i)#INCLUDE\s+\\\\' })
        if ($inc.Count) {
            Add-Finding -Category $c -Title 'lmhosts loads name mappings from a network share (#INCLUDE)' -Severity Medium -Classification Suspicious -Evidence ($inc -join "`n") `
                -Detail 'Whoever controls that share controls what these names resolve to.' -Tags 'DNS'
        } elseif ($lines.Count) {
            Add-Finding -Category $c -Title "lmhosts defines $($lines.Count) NetBIOS name mapping(s)" -Severity Low -Classification Ambiguous -Evidence ($lines -join "`n") `
                -Detail 'A legacy name file that is rarely needed today. Check that each mapping is expected.' -Tags 'DNS'
        }
    }
}

Invoke-Check -Name 'DNS servers, encrypted DNS, NRPT and cache' -ScriptBlock {
    $c = 'DNS'
    $resolvers = [ordered]@{
        '8.8.8.8' = 'Google'; '8.8.4.4' = 'Google'; '2001:4860:4860:' = 'Google'; '1.1.1.1' = 'Cloudflare'; '1.0.0.1' = 'Cloudflare'; '1.1.1.2' = 'Cloudflare'; '1.0.0.2' = 'Cloudflare'
        '1.1.1.3' = 'Cloudflare'; '1.0.0.3' = 'Cloudflare'; '2606:4700:4700:' = 'Cloudflare'; '9.9.9.' = 'Quad9'; '149.112.112.' = 'Quad9'; '2620:fe:' = 'Quad9'
        '208.67.222.' = 'OpenDNS'; '208.67.220.' = 'OpenDNS'; '2620:119:' = 'OpenDNS'; '94.140.14.' = 'AdGuard'; '94.140.15.' = 'AdGuard'; '2a10:50c0:' = 'AdGuard'
        '45.90.28.' = 'NextDNS'; '45.90.30.' = 'NextDNS'; '2a07:a8c0:' = 'NextDNS'; '2a07:a8c1:' = 'NextDNS'; '185.228.168.' = 'CleanBrowsing'; '185.228.169.' = 'CleanBrowsing'
        '76.76.2.' = 'Control D'; '76.76.10.' = 'Control D'; '76.76.19.19' = 'Alternate DNS'; '8.26.56.26' = 'Comodo'; '8.20.247.20' = 'Comodo'; '4.2.2.' = 'Lumen/Level3'
        '64.6.64.6' = 'Verisign'; '64.6.65.6' = 'Verisign'; '84.200.69.80' = 'DNS.Watch'; '84.200.70.40' = 'DNS.Watch'; '194.242.2.' = 'Mullvad'; '77.88.8.' = 'Yandex'
        '156.154.70.' = 'UltraDNS'; '156.154.71.' = 'UltraDNS'; '216.146.35.35' = 'Oracle Dyn'; '216.146.36.36' = 'Oracle Dyn'
    }
    function Get-ResolverName([string]$ip) {
        foreach ($k in $resolvers.Keys) { if ($ip -eq $k -or (($k.EndsWith('.') -or $k.EndsWith(':')) -and $ip.StartsWith($k))) { return $resolvers[$k] } }
        return $null
    }
    $vpnPattern = '(?i)(vpn|wireguard|nordlynx|tap-|tun|proton|mullvad|express|openvpn|zerotier|tailscale|cisco|anyconnect|forti|globalprotect|warp)'

    # Configured servers. Static ones (typed in, or set by a program) are in the registry; the rest came from DHCP.
    $static = @{}
    foreach ($base in 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces', 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces') {
        foreach ($k in Get-ChildItem $base -ErrorAction SilentlyContinue) { foreach ($s in ([string](Get-RegValue $k.PSPath 'NameServer') -split '[,\s]+' | Where-Object { $_ })) { $static[$s] = $true } }
    }
    $globalNs = [string](Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'NameServer')
    if ($globalNs) {
        $unknownGlobal = @($globalNs -split '[,\s]+' | Where-Object { $_ -and -not (Get-ResolverName $_) -and -not (Test-PrivateIP $_) })
        Add-Finding -Category $c -Title "A system-wide DNS server override is set: $globalNs" -Severity $(if ($unknownGlobal.Count) { 'Medium' } else { 'Low' }) -Classification $(if ($unknownGlobal.Count) { 'Suspicious' } else { 'Ambiguous' }) `
            -Detail 'Tcpip\Parameters\NameServer forces DNS servers for every adapter and does not appear in adapter settings. DNSChanger-type malware uses it.' -Evidence "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NameServer = $globalNs" -Tags 'Network', 'DNS'
    }
    $rows = @(foreach ($s in Get-DnsClientServerAddress -ErrorAction Stop | Where-Object { $_.ServerAddresses }) {
        foreach ($ip in $s.ServerAddresses) {
            $kind = if ($ip -match '^fec0:0:0:ffff::[123]$') { 'Windows default placeholder' } elseif (Test-PrivateIP $ip) { 'Local network (router/VPN/local resolver)' } else { $n = Get-ResolverName $ip; if ($n) { "Public: $n" } else { 'Public: UNKNOWN' } }
            [pscustomobject]@{ Interface = $s.InterfaceAlias; Server = $ip; Kind = $kind; Static = [bool]$static[$ip] }
        }
    })
    foreach ($g in $rows | Where-Object { $_.Kind -eq 'Public: UNKNOWN' } | Group-Object Server) {
        $ptr = ''
        if (-not $SkipNetwork) { try { $ptr = [string](Resolve-DnsName -Name $g.Name -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1 -ExpandProperty NameHost) } catch {} }
        $isStatic = @($g.Group | Where-Object { $_.Static }).Count -gt 0
        $isVpn = @($g.Group | Where-Object { $_.Interface -match $vpnPattern }).Count -gt 0
        $sev = 'Low'; $cls = 'Ambiguous'
        if ($isStatic -and -not $isVpn -and -not $mgmt.IsManaged) { $sev = 'Medium'; $cls = 'Suspicious' }
        Add-Finding -Category $c -Title "Unrecognized public DNS server $($g.Name)$(if ($ptr) { " ($ptr)" }) on $(($g.Group.Interface | Select-Object -Unique) -join ', ')" -Severity $sev -Classification $cls `
            -Detail "$(if ($isVpn) { 'Set by a VPN adapter. ' } elseif ($isStatic) { 'Typed in on the adapter (or set by a program), not assigned by the network. ' } else { 'Assigned automatically (DHCP), which usually means your ISP''s resolver. ' })Whoever runs the DNS server decides where every website name leads. DNSChanger-type malware and hijacked routers point PCs at resolvers that send banking or update sites elsewhere; the resolution tests in this section check whether answers are being falsified." `
            -Evidence ($g.Group | Format-Table -AutoSize | Out-String) -Recommendation 'If you do not recognize it, set the adapter back to automatic DNS or a provider you chose, and check the DNS settings in your router.' -Tags 'Network', 'DNS'
    }

    # Encrypted DNS (DoH) templates: queries to these server addresses are sent over HTTPS to the URL
    $knownDoh = '(?i)^https://(dns\.google|([a-z0-9-]+\.)?cloudflare-dns\.com|dns\d*\.quad9\.net|([a-z0-9-]+\.)?dns\.nextdns\.io|dns\.nextdns\.io|([a-z0-9-]+\.)*adguard-dns\.com|dns\.adguard\.com|doh(\.familyshield)?\.opendns\.com|doh\.cleanbrowsing\.org|([a-z0-9-]+\.)*controld\.com|([a-z0-9-]+\.)*mullvad\.net|dns\.alidns\.com)/'
    $doh = @(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
    foreach ($d in $doh | Where-Object { $_.DohTemplate -and $_.DohTemplate -notmatch $knownDoh }) {
        Add-Finding -Category $c -Title "Encrypted DNS for $($d.ServerAddress) goes to an unrecognized server: $($d.DohTemplate)" -Severity $(if ($mgmt.IsManaged) { 'Low' } else { 'Medium' }) -Classification $(if ($mgmt.IsManaged) { 'Ambiguous' } else { 'Suspicious' }) `
            -Detail 'Lookups sent this way are hidden from network filters and monitoring. Fine for a provider you chose; otherwise it hijacks every lookup invisibly.' -Tags 'Network', 'DNS'
    }
    $dohPolicy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'DoHPolicy'

    # Name Resolution Policy Table: per-domain DNS rules. Pointing security vendors' domains at a dead
    # server is a known way to cut endpoint protection off from its cloud without touching the agent.
    $nrpt = @(foreach ($base in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig', 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig') {
        foreach ($k in Get-ChildItem $base -ErrorAction SilentlyContinue) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            [pscustomobject]@{ Store = $(if ($base -like '*Policies*') { 'Group Policy' } else { 'Local' }); Rule = $k.PSChildName; Namespace = @($p.Name) -join ', '; Servers = [string]$p.GenericDNSServers; Options = $p.ConfigOptions }
        }
    })
    foreach ($r in $nrpt) {
        $nsList = @($r.Namespace -split ',\s*' | Where-Object { $_ } | ForEach-Object { $_.TrimStart('.') })
        $sec = @($nsList | Where-Object { $_ -match $securityDomains -or $_ -match '(?i)(^|\.)(microsoft\.com|windows\.com)$' })
        $all = $nsList -contains '' -or $r.Namespace -match '^\.?$'
        if ($sec.Count) {
            Add-Finding -Category $c -Title "NRPT rule redirects DNS for security/Microsoft domains ($($sec -join ', '))" -Severity High -Classification $(if ($mgmt.IsManaged) { 'Suspicious' } else { 'Malicious' }) `
                -Detail 'Rules like this can sink lookups for antivirus/EDR cloud services so protection silently stops reporting and updating, without stopping any service. DirectAccess and some VPNs add NRPT rules for corporate names, not for security vendors.' `
                -Evidence ($r | Format-List | Out-String) -Recommendation 'Remove the rule (Remove-DnsClientNrptRule, or the registry key) after saving this report, and check the antivirus is reporting again.' -Tags 'Network', 'DNS', 'Defender-Tamper'
        } elseif (-not $mgmt.IsManaged) {
            Add-Finding -Category $c -Title "NRPT rule for $(if ($all) { 'ALL names' } else { $r.Namespace })" -Severity $(if ($all) { 'Medium' } else { 'Low' }) -Classification $(if ($all) { 'Suspicious' } else { 'Ambiguous' }) `
                -Detail 'Per-domain DNS routing. VPN clients and DirectAccess add these; on an unmanaged PC check which software created it.' -Evidence ($r | Format-List | Out-String) -Tags 'DNS'
        }
    }

    Add-Finding -Category $c -Title "DNS servers in use: $((@($rows | Where-Object { $_.Kind -notlike 'Windows default*' }).Server | Select-Object -Unique) -join ', ')" -Classification Info `
        -Detail "Encrypted DNS policy: $(switch ($dohPolicy) { 2 { 'allowed' } 3 { 'required' } 1 { 'prohibited' } default { 'Windows default' } }). $($doh.Count) DoH template(s), $($nrpt.Count) NRPT rule(s)." `
        -Evidence ($rows | Format-Table -AutoSize | Out-String -Width 300)

    # ---- Cache and query log ----
    $answers = @{}
    try {
        foreach ($e in Get-DnsClientCache -ErrorAction Stop) {
            $n = ([string]$e.Entry).ToLowerInvariant().TrimEnd('.')
            if (-not $n) { continue }
            if (-not $answers.ContainsKey($n)) { $answers[$n] = New-Object System.Collections.Generic.List[string] }
            if ($e.Type -in 1, 28 -and $e.Data) { $answers[$n].Add([string]$e.Data) }
        }
    } catch {}
    $logged = @{}
    $dnsLog = Get-WinEvent -ListLog 'Microsoft-Windows-DNS-Client/Operational' -ErrorAction SilentlyContinue
    $logOn = [bool]($dnsLog -and $dnsLog.IsEnabled)
    if ($logOn) {
        foreach ($ev in Get-RecentEvents @{ LogName = 'Microsoft-Windows-DNS-Client/Operational'; Id = 3008; StartTime = $since } 20000) {
            $q = ([string](Get-EventDataMap $ev).QueryName).ToLowerInvariant().TrimEnd('.')
            if ($q) { $logged[$q] = $true }
        }
    }
    $names = @(@($answers.Keys) + @($logged.Keys) | Select-Object -Unique)
    $src = "$($answers.Count) cached name(s)$(if ($logOn) { " + $($logged.Count) from the DNS query log" } else { '; DNS query log is off' })"

    $infra = @(
        @{ S = 'High';   C = 'Suspicious'; R = 'cryptocurrency mining pools'; D = 'Mining malware connects to these pools; legitimate only if someone mines on this PC on purpose.'
           P = '(?i)(^|\.)(nanopool\.org|minexmr\.com|supportxmr\.com|hashvault\.pro|moneroocean\.stream|2miners\.com|f2pool\.com|nicehash\.com|unmineable\.com|herominers\.com|c3pool\.(com|org)|ethermine\.org|kryptex\.network|xmrpool\.eu|monerohash\.com|minergate\.com)$|(^|\.)(xmr|monero)[a-z0-9-]*\.' }
        @{ S = 'High';   C = 'Suspicious'; R = 'Tor web gateways'; D = 'Tor2web gateways reach hidden services from a normal browser; ransomware notes and some malware use them.'
           P = '(?i)(\.onion$|(^|\.)(onion\.(ws|ly|pet|to|link|city|cab|direct)|tor2web\.\w+))' }
        @{ S = 'Medium'; C = 'Suspicious'; R = 'tunnel / reverse-proxy services'; D = 'These expose a PC to the internet or hide a server behind a throwaway name. Developers use them; so do remote-access trojans and phishing kits.'
           P = '(?i)(^|\.)(ngrok(-free)?\.(io|app|dev)|ngrok\.com|trycloudflare\.com|loca\.lt|localtunnel\.me|serveo\.net|pagekite\.me|portmap\.(io|host)|playit\.gg|bore\.pub|localhost\.run|lhr\.life|pinggy\.(io|link)|tunnelto\.dev|localxpose\.io|loclx\.io)$' }
        @{ S = 'Medium'; C = 'Suspicious'; R = 'dynamic-DNS host names'; D = 'Free dynamic-DNS names are the favourite command-and-control addresses of remote-access trojans (AsyncRAT, njRAT, Remcos). Home users also use them for cameras, NAS boxes and game servers.'
           P = '(?i)(^|\.)(duckdns\.org|no-ip\.(com|org|biz|info)|noip\.com|ddns\.net|hopto\.org|zapto\.org|sytes\.net|serveftp\.com|servegame\.com|myftp\.(biz|org)|dynu\.(com|net)|afraid\.org|changeip\.com|3utilities\.com|bounceme\.net|redirectme\.net|publicvm\.com|linkpc\.net|kozow\.com|mooo\.com|dyndns\.(org|info)|dynv6\.net|myddns\.me|ddnsking\.com|freeddns\.org|giize\.com|gleeze\.com|camdvr\.org|ooguy\.com|accesscam\.org)$' }
        @{ S = 'Medium'; C = 'Suspicious'; R = 'data-collection / callback endpoints'; D = 'Bot APIs and request-capture sites are used to send stolen data out, and by penetration-testing tools to confirm a compromise.'
           P = '(?i)(^|\.)(api\.telegram\.org|webhook\.site|requestbin\.(com|net)|pipedream\.net|interact\.sh|oast\.(pro|live|site|online|fun|me)|burpcollaborator\.net|oastify\.com)$' }
        @{ S = 'Low';    C = 'Ambiguous';  R = 'paste and anonymous file-drop sites'; D = 'Malware commonly downloads its next stage from these. People also use them normally.'
           P = '(?i)(^|\.)(pastebin\.com|paste\.ee|pastes\.io|hastebin\.com|ghostbin\.\w+|rentry\.(co|org)|controlc\.com|justpaste\.it|transfer\.sh|temp\.sh|file\.io|anonfiles\.com|gofile\.io|catbox\.moe|0x0\.st|bashupload\.com|filebin\.net|tmpfiles\.org|ufile\.io|bayfiles\.com)$' }
        @{ S = 'Low';    C = 'Ambiguous';  R = 'public-IP lookup services'; D = 'Info-stealers look up the victim''s public IP and location first. Many normal apps (VPNs, games, speed tests) use them too.'
           P = '(?i)(^|\.)(ipinfo\.io|ip-api\.com|ipify\.org|api\.ipify\.org|icanhazip\.com|ifconfig\.me|checkip\.amazonaws\.com|myexternalip\.com|wtfismyip\.com|ipapi\.co|ipwho\.is|geoplugin\.net)$' }
    )
    foreach ($cat in $infra) {
        $hit = @($names | Where-Object { $_ -match $cat.P } | Sort-Object)
        if (-not $hit.Count) { continue }
        Add-Finding -Category $c -Title "Recent DNS lookups of $($cat.R) ($($hit.Count) name(s))" -Severity $cat.S -Classification $cat.C -Detail $cat.D -Evidence ($hit -join "`n") `
            -Recommendation 'Find the program responsible (Network connections findings, or netstat -anob while it happens). Unknown programs talking to these are worth isolating.' -Tags 'Network', 'DNS', 'C2'
    }

    $privateOk = '(?i)(^|\.)(plex\.direct|nip\.io|sslip\.io|xip\.io|localtest\.me|lvh\.me|routerlogin\.(net|com)|tplinkwifi\.net|tplinklogin\.net|myfritz\.net|fritz\.box|asusrouter\.com|mynetworksettings\.com|in-addr\.arpa|ip6\.arpa|docker\.internal|wsl\.localhost)$|^localhost\.'
    $odd = @(foreach ($n in $answers.Keys) {
        if ($hostsNames.ContainsKey($n) -or $n -match $localName -or $n -match $privateOk) { continue }
        $ips = @($answers[$n]); if (-not $ips.Count) { continue }
        $kinds = @($ips | ForEach-Object { Get-IpKind $_ })
        if ($kinds -contains 'Public') { continue }
        [pscustomobject]@{ Name = $n; Answers = ($ips -join ', '); Blocked = -not ($kinds -contains 'Private') }
    })
    $sinkSec = @($odd | Where-Object { $_.Blocked -and $_.Name -match $securityDomains })
    $privSens = @($odd | Where-Object { -not $_.Blocked -and $_.Name -match $sensitiveDomains })
    $privOther = @($odd | Where-Object { -not $_.Blocked -and $_.Name -notmatch $sensitiveDomains })
    $blockedCount = @($odd | Where-Object { $_.Blocked }).Count
    if ($privSens.Count) {
        Add-Finding -Category $c -Title "DNS answered $($privSens.Count) major-site name(s) with local-network addresses" -Severity High -Classification Suspicious `
            -Detail 'The configured DNS server (not the hosts file) said these well-known sites live on the local network. That is how a hijacked router or a rogue local DNS server intercepts sign-ins.' `
            -Evidence ($privSens | Format-Table -AutoSize | Out-String -Width 300) -Tags 'Network', 'DNS'
    }
    if ($sinkSec.Count) {
        Add-Finding -Category $c -Title "DNS is blocking $($sinkSec.Count) security or update site(s)" -Severity Medium -Classification Suspicious `
            -Detail 'Lookups came back as 0.0.0.0/127.x from the DNS server itself. DNS filters (Pi-hole, AdGuard, parental controls) do this with over-broad lists; malware-controlled resolvers do it to block protection.' `
            -Evidence ($sinkSec | Format-Table -AutoSize | Out-String -Width 300) -Tags 'Network', 'DNS', 'Defender-Tamper'
    }
    if ($privOther.Count) {
        Add-Finding -Category $c -Title "$($privOther.Count) public-looking name(s) resolved to local-network addresses" -Severity $(if ($mgmt.IsManaged) { 'Info' } else { 'Low' }) -Classification $(if ($mgmt.IsManaged) { 'Info' } else { 'Ambiguous' }) `
            -Detail 'Normal for company networks with internal DNS, routers and some home-lab setups.' -Evidence ($privOther | Select-Object -First 40 | Format-Table -AutoSize | Out-String -Width 300) -Tags 'DNS'
    }

    # Algorithm-generated names (random-looking registrable labels) and DNS tunnelling (many long, unique labels under one domain)
    $cdn = '(?i)(^|\.)(cloudfront\.net|akamai(edge|hd|zed|technologies)?\.net|akamaized\.net|edgekey\.net|edgesuite\.net|azureedge\.net|azurefd\.net|trafficmanager\.net|cloudapp\.(net|azure\.com)|windows\.net|amazonaws\.com|googleusercontent\.com|gvt[12]\.com|googlevideo\.com|1e100\.net|fastly(lb)?\.net|cdn77\.org|msedge\.net|microsoft\.com|live\.com|office\.(com|net)|apple\.com|icloud\.com|footprintdns\.com|steamcontent\.com|fbcdn\.net|whatsapp\.net|plex\.direct|arpa)$'
    $dga = @($names | Where-Object { $_ -notmatch $cdn -and $_ -notmatch $localName } | ForEach-Object {
        $rd = Get-RegistrableDomain $_; $sld = $rd.Split('.')[0]
        $vowels = [regex]::Matches($sld, '[aeiouy]').Count; $digits = [regex]::Matches($sld, '\d').Count
        if ($sld.Length -ge 10 -and (Get-Entropy $sld) -ge 3.0 -and (($vowels / $sld.Length) -lt 0.2 -or ($digits -ge 4 -and $sld.Length - $digits -ge 4))) { $rd }
    } | Select-Object -Unique)
    if ($dga.Count) {
        Add-Finding -Category $c -Title "$($dga.Count) random-looking domain name(s) were looked up" -Severity $(if ($dga.Count -ge 8) { 'Medium' } else { 'Low' }) -Classification $(if ($dga.Count -ge 8) { 'Suspicious' } else { 'Ambiguous' }) `
            -Detail 'Some malware generates domain names by algorithm (DGA) to find its control server, producing bursts of random-looking names. A few such names are often just CDN or tracking hosts.' -Evidence ($dga -join "`n") -Tags 'DNS', 'C2'
    }
    $tunnel = @($names | Where-Object { $_ -notmatch $cdn -and (($_.Split('.')[0]).Length -ge 30 -or $_.Length -ge 90) } | Group-Object { Get-RegistrableDomain $_ } | Where-Object { $_.Count -ge 15 })
    foreach ($t in $tunnel) {
        Add-Finding -Category $c -Title "$($t.Count) long, unique sub-domains of $($t.Name) were looked up (possible DNS tunnelling)" -Severity Medium -Classification Suspicious `
            -Detail 'Encoding data into DNS names lets malware send data out or receive commands even when other traffic is blocked. Some security and telemetry products also use long encoded names.' `
            -Evidence (($t.Group | Select-Object -First 20) -join "`n") -Tags 'DNS', 'C2'
    }
    $wpadNames = @($names | Where-Object { $_ -match '^wpad(\.|$)' -and ($logged.ContainsKey($_) -or @($answers[$_]).Count) })
    $wpadAnswered = @($wpadNames | Where-Object { @($answers[$_]).Count })
    if ($wpadAnswered.Count -and -not $mgmt.IsManaged) {
        Add-Finding -Category $c -Title "A WPAD proxy-configuration host resolved on this network: $($wpadAnswered -join ', ')" -Severity Medium -Classification Suspicious `
            -Detail 'Windows looks up "wpad" to find an automatic proxy. If something on the network answers, it can route this PC''s web traffic through itself (WPAD hijacking, Responder-style attacks).' `
            -Evidence (($wpadAnswered | ForEach-Object { "$_ -> $(@($answers[$_]) -join ', ')" }) -join "`n") -Tags 'Network', 'DNS'
    }

    if ($names.Count) {
        Add-Finding -Category $c -Title "DNS history reviewed: $src" -Classification Info -Detail "$blockedCount name(s) were answered with a blocking address (DNS filter)." `
            -Evidence (($names | Sort-Object | Select-Object -First 400) -join "`n")
    } else {
        Add-Finding -Category $c -Title 'The DNS cache is empty, so there is no lookup history to review' -Classification Info `
            -Detail "Normal right after a restart or ipconfig /flushdns, or when a VPN, antivirus web filter or the browser's own secure DNS handles lookups. Malware sometimes flushes it after editing the hosts file. $(if (-not $logOn) { 'Turning on the Microsoft-Windows-DNS-Client/Operational log (Event Viewer) keeps a lookup history for future scans.' })"
    }

    # ---- Live tests: is anything between this PC and the internet falsifying answers? ----
    if ($SkipNetwork) { return }
    $probe = "windiag-$([guid]::NewGuid().ToString('N').Substring(0, 16)).com"
    $nx = @(); try { $nx = @(Resolve-DnsName -Name $probe -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' }) } catch {}
    if ($nx.Count) {
        Add-Finding -Category $c -Title 'The DNS server gives answers for names that do not exist' -Severity Low -Classification Ambiguous -Evidence "$probe -> $(($nx | ForEach-Object { $_.IPAddress }) -join ', ')" `
            -Detail 'Some ISPs do this to show search/ad pages ("NXDOMAIN redirection"); malicious resolvers do it to capture typos and phishing traffic. Either way the server rewrites answers.' -Tags 'DNS'
    }
    $interceptors = '(?i)(zscaler|netskope|palo alto|fortinet|fortigate|sophos|cisco|umbrella|blue ?coat|forcepoint|check ?point|avast|avg|kaspersky|eset|bitdefender|barracuda|mcafee|trend ?micro|watchguard|norton|gen digital|webroot|f-secure|iboss|lightspeed|securly)'
    $tested = 0; $bad = 0
    foreach ($h in 'www.paypal.com', 'login.microsoftonline.com', 'accounts.google.com', 'www.virustotal.com', 'www.malwarebytes.com') {
        $addrs = @(); try { $addrs = @([Net.Dns]::GetHostAddresses($h) | ForEach-Object { $_.IPAddressToString }) } catch {}
        if (-not $addrs.Count) { continue }
        $tested++
        $public = @($addrs | Where-Object { (Get-IpKind $_) -eq 'Public' })
        if (-not $public.Count) {
            if (-not $hostsNames.ContainsKey($h)) {
                $bad++
                Add-Finding -Category $c -Title "DNS sends $h to a blocked or local address ($($addrs -join ', '))" -Severity Medium -Classification Suspicious `
                    -Detail 'The DNS server (not the hosts file) does not return the real address. DNS filters can do this; malware-controlled resolvers do it to block security sites or to phish.' -Tags 'Network', 'DNS'
            }
            continue
        }
        $state = @{ Errors = 'None' }; $tcp = $null; $ssl = $null
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            if (-not $tcp.ConnectAsync($public[0], 443).Wait(5000)) { throw 'timeout' }
            $cb = { param($s, $cert, $chain, $e) $state.Errors = [string]$e; $true }.GetNewClosure()
            $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ($cb -as [Net.Security.RemoteCertificateValidationCallback]))
            $ssl.AuthenticateAsClient($h)
            $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            if ($state.Errors -ne 'None') {
                $info = [pscustomobject]@{ Host = $h; ResolvedTo = $public[0]; Certificate = $cert.Subject; Issuer = $cert.Issuer; Errors = $state.Errors }
                if ($cert.Issuer -match $interceptors) {
                    Add-Finding -Category $c -Title "HTTPS to $h is inspected by a security product" -Classification Info -Evidence $info
                } else {
                    $bad++
                    Add-Finding -Category $c -Title "$h resolves to a server that cannot prove it is $h" -Severity High -Classification Suspicious -Evidence $info `
                        -Detail "The name resolved to $($public[0]), but that server's certificate is not valid for $h. This is what DNS hijacking (a falsified answer from the hosts file, DNS server or router) or an untrusted interception proxy looks like. A browser would show a certificate warning; never click through it." `
                        -Recommendation 'Do not sign in to that site from this PC or network. Check the router''s DNS settings and the DNS servers above.' -Tags 'Network', 'DNS'
                }
            }
        } catch {} finally { if ($ssl) { $ssl.Dispose() }; if ($tcp) { $tcp.Close() } }
    }
    if ($tested -and -not $bad) {
        Add-Finding -Category $c -Title "DNS answers for $tested sensitive site(s) led to servers with valid certificates" -Classification OK `
            -Detail 'Checked PayPal, Microsoft sign-in, Google sign-in, VirusTotal and Malwarebytes: each name led to a server that proved its identity, so DNS is not being falsified for them.'
    } elseif (-not $tested) {
        Add-Finding -Category $c -Title 'Live DNS tests skipped: names could not be resolved (offline?)' -Classification Info
    }
}

# ===========================================================================
$script:WDShell = $null
function Read-Shortcut([string]$Path) {
    <# Target and arguments of a .lnk file, or $null. #>
    try {
        if (-not $script:WDShell) { $script:WDShell = New-Object -ComObject WScript.Shell }
        $sc = $script:WDShell.CreateShortcut($Path)
        return [pscustomobject]@{ Target = [string]$sc.TargetPath; Arguments = [string]$sc.Arguments }
    } catch { return $null }
}

function Measure-ShortcutRisk($File) {
    <# Judges a shortcut by what it launches. Windows creates shortcuts constantly (Recent items, taskbar
       pins, Start menu), so the folder and the name alone say nothing; a shortcut that quietly runs a
       script host with a command line is what phishing archives and malware actually use. #>
    $sc = Read-Shortcut $File.FullName
    if (-not $sc) { return $null }
    $target = Expand-WinPath $sc.Target; $scArgs = $sc.Arguments
    $leaf = if ($target) { [IO.Path]::GetFileName($target) } else { '' }
    $score = 0; $reasons = New-Object System.Collections.Generic.List[string]
    if ($leaf -match '^(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|forfiles|conhost|wmic|msbuild|installutil|curl|bash|wsl)\.exe$' -and $scArgs.Trim()) {
        $score += 3; $reasons.Add("Runs $leaf with a command line")
    }
    foreach ($r in @(Get-CommandLineRisk "$target $scArgs")) { $score += $r.Weight; $reasons.Add($r.Reason) }
    if ($target -match '(?i)\.(ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd)$') {
        $score += 2; $reasons.Add('Opens a script file')
        if (Test-UserWritablePath $target) { $score += 1 }
    } elseif ($target -match '(?i)\.(exe|scr|com|pif)$' -and (Test-UserWritablePath $target)) {
        $sig = Get-FileSignatureInfo $target
        if ($sig.Exists -and $sig.Status -ne 'Valid') { $score += 2; $reasons.Add('Starts an unsigned program in a user-writable folder') }
    }
    if ($scArgs.Length -gt 260 -or $scArgs -match '\s{50,}') { $score += 2; $reasons.Add('Arguments are padded or very long, which hides the command from the shortcut''s Properties box') }
    $inRecent = $File.FullName -match '(?i)\\Microsoft\\Windows\\Recent\\'   # named after the opened file, e.g. report.pdf.lnk
    if (-not $inRecent -and $File.Name -match '(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip|rar|7z)\.lnk$' -and $score -gt 0) {
        $score += 2; $reasons.Add('Named to look like a document')
    }
    if ($File.Attributes -band [IO.FileAttributes]::Hidden -and $score -gt 0) { $score += 1; $reasons.Add('Hidden') }
    [pscustomobject]@{ Path = $File.FullName; Modified = $File.LastWriteTime; Target = $target
                       Arguments = $(if ($scArgs.Length -gt 300) { $scArgs.Substring(0, 300) + '...' } else { $scArgs }); Score = $score; Reasons = ($reasons -join '; ') }
}

if (-not $SkipFileScan) {
Invoke-Check -Name 'Recently dropped files in user-writable folders' -ScriptBlock {
    $c = 'Files'
    $cut = (Get-Date).AddDays(-$FileScanDays)
    $exeExt = '(?i)\.(exe|dll|scr|sys|cpl|ocx)$'
    $scriptExt = '(?i)\.(ps1|vbs|vbe|js|jse|hta|bat|cmd|wsf|jar)$'
    $shortcuts = New-Object System.Collections.Generic.List[object]
    $targets = @(
        @{ P = "$env:SystemRoot\Temp"; D = 2 }, @{ P = "$env:ProgramData"; D = 2 }, @{ P = "$env:SystemDrive\Users\Public"; D = 3 }, @{ P = "$env:SystemDrive\PerfLogs"; D = 2 }
    )
    foreach ($u in Get-UserProfilePaths) {
        $targets += @{ P = Join-Path $u 'AppData\Roaming'; D = 3 }, @{ P = Join-Path $u 'AppData\Local\Temp'; D = 3 }, @{ P = Join-Path $u 'AppData\Local'; D = 1 },
                    @{ P = Join-Path $u 'Downloads'; D = 1 }, @{ P = Join-Path $u 'Desktop'; D = 1 }
    }
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($t in $targets) {
        if (-not (Test-Path $t.P -ErrorAction SilentlyContinue)) { continue }
        Get-ChildItem -Path $t.P -Recurse -Depth $t.D -File -Force -ErrorAction SilentlyContinue |
            Where-Object { ($_.CreationTime -gt $cut -or $_.LastWriteTime -gt $cut) -and ($_.Name -match $exeExt -or $_.Name -match $scriptExt -or $_.Extension -eq '.lnk') -and $_.FullName -notmatch '(?i)\\(Microsoft\\(Edge|Teams|OneDrive|EdgeUpdate|WindowsApps)|Packages|Google\\Chrome|Mozilla\\Firefox\\Profiles|npm-cache|pip\\cache|NuGet)\\' } |
            ForEach-Object {
                $f = $_
                if ($f.Extension -eq '.lnk') { if ($shortcuts.Count -lt 1000) { $m = Measure-ShortcutRisk $f; if ($m) { $shortcuts.Add($m) } }; return }
                if ($f.Name -in 'prefs.js', 'user.js') { return }   # settings files of Firefox and its forks (Zen, LibreWolf, Waterfox), not scripts Windows runs
                if ($hits.Count -ge 400) { return }
                $isExe = $f.Name -match $exeExt
                $sig = if ($isExe) { Get-FileSignatureInfo $f.FullName } else { $null }
                if ($isExe -and $sig.IsMicrosoft) { return }
                $hidden = [bool]($f.Attributes -band [IO.FileAttributes]::Hidden)
                $dbl = $f.Name -match '(?i)\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip)\.(exe|scr|js|vbs|hta|bat|cmd)$'
                $hits.Add([pscustomobject]@{ Path = $f.FullName; Size = $f.Length; Created = $f.CreationTime; Type = $(if ($isExe) {'Binary'} else {'Script'})
                    Signed = $(if ($sig) { $sig.Status } else { '' }); Signer = $(if ($sig) { $sig.Signer -replace ',.*$', '' } else { '' }); Hidden = $hidden; DoubleExt = $dbl })
            }
    }
    $unsigned = @($hits | Where-Object { $_.Type -eq 'Binary' -and $_.Signed -ne 'Valid' })
    $risky = @($hits | Where-Object { $_.DoubleExt -or ($_.Hidden -and $_.Type -eq 'Binary') -or ($_.Type -eq 'Script' -and $_.Path -match '(?i)\\(AppData\\Roaming|ProgramData|Users\\Public|Windows\\Temp)\\') })
    if ($unsigned.Count) {
        $ev = $unsigned | Select-Object -First 60 | ForEach-Object { $_ | Add-Member -NotePropertyName SHA256 -NotePropertyValue (Get-Sha256 $_.Path) -PassThru -Force }
        Add-Finding -Category $c -Title "$($unsigned.Count) unsigned executable(s) created in user-writable folders in the last $FileScanDays days" `
            -Severity $(if (@($unsigned | Where-Object { $_.Path -notmatch '(?i)\\Downloads\\' }).Count) {'Medium'} else {'Low'}) -Classification Ambiguous `
            -Detail 'Much ordinary software is unsigned, but malware almost always is. Files outside Downloads matter most, since they were placed there by a program, not by you.' `
            -Evidence ($ev | Format-List | Out-String -Width 400) -Recommendation 'Check each SHA256 on VirusTotal. Prioritize hidden files and those in AppData\Roaming, ProgramData or Temp.' -Tags 'Files'
    }
    if ($risky.Count) {
        Add-Finding -Category $c -Title "$($risky.Count) high-risk file(s): double extensions, hidden binaries, or scripts in system-wide writable folders" -Severity High -Classification Suspicious `
            -Evidence ($risky | Select-Object -First 60 Path, Created, Type, Hidden, DoubleExt, Signed | Format-Table -AutoSize -Wrap | Out-String -Width 400) -Tags 'Files'
    }
    $badLnk = @($shortcuts | Where-Object { $_.Score -ge 3 } | Sort-Object Score -Descending)
    if ($badLnk.Count) {
        Add-Finding -Category $c -Title "$($badLnk.Count) recent shortcut(s) launch a script host or risky command" -Severity $(if ($badLnk[0].Score -ge 5) { 'High' } else { 'Medium' }) -Classification Suspicious `
            -Detail 'Malicious shortcuts (sent in archives or emails, or planted on the desktop) look like documents or folders but run PowerShell, mshta or a script when opened. Shortcuts an administrator made on purpose can look similar; check each target.' `
            -Evidence ($badLnk | Select-Object -First 40 Path, Modified, Target, Arguments, Reasons | Format-List | Out-String -Width 400) `
            -Recommendation 'Do not open these shortcuts. Check where each came from; if one was already opened, look for what it started (Processes and Persistence findings).' -Tags 'Files', 'Execution'
    }
    if (-not $unsigned.Count -and -not $risky.Count -and -not $badLnk.Count) { Add-Finding -Category $c -Title "No unsigned executables, risky scripts or risky shortcuts dropped in the last $FileScanDays days" -Classification OK }
    if ($shortcuts.Count) {
        Add-Finding -Category $c -Title "$($shortcuts.Count) recent shortcut(s) checked by what they launch ($($badLnk.Count) flagged)" -Classification $(if ($badLnk.Count) { 'Info' } else { 'OK' }) `
            -Detail 'Includes Recent items, taskbar pins and desktop shortcuts that Windows and apps create all the time. Only shortcuts that run a script host, a risky command, a script or an unsigned program are flagged.'
    }
}
}

# ===========================================================================
Invoke-Check -Name 'Trusted root certificates' -ScriptBlock {
    $c = 'Certificates'
    $authRoot = 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates'
    $known = '(?i)(zscaler|netskope|palo alto|fortinet|sophos|cisco|blue ?coat|symantec|forcepoint|check ?point|avast|avg|kaspersky|eset|bitdefender|barracuda|mcafee|trend ?micro|watchguard|norton|webroot|f-secure|iboss|lightspeed|securly)'
    $devTools = '(?i)(fiddler|charles|burp|portswigger|mitmproxy|mkcert|iis express|localhost|asp\.net core|dotnet dev|owasp|telerik)'
    $rows = @()
    foreach ($store in 'Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root') {
        foreach ($cert in Get-ChildItem $store -ErrorAction SilentlyContinue) {
            if (Test-Path (Join-Path $authRoot $cert.Thumbprint)) { continue }
            if ($cert.Subject -match '(?i)O=Microsoft|CN=Microsoft|Microsoft Root|Copyright \(c\) 1997 Microsoft' -and $cert.Subject -eq $cert.Issuer) { continue }
            if ($cert.Subject -match '(?i)(VeriSign|Thawte|Class 3 Public Primary|DigiCert|Symantec Enterprise Mobile Root|NO LIABILITY ACCEPTED|GlobalSign|Baltimore|Entrust|Starfield|Go Daddy|QuoVadis|USERTrust|Sectigo|ISRG)') { continue }
            $kind = 'Unknown'
            if ($cert.Subject -match $known) { $kind = 'Security product (TLS inspection)' } elseif ($cert.Subject -match $devTools) { $kind = 'Developer/debugging proxy' } elseif ($mgmt.PartOfDomain -and $cert.Subject -match [regex]::Escape(($mgmt.Domain -split '\.')[0])) { $kind = 'Organization CA' }
            $rows += [pscustomobject]@{ Store = ($store -replace 'Cert:\\', ''); Subject = $cert.Subject; Thumbprint = $cert.Thumbprint; NotBefore = $cert.NotBefore; NotAfter = $cert.NotAfter; Kind = $kind }
        }
    }
    $unknown = @($rows | Where-Object { $_.Kind -eq 'Unknown' })
    $recentUnknown = @($unknown | Where-Object { $_.NotBefore -gt (Get-Date).AddYears(-3) })
    $interceptors = @($rows | Where-Object { $_.Kind -eq 'Developer/debugging proxy' })
    if ($recentUnknown.Count) {
        Add-Finding -Category $c -Title "$($recentUnknown.Count) recently issued, unrecognized root certificate(s) are trusted" -Severity $(if ($mgmt.IsManaged) {'Low'} else {'Medium'}) -Classification $(if ($mgmt.IsManaged) {'Ambiguous'} else {'Suspicious'}) `
            -Detail 'A root certificate lets its owner impersonate any website to this PC. Adware and banking trojans install their own roots; so do corporate proxies, VPNs and some AV.' `
            -Evidence ($recentUnknown | Format-List | Out-String -Width 300) -Recommendation 'Search the subject name. Remove roots that belong to software you do not use (certlm.msc / certmgr.msc).' -Tags 'Network'
    }
    if ($interceptors.Count) {
        Add-Finding -Category $c -Title "Debugging-proxy root certificate(s) are trusted: $(($interceptors.Subject | ForEach-Object { ($_ -split ',')[0] }) -join '; ')" -Severity Low -Classification Ambiguous `
            -Detail 'Tools like Fiddler/Burp install roots to decrypt traffic. Fine on a developer PC you control; remove them when no longer needed.' -Tags 'Network'
    }
    Add-Finding -Category $c -Title "$($rows.Count) trusted root(s) not from Microsoft's root program" -Classification $(if ($recentUnknown.Count) {'Info'} else {'OK'}) -Evidence ($rows | Format-Table -AutoSize -Wrap | Out-String -Width 400)
}

# ===========================================================================
Invoke-Check -Name 'Security posture and ransomware precursors' -ScriptBlock {
    $c = 'Security posture'
    $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if ((Get-RegValue $pol 'EnableLUA') -eq 0) {
        Add-Finding -Category $c -Title 'User Account Control (UAC) is disabled' -Severity High -Classification Suspicious -Detail 'Every program runs with full admin rights. Malware disables UAC; so do some "tweak" guides.' -Tags 'Defense-Evasion'
    } elseif ((Get-RegValue $pol 'ConsentPromptBehaviorAdmin') -eq 0) {
        Add-Finding -Category $c -Title 'UAC elevates administrators silently (no prompt)' -Severity Medium -Classification Suspicious -Tags 'Defense-Evasion'
    } else { Add-Finding -Category $c -Title 'UAC is enabled' -Classification OK }

    try {
        $fw = @(Get-NetFirewallProfile -ErrorAction Stop | Where-Object { -not $_.Enabled })
        if ($fw.Count) {
            Add-Finding -Category $c -Title "Windows Firewall is off for: $($fw.Name -join ', ')" -Severity $(if ($mgmt.ThirdPartyAV.Count) {'Low'} else {'Medium'}) -Classification Ambiguous `
                -Detail 'Expected only if a third-party firewall is installed.' -Tags 'Defense-Evasion'
        } else { Add-Finding -Category $c -Title 'Windows Firewall is on for all profiles' -Classification OK }
    } catch {}

    if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen') -eq 0 -or (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled') -eq 'Off') {
        Add-Finding -Category $c -Title 'SmartScreen is disabled' -Severity Low -Classification Ambiguous -Tags 'Defense-Evasion'
    }

    # RDP exposure
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    if ((Get-RegValue $ts 'fDenyTSConnections') -eq 0) {
        $nla = Get-RegValue "$ts\WinStations\RDP-Tcp" 'UserAuthentication'
        $port = Get-RegValue "$ts\WinStations\RDP-Tcp" 'PortNumber'
        $d = "Port $port. Network Level Authentication: $(if ($nla -eq 1) {'on'} else {'OFF'})."
        $sev = 'Info'; $cls = 'Info'
        if ($nla -ne 1) { $sev = 'Medium'; $cls = 'Ambiguous' }
        Add-Finding -Category $c -Title 'Remote Desktop is enabled' -Severity $sev -Classification $cls -Detail "$d RDP exposed to the internet is the #1 ransomware entry point. Make sure it is reachable only over VPN." -Tags 'Exposure'
        if ($port -and $port -ne 3389) {
            Add-Finding -Category $c -Title "RDP listens on a non-standard port ($port)" -Severity Low -Classification Ambiguous -Detail 'Admins do this to reduce scanning noise; attackers do it to hide an RDP backdoor.' -Tags 'Exposure'
        }
    }
    try { if ((Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol) { Add-Finding -Category $c -Title 'SMBv1 is enabled' -Severity Low -Classification Info -Detail 'Obsolete protocol abused by WannaCry/NotPetya. Disable unless an old device needs it.' } } catch {}

    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL') -notin 1, 2) {
        Add-Finding -Category $c -Title 'LSA protection (RunAsPPL) is off' -Severity Low -Classification Info -Detail 'Hardening setting that blocks credential dumping from lsass. Not an infection sign.'
    }
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
        $hvci = $dg.SecurityServicesRunning -contains 2
        Add-Finding -Category $c -Title "Memory integrity (HVCI): $(if ($hvci) {'running'} else {'off'})" -Classification $(if ($hvci) {'OK'} else {'Info'}) `
            -Detail $(if (-not $hvci) { 'Turning on Core isolation > Memory integrity blocks most vulnerable/malicious kernel drivers.' } else { '' })
    } catch {}
    try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop; Add-Finding -Category $c -Title "Secure Boot: $(if ($sb) {'on'} else {'OFF'})" -Severity $(if ($sb) {'Info'} else {'Low'}) -Classification $(if ($sb) {'OK'} else {'Info'}) `
        -Detail $(if (-not $sb) { 'Secure Boot blocks bootkits such as BlackLotus. Off is common on older or self-built PCs.' } else { '' }) } catch {}
    if ($isAdmin) {
        $bcd = (& "$env:SystemRoot\System32\bcdedit.exe" /enum '{current}' 2>$null) -join "`n"
        if ($bcd -match '(?im)^recoveryenabled\s+No' -or $bcd -match '(?im)^bootstatuspolicy\s+IgnoreAllFailures') {
            Add-Finding -Category $c -Title 'Windows recovery at boot has been disabled (bcdedit)' -Severity High -Classification Suspicious `
                -Detail 'Ransomware runs "bcdedit /set recoveryenabled No" before encrypting so victims cannot use recovery. Rarely done legitimately.' -Evidence $bcd -Tags 'Ransomware'
        }
        if ($bcd -match '(?im)^testsigning\s+Yes' -or $bcd -match '(?im)^nointegritychecks\s+Yes') {
            Add-Finding -Category $c -Title 'Driver signature enforcement is weakened (test-signing / nointegritychecks)' -Severity High -Classification Suspicious `
                -Detail 'Lets unsigned kernel drivers (rootkits) load. Developers and some modding tools turn it on.' -Evidence $bcd -Tags 'Rootkit'
        }
        $vss = (& "$env:SystemRoot\System32\vssadmin.exe" list shadows 2>$null) -join "`n"
        $vssPattern = '(?i)(vssadmin.*delete|shadowcopy.*delete|wbadmin.*delete|win32_shadowcopy)'
        $cmdHits = @((ConvertTo-ScriptBlockLog @(Get-RecentEvents @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $since } 3000 |
                        Where-Object { $_.Message -match $vssPattern })).Blocks | Where-Object { $_.Text -match $vssPattern })
        if ($cmdHits.Count) {
            Add-Finding -Category $c -Title 'PowerShell was used to delete shadow copies/backups' -Severity Critical -Classification Malicious `
                -Detail 'Deleting restore points is the last step before ransomware encrypts files.' `
                -Evidence (($cmdHits | Select-Object -First 5 | ForEach-Object { "[$($_.Time)] $($_.Path)`n" + $_.Text.Substring(0, [Math]::Min(800, $_.Text.Length)) }) -join "`n`n") -Tags 'Ransomware'
        }
        $shadowCount = ([regex]::Matches($vss, 'Shadow Copy ID')).Count
        Add-Finding -Category $c -Title "$shadowCount volume shadow cop(ies) / restore point snapshots exist" -Classification Info -Detail 'Zero is normal if System Protection is off; if it was on and copies vanished, find out why.'
        if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' 'DisableSR') -eq 1) {
            Add-Finding -Category $c -Title 'System Restore is disabled by policy' -Severity Medium -Classification Suspicious -Tags 'Ransomware'
        }
    }
    if (Get-Service Sysmon*, Sysmon64 -ErrorAction SilentlyContinue) { Add-Finding -Category $c -Title 'Sysmon is installed (detailed telemetry available)' -Classification Info -Detail 'Microsoft-Windows-Sysmon/Operational has process, network and file events for deeper investigation.' }
    if ((Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging') -ne 1) {
        Add-Finding -Category $c -Title 'Full PowerShell script-block logging is not enabled' -Severity Info -Classification Info -Detail 'Only suspicious-looking scripts are logged by default. Enabling it gives much better forensic visibility.'
    }
}

# ===========================================================================
Invoke-Check -Name 'Remote access tools' -ScriptBlock {
    $c = 'Remote access'
    $rat = '(?i)(anydesk|teamviewer|screenconnect|connectwise control|rustdesk|atera|splashtop|netsupport|client32\.exe|ammyy|ultravnc|tightvnc|realvnc|winvnc|tvnserver|chrome remote desktop|remoting_host|remote utilities|rutserv|meshagent|mesh agent|supremo|logmein|gotoassist|goto resolve|zoho assist|simplehelp|level\.io|action1|dwagent|dwservice|tacticalrmm|tactical rmm|kaseya|n-able|ninjarmm|syncro|pulseway|getscreen|remotepc|parsec|aeroadmin|litemanager|fleetdeck)'
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -match $rat } |
            ForEach-Object { $found.Add("Installed: $($_.DisplayName) $($_.DisplayVersion) (installed $($_.InstallDate))") }
    }
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { "$($_.Name) $($_.DisplayName) $($_.PathName)" -match $rat } |
        ForEach-Object { $found.Add("Service: $($_.Name) [$($_.State)] $($_.PathName)") }
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { "$($_.Name) $($_.ExecutablePath)" -match $rat } |
        ForEach-Object { $found.Add("Running: $($_.Name) (PID $($_.ProcessId)) $($_.ExecutablePath)") }
    $uniq = @($found | Select-Object -Unique)
    if ($uniq.Count) {
        $fromTemp = @($uniq | Where-Object { $_ -match '(?i)\\(temp|downloads|appdata\\local\\temp)\\' })
        Add-Finding -Category $c -Title "Remote-access software present ($($uniq.Count) trace(s))" -Severity $(if ($fromTemp.Count) {'High'} else {'Medium'}) -Classification $(if ($fromTemp.Count) {'Suspicious'} else {'Ambiguous'}) `
            -Detail 'Legitimate tools, but tech-support scammers and ransomware gangs install them to keep access. Running from Temp/Downloads suggests someone talked a user into launching it.' `
            -Evidence ($uniq -join "`n") -Recommendation 'Make sure you or your IT provider installed each one. Uninstall any you do not use and change passwords if a stranger ever connected.' -Tags 'RemoteAccess'
    } else { Add-Finding -Category $c -Title 'No common remote-access tools found' -Classification OK }
}

# ===========================================================================
$findings = @(Get-Findings)
$verdict = Get-WinDiagVerdict $findings
if (-not $Quiet) { Write-WinDiagSummary -Findings $findings -Verdict $verdict }
if (-not $NoReport) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $paths = Export-WinDiagReport -Findings $findings -OutputDir $OutputDir -BaseName "CompromiseIndicators-$env:COMPUTERNAME-$stamp" -Title "Compromise indicators - $env:COMPUTERNAME" -Verdict $verdict -Inventory (Get-Inventory)
    if (-not $Quiet) { Write-Host "`nReport: $($paths.Html)" -ForegroundColor Green }
}
if ($PassThru) { return @($findings) + @(Get-Inventory) }   # Invoke-WinDiag separates findings from inventory tables
