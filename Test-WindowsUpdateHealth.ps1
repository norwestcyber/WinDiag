#Requires -Version 5.1
<#
.SYNOPSIS
    Diagnoses Windows Update failures and separates ordinary causes from tampering.

.DESCRIPTION
    Read-only. Checks the update services, their DLLs and permissions, update policy,
    hosts file, proxy, firewall, DNS/TLS reachability (Microsoft vs. control sites),
    clock skew, update history with error-code attribution, component store health,
    pending reboots, disk space, patch-rollback (downgrade) indicators, and known
    update-blocking/"debloat" tools.

    Each finding is classified as Benign (environmental), Ambiguous, Suspicious, or
    Malicious, and a final Diagnosis finding states the most likely explanation.

.PARAMETER OutputDir   Where reports are written. Default: Desktop\WinDiag-Reports
.PARAMETER Days        How far back to look in update history and event logs. Default 90.
.PARAMETER DeepScan    Also run DISM /ScanHealth and SFC /VERIFYONLY (5-20 minutes).
.PARAMETER SkipNetwork Skip DNS/TCP/TLS reachability tests.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Test-WindowsUpdateHealth.ps1
.EXAMPLE
    .\Test-WindowsUpdateHealth.ps1 -DeepScan -Days 180
#>
[CmdletBinding()]
param(
    [string]$OutputDir = '',
    [int]$Days = 90,
    [switch]$DeepScan,
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
$cat = 'Windows Update'

if (-not $Quiet) {
    Write-Host "WinDiag - Windows Update health  (read-only)" -ForegroundColor White
    if (-not (Test-IsAdmin)) { Write-Host "Not elevated: run as Administrator for complete results." -ForegroundColor Yellow }
    Write-Host ("Managed device: {0}  (domain={1}, AzureAD={2}, MDM={3}, SCCM={4}, WSUS={5})" -f `
        $mgmt.IsManaged, $mgmt.PartOfDomain, $mgmt.AzureAdJoined, $mgmt.MdmEnrolled, $mgmt.SccmClient, $mgmt.WsusConfigured) -ForegroundColor DarkGray
}

# Severity for a tamper-style setting depends on whether something legitimately manages the machine.
function Get-TamperSeverity { param([string]$Unmanaged = 'High', [string]$Managed = 'Low')
    if ($mgmt.IsManaged) { return $Managed } else { return $Unmanaged } }

# ---------------------------------------------------------------------------
# Error code knowledge base: code -> meaning, typical cause, classification
# Class: Benign = environmental, Ambiguous = either, Tamper = commonly produced by tampering
# ---------------------------------------------------------------------------
$ErrorMap = @{
    '0x80070070' = @('Not enough disk space', 'Benign')
    '0x80070005' = @('Access denied (permissions, AV interference, or altered ACLs)', 'Ambiguous')
    '0x80070020' = @('File in use by another process (often antivirus scanning)', 'Benign')
    '0x80070002' = @('File not found (stale download cache or corruption)', 'Benign')
    '0x80070003' = @('Path not found (stale download cache or corruption)', 'Benign')
    '0x8007000D' = @('Invalid data (corrupt download or component store)', 'Benign')
    '0x80070057' = @('Invalid parameter (corrupt cache or bad update metadata)', 'Benign')
    '0x80070422' = @('A required service is DISABLED', 'Tamper')
    '0x80070490' = @('Element not found (component store corruption)', 'Benign')
    '0x80070643' = @('Installer failure (.NET/MSI, or WinRE partition too small for KB5034441)', 'Benign')
    '0x80070BC9' = @('Pending reboot blocks installation', 'Benign')
    '0x80073701' = @('Assembly missing (component store corruption)', 'Benign')
    '0x80073712' = @('Component store corrupt', 'Benign')
    '0x800736B3' = @('Assembly not found (component store corruption)', 'Benign')
    '0x800736CC' = @('File mismatch in component store', 'Benign')
    '0x800F081F' = @('Source files not found (component store corruption)', 'Benign')
    '0x800F0831' = @('Missing manifest from a previous update (CBS corruption)', 'Benign')
    '0x800F0922' = @('Install failed (small System Reserved partition, VPN, or .NET)', 'Benign')
    '0x800F0920' = @('Hardware/servicing timeout', 'Benign')
    '0x800F0982' = @('Language pack / component mismatch', 'Benign')
    '0x800F0988' = @('Component cleanup needed', 'Benign')
    '0x800F0845' = @('Update failed at boot (driver or servicing issue)', 'Benign')
    '0x80240017' = @('Update not applicable to this system', 'Benign')
    '0x80240034' = @('Download failed', 'Ambiguous')
    '0x8024200D' = @('Update needs to be downloaded again', 'Benign')
    '0x80242016' = @('Post-reboot operation failed', 'Benign')
    '0x80242006' = @('Update handler failure (corrupt cache)', 'Benign')
    '0x8024402C' = @('Proxy or server name could not be resolved', 'Ambiguous')
    '0x8024401C' = @('Request timed out', 'Benign')
    '0x80244018' = @('HTTP 403 forbidden (proxy/firewall)', 'Ambiguous')
    '0x80244019' = @('HTTP 404 (WSUS or proxy problem)', 'Benign')
    '0x8024401B' = @('Proxy authentication required', 'Benign')
    '0x80244022' = @('HTTP 503 service unavailable (server side or WSUS)', 'Benign')
    '0x80244007' = @('WSUS SOAP fault (server-side WSUS problem)', 'Benign')
    '0x8024002E' = @('Windows Update access DISABLED by policy', 'Tamper')
    '0x8024500C' = @('Windows Update access BLOCKED by policy', 'Tamper')
    '0x80246008' = @('BITS failed to start a download', 'Ambiguous')
    '0x80200053' = @('BITS: content rejected (proxy/filtering)', 'Ambiguous')
    '0x80072EE2' = @('Network timeout reaching update servers', 'Ambiguous')
    '0x80072EE7' = @('Server name could not be resolved (DNS or hosts file)', 'Ambiguous')
    '0x80072EFD' = @('Cannot connect to update servers', 'Ambiguous')
    '0x80072EFE' = @('Connection aborted (filtering or TLS inspection)', 'Ambiguous')
    '0x80072F8F' = @('TLS certificate error (clock skew or TLS interception)', 'Ambiguous')
    '0x80072F76' = @('Malformed server response (proxy interference)', 'Ambiguous')
    '0x80092004' = @('Cryptographic object not found (catalog/crypto store damage)', 'Ambiguous')
    '0x800B0109' = @('Certificate chain to untrusted root', 'Ambiguous')
    '0x800B0100' = @('File has no signature', 'Ambiguous')
    '0x80096004' = @('Signature verification failed', 'Ambiguous')
    '0xC1900101' = @('Feature update rolled back (driver problem)', 'Benign')
    '0xC1900208' = @('Incompatible application blocks feature update', 'Benign')
    '0xC1900200' = @('Hardware does not meet requirements', 'Benign')
    '0x8024A105' = @('Update agent busy/reset needed', 'Benign')
    '0x80240438' = @('No route to update service (network or policy)', 'Ambiguous')
}

# Tracks the strongest observations for the final diagnosis
$diag = @{ Tamper = New-Object System.Collections.Generic.List[string]; Env = New-Object System.Collections.Generic.List[string]
           Failures = 0; TamperCodes = 0; NetMsOnlyFail = $false; TweakTool = $false; GeneralNetFail = $false }

# ===========================================================================
Invoke-Check -Name 'Update services' -ScriptBlock {
    $spec = @(
        @{ N = 'wuauserv';         Ok = @(2,3); Dll = 'wuaueng.dll' }
        @{ N = 'BITS';             Ok = @(2,3); Dll = 'qmgr.dll' }
        @{ N = 'UsoSvc';           Ok = @(2,3); Dll = 'usosvc.dll' }
        @{ N = 'WaaSMedicSvc';     Ok = @(2,3); Dll = 'WaaSMedicSvc.dll' }
        @{ N = 'CryptSvc';         Ok = @(2,3); Dll = 'cryptsvc.dll' }
        @{ N = 'TrustedInstaller'; Ok = @(2,3); Exe = 'TrustedInstaller.exe' }
        @{ N = 'DoSvc';            Ok = @(2,3); Dll = 'dosvc.dll' }
    )
    $startNames = @{ 0 = 'Boot'; 1 = 'System'; 2 = 'Automatic'; 3 = 'Manual'; 4 = 'Disabled' }
    foreach ($s in $spec) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.N)"
        if (-not (Test-Path $key)) {
            $sev = 'High'; if ($s.N -in @('DoSvc','WaaSMedicSvc','UsoSvc')) { $sev = 'Medium' }
            Add-Finding -Category $cat -Title "Service '$($s.N)' is missing from the registry" -Severity $sev -Classification Suspicious `
                -Detail 'Core update services should always exist. Deletion is a known way to break updates permanently; some heavily modified Windows builds (AtlasOS, ReviOS, Tiny11) also remove them.' `
                -Recommendation 'Determine whether this is a modified Windows image. If not, treat as tampering.' -Tags 'WU-Tamper'
            $diag.Tamper.Add("$($s.N) service missing")
            continue
        }
        $start = Get-RegValue $key 'Start'
        $image = Get-RegValue $key 'ImagePath'
        $svc = Get-Service -Name $s.N -ErrorAction SilentlyContinue
        $state = if ($svc) { [string]$svc.Status } else { 'Unknown' }

        if ($start -eq 4) {
            Add-Finding -Category $cat -Title "Service '$($s.N)' is DISABLED" -Severity (Get-TamperSeverity 'High' 'Medium') -Classification Suspicious `
                -Detail "Start type is Disabled (status: $state). Windows never sets this itself. Causes error 0x80070422. Done by attackers, update-blocker tools, or an admin." `
                -Evidence ([pscustomobject]@{ Service = $s.N; Start = $startNames[[int]$start]; ImagePath = $image }) `
                -Recommendation 'Check Event ID 7040 below for when and by whom it was changed. Re-enable only after you know why it was disabled.' -Tags 'WU-Tamper'
            $diag.Tamper.Add("$($s.N) disabled")
        } elseif ($start -notin $s.Ok) {
            Add-Finding -Category $cat -Title "Service '$($s.N)' has an unusual start type ($start)" -Severity Low -Classification Ambiguous -Tags 'WU-Tamper'
        } else {
            Add-Finding -Category $cat -Title "Service '$($s.N)' start type OK ($($startNames[[int]$start]), $state)" -Classification OK
        }

        # Binary behind the service
        $binPath = $null
        if ($s.Dll) {
            $binPath = Expand-WinPath (Get-RegValue "$key\Parameters" 'ServiceDll')
            if (-not $binPath) { $binPath = Expand-WinPath (Get-RegValue $key 'ServiceDll') }
            if ($image -and $image -notmatch '(?i)\\system32\\svchost\.exe') {
                Add-Finding -Category $cat -Title "Service '$($s.N)' no longer runs inside svchost.exe" -Severity Critical -Classification Malicious `
                    -Detail "ImagePath was changed to: $image" -Recommendation 'This is service hijacking. Isolate the machine and investigate.' -Tags 'WU-Tamper','Persistence'
                $diag.Tamper.Add("$($s.N) ImagePath hijacked")
            }
        } else { $binPath = Resolve-CommandPath $image }

        if ($binPath) {
            $expectedName = if ($s.Dll) { $s.Dll } else { $s.Exe }
            $sig = Get-FileSignatureInfo $binPath
            $leaf = [IO.Path]::GetFileName($binPath)
            if ($leaf -ne $expectedName -or $binPath -notmatch '(?i)^[a-z]:\\windows\\(system32|servicing)\\') {
                Add-Finding -Category $cat -Title "Service '$($s.N)' points to an unexpected binary" -Severity Critical -Classification Malicious `
                    -Detail "Expected $expectedName in System32/servicing, found: $binPath" -Evidence $sig `
                    -Recommendation 'Service DLL/Image hijacking. Isolate and investigate.' -Tags 'WU-Tamper','Persistence'
                $diag.Tamper.Add("$($s.N) binary path hijacked")
            } elseif ($sig.Exists -and -not $sig.IsMicrosoft) {
                Add-Finding -Category $cat -Title "Service binary for '$($s.N)' is not validly Microsoft-signed" -Severity Critical -Classification Malicious `
                    -Detail "Signature status: $($sig.Status). Signer: $($sig.Signer)" -Evidence $sig `
                    -Recommendation 'A replaced system binary. Isolate the machine; get the SHA256 checked; plan a reimage.' -Tags 'WU-Tamper'
                $diag.Tamper.Add("$($s.N) binary not Microsoft-signed")
            } elseif (-not $sig.Exists) {
                Add-Finding -Category $cat -Title "Service binary for '$($s.N)' is missing ($binPath)" -Severity High -Classification Ambiguous `
                    -Detail 'Can be corruption or deliberate deletion.' -Recommendation 'Run DISM /RestoreHealth and SFC; see whether it is restored.' -Tags 'WU-Tamper'
            }
        }

        # Service permissions: a deny ACE prevents Windows from starting/repairing the service
        # (WaaSMedicSvc is protected and locked down by design, so it is skipped)
        if ($s.N -eq 'WaaSMedicSvc') { continue }
        $sd = (& "$env:SystemRoot\System32\sc.exe" sdshow $s.N 2>$null) -join ''
        if ($sd -match '\(D;') {
            Add-Finding -Category $cat -Title "Service '$($s.N)' has DENY permissions in its security descriptor" -Severity (Get-TamperSeverity 'High' 'Medium') -Classification Suspicious `
                -Detail 'Deny entries stop Windows (and WaaSMedic) from restarting or repairing the service. Used by update-blocker tools and by malware.' `
                -Evidence $sd -Tags 'WU-Tamper'
            $diag.Tamper.Add("$($s.N) service DACL has deny ACEs")
        }
        try {
            $acl = Get-Acl -Path $key -ErrorAction Stop
            $deny = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' })
            if ($deny.Count) {
                Add-Finding -Category $cat -Title "Registry key for service '$($s.N)' has DENY permissions" -Severity (Get-TamperSeverity 'High' 'Medium') -Classification Suspicious `
                    -Detail 'Locks the service configuration so Windows cannot restore it. Windows Update Blocker-style tools and malware do this.' `
                    -Evidence ($deny | Select-Object IdentityReference, RegistryRights, AccessControlType) -Tags 'WU-Tamper'
                $diag.Tamper.Add("$($s.N) registry key locked with deny ACEs")
            }
        } catch {}
    }

    # When and by whom start types changed (Event 7040)
    $names = 'Windows Update|Background Intelligent Transfer|Update Orchestrator|Windows Update Medic|Cryptographic Services|Windows Modules Installer|Delivery Optimization'
    $ev = Get-RecentEvents @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7040; StartTime = $since } 500 |
          Where-Object { $_.Message -match $names }
    $toDisabled = @($ev | Where-Object { $_.Message -match '(?i)disabled' })
    if ($toDisabled.Count) {
        $rows = $toDisabled | Select-Object TimeCreated, @{ n = 'User'; e = { try { $_.UserId.Translate([Security.Principal.NTAccount]).Value } catch { [string]$_.UserId } } }, Message
        Add-Finding -Category $cat -Title "Update service(s) were set to Disabled $($toDisabled.Count) time(s) in the last $Days days" -Severity (Get-TamperSeverity 'High' 'Medium') -Classification Suspicious `
            -Detail 'Event 7040 records the change and the account that made it. An unfamiliar account, SYSTEM at an odd hour, or a change right after a suspicious download points to tampering.' `
            -Evidence $rows -Recommendation 'Match each timestamp against installs, downloads and logons around the same time.' -Tags 'WU-Tamper'
        $diag.Tamper.Add('7040 events: update services set to Disabled')
    } elseif ($ev.Count) {
        Add-Finding -Category $cat -Title "$($ev.Count) routine start-type change(s) for update services (none to Disabled)" -Classification Info `
            -Detail 'BITS and other services switch between automatic and manual on their own. This is normal.'
    }
}

# ===========================================================================
Invoke-Check -Name 'Update policy' -ScriptBlock {
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $au = "$wu\AU"
    $vals = [ordered]@{
        WUServer                                    = Get-RegValue $wu 'WUServer'
        WUStatusServer                              = Get-RegValue $wu 'WUStatusServer'
        UpdateServiceUrlAlternate                   = Get-RegValue $wu 'UpdateServiceUrlAlternate'
        DisableWindowsUpdateAccess                  = Get-RegValue $wu 'DisableWindowsUpdateAccess'
        DoNotConnectToWindowsUpdateInternetLocations = Get-RegValue $wu 'DoNotConnectToWindowsUpdateInternetLocations'
        SetDisableUXWUAccess                        = Get-RegValue $wu 'SetDisableUXWUAccess'
        DisableDualScan                             = Get-RegValue $wu 'DisableDualScan'
        TargetReleaseVersionInfo                    = Get-RegValue $wu 'TargetReleaseVersionInfo'
        NoAutoUpdate                                = Get-RegValue $au 'NoAutoUpdate'
        AUOptions                                   = Get-RegValue $au 'AUOptions'
        UseWUServer                                 = Get-RegValue $au 'UseWUServer'
        NoWindowsUpdate_Explorer                    = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoWindowsUpdate'
        NoWindowsUpdate_User                        = Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoWindowsUpdate'
        DisableWUAccess_InternetComm                = Get-RegValue 'HKLM:\SYSTEM\Internet Communication Management\Internet Communication' 'DisableWindowsUpdateAccess'
        DisableWUAccess_User                        = Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate' 'DisableWindowsUpdateAccess'
    }
    $set = [ordered]@{}; foreach ($k in $vals.Keys) { if ($null -ne $vals[$k]) { $set[$k] = $vals[$k] } }
    if (-not $set.Count) { Add-Finding -Category $cat -Title 'No Windows Update policies set (default behaviour)' -Classification OK }

    $blockers = @('DisableWindowsUpdateAccess','DoNotConnectToWindowsUpdateInternetLocations','SetDisableUXWUAccess',
                  'NoWindowsUpdate_Explorer','NoWindowsUpdate_User','DisableWUAccess_InternetComm','DisableWUAccess_User')
    $hit = @($blockers | Where-Object { $set.Contains($_) -and [int]$set[$_] -eq 1 })
    if ($hit.Count) {
        Add-Finding -Category $cat -Title "Policy blocks access to Windows Update ($($hit -join ', '))" -Severity (Get-TamperSeverity 'High' 'Low') -Classification $(if ($mgmt.IsManaged) {'Ambiguous'} else {'Suspicious'}) `
            -Detail $(if ($mgmt.IsManaged) { 'This device is managed (domain/Intune/SCCM); these settings are often deployed deliberately with WSUS or another patch tool.' } else { 'This device is NOT managed by an organization, so nothing legitimate should have set these. Produces errors 0x8024002E / 0x8024500C.' }) `
            -Evidence ([pscustomobject]$set) -Recommendation 'Ask whoever administers the PC. If nobody set these, treat as tampering.' -Tags 'WU-Tamper'
        if (-not $mgmt.IsManaged) { $diag.Tamper.Add('Policy blocks Windows Update on an unmanaged PC') }
    }
    if ($set.Contains('NoAutoUpdate') -and [int]$set['NoAutoUpdate'] -eq 1) {
        Add-Finding -Category $cat -Title 'Automatic updates are turned off by policy (NoAutoUpdate=1)' -Severity (Get-TamperSeverity 'Medium' 'Low') -Classification $(if ($mgmt.IsManaged) {'Ambiguous'} else {'Suspicious'}) `
            -Detail 'Common with privacy/debloat tools; also used by malware to keep a vulnerability open.' -Tags 'WU-Tamper'
        if (-not $mgmt.IsManaged) { $diag.Tamper.Add('NoAutoUpdate policy on an unmanaged PC') }
    }
    if ($set.Contains('WUServer')) {
        $url = [string]$set['WUServer']
        $sev = 'Info'; $cls = 'Info'; $d = "Updates come from WSUS server $url."
        if (-not $mgmt.IsManaged) {
            $sev = 'High'; $cls = 'Suspicious'
            $d = "Updates are redirected to $url but this PC is not domain/Intune/SCCM managed. A rogue update server is a known attack path (fake updates, or a server that simply reports 'no updates')."
            $diag.Tamper.Add("WSUS redirect to $url on unmanaged PC")
        }
        Add-Finding -Category $cat -Title "Updates are redirected to a WSUS server: $url" -Severity $sev -Classification $cls -Detail $d -Evidence ([pscustomobject]$set) -Tags 'WU-Tamper'
        if ($url -match '^(?i)http://') {
            Add-Finding -Category $cat -Title 'WSUS uses plain HTTP' -Severity Low -Classification Info `
                -Detail 'Update metadata over HTTP can be intercepted on the local network (WSUSpect-style attacks). Microsoft recommends HTTPS for WSUS.'
        }
        if (-not $SkipNetwork) {
            try {
                $u = [Uri]$url
                $tcp = New-Object Net.Sockets.TcpClient
                $ok = $tcp.ConnectAsync($u.Host, $u.Port).Wait(4000) -and $tcp.Connected
                $tcp.Close()
                if (-not $ok) {
                    Add-Finding -Category $cat -Title "WSUS server $($u.Host):$($u.Port) is unreachable" -Severity High -Classification Benign `
                        -Detail 'A very common cause of update failures on managed PCs (off the corporate network, VPN down, or server retired).' -Tags 'WU-Env'
                    $diag.Env.Add('WSUS server unreachable')
                } else { Add-Finding -Category $cat -Title "WSUS server $($u.Host):$($u.Port) is reachable" -Classification OK }
            } catch {}
        }
    }

    # Pauses: the Settings UI caps pauses at 35 days; longer pauses come from registry edits/tools
    $ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    $maxPause = Get-RegValue $ux 'FlightSettingsMaxPauseDays'
    if ($maxPause -and [int]$maxPause -gt 35) {
        Add-Finding -Category $cat -Title "Maximum pause length was raised to $maxPause days" -Severity Medium -Classification Suspicious `
            -Detail 'Only registry edits or tweak tools do this; the normal limit is 35 days.' -Tags 'WU-Tamper','TweakTool'
        $diag.TweakTool = $true
    }
    foreach ($n in 'PauseUpdatesExpiryTime','PauseQualityUpdatesEndTime','PauseFeatureUpdatesEndTime') {
        $v = Get-RegValue $ux $n
        if ($v) {
            $dt = $null
            try { $dt = [datetime]::Parse($v, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) } catch {}
            if ($dt -and $dt -gt (Get-Date).ToUniversalTime()) {
                $daysLeft = [int]($dt - (Get-Date).ToUniversalTime()).TotalDays
                $sev = 'Low'; $cls = 'Benign'
                if ($daysLeft -gt 36) { $sev = 'Medium'; $cls = 'Suspicious' }
                Add-Finding -Category $cat -Title "Updates are paused ($n) for $daysLeft more day(s)" -Severity $sev -Classification $cls `
                    -Detail $(if ($daysLeft -gt 36) { 'Longer than Windows allows from Settings, so it was set by a tool or script.' } else { 'Set from Settings > Windows Update. Explains "no updates installing".' }) -Tags 'WU-Env'
                if ($daysLeft -gt 36) { $diag.Tamper.Add('Updates paused beyond the 35-day UI limit') } else { $diag.Env.Add('Updates paused by user') }
            }
        }
    }
}

# ===========================================================================
Invoke-Check -Name 'Hosts file and DNS overrides' -ScriptBlock {
    $dbPath = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DataBasePath'
    if ($dbPath -and (Expand-WinPath $dbPath) -notmatch '(?i)\\system32\\drivers\\etc\\?$') {
        Add-Finding -Category $cat -Title 'The hosts file location was redirected' -Severity Critical -Classification Malicious `
            -Detail "DataBasePath = $dbPath. Malware moves the hosts file so edits are hidden from anyone checking the normal one." -Tags 'WU-Tamper','Network'
        $diag.Tamper.Add('Hosts file path redirected')
    }
    $hosts = Join-Path (Expand-WinPath $(if ($dbPath) { $dbPath } else { '%SystemRoot%\System32\drivers\etc' })) 'hosts'
    if (-not (Test-Path $hosts)) { Add-Finding -Category $cat -Title "Hosts file not found at $hosts" -Classification Info; return }
    $lines = Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*[^#\s]' }
    $msPattern = '(?i)(microsoft|windowsupdate|windows\.com|msftncsi|msftconnecttest|wdcp|smartscreen|defender|mp\.microsoft|live\.com|office\.com|msedge|azureedge|digicert|virustotal|malwarebytes|kaspersky|eset|bitdefender|sophos|avast|norton|mcafee|trendmicro|crowdstrike|sentinelone)'
    $critPattern = '(?i)(windowsupdate|update\.microsoft|delivery\.mp\.microsoft|download\.microsoft|go\.microsoft|wdcp|wd\.microsoft|definitionupdates|smartscreen|defender|digicert|virustotal|malwarebytes|kaspersky|eset|bitdefender|sophos|avast|norton|mcafee|trendmicro|crowdstrike|sentinelone|^\S+\s+(www\.)?microsoft\.com\b)'
    $all = @($lines | Where-Object { $_ -match $msPattern })
    $bad = @($all | Where-Object { $_ -match $critPattern })
    $telemetryOnly = @($all | Where-Object { $_ -notmatch $critPattern })
    if ($telemetryOnly.Count -and -not $bad.Count) {
        Add-Finding -Category $cat -Title "Hosts file blocks $($telemetryOnly.Count) Microsoft telemetry/service name(s), none used by updates" -Severity Low -Classification Ambiguous `
            -Detail 'Typical of privacy/anti-telemetry tools. Does not block Windows Update or Defender.' -Evidence ($telemetryOnly -join "`n") -Tags 'TweakTool'
        $diag.TweakTool = $true
    }
    if ($bad.Count) {
        $blocking = @($bad | Where-Object { $_ -match '^\s*(0\.0\.0\.0|127\.|::1?\b)' })
        Add-Finding -Category $cat -Title "Hosts file overrides $($bad.Count) Microsoft/security domain(s)" -Severity High -Classification Suspicious `
            -Detail "$($blocking.Count) entr(ies) point to a black-hole address (blocking). Telemetry blockers sometimes add Microsoft entries, but blocking update or security-vendor sites is a classic malware move. Redirects to real IPs are worse." `
            -Evidence ($bad -join "`n") -Recommendation 'Compare against any privacy tool you installed. Entries for update, Defender or AV-vendor domains should not exist.' -Tags 'WU-Tamper','Network'
        $diag.Tamper.Add('Hosts file blocks Microsoft/security domains')
    } elseif ($lines -and -not $all.Count) {
        Add-Finding -Category $cat -Title "Hosts file has $(@($lines).Count) custom entr(ies), none for Microsoft/security domains" -Classification Info -Evidence ($lines -join "`n")
    } elseif (-not $lines) { Add-Finding -Category $cat -Title 'Hosts file contains no active entries' -Classification OK }
}

# ===========================================================================
Invoke-Check -Name 'Proxy configuration' -ScriptBlock {
    $wh = (& "$env:SystemRoot\System32\netsh.exe" winhttp show proxy 2>$null) -join "`n"
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $ev = [pscustomobject]@{
        WinHTTP = $wh.Trim()
        UserProxyEnable = $ie.ProxyEnable; UserProxyServer = $ie.ProxyServer; UserAutoConfigURL = $ie.AutoConfigURL
        EnvHttpProxy = $env:HTTP_PROXY; EnvHttpsProxy = $env:HTTPS_PROXY
    }
    $whProxy = $null
    if ($wh -match '(?im)Proxy Server\(s\)\s*:\s*(\S+)') { $whProxy = $Matches[1] }
    if ($whProxy) {
        $local = $whProxy -match '(?i)(127\.0\.0\.1|localhost|\[::1\])'
        $sev = 'Info'; $cls = 'Info'
        if (-not $mgmt.IsManaged) { $sev = 'Medium'; $cls = 'Suspicious' }
        Add-Finding -Category $cat -Title "System (WinHTTP) proxy is set: $whProxy" -Severity $sev -Classification $cls `
            -Detail $(if ($local) { 'Points to this PC. Legit for debugging tools (Fiddler) or some AV web shields; malware also uses a local proxy to intercept or block traffic.' } else { 'Windows Update uses this proxy. On an unmanaged PC, an unknown proxy can block updates or intercept traffic.' }) `
            -Evidence $ev -Recommendation 'Confirm the proxy belongs to software you trust.' -Tags 'WU-Tamper','Network'
        if (-not $mgmt.IsManaged) { $diag.Tamper.Add("Unexplained WinHTTP proxy $whProxy") }
    } else { Add-Finding -Category $cat -Title 'System (WinHTTP) proxy: direct access' -Classification OK }
    if ($ie -and $ie.ProxyEnable -eq 1 -and $ie.ProxyServer) {
        Add-Finding -Category $cat -Title "User proxy is enabled: $($ie.ProxyServer)" -Severity $(if ($mgmt.IsManaged) {'Info'} else {'Low'}) -Classification Ambiguous -Evidence $ev -Tags 'Network'
    }
    if ($ie -and $ie.AutoConfigURL) {
        $sev = 'Low'; if ($ie.AutoConfigURL -match '(?i)^file:|\\appdata\\|\\temp\\' -or -not $mgmt.IsManaged) { $sev = 'Medium' }
        Add-Finding -Category $cat -Title "Proxy auto-config (PAC) script set: $($ie.AutoConfigURL)" -Severity $sev -Classification $(if ($mgmt.IsManaged) {'Ambiguous'} else {'Suspicious'}) `
            -Detail 'PAC scripts are a common way for banking trojans and adware to route browsing through an attacker proxy.' -Tags 'Network'
    }
}

# ===========================================================================
Invoke-Check -Name 'Firewall rules blocking update/security components' -ScriptBlock {
    $targets = '(?i)\\(svchost|wuauclt|usoclient|MoUsoCoreWorker|TiWorker|TrustedInstaller|MsMpEng|MpCmdRun|NisSrv|SecurityHealthService|MpDefenderCoreService|SenseCncProxy|MsSense)\.exe$'
    $rules = @(Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True -ErrorAction Stop)
    $hits = foreach ($r in $rules) {
        $app = ($r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
        $svc = ($r | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue).Service
        $updSvc = $svc -and $svc -match '(?i)^(wuauserv|bits|usosvc|dosvc|windefend|wdnissvc)$'
        $svchostOther = $app -match '(?i)\\svchost\.exe$' -and $svc -and $svc -notmatch '^(Any|\*)$' -and -not $updSvc
        if ((($app -and $app -match $targets) -and -not $svchostOther) -or $updSvc) {
            [pscustomobject]@{ Name = $r.DisplayName; Program = $app; Service = $svc; Group = $r.Group; Source = $r.PolicyStoreSourceType }
        }
    }
    if ($hits) {
        Add-Finding -Category $cat -Title "$(@($hits).Count) outbound firewall rule(s) block update or Defender components" -Severity (Get-TamperSeverity 'High' 'Medium') -Classification Suspicious `
            -Detail 'Blocking Defender or update binaries from the network is a known technique (e.g. EDR-silencing tools). Some update blockers do it too.' `
            -Evidence $hits -Recommendation 'Identify who created the rules. Windows does not create these.' -Tags 'WU-Tamper','Defender-Tamper'
        $diag.Tamper.Add('Firewall rules block update/Defender binaries')
    } else { Add-Finding -Category $cat -Title 'No outbound firewall rules block update or Defender components' -Classification OK }
}

# ===========================================================================
if (-not $SkipNetwork) {
Invoke-Check -Name 'Network reachability (Microsoft vs. control sites)' -ScriptBlock {
    $ms = 'sls.update.microsoft.com','fe3.delivery.mp.microsoft.com','download.windowsupdate.com','go.microsoft.com','definitionupdates.microsoft.com'
    $ctl = 'www.google.com','www.cloudflare.com','www.wikipedia.org'
    $sinkhole = '^(0\.0\.0\.0|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1?$|169\.254\.)'

    function Test-Endpoint([string]$name) {
        $r = [ordered]@{ Host = $name; SystemResolve = ''; DnsResolve = ''; Sinkholed = $false; HostsDiffers = $false; Tcp443 = $false }
        $sys = @(); $dns = @()
        try { $sys = @([Net.Dns]::GetHostAddresses($name) | ForEach-Object { $_.IPAddressToString }) } catch {}
        try { $dns = @(Resolve-DnsName -Name $name -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop |
                       Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) } catch {}
        $r.SystemResolve = $sys -join ', '; $r.DnsResolve = $dns -join ', '
        if (@($sys | Where-Object { $_ -match $sinkhole }).Count -or @($dns | Where-Object { $_ -match $sinkhole }).Count) { $r.Sinkholed = $true }
        if ($sys.Count -and $dns.Count -and -not (@($sys | Where-Object { $dns -contains $_ }).Count)) { $r.HostsDiffers = $true }
        if ($sys.Count -and -not $r.Sinkholed) {
            try { $t = New-Object Net.Sockets.TcpClient; $r.Tcp443 = ($t.ConnectAsync($sys[0], 443).Wait(4000) -and $t.Connected); $t.Close() } catch {}
        }
        [pscustomobject]$r
    }
    $msRes  = @($ms  | ForEach-Object { Test-Endpoint $_ })
    $ctlRes = @($ctl | ForEach-Object { Test-Endpoint $_ })
    $msFail  = @($msRes  | Where-Object { -not $_.Tcp443 })
    $ctlFail = @($ctlRes | Where-Object { -not $_.Tcp443 })
    $ev = $msRes + $ctlRes | Format-Table -AutoSize | Out-String -Width 300

    if ($ctlFail.Count -eq $ctlRes.Count -and $msFail.Count -eq $msRes.Count) {
        Add-Finding -Category $cat -Title 'No internet connectivity (Microsoft AND control sites unreachable)' -Severity High -Classification Benign `
            -Detail 'General connectivity problem (offline, captive portal, firewall, or proxy required). Not specific to Windows Update.' -Evidence $ev -Tags 'WU-Env','Network'
        $diag.Env.Add('No general internet connectivity'); $diag.GeneralNetFail = $true
    } elseif ($msFail.Count -and -not $ctlFail.Count) {
        $sink = @($msFail | Where-Object { $_.Sinkholed -or $_.HostsDiffers })
        $sev = 'High'; $cls = 'Suspicious'
        if ($mgmt.IsManaged -and -not $sink.Count) { $sev = 'Medium'; $cls = 'Ambiguous' }
        Add-Finding -Category $cat -Title "Microsoft update endpoints are selectively unreachable ($($msFail.Count)/$($msRes.Count)) while other sites work" -Severity $sev -Classification $cls `
            -Detail $(if ($sink.Count) { 'Some names resolve to black-hole/private addresses or differ from public DNS (hosts file or DNS tampering).' } else { 'Selective blocking. Can be a corporate firewall/filter, a router-level blocklist (Pi-hole), or malware.' }) `
            -Evidence $ev -Recommendation 'Check router/DNS filters (Pi-hole, NextDNS, parental controls) before suspecting the PC itself.' -Tags 'WU-Tamper','Network'
        $diag.NetMsOnlyFail = $true; $diag.Tamper.Add('Only Microsoft endpoints blocked')
    } elseif ($msFail.Count) {
        Add-Finding -Category $cat -Title "Some endpoints unreachable (Microsoft $($msFail.Count)/$($msRes.Count), control $($ctlFail.Count)/$($ctlRes.Count))" -Severity Medium -Classification Benign `
            -Detail 'Partial connectivity problems affecting both groups suggests an unstable network rather than targeted blocking.' -Evidence $ev -Tags 'WU-Env','Network'
        $diag.Env.Add('Unstable network connectivity')
    } else {
        Add-Finding -Category $cat -Title 'All Microsoft update endpoints and control sites are reachable' -Classification OK -Evidence $ev
    }

    # TLS interception check: what root signs the certificate we are actually served?
    $known = '(?i)(zscaler|netskope|palo alto|fortinet|fortigate|sophos|cisco|umbrella|blue ?coat|symantec|forcepoint|check ?point|avast|avg|kaspersky|eset|bitdefender|barracuda|mcafee|trend ?micro|watchguard|norton|gen digital|webroot|f-secure|cloudflare gateway|menlo|iboss|lightspeed|securly|untangle)'
    foreach ($h in 'sls.update.microsoft.com','www.microsoft.com') {
        $state = @{ Errors = 'None' }
        $tcp = $null; $ssl = $null
        try {
            $tcp = New-Object Net.Sockets.TcpClient
            if (-not $tcp.ConnectAsync($h, 443).Wait(5000)) { throw 'timeout' }
            $cb = { param($s, $c, $ch, $e) $state.Errors = [string]$e; $true }.GetNewClosure()
            $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ($cb -as [Net.Security.RemoteCertificateValidationCallback]))
            $ssl.AuthenticateAsClient($h)
            $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
            $chain.ChainPolicy.RevocationMode = 'NoCheck'
            [void]$chain.Build($cert)
            $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
            $info = [pscustomobject]@{ Host = $h; Subject = $cert.Subject; Issuer = $cert.Issuer; Root = $root.Subject; RootThumbprint = $root.Thumbprint; ValidationErrors = $state.Errors }
            if ($root.Subject -match '(?i)(microsoft|digicert|baltimore|globalsign)' -and $state.Errors -eq 'None') {
                Add-Finding -Category $cat -Title "TLS to $h is genuine (root: $($root.GetNameInfo('SimpleName', $false)))" -Classification OK -Evidence $info
            } elseif ($root.Subject -match $known -or $cert.Issuer -match $known) {
                Add-Finding -Category $cat -Title "TLS to $h is intercepted by a security product/proxy" -Severity Medium -Classification Ambiguous `
                    -Detail 'HTTPS inspection by AV or a corporate proxy. Usually legitimate, but Windows Update often fails behind TLS inspection (0x80072F8F/0x80072EFE). Microsoft recommends excluding update URLs.' -Evidence $info -Tags 'WU-Env','Network'
                $diag.Env.Add('TLS inspection by a security product/proxy')
            } else {
                Add-Finding -Category $cat -Title "TLS to $h is signed by an UNKNOWN root certificate" -Severity High -Classification Suspicious `
                    -Detail 'Traffic to Microsoft is being intercepted by something that is not a recognized security product. This is how malicious proxies and adware (e.g. Superfish-style) work.' `
                    -Evidence $info -Recommendation 'Find where this root certificate came from (certlm.msc > Trusted Root). Remove it only after identifying the software that installed it.' -Tags 'WU-Tamper','Network'
                $diag.Tamper.Add("Unknown TLS interception root for $h")
            }
        } catch {
            if (-not $diag.GeneralNetFail) {
                Add-Finding -Category $cat -Title "TLS handshake with $h failed" -Severity Low -Classification Ambiguous -Detail $_.Exception.Message -Tags 'Network'
            }
        } finally { if ($ssl) { $ssl.Dispose() }; if ($tcp) { $tcp.Close() } }
    }
}

Invoke-Check -Name 'Clock accuracy' -ScriptBlock {
    $serverTime = $null
    foreach ($u in 'https://www.microsoft.com/', 'http://www.msftconnecttest.com/connecttest.txt') {
        try {
            $resp = Invoke-WebRequest -Uri $u -Method Head -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
            if ($resp.Headers['Date']) { $serverTime = [datetime]::Parse(($resp.Headers['Date'] | Select-Object -First 1)).ToUniversalTime(); break }
        } catch {}
    }
    if (-not $serverTime) { Add-Finding -Category $cat -Title 'Could not obtain a reference time from the internet' -Classification Info; return }
    $skew = [Math]::Abs(((Get-Date).ToUniversalTime() - $serverTime).TotalMinutes)
    if ($skew -gt 5) {
        Add-Finding -Category $cat -Title ("System clock is off by {0:n0} minutes" -f $skew) -Severity High -Classification Benign `
            -Detail 'Clock skew breaks TLS certificate checks (0x80072F8F) and update downloads. Usually a dead CMOS battery, wrong time zone, or stopped Windows Time service.' `
            -Recommendation 'Settings > Time & language > Sync now. Check the w32time service.' -Tags 'WU-Env'
        $diag.Env.Add('Clock skew')
    } else { Add-Finding -Category $cat -Title ("System clock accurate (skew {0:n1} min)" -f $skew) -Classification OK }
}
}

Invoke-Check -Name 'TLS protocol settings' -ScriptBlock {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client'
    $en = Get-RegValue $k 'Enabled'; $dbd = Get-RegValue $k 'DisabledByDefault'
    if ($en -eq 0 -or $dbd -eq 1) {
        Add-Finding -Category $cat -Title 'TLS 1.2 client is disabled in SCHANNEL' -Severity High -Classification Benign `
            -Detail 'Windows Update requires TLS 1.2. Usually left behind by hardening scripts or old guides.' -Evidence ([pscustomobject]@{ Enabled = $en; DisabledByDefault = $dbd }) -Tags 'WU-Env'
        $diag.Env.Add('TLS 1.2 disabled')
    } else { Add-Finding -Category $cat -Title 'TLS 1.2 client not disabled' -Classification OK }
}

# ===========================================================================
Invoke-Check -Name 'Update history and error attribution' -ScriptBlock {
    $hist = @()
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        # Store app updates flood the history (several a day), so read deep enough to reach the monthly OS updates
        if ($total -gt 0) { $hist = @($searcher.QueryHistory(0, [Math]::Min($total, 3000))) }
    } catch {
        Add-Finding -Category $cat -Title 'Could not read update history from the Windows Update agent' -Severity Medium -Classification Ambiguous `
            -Detail "$($_.Exception.Message). Happens when wuauserv is disabled or its COM registration is damaged." -Tags 'WU-Failure'
    }
    $resultNames = @{ 0 = 'NotStarted'; 1 = 'InProgress'; 2 = 'Succeeded'; 3 = 'SucceededWithErrors'; 4 = 'Failed'; 5 = 'Aborted' }
    $rows = foreach ($h in $hist) {
        if ($h.Date -lt $since.ToUniversalTime()) { continue }
        $code = '0x{0:X8}' -f [int32]$h.HResult
        $kb = ''; if ($h.Title -match '(KB\d{6,8})') { $kb = $Matches[1] }
        [pscustomobject]@{
            Date = $h.Date.ToLocalTime(); Result = $resultNames[[int]$h.ResultCode]; Operation = $(if ($h.Operation -eq 2) {'Uninstall'} else {'Install'})
            KB = $kb; HResult = $code; Title = $h.Title; Client = $h.ClientApplicationID
        }
    }
    $rows = @($rows)
    $failed = @($rows | Where-Object { $_.Result -in @('Failed','Aborted') -and $_.HResult -ne '0x00000000' })
    $succ = @($rows | Where-Object { $_.Result -eq 'Succeeded' -and $_.Operation -eq 'Install' })
    $diag.Failures = $failed.Count

    # OS quality updates. Titles changed in 2025 from "2024-09 Cumulative Update for Windows 11 ..." to "2025-10 Security Update (KB...) (26100.xxxx)".
    $quality = '(?i)(cumulative update|security update|security monthly quality rollup|quality rollup)'
    $notOs = '(?i)(\.net|office|edge|defender|security intelligence|definition update|malicious software removal|KB2267602|KB890830)'
    $storeApp = '^[0-9A-Z]{12}-'
    $lastOk = ($hist | Where-Object { $_.ResultCode -in 2, 3 -and $_.Operation -eq 1 -and $_.Title -match $quality -and $_.Title -notmatch $notOs } | Sort-Object Date -Descending | Select-Object -First 1)
    $lastDate = $null; $lastTitle = ''
    if ($lastOk) { $lastDate = $lastOk.Date.ToLocalTime(); $lastTitle = "$($lastOk.Title) (update history)" }
    # Updates installed outside the agent (WSUS/SCCM, wusa, offline servicing) appear only as hotfixes
    $hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object {
        $on = $null; try { $on = $_.InstalledOn } catch {}
        if ($on) { [pscustomobject]@{ HotFixID = $_.HotFixID; Description = $_.Description; InstalledOn = $on } } } | Sort-Object InstalledOn -Descending)
    $lastSecHf = $hotfixes | Where-Object { $_.Description -eq 'Security Update' } | Select-Object -First 1
    if ($lastSecHf -and (-not $lastDate -or $lastSecHf.InstalledOn.Date -gt $lastDate.Date)) {
        $lastDate = $lastSecHf.InstalledOn; $lastTitle = "$($lastSecHf.HotFixID) (installed hotfix, Security Update)"
    }
    if (-not $lastDate) {
        $any = ($hist | Where-Object { $_.ResultCode -in 2, 3 -and $_.Operation -eq 1 -and $_.Title -notmatch $notOs -and $_.Title -notmatch $storeApp } | Sort-Object Date -Descending | Select-Object -First 1)
        if ($any) { $lastDate = $any.Date.ToLocalTime(); $lastTitle = "$($any.Title) (not identified as a monthly quality update)" }
    }
    if ($lastDate) {
        $age = [int]((Get-Date) - $lastDate).TotalDays
        if ($age -gt 45) {
            Add-Finding -Category $cat -Title "No Windows quality/security update has installed in $age days" -Severity High -Classification Ambiguous `
                -Detail "Last success: $lastDate - $lastTitle. Monthly security updates should install every ~30 days." -Tags 'WU-Failure'
        } else { Add-Finding -Category $cat -Title "Last Windows quality/security update installed $age day(s) ago" -Classification OK -Detail "$lastDate - $lastTitle" }
    } elseif ($hist.Count -or $hotfixes.Count) {
        Add-Finding -Category $cat -Title 'No successful Windows quality/security update appears in update history or installed hotfixes' -Severity High -Classification Ambiguous -Tags 'WU-Failure'
    }

    if (-not $failed.Count) {
        Add-Finding -Category $cat -Title "No failed updates in the last $Days days ($($succ.Count) succeeded)" -Classification OK
    } else {
        $byCode = $failed | Group-Object HResult | Sort-Object Count -Descending
        foreach ($g in $byCode) {
            $m = $ErrorMap[$g.Name]
            $meaning = if ($m) { $m[0] } else { 'Unrecognized code - search Microsoft docs for it' }
            $class = if ($m) { $m[1] } else { 'Ambiguous' }
            $kbs = ($g.Group | Where-Object KB | Select-Object -ExpandProperty KB -Unique) -join ', '
            switch ($class) {
                'Benign' { $sev = 'Medium'; $cls = 'Benign'; $tag = 'WU-Env'; $diag.Env.Add("Error $($g.Name): $meaning") }
                'Tamper' { $sev = 'High'; $cls = 'Suspicious'; $tag = 'WU-Tamper'; $diag.TamperCodes++ }
                default  { $sev = 'Medium'; $cls = 'Ambiguous'; $tag = 'WU-Failure' }
            }
            $detail = "$meaning. Seen $($g.Count) time(s)."
            if ($kbs) { $detail += " Updates: $kbs." }
            if ($class -eq 'Tamper') { $detail += ' This code is produced when services or policy were deliberately changed; see the Services/Policy findings.' }
            if ($class -eq 'Ambiguous') { $detail += ' Cross-check with the network, proxy, hosts and TLS findings to tell blocking from flaky connectivity.' }
            Add-Finding -Category $cat -Title "Update error $($g.Name): $meaning" -Severity $sev -Classification $cls -Detail $detail `
                -Evidence ($g.Group | Select-Object -First 10 Date, Result, KB, Title | Format-Table -AutoSize | Out-String -Width 300) -Tags $tag
        }
        # Same KB failing repeatedly while others install = targeted failure (or just a known bad update)
        $repeat = @($failed | Where-Object KB | Group-Object KB | Where-Object Count -ge 3)
        foreach ($r in $repeat) {
            $isSec = $r.Group[0].Title -match '(?i)(security|cumulative)'
            Add-Finding -Category $cat -Title "$($r.Name) has failed $($r.Count) times" -Severity $(if ($isSec) {'Medium'} else {'Low'}) -Classification Ambiguous `
                -Detail "$($r.Group[0].Title). A single update failing repeatedly is usually a known issue with that update (check Microsoft's release health page) or a corrupt component store." -Tags 'WU-Failure'
        }
    }
    $un = @($rows | Where-Object { $_.Operation -eq 'Uninstall' -and $_.Title -match '(?i)(security|cumulative)' })
    if ($un.Count) {
        Add-Finding -Category $cat -Title "$($un.Count) security/cumulative update(s) were uninstalled" -Severity Medium -Classification Ambiguous `
            -Detail 'Uninstalling a patch re-opens what it fixed. Legit when troubleshooting a bad update; also an attacker technique.' -Evidence ($un | Format-Table -AutoSize | Out-String -Width 300) -Tags 'WU-Tamper'
    }
    $hf = @($hotfixes | Select-Object -First 5)
    if ($hf.Count) { Add-Finding -Category $cat -Title "Most recent hotfix: $($hf[0].HotFixID) on $($hf[0].InstalledOn.ToShortDateString())" -Classification Info -Evidence ($hf | Select-Object HotFixID, Description, InstalledOn) }
}

# ===========================================================================
Invoke-Check -Name 'Update agent binary integrity' -ScriptBlock {
    $files = @('System32\wuaueng.dll','System32\wuapi.dll','System32\wuauclt.exe','System32\usoclient.exe','System32\MoUsoCoreWorker.exe',
               'System32\qmgr.dll','System32\poqexec.exe','System32\wusa.exe','System32\usosvc.dll','servicing\TrustedInstaller.exe','System32\ntoskrnl.exe','System32\ci.dll')
    $bad = @(); $missing = @()
    foreach ($f in $files) {
        $p = Join-Path $env:SystemRoot $f
        $s = Get-FileSignatureInfo $p
        if (-not $s.Exists) { $missing += $p; continue }
        if (-not $s.IsMicrosoft) { $bad += $s }
    }
    if ($bad.Count) {
        Add-Finding -Category $cat -Title "$($bad.Count) Windows Update/servicing binar(ies) are not validly Microsoft-signed" -Severity Critical -Classification Malicious `
            -Detail 'Core update and kernel files should always carry a valid Microsoft signature. HashMismatch means the file was altered.' `
            -Evidence ($bad | ForEach-Object { $_ | Add-Member -NotePropertyName SHA256 -NotePropertyValue (Get-Sha256 $_.Path) -PassThru -Force } | Select-Object Path, Status, Signer, SHA256) `
            -Recommendation 'Isolate the machine. Submit the SHA256 hashes to VirusTotal. Plan to reimage.' -Tags 'WU-Tamper'
        $diag.Tamper.Add('Update/servicing binaries not Microsoft-signed')
    } else { Add-Finding -Category $cat -Title 'Windows Update and servicing binaries are Microsoft-signed' -Classification OK }
    if ($missing.Count) {
        Add-Finding -Category $cat -Title "$($missing.Count) expected update binar(ies) missing" -Severity Medium -Classification Ambiguous -Evidence ($missing -join "`n") `
            -Detail 'Can be an edition difference (Server/LTSC), a stripped Windows image, or deletion.'
    }

    # Patch rollback ("Windows Downdate") indicators
    $poq = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide\Configuration' 'PoqexecCmdline'
    if ($poq) {
        $txt = ($poq -join ' ')
        if ($txt -notmatch '(?i)\\system32\\poqexec\.exe\s+/display_progress\s+\\SystemRoot\\WinSxS\\pending\.xml') {
            Add-Finding -Category $cat -Title 'Servicing boot action (PoqexecCmdline) was modified' -Severity Critical -Classification Malicious `
                -Detail 'This value controls what runs during update-at-boot. Changing it is the core of the 2024 "Windows Downdate" patch-rollback technique.' -Evidence $txt -Tags 'WU-Tamper'
            $diag.Tamper.Add('PoqexecCmdline modified (downgrade attack)')
        } else { Add-Finding -Category $cat -Title 'Servicing boot action (PoqexecCmdline) is default' -Classification OK }
    }
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    foreach ($kf in 'ntoskrnl.exe','ci.dll') {
        try {
            $vi = (Get-Item (Join-Path "$env:SystemRoot\System32" $kf) -ErrorAction Stop).VersionInfo
            if ($cv -and [int]$vi.FileBuildPart -eq [int]$cv.CurrentBuild -and [int]$vi.FilePrivatePart -lt [int]$cv.UBR) {
                Add-Finding -Category $cat -Title "$kf is older than the installed OS revision ($($vi.FileBuildPart).$($vi.FilePrivatePart) < $($cv.CurrentBuild).$($cv.UBR))" -Severity Medium -Classification Ambiguous `
                    -Detail 'After a cumulative update these files normally match the OS revision. An older file can mean a failed/partial update or a deliberate rollback that still reports "up to date". Exception: hotpatch-enrolled devices (some Enterprise/Server editions) raise the revision without replacing these files.' `
                    -Recommendation 'Run DISM /RestoreHealth then reinstall the latest cumulative update; recheck.' -Tags 'WU-Tamper'
            }
        } catch {}
    }
}

# ===========================================================================
Invoke-Check -Name 'Update cache and catalog folders' -ScriptBlock {
    foreach ($p in "$env:SystemRoot\SoftwareDistribution", "$env:SystemRoot\System32\catroot2") {
        if (-not (Test-Path $p)) {
            Add-Finding -Category $cat -Title "$p is missing" -Severity Low -Classification Benign -Detail 'Windows recreates it automatically; often deleted during manual troubleshooting.'
            continue
        }
        $item = Get-Item $p -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Add-Finding -Category $cat -Title "$p is a junction/symlink (redirected)" -Severity High -Classification Suspicious `
                -Detail "Target: $($item.Target). Redirecting the update cache lets an attacker feed or block update files. Some disk-space tools do it too." -Tags 'WU-Tamper'
            $diag.Tamper.Add("$p redirected")
        }
        try {
            $deny = @((Get-Acl $p).Access | Where-Object { $_.AccessControlType -eq 'Deny' })
            if ($deny.Count) {
                Add-Finding -Category $cat -Title "$p has DENY permissions" -Severity High -Classification Suspicious `
                    -Detail 'Prevents Windows Update from writing its cache. A known update-blocking trick.' -Evidence ($deny | Select-Object IdentityReference, FileSystemRights) -Tags 'WU-Tamper'
                $diag.Tamper.Add("$p deny ACL")
            }
        } catch {}
    }
    try {
        $size = (Get-ChildItem "$env:SystemRoot\SoftwareDistribution\Download" -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        if ($size -gt 10GB) { Add-Finding -Category $cat -Title ("Update download cache is {0:n1} GB" -f ($size / 1GB)) -Severity Low -Classification Benign -Detail 'A bloated cache often holds stuck downloads.' -Tags 'WU-Env' }
    } catch {}
}

# ===========================================================================
Invoke-Check -Name 'Component store health' -RequiresAdmin -ScriptBlock {
    $dismArgs = if ($DeepScan) { '/ScanHealth' } else { '/CheckHealth' }
    $out = (& "$env:SystemRoot\System32\dism.exe" /Online /Cleanup-Image $dismArgs /English 2>&1) -join "`n"
    if ($out -match '(?i)no component store corruption detected') {
        Add-Finding -Category $cat -Title "Component store healthy (DISM $dismArgs)" -Classification OK
    } elseif ($out -match '(?i)repairable') {
        $fixable = $out -notmatch '(?i)not repairable'
        Add-Finding -Category $cat -Title "Component store is corrupted ($(if ($fixable) {'repairable'} else {'NOT repairable'}))" -Severity High -Classification Benign `
            -Detail 'The most common cause of repeated update failures (0x800F081F, 0x80073712). Usually caused by interrupted updates, power loss or disk errors.' `
            -Evidence $out -Recommendation 'Run: DISM /Online /Cleanup-Image /RestoreHealth, then sfc /scannow, then retry updates.' -Tags 'WU-Env'
        $diag.Env.Add('Component store corruption')
    } elseif (-not $DeepScan) {
        Add-Finding -Category $cat -Title 'DISM CheckHealth found no flagged corruption (run -DeepScan for a full scan)' -Classification Info -Evidence $out
    } else { Add-Finding -Category $cat -Title 'DISM result could not be interpreted' -Classification Info -Evidence $out }

    if ($DeepScan) {
        $prev = [Console]::OutputEncoding
        try { [Console]::OutputEncoding = [Text.Encoding]::Unicode; $sfc = (& "$env:SystemRoot\System32\sfc.exe" /verifyonly 2>&1) -join "`n" }
        finally { [Console]::OutputEncoding = $prev }
        $sfc = $sfc -replace "`0", ''
        if ($sfc -match '(?i)did not find any integrity violations') {
            Add-Finding -Category $cat -Title 'SFC: no integrity violations' -Classification OK
        } elseif ($sfc -match '(?i)found integrity violations') {
            $cbs = Get-Content "$env:SystemRoot\Logs\CBS\CBS.log" -Tail 20000 -ErrorAction SilentlyContinue |
                   Where-Object { $_ -match '\[SR\].*(do not match|corrupt|Cannot)' } | Select-Object -Last 40
            $secHit = @($cbs | Where-Object { $_ -match '(?i)(wuaueng|wuapi|usoclient|qmgr|ntoskrnl|lsass|winlogon|svchost|msmpeng|ci\.dll|samsrv|kerberos|msv1_0)' })
            Add-Finding -Category $cat -Title 'SFC found system file integrity violations' -Severity $(if ($secHit.Count) {'High'} else {'Medium'}) -Classification $(if ($secHit.Count) {'Suspicious'} else {'Benign'}) `
                -Detail $(if ($secHit.Count) { 'Security-relevant files are among those modified. Corruption is still possible, but replacement of these files is an attacker technique.' } else { 'Usually corruption. Repair with sfc /scannow after DISM /RestoreHealth.' }) `
                -Evidence ($cbs -join "`n") -Tags 'WU-Env'
            if ($secHit.Count) { $diag.Tamper.Add('SFC: security-relevant system files modified') } else { $diag.Env.Add('System file corruption') }
        }
    }
    $cbsErr = @(Get-Content "$env:SystemRoot\Logs\CBS\CBS.log" -Tail 8000 -ErrorAction SilentlyContinue | Where-Object { $_ -match '(?i)(ERROR_SXS_ASSEMBLY_MISSING|CBS_E_STORE_CORRUPTION|0x800f081f|Failed to pin deployment)' })
    if ($cbsErr.Count) {
        Add-Finding -Category $cat -Title "CBS.log shows $($cbsErr.Count) servicing corruption error(s)" -Severity Medium -Classification Benign -Evidence (($cbsErr | Select-Object -Last 15) -join "`n") -Tags 'WU-Env'
        $diag.Env.Add('CBS servicing errors')
    }
}

# ===========================================================================
Invoke-Check -Name 'Reboot, disk space and recovery environment' -ScriptBlock {
    $pend = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pend += 'Servicing (CBS)' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pend += 'Windows Update' }
    $pfro = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
    if ($pend.Count) {
        Add-Finding -Category $cat -Title "A reboot is pending ($($pend -join ', '))" -Severity Medium -Classification Benign -Detail 'Pending reboots block further updates (0x80070BC9). Restart and retry.' -Tags 'WU-Env'
        $diag.Env.Add('Pending reboot')
    }
    if ($pfro) {
        $pairs = @(); for ($i = 0; $i + 1 -lt $pfro.Count; $i += 2) { $pairs += [pscustomobject]@{ Source = $pfro[$i] -replace '^\\\?\?\\', ''; Dest = $pfro[$i + 1] -replace '^!?\\\?\?\\', '' } }
        $secTargets = @($pairs | Where-Object { $_.Source -match '(?i)(windows defender|msmpeng|mpcmdrun|\\(eset|kaspersky|bitdefender|malwarebytes|sophos|avast|avg|norton|mcafee|crowdstrike|sentinel)|wuaueng|usoclient|wuauclt)' })
        if ($secTargets.Count) {
            Add-Finding -Category $cat -Title 'Files of security/update components are queued for deletion or replacement at reboot' -Severity High -Classification Suspicious `
                -Detail 'Malware queues boot-time deletions to remove AV that it cannot touch while running. AV upgrades also use this, so check which product.' -Evidence ($secTargets | Format-Table -AutoSize | Out-String -Width 300) -Tags 'WU-Tamper','Defender-Tamper'
            $diag.Tamper.Add('Boot-time deletion of security components queued')
        } else {
            Add-Finding -Category $cat -Title "$($pairs.Count) file operation(s) queued for next reboot" -Classification Info -Evidence ($pairs | Select-Object -First 30 | Format-Table -AutoSize | Out-String -Width 300)
        }
    }
    try {
        $up = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        if ($up.TotalDays -gt 30) { Add-Finding -Category $cat -Title ("No restart for {0:n0} days" -f $up.TotalDays) -Severity Low -Classification Benign -Detail 'Long uptimes leave updates half-installed. Fast Startup "shutdowns" do not count as restarts.' -Tags 'WU-Env' }
    } catch {}
    try {
        $sys = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'"
        $freeGB = [Math]::Round($sys.FreeSpace / 1GB, 1)
        if ($freeGB -lt 5) { Add-Finding -Category $cat -Title "Only $freeGB GB free on $env:SystemDrive" -Severity High -Classification Benign -Detail 'Too little space for cumulative updates (0x80070070). Free at least 10-20 GB.' -Tags 'WU-Env'; $diag.Env.Add('Low disk space') }
        elseif ($freeGB -lt 15) { Add-Finding -Category $cat -Title "$freeGB GB free on $env:SystemDrive (tight)" -Severity Medium -Classification Benign -Detail 'Feature updates need ~20 GB.' -Tags 'WU-Env'; $diag.Env.Add('Low disk space') }
        else { Add-Finding -Category $cat -Title "$freeGB GB free on $env:SystemDrive" -Classification OK }
    } catch {}
    if (Test-IsAdmin) {
        $re = (& "$env:SystemRoot\System32\reagentc.exe" /info 2>$null) -join "`n"
        if ($re -match '(?im)Windows RE status:\s*Disabled') {
            Add-Finding -Category $cat -Title 'Windows Recovery Environment (WinRE) is disabled' -Severity Low -Classification Ambiguous `
                -Detail 'Causes 0x80070643 for WinRE security updates. Often disabled during disk resizing; ransomware also disables recovery (reagentc /disable).' -Tags 'WU-Env'
        }
    }
}

# ===========================================================================
Invoke-Check -Name 'Update-blocking and "debloat" tools' -ScriptBlock {
    $namePattern = '(?i)(windows update blocker|wub|stopupdates10|wu10man|wumgr|update manager for windows|o&o shutup|shutup10|windows10debloater|win10tweaker|winaero tweaker|sophia script|winutil|wumt|windows update minitool|blackbird|tron script|privatezilla|debloat|atlas ?os|revios|tiny11|ghost spectre)'
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -match $namePattern } | ForEach-Object { $found.Add("Installed: $($_.DisplayName)") }
    }
    $fileNames = '(?i)^(wub(_x64)?\.exe|stopupdates10.*\.exe|wu10man.*\.exe|wumgr.*\.exe|oosu10\.exe|wumt_x(64|86)\.exe|winutil\.ps1|blackbird\.exe|privatezilla\.exe|windows10debloater.*\.ps1)$'
    $roots = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:ProgramData", "$env:SystemDrive\")
    foreach ($r in $roots) {
        if (-not $r -or -not (Test-Path $r)) { continue }
        Get-ChildItem -Path $r -Recurse -Depth 2 -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $fileNames } |
            Select-Object -First 10 | ForEach-Object { $found.Add("File: $($_.FullName)") }
    }
    foreach ($m in "$env:SystemRoot\AtlasModules", "$env:SystemRoot\AtlasDesktop", "$env:SystemRoot\ReviOS") { if (Test-Path $m) { $found.Add("Modified Windows build marker: $m") } }
    if ($found.Count) {
        $diag.TweakTool = $true
        Add-Finding -Category $cat -Title "Update-blocking / debloat tool traces found ($($found.Count))" -Severity Info -Classification Info `
            -Detail 'These tools disable services, add policies, lock permissions and edit hosts on purpose. If one was used, the matching "suspicious" findings above are probably its doing, not an attacker''s. Verify the timing matches.' `
            -Evidence ($found -join "`n") -Tags 'TweakTool'
    } else { Add-Finding -Category $cat -Title 'No known update-blocking or debloat tools found' -Classification OK }

    foreach ($t in @(@{ P = '\Microsoft\Windows\UpdateOrchestrator\'; N = 'Schedule Scan' }, @{ P = '\Microsoft\Windows\WindowsUpdate\'; N = 'Scheduled Start' }, @{ P = '\Microsoft\Windows\WaaSMedic\'; N = 'PerformRemediation' })) {
        $task = Get-ScheduledTask -TaskPath $t.P -TaskName $t.N -ErrorAction SilentlyContinue
        if ($task -and $task.State -eq 'Disabled') {
            Add-Finding -Category $cat -Title "Update task '$($t.P)$($t.N)' is disabled" -Severity Medium -Classification Suspicious `
                -Detail 'Windows does not disable this task itself.' -Tags 'WU-Tamper'
            $diag.Tamper.Add("Task $($t.N) disabled")
        }
    }
    if ($mgmt.ThirdPartyAV.Count) {
        Add-Finding -Category $cat -Title "Third-party antivirus installed: $($mgmt.ThirdPartyAV -join ', ')" -Classification Info `
            -Detail 'Third-party AV can lock files mid-update (0x80070020) or inspect TLS. Temporarily disabling its web/file shield is a valid troubleshooting step.' -Tags 'WU-Env'
    }
}

# ===========================================================================
# Final diagnosis
# ===========================================================================
$tamper = @($diag.Tamper | Select-Object -Unique)
$envs   = @($diag.Env | Select-Object -Unique)
if ($tamper.Count -and $diag.TweakTool) {
    $t = 'Updates appear to be blocked deliberately, and an update-blocking/debloat tool is present'
    $d = "Tamper signs: $($tamper -join '; '). A tweak tool was found, which explains these if you (or the PC's previous owner) ran it. If nobody remembers running it, or the Compromise sweep also has findings, treat it as malicious."
    $sev = 'Medium'; $cls = 'Suspicious'
} elseif ($tamper.Count) {
    $t = 'Updates appear to be deliberately blocked or tampered with'
    $d = "Tamper signs: $($tamper -join '; '). No management system or tweak tool explains them. Run Test-CompromiseIndicators.ps1 (or Invoke-WinDiag.ps1) before repairing anything."
    $sev = 'High'; $cls = 'Suspicious'
    if (@($script:WDFindings | Where-Object { $_.Classification -eq 'Malicious' }).Count) { $sev = 'Critical'; $cls = 'Malicious' }
} elseif ($envs.Count) {
    $t = 'Update problems match ordinary causes, not tampering'
    $d = "Likely causes: $($envs -join '; '). Fix these first."
    $sev = 'Low'; $cls = 'Benign'
} elseif ($diag.Failures) {
    $t = 'Update failures found, cause not determined'
    $d = 'No tampering signs and no obvious environmental cause. Try: DISM /Online /Cleanup-Image /RestoreHealth, sfc /scannow, restart, retry. Re-run with -DeepScan.'
    $sev = 'Low'; $cls = 'Ambiguous'
} else {
    $t = 'Windows Update looks healthy'; $d = 'No failures, tampering or environmental problems found.'; $sev = 'Info'; $cls = 'OK'
}
$script:WDQuiet = $true
Add-Finding -Category 'Diagnosis' -Title $t -Severity $sev -Classification $cls -Detail $d -Tags 'Diagnosis'
$script:WDQuiet = [bool]$Quiet

$findings = @(Get-Findings)
if (-not $Quiet) {
    Write-Host "`nDIAGNOSIS: $t" -ForegroundColor $(switch ($cls) { 'Malicious' {'Magenta'} 'Suspicious' {'Red'} 'Benign' {'Cyan'} 'OK' {'Green'} default {'Yellow'} })
    Write-Host "  $d"
}
if (-not $NoReport) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $paths = Export-WinDiagReport -Findings $findings -OutputDir $OutputDir -BaseName "WindowsUpdateHealth-$env:COMPUTERNAME-$stamp" -Title "Windows Update health - $env:COMPUTERNAME" -Inventory (Get-Inventory)
    if (-not $Quiet) { Write-Host "`nReport: $($paths.Html)" -ForegroundColor Green }
}
if ($PassThru) { return @($findings) + @(Get-Inventory) }
