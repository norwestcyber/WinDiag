#Requires -Version 5.1
<#
    Common.ps1 - shared helpers for the WinDiag toolkit.
    Dot-source this file; do not run it directly.

    Every check is READ-ONLY. Nothing in this toolkit changes services, registry,
    files, firewall rules or Defender settings. It only reads and reports.

    Finding classifications
      OK         - check ran and found nothing wrong
      Info       - context / posture information
      Benign     - an ordinary environmental cause (disk, network, corruption, reboot)
      Ambiguous  - could be environmental OR tampering; needs correlation
      Suspicious - pattern associated with tampering, but legitimate explanations exist
                   (management tools, "debloat"/update-blocker utilities, corporate proxies)
      Malicious  - strong indicator that is rarely legitimate
#>

if ([Environment]::OSVersion.Platform -ne 'Win32NT' -and -not $env:WINDIAG_TEST) { throw 'WinDiag runs on Windows only.' }

$script:WinDiagVersion = '1.3.0'
$script:SeverityRank   = @{ Info = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
$script:WDFindings     = New-Object System.Collections.Generic.List[object]
$script:WDInventory    = New-Object System.Collections.Generic.List[object]
$script:WDSigCache     = @{}
$script:WDMgmtContext  = $null
if (-not (Get-Variable -Name WDQuiet -Scope Script -ErrorAction SilentlyContinue)) { $script:WDQuiet = $false }

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-DefaultOutputDir {
    $desk = [Environment]::GetFolderPath('Desktop')
    if ($desk -and (Test-Path $desk)) { return (Join-Path $desk 'WinDiag-Reports') }
    $base = if ($env:TEMP) { $env:TEMP } else { (Get-Location).Path }
    return (Join-Path $base 'WinDiag-Reports')
}

function Get-SystemInfoSummary {
    $os = $null; $cs = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch {}
    try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch {}
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $build = ''
    if ($cv) { $build = '{0}.{1}' -f $cv.CurrentBuild, $cv.UBR }
    [pscustomobject][ordered]@{
        ComputerName = $env:COMPUTERNAME
        User         = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
        IsAdmin      = Test-IsAdmin
        OS           = if ($os) { $os.Caption } else { '' }
        DisplayVer   = if ($cv) { $cv.DisplayVersion } else { '' }
        Build        = $build
        LastBoot     = if ($os) { $os.LastBootUpTime } else { $null }
        Domain       = if ($cs) { $cs.Domain } else { '' }
        PartOfDomain = if ($cs) { [bool]$cs.PartOfDomain } else { $false }
        RunTime      = Get-Date
        ToolVersion  = $script:WinDiagVersion
        PSVersion    = $PSVersionTable.PSVersion.ToString()
    }
}

function Get-ManagementContext {
    <# Works out whether this machine is managed. Management explains many
       "suspicious" settings (WSUS servers, disabled auto-update, proxies). #>
    if ($script:WDMgmtContext) { return $script:WDMgmtContext }
    $ctx = [ordered]@{
        PartOfDomain = $false; Domain = ''; AzureAdJoined = $false; MdmEnrolled = $false
        SccmClient = $false; WsusConfigured = $false; ThirdPartyAV = @(); IsManaged = $false
    }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $ctx.PartOfDomain = [bool]$cs.PartOfDomain; $ctx.Domain = $cs.Domain
    } catch {}
    try {
        $ds = & "$env:SystemRoot\System32\dsregcmd.exe" /status 2>$null
        if ($ds -match 'AzureAdJoined\s*:\s*YES') { $ctx.AzureAdJoined = $true }
    } catch {}
    try {
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and $p.PSObject.Properties['ProviderID'] -and $p.ProviderID -eq 'MS DM Server') { $ctx.MdmEnrolled = $true }
        }
    } catch {}
    if (Get-Service -Name CcmExec -ErrorAction SilentlyContinue) { $ctx.SccmClient = $true }
    $wu = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
    if ($wu -and $wu.PSObject.Properties['WUServer'] -and $wu.WUServer) { $ctx.WsusConfigured = $true }
    try {
        $av = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
        $ctx.ThirdPartyAV = @($av | Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' } |
                              Select-Object -ExpandProperty displayName -Unique)
    } catch {}
    $ctx.IsManaged = ($ctx.PartOfDomain -or $ctx.AzureAdJoined -or $ctx.MdmEnrolled -or $ctx.SccmClient)
    $script:WDMgmtContext = [pscustomobject]$ctx
    return $script:WDMgmtContext
}

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
function ConvertTo-EvidenceText {
    param($Evidence)
    if ($null -eq $Evidence) { return '' }
    if ($Evidence -is [string]) { return $Evidence }
    try { return ($Evidence | Format-List * | Out-String -Width 400).Trim() } catch { return [string]$Evidence }
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Info','Low','Medium','High','Critical')][string]$Severity = 'Info',
        [ValidateSet('OK','Info','Benign','Ambiguous','Suspicious','Malicious')][string]$Classification = 'Info',
        [string]$Detail = '',
        $Evidence = $null,
        [string]$Recommendation = '',
        [string[]]$Tags = @()
    )
    $f = [pscustomobject][ordered]@{
        Time           = Get-Date
        Category       = $Category
        Severity       = $Severity
        Classification = $Classification
        Title          = $Title
        Detail         = $Detail
        Evidence       = ConvertTo-EvidenceText $Evidence
        Recommendation = $Recommendation
        Tags           = ($Tags -join ',')
    }
    $script:WDFindings.Add($f)
    if (-not $script:WDQuiet) {
        $color = switch ($Severity) { 'Critical' {'Magenta'} 'High' {'Red'} 'Medium' {'Yellow'} 'Low' {'Cyan'} default {'Gray'} }
        if ($Classification -eq 'OK') { $color = 'DarkGreen' }
        $tag = if ($Classification -eq 'OK') { 'OK' } else { $Severity.ToUpper() }
        Write-Host ('  [{0,-8}] {1}' -f $tag, $Title) -ForegroundColor $color
    }
}

function Get-Findings { return $script:WDFindings.ToArray() }

function Add-Inventory {
    <# A full listing (e.g. every service) shown as a filterable table after the findings and saved as its
       own CSV. Rows whose FlagColumn is non-empty are highlighted. #>
    param([Parameter(Mandatory)][string]$Name, [string]$Description = '', [object[]]$Rows = @(), [string]$FlagColumn = '')
    $script:WDInventory.Add([pscustomobject]@{ InventoryName = $Name; Description = $Description; FlagColumn = $FlagColumn; Rows = @($Rows) })
}

function Get-Inventory { return $script:WDInventory.ToArray() }

function Invoke-Check {
    <# Runs one check block; a failure in one check never stops the others. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$ScriptBlock, [switch]$RequiresAdmin)
    if (-not $script:WDQuiet) { Write-Host "`n> $Name" -ForegroundColor White }
    if ($RequiresAdmin -and -not (Test-IsAdmin)) {
        Add-Finding -Category $Name -Title "$Name skipped: needs an elevated (Administrator) PowerShell" -Severity Info -Classification Info
        return
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try { & $ScriptBlock }
    catch {
        if ($_.FullyQualifiedErrorId -match 'ScriptContainedMaliciousContent') {
            # Antivirus (AMSI) judged the check's own detection code to look like the attack it detects
            Add-Finding -Category $Name -Title "$Name check was blocked by antivirus (AMSI)" -Severity Low -Classification Info `
                -Detail 'The antivirus refused to run this check because its detection code resembles the technique it looks for. The rest of the scan is unaffected; this one area was not checked.' `
                -Evidence ($_.ScriptStackTrace)
        } else {
            Add-Finding -Category $Name -Title "$Name check could not complete" -Severity Info -Classification Info `
                -Detail $_.Exception.Message -Evidence ($_.ScriptStackTrace)
        }
    }
    $sw.Stop()
    if (-not $script:WDQuiet) { Write-Host ('    ({0:n1}s)' -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray }
}

# ---------------------------------------------------------------------------
# File / signature helpers
# ---------------------------------------------------------------------------
function Get-FileSignatureInfo {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $key = $Path.ToLowerInvariant()
    if ($script:WDSigCache.ContainsKey($key)) { return $script:WDSigCache[$key] }
    $info = [pscustomobject][ordered]@{
        Path = $Path; Exists = $false; Status = 'Missing'; Signer = ''; IsMicrosoft = $false; IsOSBinary = $false
        Company = ''; OriginalFilename = ''; FileVersion = ''; Created = $null; Modified = $null; Size = 0
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue) {
        $info.Exists = $true
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $info.Status = [string]$sig.Status
            if ($sig.SignerCertificate) { $info.Signer = $sig.SignerCertificate.Subject }
            if ($sig.PSObject.Properties['IsOSBinary']) { $info.IsOSBinary = [bool]$sig.IsOSBinary }
        } catch { $info.Status = 'Error' }
        $info.IsMicrosoft = ($info.Status -eq 'Valid' -and ($info.Signer -match 'O=Microsoft Corporation' -or $info.IsOSBinary))
        try {
            $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
            $info.Created = $fi.CreationTime; $info.Modified = $fi.LastWriteTime; $info.Size = $fi.Length
            $vi = $fi.VersionInfo
            if ($vi) { $info.Company = $vi.CompanyName; $info.OriginalFilename = $vi.OriginalFilename; $info.FileVersion = $vi.FileVersion }
        } catch {}
    }
    $script:WDSigCache[$key] = $info
    return $info
}

function Get-Sha256 {
    param([string]$Path)
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return '' }
}

function Expand-WinPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $p = [Environment]::ExpandEnvironmentVariables($Path.Trim())
    $p = $p -replace '^\\\?\?\\', ''
    $p = $p -replace '^(?i)\\SystemRoot\\', ($env:SystemRoot + '\')
    $p = $p -replace '^(?i)SystemRoot\\', ($env:SystemRoot + '\')
    if ($p -match '^(?i)system32\\') { $p = Join-Path $env:SystemRoot $p }
    return $p
}

function Resolve-CommandPath {
    <# Extracts the executable path from a command line (quoted, unquoted with spaces, or bare name). #>
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $cmd = Expand-WinPath $CommandLine
    $path = $null
    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        if ($end -gt 1) { $path = $cmd.Substring(1, $end - 1) }
    } else {
        $parts = $cmd -split ' '
        for ($i = 0; $i -lt [Math]::Min($parts.Count, 12); $i++) {
            $candidate = ($parts[0..$i] -join ' ')
            if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) { $path = $candidate; break }
            if (Test-Path -LiteralPath "$candidate.exe" -PathType Leaf -ErrorAction SilentlyContinue) { $path = "$candidate.exe"; break }
        }
        if (-not $path) { $path = $parts[0] }
    }
    if ($path -and -not [IO.Path]::IsPathRooted($path)) {
        $sys = Join-Path "$env:SystemRoot\System32" $path
        if (Test-Path -LiteralPath $sys -PathType Leaf -ErrorAction SilentlyContinue) { $path = $sys }
        elseif (Test-Path -LiteralPath "$sys.exe" -PathType Leaf -ErrorAction SilentlyContinue) { $path = "$sys.exe" }
        else {
            $gc = Get-Command $path -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($gc) { $path = $gc.Source }
        }
    }
    return $path
}

function Get-HostedPayloadPath {
    <# For LOLBin hosts (rundll32, regsvr32, wscript, cscript, mshta, powershell -File)
       returns the file they actually load, which is what needs judging. #>
    param([string]$CommandLine, [string]$ExePath)
    if (-not $CommandLine -or -not $ExePath) { return $null }
    $exe = [IO.Path]::GetFileName($ExePath).ToLowerInvariant()
    if ($exe -notin @('rundll32.exe','regsvr32.exe','wscript.exe','cscript.exe','mshta.exe','powershell.exe','pwsh.exe')) { return $null }
    $cmd = Expand-WinPath $CommandLine
    $idx = $cmd.IndexOf($exe, [StringComparison]::OrdinalIgnoreCase)
    if ($idx -lt 0) { return $null }
    $rest = $cmd.Substring($idx + $exe.Length).TrimStart('"', ' ')
    if ($exe -in @('powershell.exe','pwsh.exe')) {
        if ($rest -match '(?i)-f(ile)?\s+("([^"]+)"|(\S+))') { if ($Matches[3]) { return $Matches[3] } else { return $Matches[4] } }
        return $null
    }
    $tokens = [regex]::Matches($rest, '"[^"]+"|\S+') | ForEach-Object { $_.Value.Trim('"') }
    foreach ($t in $tokens) {
        if ($t -match '^[/-]') { continue }
        $t = ($t -split ',')[0]
        if ($t -match '^(?i)(javascript|vbscript|https?):') { return $t }
        $t = Expand-WinPath $t
        if (-not [IO.Path]::IsPathRooted($t)) {
            foreach ($cand in @((Join-Path "$env:SystemRoot\System32" $t), (Join-Path "$env:SystemRoot\System32" "$t.dll"))) {
                if (Test-Path -LiteralPath $cand -PathType Leaf -ErrorAction SilentlyContinue) { return $cand }
            }
        }
        return $t
    }
    return $null
}

function Test-UserWritablePath {
    <# Locations ordinary users can write to. Legit software lives here too
       (Teams, Discord, browsers), so this is a weight, not a verdict. #>
    param([string]$Path)
    if (-not $Path) { return $false }
    $patterns = @(
        '\\AppData\\', '\\Temp\\', '\\Tmp\\', '^[A-Za-z]:\\Users\\Public\\', '\\Downloads\\', '\\Desktop\\',
        '\\Documents\\', '\\Music\\', '\\Pictures\\', '\\Videos\\', '\$Recycle\.Bin', '^[A-Za-z]:\\PerfLogs',
        '^[A-Za-z]:\\Windows\\Tasks\\', '^[A-Za-z]:\\Windows\\Tracing\\', '^[A-Za-z]:\\Windows\\Temp\\',
        '^[A-Za-z]:\\Windows\\debug\\', '^[A-Za-z]:\\ProgramData\\[^\\]+$', '^[A-Za-z]:\\[^\\]+\.(exe|dll|scr|bat|ps1|vbs|js)$'
    )
    foreach ($p in $patterns) { if ($Path -match $p) { return $true } }
    return $false
}

function Get-CommandLineRisk {
    <# Returns reasons a command line looks like attacker tradecraft, with a weight (1-3). #>
    param([string]$CommandLine)
    $hits = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return }
    $rules = @(
        @{ W = 3; R = 'Encoded PowerShell command';         P = '(?i)\s-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{24,}' }
        @{ W = 2; R = 'Invoke-Expression';                  P = '(?i)\b(iex|invoke-expression)\b' }
        @{ W = 3; R = 'Downloads and runs content';         P = '(?i)(downloadstring|downloadfile|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|start-bitstransfer)' }
        @{ W = 2; R = 'Base64 decoding';                    P = '(?i)frombase64string' }
        @{ W = 1; R = 'Hidden window';                      P = '(?i)-w(in|indowstyle)?\s+h(idden)?\b' }
        @{ W = 3; R = 'mshta running remote/inline script'; P = '(?i)mshta(\.exe)?["\s]+.*(https?:|javascript:|vbscript:)' }
        @{ W = 3; R = 'rundll32 script/URL abuse';          P = '(?i)rundll32(\.exe)?["\s]+.*(javascript:|url\.dll|shell32\.dll,\s*shellexec_rundll|mshtml)' }
        @{ W = 3; R = 'regsvr32 remote scriptlet (Squiblydoo)'; P = '(?i)regsvr32.*(/i:\s*https?|scrobj\.dll)' }
        @{ W = 3; R = 'certutil download/decode';           P = '(?i)certutil(\.exe)?["\s]+.*(-urlcache|-decode|-decodehex|-split)' }
        @{ W = 2; R = 'bitsadmin transfer/notify';          P = '(?i)bitsadmin.*(/transfer|/addfile|/setnotifycmdline)' }
        @{ W = 2; R = 'WMI process creation';               P = '(?i)wmic.*process\s+call\s+create' }
        @{ W = 2; R = 'URL with raw IP address';            P = '(?i)https?://\d{1,3}(\.\d{1,3}){3}' }
        @{ W = 3; R = 'Deletes shadow copies/backups (ransomware)'; P = '(?i)(vssadmin.*delete|wbadmin.*delete|shadowcopy\s+delete|bcdedit.*(recoveryenabled\s+no|ignoreallfailures))' }
        @{ W = 3; R = 'Weakens Defender';                   P = '(?i)(add-mppreference.*exclusion|set-mppreference.*-disable|disableantispyware|disablerealtimemonitoring)' }
        @{ W = 2; R = 'Script host running file from user-writable path'; P = '(?i)(wscript|cscript)(\.exe)?["\s]+.*\\(appdata|temp|users\\public|downloads)\\' }
        @{ W = 1; R = 'Runs from user-writable path';       P = '(?i)\\(appdata\\roaming|appdata\\local\\temp|users\\public|windows\\temp|programdata)\\[^\\]+\.(exe|dll|ps1|vbs|js|bat|cmd|hta)' }
        @{ W = 2; R = 'PowerShell with -nop and hidden/bypass'; P = '(?i)powershell.*-nop.*(-w\s*h|bypass)' }
        @{ W = 2; R = 'Disables UAC/firewall/logging';      P = '(?i)(enablelua.*\b0\b|netsh\s+(adv)?firewall\s+set.*(off|disable)|wevtutil\s+cl|clear-eventlog)' }
    )
    foreach ($r in $rules) { if ($CommandLine -match $r.P) { $hits.Add([pscustomobject]@{ Reason = $r.R; Weight = $r.W }) } }
    return $hits.ToArray()
}

function Get-RiskSeverity {
    <# Turns signals about a binary/command into a severity + classification. #>
    param($SigInfo, [object[]]$CmdRisk = @(), [switch]$UserWritable, [switch]$MasqueradeName)
    $score = 0
    $reasons = New-Object System.Collections.Generic.List[string]
    foreach ($c in $CmdRisk) { $score += $c.Weight; $reasons.Add($c.Reason) }
    if ($SigInfo) {
        if (-not $SigInfo.Exists) { $score += 1; $reasons.Add('Target file missing') }
        elseif ($SigInfo.Status -eq 'HashMismatch') { $score += 3; $reasons.Add('Signature hash mismatch (file altered after signing)') }
        elseif ($SigInfo.Status -ne 'Valid') { $score += 1; $reasons.Add("Not validly signed ($($SigInfo.Status))") }
    }
    if ($UserWritable) {
        $score += 1; $reasons.Add('Located in user-writable folder')
        if ($SigInfo -and $SigInfo.Exists -and $SigInfo.Status -ne 'Valid') { $score += 1 }
    }
    if ($MasqueradeName) { $score += 3; $reasons.Add('System binary name in unexpected location') }
    $sev = 'Info'; $cls = 'OK'
    if ($score -ge 6)     { $sev = 'High';   $cls = 'Malicious' }
    elseif ($score -ge 4) { $sev = 'High';   $cls = 'Suspicious' }
    elseif ($score -ge 3) { $sev = 'Medium'; $cls = 'Suspicious' }
    elseif ($score -ge 2) { $sev = 'Low';    $cls = 'Ambiguous' }
    elseif ($score -ge 1) { $sev = 'Info';   $cls = 'Info' }
    [pscustomobject]@{ Score = $score; Severity = $sev; Classification = $cls; Reasons = ($reasons -join '; ') }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $p = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $p.$Name
    } catch { return $null }
}

function Get-UserHives {
    <# Loaded user registry hives (other users' hives are readable only when elevated). #>
    Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
        ForEach-Object {
            $name = $_.PSChildName
            try { $name = (New-Object Security.Principal.SecurityIdentifier($_.PSChildName)).Translate([Security.Principal.NTAccount]).Value } catch {}
            [pscustomobject]@{ Sid = $_.PSChildName; User = $name; Root = "Registry::HKEY_USERS\$($_.PSChildName)" }
        }
}

function Get-UserProfilePaths {
    try { Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special -and $_.LocalPath -and (Test-Path $_.LocalPath -ErrorAction SilentlyContinue) } | Select-Object -ExpandProperty LocalPath }
    catch { @($env:USERPROFILE) }
}

function Get-RecentEvents {
    <# Get-WinEvent wrapper that returns nothing (instead of throwing) when no events match. #>
    param([hashtable]$Filter, [int]$Max = 200)
    try { return @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
    catch { return @() }
}

# ---------------------------------------------------------------------------
# Verdict + reporting
# ---------------------------------------------------------------------------
function Get-WinDiagVerdict {
    param([object[]]$Findings)
    $mal  = @($Findings | Where-Object { $_.Classification -eq 'Malicious' -and $script:SeverityRank[$_.Severity] -ge 3 })
    $susH = @($Findings | Where-Object { $_.Classification -eq 'Suspicious' -and $script:SeverityRank[$_.Severity] -ge 3 })
    $susM = @($Findings | Where-Object { $_.Classification -eq 'Suspicious' -and $script:SeverityRank[$_.Severity] -eq 2 })
    $ben  = @($Findings | Where-Object { $_.Classification -in @('Benign','Ambiguous') -and $script:SeverityRank[$_.Severity] -ge 2 })
    if ($mal.Count -gt 0) {
        $v = 'COMPROMISE INDICATORS FOUND'; $lvl = 'Critical'
        $txt = "$($mal.Count) strong indicator(s) were found. Treat this machine as potentially compromised: disconnect it from the network, preserve the report, and investigate or reimage before trusting it."
    } elseif ($susH.Count -gt 0 -or $susM.Count -ge 3) {
        $v = 'SUSPICIOUS - INVESTIGATE'; $lvl = 'High'
        $txt = "$($susH.Count + $susM.Count) finding(s) look like deliberate tampering. Each has possible legitimate explanations (management tools, update blockers, corporate proxies); confirm who made each change before ruling out an attacker."
    } elseif ($susM.Count -gt 0) {
        $v = 'MINOR ANOMALIES'; $lvl = 'Medium'
        $txt = 'A small number of unusual settings were found. Review them, but nothing points strongly to compromise.'
    } elseif ($ben.Count -gt 0) {
        $v = 'ENVIRONMENTAL ISSUES - NO TAMPERING INDICATORS'; $lvl = 'Low'
        $txt = 'Problems were found, but they match ordinary causes (connectivity, disk, corruption, pending reboot) rather than tampering.'
    } else {
        $v = 'NO SIGNIFICANT ISSUES'; $lvl = 'Info'
        $txt = 'No problems or tampering indicators were found by these checks. This does not prove the machine is clean; it means these common signals are absent.'
    }
    [pscustomobject]@{ Verdict = $v; Level = $lvl; Summary = $txt
        Malicious = $mal.Count; SuspiciousHigh = $susH.Count; SuspiciousMedium = $susM.Count; Environmental = $ben.Count }
}

function ConvertTo-HtmlText { param([string]$s) if ($null -eq $s) { return '' } return [System.Net.WebUtility]::HtmlEncode($s) }

function Export-WinDiagReport {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory)][string]$OutputDir,
        [Parameter(Mandatory)][string]$BaseName,
        [string]$Title = 'WinDiag report',
        [string[]]$Notes = @(),
        $SystemInfo = $null,
        $Verdict = $null,
        [object[]]$Inventory = @()
    )
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    if (-not $SystemInfo) { $SystemInfo = Get-SystemInfoSummary }
    if (-not $Verdict)    { $Verdict = Get-WinDiagVerdict $Findings }

    $sorted = $Findings | Sort-Object @{ e = { $script:SeverityRank[$_.Severity] }; Descending = $true },
                                     @{ e = { @{Malicious=5;Suspicious=4;Ambiguous=3;Benign=2;Info=1;OK=0}[$_.Classification] }; Descending = $true },
                                     Category, Title

    $json = Join-Path $OutputDir "$BaseName.json"
    $csv  = Join-Path $OutputDir "$BaseName.csv"
    $html = Join-Path $OutputDir "$BaseName.html"

    $Inventory = @($Inventory | Where-Object { $_ -and @($_.Rows).Count })
    [pscustomobject]@{ System = $SystemInfo; Verdict = $Verdict; Notes = $Notes; Findings = $sorted
                       Inventory = @($Inventory | ForEach-Object { [pscustomobject]@{ Name = $_.InventoryName; Description = $_.Description; Rows = @($_.Rows) } }) } |
        ConvertTo-Json -Depth 5 | Set-Content -Path $json -Encoding UTF8
    $sorted | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    $invCsv = foreach ($inv in $Inventory) {
        $p = Join-Path $OutputDir ("$BaseName-$($inv.InventoryName -replace '[^\w-]', '').csv")
        @($inv.Rows) | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8
        $p
    }

    $invHtml = foreach ($inv in $Inventory) {
        $rowsIn = @($inv.Rows)
        $cols = @($rowsIn[0].PSObject.Properties.Name)
        $head = ($cols | ForEach-Object { "<th>$(ConvertTo-HtmlText $_)</th>" }) -join ''
        $flagN = 0
        $body = foreach ($r in $rowsIn) {
            $isFlag = $inv.FlagColumn -and [string]$r.($inv.FlagColumn)
            if ($isFlag) { $flagN++ }
            $cells = foreach ($col in $cols) { "<td$(if ($col -match '(?i)path|line') { " class='p'" })>$(ConvertTo-HtmlText ([string]$r.$col))</td>" }
            "<tr$(if ($isFlag) { " class='flag'" })>$($cells -join '')</tr>"
        }
        $flagBox = ''
        if ($inv.FlagColumn) { $flagBox = "<label><input type='checkbox' class='invflag'> Flagged only ($flagN)</label>" }
        @"
<section class="inv"><h2>$(ConvertTo-HtmlText $inv.InventoryName) <span class="n">($($rowsIn.Count))</span></h2>
<div class="d">$(ConvertTo-HtmlText $inv.Description)</div>
<div class="invbar"><input type="search" class="invfilter" placeholder="Filter rows" aria-label="Filter $(ConvertTo-HtmlText $inv.InventoryName)">$flagBox<span>Click a column to sort.</span></div>
<div class="tw"><table class="invt"><thead><tr>$head</tr></thead><tbody>
$($body -join "`n")
</tbody></table></div></section>
"@
    }

    $counts = foreach ($s in 'Critical','High','Medium','Low','Info') {
        $n = @($sorted | Where-Object { $_.Severity -eq $s -and $_.Classification -ne 'OK' }).Count
        "<div class='count sev-$($s.ToLower())'><b>$n</b><span>$s</span></div>"
    }
    $okCount = @($sorted | Where-Object { $_.Classification -eq 'OK' }).Count

    $rows = foreach ($f in $sorted) {
        $ev = ''
        if ($f.Evidence) { $ev = "<details><summary>Evidence</summary><pre>$(ConvertTo-HtmlText $f.Evidence)</pre></details>" }
        $rec = ''
        if ($f.Recommendation) { $rec = "<div class='rec'>$(ConvertTo-HtmlText $f.Recommendation)</div>" }
        $okClass = ''
        if ($f.Classification -eq 'OK') { $okClass = ' ok' }
        @"
<tr class="sev-$($f.Severity.ToLower())$okClass" data-sev="$($f.Severity)" data-cls="$($f.Classification)">
  <td><span class="pill sev-$($f.Severity.ToLower())">$($f.Severity)</span></td>
  <td><span class="cls cls-$($f.Classification.ToLower())">$($f.Classification)</span></td>
  <td>$(ConvertTo-HtmlText $f.Category)</td>
  <td><div class="t">$(ConvertTo-HtmlText $f.Title)</div><div class="d">$(ConvertTo-HtmlText $f.Detail)</div>$rec$ev</td>
</tr>
"@
    }

    $notesHtml = ''
    if ($Notes -and $Notes.Count) {
        $notesHtml = "<section class='notes'><h2>Correlation notes</h2><ul>" +
            (($Notes | ForEach-Object { "<li>$(ConvertTo-HtmlText $_)</li>" }) -join '') + "</ul></section>"
    }
    $sysRows = ($SystemInfo.PSObject.Properties | ForEach-Object { "<tr><th>$($_.Name)</th><td>$(ConvertTo-HtmlText ([string]$_.Value))</td></tr>" }) -join ''

    $page = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(ConvertTo-HtmlText $Title)</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#5d6676;--line:#e2e5ea;--crit:#8e1b6e;--high:#c62828;--med:#b26a00;--low:#1565c0;--info:#6b7280;--ok:#2e7d32}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1c2027;--fg:#e6e8eb;--muted:#9aa3b2;--line:#2c323c;--crit:#e05bbf;--high:#ff6b6b;--med:#f0a640;--low:#64a8ff;--info:#9aa3b2;--ok:#6cc070}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 10px}.sub{color:var(--muted);margin-bottom:18px}
.verdict{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--info);border-radius:8px;padding:16px;margin-bottom:16px}
.verdict.lvl-critical{border-left-color:var(--crit)}.verdict.lvl-high{border-left-color:var(--high)}.verdict.lvl-medium{border-left-color:var(--med)}.verdict.lvl-low{border-left-color:var(--low)}.verdict.lvl-info{border-left-color:var(--ok)}
.verdict b{font-size:18px;display:block;margin-bottom:4px}
.counts{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}.count{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:96px}
.count b{font-size:20px;display:block}.count span{color:var(--muted);font-size:12px}
.count.sev-critical b{color:var(--crit)}.count.sev-high b{color:var(--high)}.count.sev-medium b{color:var(--med)}.count.sev-low b{color:var(--low)}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:16px;overflow-x:auto}
.notes li{margin-bottom:6px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;padding:8px;border-bottom:1px solid var(--line)}
.sys th{width:160px;color:var(--muted);font-weight:500}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff;background:var(--info)}
.pill.sev-critical{background:var(--crit)}.pill.sev-high{background:var(--high)}.pill.sev-medium{background:var(--med)}.pill.sev-low{background:var(--low)}
.cls{font-size:12px;font-weight:600}.cls-malicious{color:var(--crit)}.cls-suspicious{color:var(--high)}.cls-ambiguous{color:var(--med)}.cls-benign{color:var(--low)}.cls-ok{color:var(--ok)}.cls-info{color:var(--muted)}
.t{font-weight:600}.d{color:var(--muted);margin-top:2px}.rec{margin-top:6px;padding:6px 8px;border-radius:6px;background:color-mix(in srgb,var(--low) 10%,transparent)}
pre{white-space:pre-wrap;word-break:break-word;font:12px/1.4 Consolas,monospace;background:var(--bg);padding:8px;border-radius:6px;max-height:360px;overflow:auto}
summary{cursor:pointer;color:var(--muted);margin-top:6px}
.filters{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:10px;color:var(--muted)}
tr.ok.hidden{display:none}
.inv .d{color:var(--muted);margin-bottom:8px}.inv .n{color:var(--muted);font-weight:400}
.invbar{display:flex;gap:14px;flex-wrap:wrap;align-items:center;margin-bottom:8px;color:var(--muted)}
.invbar input[type=search]{padding:5px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);min-width:220px;font:inherit}
.tw{max-height:640px;overflow:auto}
table.invt th{cursor:pointer;white-space:nowrap;position:sticky;top:0;background:var(--card);z-index:1}
table.invt th[data-dir=asc]:after{content:" \25B2"}table.invt th[data-dir=desc]:after{content:" \25BC"}
table.invt td{font-size:12px}table.invt td.p{font:12px/1.4 Consolas,monospace;word-break:break-all;min-width:220px}
table.invt tr.flag td{background:color-mix(in srgb,var(--high) 12%,transparent)}
</style></head><body><main>
<h1>$(ConvertTo-HtmlText $Title)</h1>
<div class="sub">$(ConvertTo-HtmlText $SystemInfo.ComputerName) &middot; $(ConvertTo-HtmlText ([string]$SystemInfo.RunTime)) &middot; WinDiag $script:WinDiagVersion &middot; read-only scan$(if (-not $SystemInfo.IsAdmin) { ' &middot; <b>NOT elevated: some checks were skipped</b>' })</div>
<div class="verdict lvl-$($Verdict.Level.ToLower())"><b>$(ConvertTo-HtmlText $Verdict.Verdict)</b>$(ConvertTo-HtmlText $Verdict.Summary)</div>
<div class="counts">$($counts -join '')<div class="count"><b style="color:var(--ok)">$okCount</b><span>Checks passed</span></div></div>
$notesHtml
<section><h2>Findings</h2>
<div class="filters"><label><input type="checkbox" id="showok"> Show passed checks</label></div>
<table><thead><tr><th>Severity</th><th>Type</th><th>Area</th><th>Finding</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table></section>
$($invHtml -join "`n")
<section><h2>System</h2><table class="sys">$sysRows</table></section>
</main>
<script>
(function(){var cb=document.getElementById('showok');function apply(){document.querySelectorAll('tr.ok').forEach(function(r){r.classList.toggle('hidden',!cb.checked)})}cb.addEventListener('change',apply);apply();})();
document.querySelectorAll('section.inv').forEach(function(sec){
  var q=sec.querySelector('input.invfilter'),fl=sec.querySelector('input.invflag'),tb=sec.querySelector('tbody'),n=sec.querySelector('.n'),rows=[].slice.call(tb.rows);
  function apply(){var t=q.value.toLowerCase(),only=fl&&fl.checked,k=0;rows.forEach(function(r){var m=(!t||r.textContent.toLowerCase().indexOf(t)>=0)&&(!only||r.classList.contains('flag'));r.style.display=m?'':'none';if(m)k++});n.textContent='('+(k===rows.length?k:k+' of '+rows.length)+')'}
  q.addEventListener('input',apply);if(fl)fl.addEventListener('change',apply);
  sec.querySelectorAll('th').forEach(function(th,i){th.addEventListener('click',function(){var asc=th.dataset.dir!=='asc';sec.querySelectorAll('th').forEach(function(h){delete h.dataset.dir});th.dataset.dir=asc?'asc':'desc';
    rows.sort(function(a,b){var x=a.cells[i].textContent,y=b.cells[i].textContent,nx=parseFloat(x),ny=parseFloat(y),c=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y,undefined,{sensitivity:'base'});return asc?c:-c});
    rows.forEach(function(r){tb.appendChild(r)})})})
});
</script></body></html>
"@
    Set-Content -Path $html -Value $page -Encoding UTF8
    [pscustomobject]@{ Html = $html; Json = $json; Csv = $csv; InventoryCsv = @($invCsv) }
}

function Write-WinDiagSummary {
    param([object[]]$Findings, $Verdict)
    if (-not $Verdict) { $Verdict = Get-WinDiagVerdict $Findings }
    $color = switch ($Verdict.Level) { 'Critical' {'Magenta'} 'High' {'Red'} 'Medium' {'Yellow'} 'Low' {'Cyan'} default {'Green'} }
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host " VERDICT: $($Verdict.Verdict)" -ForegroundColor $color
    Write-Host " $($Verdict.Summary)"
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    $top = $Findings | Where-Object { $_.Classification -notin @('OK','Info') -and $script:SeverityRank[$_.Severity] -ge 2 } |
           Sort-Object @{ e = { $script:SeverityRank[$_.Severity] }; Descending = $true } | Select-Object -First 15
    foreach ($f in $top) { Write-Host ('  {0,-8} {1,-10} {2}' -f $f.Severity, $f.Classification, $f.Title) }
}
