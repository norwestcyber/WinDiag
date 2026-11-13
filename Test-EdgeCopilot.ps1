#Requires -Version 5.1

<#
.SYNOPSIS
    Read-only review of Microsoft Edge and Copilot: extensions, policies, launch settings,
    native messaging hosts, Copilot apps, AI agent connectors (MCP) and network connections.

.DESCRIPTION
    Copilot in Edge sees what the browser sees, and Copilot agents can call "connectors"
    (MCP servers) that act on files, apps and settings. That makes both attractive to attackers:
      - extensions that read Copilot/ChatGPT pages (prompt and chat harvesting), steal cookies,
        proxy traffic, or take over search and the homepage
      - extensions force-installed by policy or side-loaded from outside the stores
      - Edge started with remote debugging (how info-stealers dump cookies) or with extra flags
        hidden in its shortcuts and protocol handlers
      - native messaging hosts: programs an extension can launch on this PC
      - fake "Copilot" apps and installers
      - third-party or side-loaded agent connectors, and GitHub Copilot MCP servers

    Nothing is changed. Cookies, passwords, history and Copilot conversations are never read;
    only settings files, extension manifests and extension code.

.PARAMETER Days          "Recently installed" window. Default 30.
.PARAMETER SkipCodeScan  Do not scan extension code for exfiltration patterns (faster).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Test-EdgeCopilot.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputDir = '',
    [int]$Days = 30,
    [switch]$SkipCodeScan,
    [switch]$Quiet,
    [switch]$NoReport,
    [switch]$PassThru
)

. (Join-Path $PSScriptRoot 'Common.ps1')
if (-not $OutputDir) { $OutputDir = Get-DefaultOutputDir }
$script:WDQuiet = [bool]$Quiet
$ErrorActionPreference = 'Continue'
$mgmt = Get-ManagementContext
$isAdmin = Test-IsAdmin
$recent = (Get-Date).AddDays(-$Days)

if (-not $Quiet) {
    Write-Host 'WinDiag - Edge and Copilot review  (read-only)' -ForegroundColor White
    if (-not $isAdmin) { Write-Host 'Not elevated: only your own Edge profiles and apps are checked. Run as Administrator to include other users.' -ForegroundColor Yellow }
}

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------
$storeUpdate = '^(?i)https://(edge\.microsoft\.com/extensionwebstorebase/|clients2\.google\.com/service/update2/crx)'
$broadHost   = '^(?i)(<all_urls>|(\*|https?|file)://\*/.*)$'
$aiSites     = '(?i)(copilot\.microsoft\.com|copilot\.cloud\.microsoft|m365\.cloud\.microsoft|edgeservices\.bing\.com|[/.]bing\.com/|chatgpt\.com|chat\.openai\.com|gemini\.google\.com|claude\.ai|perplexity\.ai|chat\.deepseek\.com|grok\.com|meta\.ai|poe\.com)'
$knownSearch = '(?i)^https?://([a-z0-9-]+\.)*(bing\.com|google\.[a-z.]+|duckduckgo\.com|yahoo\.com|ecosia\.org|brave\.com|startpage\.com|yandex\.[a-z]+|baidu\.com|qwant\.com|kagi\.com|perplexity\.ai|chatgpt\.com|naver\.com|so\.com|sogou\.com)(/|$)'
$msPublisher = '(?i)O=Microsoft Corporation'
$msDomains   = '(?i)(^|\.)(microsoft|microsoft\.com|microsoftonline\.com|bing\.com|bing\.net|msn\.com|live\.com|live\.net|office\.com|office\.net|office365\.com|cloud\.microsoft|windows\.com|windows\.net|windowsupdate\.com|azure\.com|azure\.net|azureedge\.net|azurefd\.net|azurewebsites\.net|msedge\.net|msftconnecttest\.com|msauth\.net|msftauth\.net|msecnd\.net|aka\.ms|skype\.com|sharepoint\.com|onedrive\.com|trafficmanager\.net|akamaized\.net|akamaiedge\.net|akamaitechnologies\.com|edgekey\.net|edgesuite\.net|footprintdns\.com|github\.com|githubcopilot\.com|githubusercontent\.com)\.?$'
$badEdgeArgs = '(?i)--(remote-debugging-port|remote-debugging-pipe|remote-debugging-address|remote-allow-origins|load-extension|disable-extensions-except|headless|disable-web-security|proxy-server|proxy-pac-url|host-resolver-rules|ignore-certificate-errors|silent-debugger-extension-api|enable-automation)\b'
$edgeDirs    = '(?i)(^[a-z]:\\Program Files( \(x86\))?\\Microsoft\\(Edge|Edge Beta|Edge Dev|EdgeWebView|EdgeCore)\\|\\AppData\\Local\\Microsoft\\Edge SxS\\Application\\|^[a-z]:\\Windows\\SystemApps\\)'

$locationNames = @{ 1 = 'Store'; 2 = 'External (preferences file)'; 3 = 'External (registry)'; 4 = 'Unpacked (developer mode)'; 5 = 'Built-in component'
                    6 = 'External (default install)'; 7 = 'Policy (downloaded)'; 8 = 'Command line'; 9 = 'Policy'; 10 = 'Built-in component' }

$permRisk = [ordered]@{
    debugger               = @(3, 'debugger: full control of any tab (read pages and cookies, inject code)')
    proxy                  = @(2, 'proxy: can route all browsing through a server of its choice')
    webAuthenticationProxy = @(2, 'webAuthenticationProxy: can intercept passkey/WebAuthn sign-ins')
    nativeMessaging        = @(1, 'nativeMessaging: can start a program on this PC')
    management             = @(1, 'management: can disable or remove other extensions')
    cookies                = @(1, 'cookies: can read session cookies')
    webRequestBlocking     = @(1, 'webRequestBlocking: can rewrite web traffic')
    clipboardRead          = @(1, 'clipboardRead: can read the clipboard')
    desktopCapture         = @(1, 'desktopCapture: can record the screen')
    tabCapture             = @(1, 'tabCapture: can record tabs')
    privacy                = @(1, 'privacy: can change browser privacy/security settings')
}

$codeRisk = @(
    @{ W = 3; R = 'Sends data to a Telegram bot or Discord webhook (a common stealer exfiltration channel)'; P = '(?i)(api\.telegram\.org/bot|discord(app)?\.com/api/webhooks/)' }
    @{ W = 2; R = 'Contacts a raw IP address';         P = '(?i)\b(https?|wss?)://\d{1,3}(\.\d{1,3}){3}' }
    @{ W = 1; R = 'Reads all cookies';                 P = 'cookies\.getAll\s*\(' }
    @{ W = 1; R = 'Attaches the debugger to tabs';     P = 'debugger\.attach\s*\(' }
    @{ W = 1; R = 'Builds and runs code at run time';  P = '(\bnew\s+Function\s*\(|\beval\s*\()' }
)

$extNames = @{}     # extension id -> name, filled by the extension check and used by later checks

# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------
try { Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop } catch {}

function ConvertFrom-JsonText([string]$Text) {
    <# Chromium preference files contain empty and case-duplicate keys that ConvertFrom-Json in
       Windows PowerShell rejects, so parse to dictionaries instead. #>
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    if ($PSVersionTable.PSVersion.Major -ge 6) { return ($Text | ConvertFrom-Json -AsHashtable -Depth 200) }
    $js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $js.MaxJsonLength = [int]::MaxValue; $js.RecursionLimit = 1000
    return $js.DeserializeObject($Text)
}

function Read-JsonFile([string]$Path, [switch]$Lenient) {
    <# Opens with full sharing so files Edge holds open can still be read. -Lenient accepts
       comments and trailing commas (VS Code settings). #>
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite, Delete')
        try { $txt = (New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8, $true)).ReadToEnd() } finally { $fs.Dispose() }
        if ($Lenient) { $txt = $txt -replace '(?m)^\s*//.*$', '' -replace ',(\s*[}\]])', '$1' }
        return ConvertFrom-JsonText $txt
    } catch { return $null }
}

function Get-JsonValue($Object, [string]$Path) {
    <# Get-JsonValue $prefs 'extensions.settings' -> nested value, or $null when any level is missing #>
    $o = $Object
    foreach ($k in $Path.Split('.')) {
        if ($o -is [Collections.IDictionary] -and ([Collections.IDictionary]$o).Contains($k)) { $o = $o[$k] } else { return $null }
    }
    return $o
}

function ConvertFrom-ChromeTime($Value) {
    <# Chromium stores times as microseconds since 1601-01-01 UTC. #>
    try { $n = [int64]$Value; if ($n -le 0) { return $null }; return [DateTime]::FromFileTimeUtc($n * 10).ToLocalTime() } catch { return $null }
}

function Test-PublicIP([string]$ip) {
    if (-not $ip -or $ip -in @('0.0.0.0', '::', '::1')) { return $false }
    return ($ip -notmatch '^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fc|fd|::ffff:(10|127|192\.168)\.)')
}

function Get-EdgeProfiles {
    foreach ($up in Get-UserProfilePaths) {
        foreach ($ch in 'Edge', 'Edge Beta', 'Edge Dev', 'Edge SxS') {
            $ud = Join-Path $up "AppData\Local\Microsoft\$ch\User Data"
            if (-not (Test-Path -LiteralPath $ud -ErrorAction SilentlyContinue)) { continue }
            $ls = Read-JsonFile (Join-Path $ud 'Local State')
            foreach ($d in Get-ChildItem -LiteralPath $ud -Directory -ErrorAction SilentlyContinue) {
                if (-not (Test-Path -LiteralPath (Join-Path $d.FullName 'Preferences'))) { continue }
                $display = [string](Get-JsonValue (Get-JsonValue (Get-JsonValue $ls 'profile.info_cache') $d.Name) 'name')
                $label = "$(Split-Path $up -Leaf) / $ch / $($d.Name)"
                if ($display -and $display -ne $d.Name) { $label += " ($display)" }
                [pscustomobject]@{ User = Split-Path $up -Leaf; Channel = $ch; Profile = $d.Name; Dir = $d.FullName; UserData = $ud; LocalState = $ls; Label = $label }
            }
        }
    }
}

function Resolve-ExtensionName($Manifest, [string]$Dir) {
    $n = [string]$Manifest['name']
    if ($n -notmatch '^__MSG_(.+)__$' -or -not $Dir) { return $n }
    $key = $Matches[1]
    foreach ($loc in @([string]$Manifest['default_locale'], 'en', 'en_US', 'en_GB') | Where-Object { $_ } | Select-Object -Unique) {
        $msgs = Read-JsonFile (Join-Path $Dir "_locales\$loc\messages.json")
        if ($msgs -is [Collections.IDictionary]) { foreach ($k in $msgs.Keys) { if ($k -ieq $key) { return [string](Get-JsonValue $msgs[$k] 'message') } } }
    }
    return $n
}

function Find-ExtensionCodeRisk([string]$Dir) {
    <# Looks for exfiltration patterns in an extension's own code. Capped so huge extensions stay fast. #>
    $hits = @{}
    $files = Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Extension -in '.js', '.mjs', '.html' -and $_.Length -lt 3MB } | Select-Object -First 400
    foreach ($f in $files) {
        $txt = $null; try { $txt = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        foreach ($r in $codeRisk) {
            if (-not $hits.ContainsKey($r.R) -and $txt -match $r.P) { $hits[$r.R] = [pscustomobject]@{ Reason = $r.R; Weight = $r.W; File = $f.FullName.Substring($Dir.Length).TrimStart('\') } }
        }
        if ($hits.Count -eq $codeRisk.Count) { break }
    }
    return @($hits.Values)
}

$script:WDShell = $null
function Read-Shortcut([string]$Path) {
    <# Target and arguments of a .lnk file, or $null. #>
    try {
        if (-not $script:WDShell) { $script:WDShell = New-Object -ComObject WScript.Shell }
        $sc = $script:WDShell.CreateShortcut($Path)
        return [pscustomobject]@{ Target = [string]$sc.TargetPath; Arguments = [string]$sc.Arguments }
    } catch { return $null }
}

function Test-MicrosoftPackage($Package) {
    <# Store/System packages from Microsoft are trusted as-is. Microsoft "sparse" packages (Edge registers
       one) report a Developer signature, so for those the package signature itself must chain to a
       Microsoft root; a side-loaded package that only claims Microsoft as publisher fails this. #>
    if ($Package.Publisher -notmatch $msPublisher) { return $false }
    if ([string]$Package.SignatureKind -in 'Store', 'System') { return $true }
    try {
        $raw = [IO.File]::ReadAllBytes((Join-Path $Package.InstallLocation 'AppxSignature.p7x'))
        $der = New-Object byte[] ($raw.Length - 4); [Array]::Copy($raw, 4, $der, 0, $der.Length)   # skip the 'PKCX' header
        Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
        $cms = New-Object Security.Cryptography.Pkcs.SignedCms
        $cms.Decode($der); $cms.CheckSignature($true)
        $cert = $cms.SignerInfos[0].Certificate
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        $chain.ChainPolicy.VerificationFlags = 'IgnoreNotTimeValid'   # package signatures outlive their certificates
        $built = $chain.Build($cert)
        $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
        return ($built -and $cert.Subject -match $msPublisher -and $root.Subject -match '(?i)CN=Microsoft Root')
    } catch { return $false }
}

$script:WDPackages = $null
function Get-AppPackages {
    if ($null -eq $script:WDPackages) {
        $script:WDPackages = @(try { if ($isAdmin) { Get-AppxPackage -AllUsers -ErrorAction Stop } else { Get-AppxPackage -ErrorAction Stop } } catch {}) |
                             Where-Object { $_ } | Sort-Object PackageFullName -Unique
    }
    return $script:WDPackages
}

function Get-UninstallEntries {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
    $keys += @(Get-UserHives | ForEach-Object { "$($_.Root)\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" })
    foreach ($k in $keys) { Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } }
}

$profiles = @(Get-EdgeProfiles)

# ===========================================================================
Invoke-Check -Name 'Edge extensions' -ScriptBlock {
    $c = 'Edge extensions'
    if (-not $profiles.Count) { Add-Finding -Category $c -Title 'No Microsoft Edge profiles found' -Classification Info; return }
    foreach ($pr in $profiles) {
        $settings = @{}
        foreach ($f in 'Preferences', 'Secure Preferences') {   # Secure Preferences is read last and wins: it is integrity-protected
            $s = Get-JsonValue (Read-JsonFile (Join-Path $pr.Dir $f)) 'extensions.settings'
            if ($s -is [Collections.IDictionary]) { foreach ($id in $s.Keys) { $settings[$id] = $s[$id] } }
        }
        $extRoot = Join-Path $pr.Dir 'Extensions'
        $onDisk = @(); if (Test-Path -LiteralPath $extRoot) { $onDisk = @(Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) }
        $inv = New-Object System.Collections.Generic.List[object]
        $flagged = 0
        foreach ($id in @(@($settings.Keys) + $onDisk | Select-Object -Unique)) {
            $s = $settings[$id]
            $loc = [int](Get-JsonValue $s 'location')
            $path = [string](Get-JsonValue $s 'path')
            $dir = $null
            if ($path -and [IO.Path]::IsPathRooted($path)) { $dir = $path } elseif ($path) { $dir = Join-Path $extRoot $path }
            if ((-not $dir -or -not (Test-Path -LiteralPath $dir)) -and $id -in $onDisk) {
                $dir = Get-ChildItem -LiteralPath (Join-Path $extRoot $id) -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
            }
            $manifest = $null
            if ($dir) { $manifest = Read-JsonFile (Join-Path $dir 'manifest.json') }
            if (-not $manifest) { $manifest = Get-JsonValue $s 'manifest' }
            if (-not $manifest) { continue }   # settings left behind by an extension that is no longer installed

            $name = Resolve-ExtensionName $manifest $dir
            if (-not $name) { $name = $id }
            $extNames[$id] = $name
            $version = [string]$manifest['version']
            $upd = [string]$manifest['update_url']
            $bits = 0; foreach ($x in @(Get-JsonValue $s 'disable_reasons')) { try { $bits = $bits -bor [int64]$x } catch {} }
            $state = Get-JsonValue $s 'state'
            $enabled = -not ($bits -ne 0 -or ($null -ne $state -and [int]$state -eq 0))
            $installed = ConvertFrom-ChromeTime (Get-JsonValue $s 'first_install_time')
            if (-not $installed) { $installed = ConvertFrom-ChromeTime (Get-JsonValue $s 'install_time') }
            $isComponent = $loc -in 5, 10 -or ($dir -and $dir -match '(?i)\\Microsoft\\Edge[^\\]*\\Application\\')
            $source = if ($isComponent) { 'Built-in component' } elseif ($locationNames.ContainsKey($loc)) { $locationNames[$loc] } elseif ($id -in $onDisk -and -not $s) { 'Files only (not registered)' } else { "Unknown ($loc)" }
            $inv.Add([pscustomobject]@{ Name = $name; Id = $id; Version = $version; Source = $source; Enabled = $enabled; Installed = $installed })
            if ($isComponent) { continue }

            $apiPerms = @(@($manifest['permissions']) | Where-Object { $_ -is [string] -and $_ -notmatch '://|^<all_urls>$' })
            $hosts = @(@($manifest['permissions']) + @($manifest['host_permissions']) | Where-Object { $_ -is [string] -and $_ -match '://|^<all_urls>$' })
            $csMatches = @(foreach ($cs in @($manifest['content_scripts'])) { if ($cs -is [Collections.IDictionary]) { @($cs['matches']) } }) | Where-Object { $_ -is [string] }
            $score = 0; $reasons = New-Object System.Collections.Generic.List[string]
            switch ($loc) {
                4 { $score += 3; $reasons.Add('Loaded unpacked in developer mode (skips store review; a common way malware adds extensions)') }
                8 { $score += 4; $reasons.Add('Loaded from the command line (--load-extension)') }
                3 { $score += 1; $reasons.Add('Side-loaded through the registry') }
                2 { $score += 1; $reasons.Add('Side-loaded through an external preferences file') }
                { $_ -in 7, 9 } { if (-not $mgmt.IsManaged) { $score += 2; $reasons.Add('Force-installed by policy on a PC no organization manages') } }
            }
            if ($upd -and $upd -notmatch $storeUpdate) { $score += 3; $reasons.Add("Updates from a non-store server ($upd)") }
            elseif (-not $upd -and -not (Get-JsonValue $s 'from_webstore') -and $loc -ne 4) { $score += 1; $reasons.Add('Not from the Edge or Chrome store') }
            if (@($hosts + $csMatches | Where-Object { $_ -match $broadHost }).Count) { $score += 1; $reasons.Add('Can read and change every website') }
            $ai = @($hosts + $csMatches | Where-Object { $_ -match $aiSites } | Select-Object -Unique)
            if ($ai.Count) { $score += 2; $reasons.Add("Targets AI assistant pages ($(($ai | Select-Object -First 4) -join ', ')), so it can read Copilot/ChatGPT prompts and answers") }
            foreach ($p in $apiPerms) { if ($permRisk.Contains($p)) { $score += $permRisk[$p][0]; $reasons.Add($permRisk[$p][1]) } }
            if ($name -match '(?i)\b(microsoft|edge|copilot|bing|defender|windows|office|outlook)\b' -and $upd -notmatch $storeUpdate) {
                $score += 2; $reasons.Add('Uses a Microsoft product name but does not come from a store')
            }
            $ov = $manifest['chrome_settings_overrides']
            if ($ov -is [Collections.IDictionary] -and $ov.Count) { $score += 2; $reasons.Add("Takes over browser settings ($(@($ov.Keys) -join ', ')), typical of search/homepage hijackers") }
            $uo = $manifest['chrome_url_overrides']
            if ($uo -is [Collections.IDictionary] -and ([Collections.IDictionary]$uo).Contains('newtab')) { $score += 1; $reasons.Add('Replaces the new tab page') }
            $bl = Get-JsonValue $s 'blacklist_state'; if ($null -eq $bl) { $bl = Get-JsonValue $s 'blocklist_state' }
            $blocklisted = $null -ne $bl -and [int]$bl -in 1, 4    # 1 = malware, 4 = potentially unwanted
            if ($bits -band 256) { $score += 2; $reasons.Add('Edge found its files were changed after install (disabled as corrupted)') }
            if ($bits -band 128) { $score += 2; $reasons.Add('Disabled by the store as policy-violating or unwanted') }
            $code = @()
            if (-not $SkipCodeScan -and $dir -and (Test-Path -LiteralPath $dir)) { $code = @(Find-ExtensionCodeRisk $dir) }
            foreach ($h in $code) { $score += $h.Weight; $reasons.Add("$($h.Reason) [$($h.File)]") }
            $exfil = @($code | Where-Object { $_.Weight -ge 3 }).Count -gt 0
            if ($installed -and $installed -gt $recent) { $reasons.Add("Installed $($installed.ToShortDateString())") }

            if ($blocklisted) { $sev = 'Critical'; $cls = 'Malicious'; $reasons.Insert(0, 'Edge blocklisted it as malware or unwanted software') }
            elseif (($score -ge 7 -and $exfil) -or $score -ge 10) { $sev = 'High'; $cls = 'Malicious' }
            elseif ($score -ge 6) { $sev = 'High'; $cls = 'Suspicious' }
            elseif ($score -ge 4) { $sev = 'Medium'; $cls = 'Suspicious' }
            elseif ($score -ge 2) { $sev = 'Low'; $cls = 'Ambiguous' }
            else { continue }
            if (-not $enabled -and $cls -ne 'Malicious') { $sev = @{ High = 'Medium'; Medium = 'Low'; Low = 'Low' }[$sev] }
            $flagged++
            $store = if ($upd -match 'edge\.microsoft\.com') { "https://microsoftedge.microsoft.com/addons/detail/$id" } elseif ($upd -match 'google\.com') { "https://chromewebstore.google.com/detail/$id" } else { '' }
            $ev = [pscustomobject][ordered]@{ Profile = $pr.Label; Name = $name; Id = $id; Version = $version; Source = $source; Enabled = $enabled; Installed = $installed
                UpdateUrl = $upd; Folder = $dir; ApiPermissions = ($apiPerms -join ', '); SiteAccess = ((@($hosts + $csMatches) | Select-Object -Unique -First 15) -join ', '); StorePage = $store }
            Add-Finding -Category $c -Title "Extension '$name'$(if (-not $enabled) { ' (disabled)' }) in $($pr.Label)" -Severity $sev -Classification $cls `
                -Detail (($reasons -join '; ') + '.') -Evidence $ev `
                -Recommendation 'If you did not install it on purpose, remove it at edge://extensions, then sign out of important sites and change their passwords from another device. Check its store page, publisher and recent reviews.' `
                -Tags 'Browser', 'Extension'
        }
        $user = @($inv | Where-Object { $_.Source -ne 'Built-in component' })
        Add-Finding -Category $c -Title "$($pr.Label): $($user.Count) extension(s), $($inv.Count - $user.Count) built-in ($flagged flagged)" -Classification $(if ($flagged) { 'Info' } else { 'OK' }) `
            -Evidence ($inv | Sort-Object Source, Name | Format-Table Name, Id, Version, Source, Enabled, Installed -AutoSize | Out-String -Width 300)
    }
}

# ===========================================================================
Invoke-Check -Name 'Edge homepage, search and startup settings' -ScriptBlock {
    $c = 'Edge settings'
    foreach ($pr in $profiles) {
        $prefs = Read-JsonFile (Join-Path $pr.Dir 'Preferences'); $secure = Read-JsonFile (Join-Path $pr.Dir 'Secure Preferences')
        $search = Get-JsonValue $secure 'default_search_provider_data.template_url_data'
        if (-not $search) { $search = Get-JsonValue $prefs 'default_search_provider_data.template_url_data' }
        $searchUrl = [string](Get-JsonValue $search 'url')
        $homePage = [string](Get-JsonValue $secure 'homepage'); if (-not $homePage) { $homePage = [string](Get-JsonValue $prefs 'homepage') }
        $homeIsNtp = Get-JsonValue $secure 'homepage_is_newtabpage'
        $startup = @(@(Get-JsonValue $secure 'session.startup_urls') + @(Get-JsonValue $prefs 'session.startup_urls') | Where-Object { $_ } | Select-Object -Unique)
        $ntp = @(Get-JsonValue $prefs 'extensions.chrome_url_overrides.newtab') | Where-Object { $_ }
        $ntpExt = @($ntp | ForEach-Object { $i = ([string]$_ -replace '^chrome-extension://([a-p]{32}).*$', '$1'); if ($extNames.ContainsKey($i)) { "$($extNames[$i]) ($i)" } else { [string]$_ } })

        if ($searchUrl -and $searchUrl -notmatch $knownSearch) {
            Add-Finding -Category $c -Title "Default search engine in $($pr.Label) is an unrecognized site: $(([uri]$searchUrl).Host)" -Severity Medium -Classification Suspicious `
                -Detail 'Search hijackers (adware and malicious extensions) replace the search engine to log searches and inject ads.' -Evidence $searchUrl `
                -Recommendation 'Reset it at edge://settings/search and remove any extension that changed it.' -Tags 'Browser'
        }
        if ($ntpExt.Count) {
            Add-Finding -Category $c -Title "New tab page in $($pr.Label) is replaced by an extension" -Severity Low -Classification Ambiguous -Evidence ($ntpExt -join "`n") `
                -Detail 'Common for productivity "new tab" add-ons, and for hijackers that show ads or a fake search box.' -Tags 'Browser'
        }
        $ev = [pscustomobject][ordered]@{ SearchEngine = $(if ($searchUrl) { $searchUrl } else { 'Edge default' }); Homepage = $(if ($homeIsNtp -or -not $homePage) { 'New tab page' } else { $homePage })
                                          StartupPages = ($startup -join ', '); NewTabOverride = ($ntpExt -join ', ') }
        Add-Finding -Category $c -Title "Search, homepage and startup pages for $($pr.Label)" -Classification Info -Evidence $ev `
            -Detail 'For review: make sure you recognize each site. Unwanted entries here are the usual visible sign of a browser hijacker.'
    }
}

# ===========================================================================
Invoke-Check -Name 'Edge and Copilot policies' -ScriptBlock {
    $c = 'Edge policy'
    $roots = @([pscustomobject]@{ Scope = 'HKLM (all users)'; Root = 'HKLM:' }) + @(Get-UserHives | ForEach-Object { [pscustomobject]@{ Scope = $_.User; Root = $_.Root } })
    $all = New-Object System.Collections.Generic.List[object]
    $psProps = '^PS(Path|ParentPath|ChildName|Drive|Provider)$'
    foreach ($r in $roots) {
        $base = "$($r.Root)\SOFTWARE\Policies\Microsoft\Edge"
        if (-not (Test-Path -LiteralPath $base)) { continue }
        $vals = Get-ItemProperty -LiteralPath $base -ErrorAction SilentlyContinue
        if ($vals) { foreach ($p in $vals.PSObject.Properties | Where-Object { $_.Name -notmatch $psProps }) { $all.Add([pscustomobject]@{ Scope = $r.Scope; Name = $p.Name; Value = $p.Value }) } }
        foreach ($sub in Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -notin 'Recommended', 'WebView2' }) {
            $sv = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
            $list = @(); if ($sv) { $list = @($sv.PSObject.Properties | Where-Object { $_.Name -notmatch $psProps } | ForEach-Object { [string]$_.Value }) }
            $all.Add([pscustomobject]@{ Scope = $r.Scope; Name = $sub.PSChildName; Value = $list })
        }
    }
    function Get-Pol([string]$n) { @($all | Where-Object { $_.Name -eq $n }) }

    if (-not $all.Count) { Add-Finding -Category $c -Title 'No Edge policies are set' -Classification OK }
    else {
        Add-Finding -Category $c -Title "$($all.Count) Edge polic(ies) set$(if (-not $mgmt.IsManaged) { ' on a PC no organization manages' })" `
            -Severity $(if ($mgmt.IsManaged) { 'Info' } else { 'Low' }) -Classification $(if ($mgmt.IsManaged) { 'Info' } else { 'Ambiguous' }) `
            -Detail 'Edge then shows "Your browser is managed by your organization". On a home PC that is a classic sign of a hijacker or adware locking its settings in; privacy tweak tools also set policies.' `
            -Evidence ($all | Format-Table Scope, Name, @{ n = 'Value'; e = { @($_.Value) -join '; ' } } -AutoSize -Wrap | Out-String -Width 400) -Tags 'Browser'
    }

    function Add-ForcedExtension([string]$Id, [string]$Url, [string]$Scope, [string]$Via) {
        $offStore = $Url -and $Url -notmatch $storeUpdate
        $sev = if ($offStore) { 'High' } elseif ($mgmt.IsManaged) { 'Info' } else { 'Medium' }
        $cls = if ($offStore -and -not $mgmt.IsManaged) { 'Malicious' } elseif ($offStore -or -not $mgmt.IsManaged) { 'Suspicious' } else { 'Info' }
        $nm = if ($extNames.ContainsKey($Id)) { "'$($extNames[$Id])' ($Id)" } else { $Id }
        Add-Finding -Category $c -Title "Policy force-installs extension $nm ($Scope)" -Severity $sev -Classification $cls `
            -Detail "Set via $Via. Force-installed extensions cannot be removed by the user.$(if ($offStore) { " It updates from $Url, outside the stores, so nobody reviewed it." }) Malware uses this to make its extension permanent; organizations use it for legitimate add-ons." `
            -Evidence "$Id;$Url" -Recommendation 'If no organization manages this PC, delete the policy value (HKLM/HKCU\SOFTWARE\Policies\Microsoft\Edge) after saving this report, then remove the extension.' -Tags 'Browser', 'Extension', 'Persistence'
    }
    foreach ($p in Get-Pol 'ExtensionInstallForcelist') { foreach ($e in @($p.Value)) { $id, $url = ([string]$e) -split ';', 2; Add-ForcedExtension $id $url $p.Scope 'ExtensionInstallForcelist' } }
    foreach ($p in Get-Pol 'ExtensionSettings') {
        $es = ConvertFrom-JsonText ([string]@($p.Value)[0])
        if ($es -is [Collections.IDictionary]) {
            foreach ($id in $es.Keys) {
                $mode = [string](Get-JsonValue $es[$id] 'installation_mode')
                if ($mode -in 'force_installed', 'normal_installed') { Add-ForcedExtension $id ([string](Get-JsonValue $es[$id] 'update_url')) $p.Scope "ExtensionSettings ($mode)" }
            }
        }
    }

    $rules = @(
        @{ N = 'SmartScreenEnabled';             T = { $args[0] -eq 0 };    S = 'Medium'; Title = 'SmartScreen is turned off in Edge by policy'; D = 'SmartScreen blocks known phishing sites and malware downloads. Malware and adware turn it off.' }
        @{ N = 'DeveloperToolsAvailability';     T = { $args[0] -eq 2 };    S = 'Medium'; Title = 'Edge developer tools are blocked by policy'; D = 'Malicious extensions installed by policy often block DevTools so they cannot be inspected or removed.' }
        @{ N = 'ProxyServer';                    T = { $args[0] };          S = 'Medium'; Title = 'Edge traffic is forced through a proxy by policy'; D = 'The proxy sees every site visited and can alter unencrypted traffic.' }
        @{ N = 'ProxyPacUrl';                    T = { $args[0] };          S = 'Medium'; Title = 'Edge uses a proxy script (PAC) set by policy'; D = 'PAC scripts are how banking trojans and adware route chosen sites through their own proxy.' }
        @{ N = 'ProxySettings';                  T = { $args[0] };          S = 'Medium'; Title = 'Edge proxy settings are forced by policy'; D = 'The proxy sees every site visited and can alter unencrypted traffic.' }
        @{ N = 'DefaultSearchProviderSearchURL'; T = { $args[0] -and $args[0] -notmatch $knownSearch }; S = 'Medium'; Title = 'An unrecognized search engine is forced by policy'; D = 'Search hijackers set this so the user cannot change it back.' }
        @{ N = 'HomepageLocation';               T = { $args[0] };          S = 'Low';    Title = 'The homepage is forced by policy'; D = 'Hijackers lock the homepage this way.' }
        @{ N = 'RestoreOnStartupURLs';           T = { @($args[0]).Count }; S = 'Low';    Title = 'Startup pages are forced by policy'; D = 'Hijackers lock startup pages this way.' }
        @{ N = 'NewTabPageLocation';             T = { $args[0] };          S = 'Low';    Title = 'The new tab page is forced by policy'; D = 'Hijackers lock the new tab page this way.' }
        @{ N = 'ExtensionInstallSources';        T = { @($args[0]).Count }; S = 'Low';    Title = 'Sites other than the stores may install extensions'; D = 'The listed sites can install extensions directly, skipping store review.' }
        @{ N = 'DnsOverHttpsTemplates';          T = { $args[0] };          S = 'Low';    Title = 'A DNS-over-HTTPS server is forced by policy'; D = 'All of Edge''s lookups go to this server. Fine for a known provider (Cloudflare, Quad9, NextDNS); otherwise it can silently redirect sites.' }
    )
    foreach ($rule in $rules) {
        foreach ($p in Get-Pol $rule.N) {
            if (-not (& $rule.T $p.Value)) { continue }
            $sev = if ($mgmt.IsManaged) { 'Low' } else { $rule.S }
            $cls = if ($mgmt.IsManaged -or $sev -eq 'Low') { 'Ambiguous' } else { 'Suspicious' }
            Add-Finding -Category $c -Title "$($rule.Title) ($($p.Scope))" -Severity $sev -Classification $cls -Detail $rule.D -Evidence "$($rule.N) = $(@($p.Value) -join '; ')" -Tags 'Browser'
        }
    }

    # Copilot-related policies are context (privacy posture), not threats
    $copilotPol = 'HubsSidebarEnabled', 'CopilotPageContext', 'EdgeEntraCopilotPageContext', 'CopilotCDPPageContext', 'Microsoft365CopilotChatIconEnabled', 'DiscoverPageContextEnabled',
                  'EdgeCopilotEnabled', 'ComposeInlineEnabled', 'GenAILocalFoundationalModelSettings', 'EdgeSidebarAppUrlHostAllowList', 'EdgeSidebarAppUrlHostBlockList', 'EdgeSidebarCustomizeEnabled'
    $cp = @($all | Where-Object { $_.Name -in $copilotPol })
    $win = @()
    foreach ($r in $roots) {
        foreach ($k in 'SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot', 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI') {
            $v = Get-ItemProperty -LiteralPath "$($r.Root)\$k" -ErrorAction SilentlyContinue
            if ($v) { $win += $v.PSObject.Properties | Where-Object { $_.Name -notmatch $psProps } | ForEach-Object { [pscustomobject]@{ Scope = $r.Scope; Name = "$(Split-Path $k -Leaf)\$($_.Name)"; Value = $_.Value } } }
        }
    }
    if ($cp.Count -or $win.Count) {
        Add-Finding -Category $c -Title "$($cp.Count + $win.Count) Copilot / Windows AI polic(ies) set" -Classification Info `
            -Detail 'Controls whether Copilot can read the current page (page context), appear in the sidebar, or run in Windows. Context only.' `
            -Evidence (@($cp) + @($win) | Format-Table Scope, Name, @{ n = 'Value'; e = { @($_.Value) -join '; ' } } -AutoSize | Out-String -Width 300)
    }
}

# ===========================================================================
Invoke-Check -Name 'Edge launch settings and remote debugging' -ScriptBlock {
    $c = 'Edge launch'
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $byPid = @{}; foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
    $edgeProcs = @($procs | Where-Object { $_.Name -in 'msedge.exe', 'msedgewebview2.exe' })

    # Binaries: an "msedge.exe" outside Edge's folders that Microsoft did not sign is a masquerade
    $paths = @($edgeProcs | Where-Object { $_.ExecutablePath } | Select-Object -ExpandProperty ExecutablePath -Unique)
    foreach ($path in $paths) {
        $sig = Get-FileSignatureInfo $path
        if ($sig.Exists -and -not $sig.IsMicrosoft) {
            Add-Finding -Category $c -Title "Edge process running from a binary Microsoft did not sign: $path" -Severity Critical -Classification Malicious -Evidence $sig `
                -Detail 'A fake msedge.exe/msedgewebview2.exe is malware hiding behind the browser''s name.' -Recommendation 'Isolate the PC; record the path and SHA256; investigate before removing.' -Tags 'Browser', 'Execution'
        } elseif ($path -notmatch $edgeDirs -and $sig.Exists) {
            Add-Finding -Category $c -Title "Microsoft-signed Edge/WebView2 binary in a non-standard folder: $path" -Classification Info `
                -Detail 'Usually an app that ships its own fixed WebView2 runtime.'
        }
    }

    # Main browser/WebView2 processes (no --type=) started with risky switches
    foreach ($p in $edgeProcs | Where-Object { $_.CommandLine -and $_.CommandLine -notmatch '\s--type=' }) {
        $flags = @([regex]::Matches($p.CommandLine, $badEdgeArgs) | ForEach-Object { $_.Value } | Select-Object -Unique)
        if (-not $flags.Count) { continue }
        $parent = $byPid[[int]$p.ParentProcessId]; $parentName = if ($parent) { $parent.Name } else { '?' }
        $debug = @($flags | Where-Object { $_ -match 'remote-debugging' }).Count -gt 0
        $headless = $flags -contains '--headless'
        if ($p.Name -eq 'msedgewebview2.exe') { $sev = 'Low'; $cls = 'Ambiguous' }
        elseif ($debug -and $headless) { $sev = 'High'; $cls = 'Suspicious' }
        else { $sev = 'Medium'; $cls = 'Suspicious' }
        Add-Finding -Category $c -Title "$($p.Name) (PID $($p.ProcessId)) is running with $($flags -join ' ')" -Severity $sev -Classification $cls `
            -Detail "Started by $parentName. Remote debugging lets any local program read every cookie and page, which is how current info-stealers get around Edge's cookie encryption (often with --headless so nothing is visible). Test automation (Playwright, Selenium, Power Automate) and some developer tools use the same switches." `
            -Evidence ([pscustomobject]@{ PID = $p.ProcessId; Parent = "$parentName ($($p.ParentProcessId))"; Started = $p.CreationDate; CommandLine = $p.CommandLine.Substring(0, [Math]::Min(1500, $p.CommandLine.Length)) }) `
            -Recommendation 'If you are not running automation or debugging, close Edge from Task Manager and find what started it.' -Tags 'Browser', 'Credential'
    }
    $edgePids = @($edgeProcs | ForEach-Object { [int]$_.ProcessId })
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { [int]$_.OwningProcess -in $edgePids })
    if ($listen.Count) {
        Add-Finding -Category $c -Title "Edge/WebView2 is listening on TCP port(s) $(($listen | ForEach-Object { $_.LocalPort } | Select-Object -Unique) -join ', ')" -Severity Medium -Classification Suspicious `
            -Detail 'The browser does not normally accept incoming connections; an open port is almost always a remote-debugging port.' `
            -Evidence ($listen | ForEach-Object { [pscustomobject]@{ Address = "$($_.LocalAddress):$($_.LocalPort)"; PID = $_.OwningProcess; Process = $byPid[[int]$_.OwningProcess].Name } } | Format-Table -AutoSize | Out-String) -Tags 'Browser', 'Credential'
    }

    # Shortcuts
    $lnkDirs = @("$env:PUBLIC\Desktop", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs")
    foreach ($up in Get-UserProfilePaths) { $lnkDirs += (Join-Path $up 'Desktop'), (Join-Path $up 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'), (Join-Path $up 'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch') }
    $lnkCount = 0
    foreach ($d in $lnkDirs | Where-Object { Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue }) {
        foreach ($l in Get-ChildItem -LiteralPath $d -Recurse -Depth 3 -Filter *.lnk -File -ErrorAction SilentlyContinue) {
            $sc = Read-Shortcut $l.FullName
            if (-not $sc -or -not $sc.Target) { continue }
            $target = $sc.Target; $scArgs = $sc.Arguments
            $toEdge = $target -match '(?i)\\msedge(_proxy)?\.exe$'
            $namedEdge = $l.BaseName -match '(?i)^microsoft edge'
            if ($toEdge) { $lnkCount++ }
            if ($namedEdge -and -not $toEdge) {
                Add-Finding -Category $c -Title "'$($l.Name)' shortcut does not start Edge" -Severity High -Classification Suspicious -Evidence "$($l.FullName)`nTarget: $target $scArgs" `
                    -Detail 'A shortcut named after Edge that runs something else is a known way to run malware each time the user opens the browser.' -Tags 'Browser', 'Persistence'
            } elseif ($toEdge -and $scArgs -match $badEdgeArgs) {
                Add-Finding -Category $c -Title "Edge shortcut adds risky switches: $($l.Name)" -Severity High -Classification Suspicious -Evidence "$($l.FullName)`nTarget: $target $scArgs" `
                    -Detail 'Malware edits browser shortcuts so every launch also loads its own extension or opens a debugging port (switches listed in the evidence).' -Tags 'Browser', 'Persistence'
            } elseif ($toEdge -and $namedEdge -and $scArgs -match '(?i)\bhttps?://') {
                Add-Finding -Category $c -Title "Edge shortcut always opens a website: $($l.Name)" -Severity Low -Classification Ambiguous -Evidence "$($l.FullName)`nTarget: $target $scArgs" `
                    -Detail 'Adware adds a URL to browser shortcuts so its page opens on every launch.' -Tags 'Browser'
            } elseif ($toEdge -and $target -notmatch $edgeDirs) {
                $sig = Get-FileSignatureInfo $target
                if ($sig.Exists -and -not $sig.IsMicrosoft) {
                    Add-Finding -Category $c -Title "Shortcut $($l.Name) points to a fake msedge.exe" -Severity Critical -Classification Malicious -Evidence $sig -Tags 'Browser', 'Persistence'
                }
            }
        }
    }

    # Protocol and file handlers
    $handlerRoots = @([pscustomobject]@{ Scope = 'HKLM'; Root = 'HKLM:\SOFTWARE\Classes' }) + @(Get-UserHives | ForEach-Object { [pscustomobject]@{ Scope = $_.User; Root = "$($_.Root)\SOFTWARE\Classes" } })
    $handlersOk = 0
    foreach ($cls in 'MSEdgeHTM', 'MSEdgePDF', 'MSEdgeMHT', 'microsoft-edge') {
        foreach ($r in $handlerRoots) {
            $cmd = [string](Get-RegValue "$($r.Root)\$cls\shell\open\command" '(default)')
            if (-not $cmd) { continue }
            $exe = Resolve-CommandPath $cmd
            if ($exe -notmatch '(?i)\\msedge\.exe$' -or $cmd -match $badEdgeArgs) {
                Add-Finding -Category $c -Title "Edge's '$cls' handler was changed ($($r.Scope))" -Severity High -Classification Suspicious -Evidence $cmd `
                    -Detail 'Every link or file opened with Edge goes through this command. Malware rewrites it to run itself first or to add debugging/extension switches.' -Tags 'Browser', 'Persistence'
            } else { $handlersOk++ }
        }
    }

    # WebView2 (used by the Copilot app, Outlook, Teams, Widgets): environment and policy overrides
    foreach ($scope in 'Machine', 'User') {
        foreach ($v in 'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS', 'WEBVIEW2_BROWSER_EXECUTABLE_FOLDER') {
            $val = [Environment]::GetEnvironmentVariable($v, $scope)
            if (-not $val) { continue }
            $bad = $v -like '*ARGUMENTS' -and $val -match $badEdgeArgs
            Add-Finding -Category $c -Title "$v is set ($scope)" -Severity $(if ($bad -or $v -like '*FOLDER') { 'Medium' } else { 'Low' }) -Classification $(if ($bad -or $v -like '*FOLDER') { 'Suspicious' } else { 'Ambiguous' }) `
                -Detail 'Applies to every WebView2 app, including the Copilot app. Extra arguments can open a debugging port into all of them; a browser folder override makes them load a different browser engine. Developers set these while debugging.' `
                -Evidence "$v = $val" -Tags 'Browser'
        }
    }
    foreach ($r in @('HKLM:') + @(Get-UserHives | ForEach-Object { $_.Root })) {
        $k = "$r\SOFTWARE\Policies\Microsoft\Edge\WebView2\BrowserExecutableFolder"
        $v = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
        if (-not $v) { continue }
        foreach ($p in $v.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' }) {
            $sig = Get-FileSignatureInfo (Join-Path (Expand-WinPath ([string]$p.Value)) 'msedgewebview2.exe')
            if (-not $sig.IsMicrosoft) {
                Add-Finding -Category $c -Title "WebView2 for '$($p.Name)' is redirected to a non-Microsoft browser folder" -Severity High -Classification Suspicious -Evidence "$k`n$($p.Name) = $($p.Value)" `
                    -Detail 'The app would run its web content in whatever engine is in that folder.' -Tags 'Browser'
            }
        }
    }
    Add-Finding -Category $c -Title "Edge launch review: $($edgeProcs.Count) Edge/WebView2 process(es), $lnkCount Edge shortcut(s), $handlersOk handler(s) default" -Classification OK
}

# ===========================================================================
Invoke-Check -Name 'Native messaging hosts' -ScriptBlock {
    $c = 'Edge native messaging'
    $roots = @([pscustomobject]@{ S = 'HKLM'; R = 'HKLM:\SOFTWARE' }, [pscustomobject]@{ S = 'HKLM (32-bit)'; R = 'HKLM:\SOFTWARE\WOW6432Node' }) +
             @(Get-UserHives | ForEach-Object { [pscustomobject]@{ S = $_.User; R = "$($_.Root)\SOFTWARE" } })
    $rows = New-Object System.Collections.Generic.List[object]
    $flagged = 0
    foreach ($r in $roots) {
        foreach ($vendor in 'Microsoft\Edge', 'Google\Chrome') {    # Edge also honours Chrome's registrations
            foreach ($h in Get-ChildItem -LiteralPath "$($r.R)\$vendor\NativeMessagingHosts" -ErrorAction SilentlyContinue) {
                $mfPath = Expand-WinPath ([string](Get-RegValue $h.PSPath '(default)'))
                $mf = Read-JsonFile $mfPath
                $exe = $null; $origins = @()
                if ($mf) {
                    $exe = [string]$mf['path']
                    if ($exe -and -not [IO.Path]::IsPathRooted($exe)) { $exe = Join-Path (Split-Path $mfPath -Parent) $exe }
                    $origins = @(@($mf['allowed_origins']) | Where-Object { $_ })
                }
                $sig = if ($exe) { Get-FileSignatureInfo $exe } else { $null }
                $allowed = @($origins | ForEach-Object { $oid = ([string]$_ -replace '^chrome-extension://', '').Trim('/'); if ($extNames.ContainsKey($oid)) { "$($extNames[$oid]) ($oid)" } else { $oid } })
                $row = [pscustomobject][ordered]@{ Host = $h.PSChildName; Scope = $r.S; Registry = ($vendor -split '\\')[1]; Program = $exe
                    Signature = $(if ($sig) { $sig.Status } else { '' }); Signer = $(if ($sig) { $sig.Signer -replace ',.*$', '' } else { '' }); AllowedExtensions = ($allowed -join ', '); Manifest = $mfPath }
                $rows.Add($row)
                $reasons = @(); $sev = $null; $cls = $null
                if (-not $mf -and -not $isAdmin -and $mfPath -and -not (Test-UserWritablePath $mfPath)) {
                    $row.Program = '(not checked: protected folder, run elevated)'   # e.g. Defender's folder denies standard users
                }
                elseif (-not $mf) { $sev = 'Low'; $cls = 'Ambiguous'; $reasons += 'Its manifest is missing or unreadable (often left over after an uninstall)' }
                elseif (-not $sig -or -not $sig.Exists) { $sev = 'Low'; $cls = 'Ambiguous'; $reasons += 'The program it points to does not exist' }
                else {
                    $uw = Test-UserWritablePath $exe
                    if ($exe -match '(?i)\.(bat|cmd|ps1|vbs|js|py)$') {
                        $txt = ''; try { $txt = [IO.File]::ReadAllText($exe) } catch {}
                        $cr = @(Get-CommandLineRisk $txt)
                        $reasons += 'The host is a script'; if ($cr.Count) { $reasons += $cr.Reason }
                        $sev = if ($cr.Count -or $uw) { 'High' } else { 'Medium' }; $cls = 'Suspicious'
                    } elseif ($sig.Status -ne 'Valid') {
                        $reasons += "The program is not validly signed ($($sig.Status))"
                        if ($uw) { $sev = 'High'; $cls = 'Suspicious'; $reasons += 'and sits in a user-writable folder' } else { $sev = 'Medium'; $cls = 'Ambiguous' }
                    } elseif ($uw -and -not $sig.IsMicrosoft) { $sev = 'Low'; $cls = 'Ambiguous'; $reasons += "Signed by $($row.Signer) but runs from a user-writable folder" }
                }
                if (-not $sev) { continue }
                $flagged++
                Add-Finding -Category $c -Title "Native messaging host '$($h.PSChildName)' ($($r.S))" -Severity $sev -Classification $cls -Evidence $row `
                    -Detail "$($reasons -join '; '). A native messaging host is a program the listed extensions can start and talk to, so a malicious extension + host pair can run anything on this PC." `
                    -Recommendation 'Identify the software that registered it. If unknown, remove the extension(s) it serves and the registry key.' -Tags 'Browser', 'Persistence'
            }
        }
    }
    Add-Finding -Category $c -Title "$($rows.Count) native messaging host(s) registered ($flagged flagged)" -Classification $(if ($flagged) { 'Info' } else { 'OK' }) `
        -Evidence ($rows | Format-List | Out-String -Width 400)
}

# ===========================================================================
Invoke-Check -Name 'Copilot apps and Copilot in Edge' -ScriptBlock {
    $c = 'Copilot'
    $pkgs = @(Get-AppPackages | Where-Object { $_.Name -match '(?i)copilot|MicrosoftOfficeHub|M365' })
    $inv = foreach ($p in $pkgs) {
        $kind = [string]$p.SignatureKind
        if (-not (Test-MicrosoftPackage $p)) {
            Add-Finding -Category $c -Title "Copilot-named app '$($p.Name)' is not a Microsoft Store/system package" -Severity High -Classification Suspicious `
                -Detail "Publisher: $($p.Publisher). Signature: $kind (Developer/None = side-loaded). Fake Copilot apps have been used to spread malware." `
                -Evidence ($p | Select-Object Name, Version, Publisher, SignatureKind, InstallLocation) -Tags 'Copilot'
        }
        [pscustomobject]@{ Package = $p.Name; Version = $p.Version; Publisher = ($p.Publisher -replace '^CN=([^,]+).*$', '$1'); Signature = $kind; Location = $p.InstallLocation }
    }
    Add-Finding -Category $c -Title "$(@($inv).Count) Copilot app package(s) installed" -Classification Info -Evidence (@($inv) | Format-Table -AutoSize | Out-String -Width 400)

    foreach ($u in Get-UninstallEntries | Where-Object { $_.DisplayName -match '(?i)copilot' }) {
        if ($u.Publisher -match '(?i)microsoft|github') { continue }
        Add-Finding -Category $c -Title "Installed program '$($u.DisplayName)' uses the Copilot name but is not from Microsoft/GitHub" -Severity Medium -Classification Suspicious `
            -Detail "Publisher: $($u.Publisher). Fake AI-assistant installers are a common malware lure." -Evidence ($u | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString) -Tags 'Copilot'
    }
    foreach ($p in Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)copilot' -and $_.ExecutablePath }) {
        $sig = Get-FileSignatureInfo $p.ExecutablePath
        if ($sig.Exists -and -not $sig.IsMicrosoft -and $sig.Signer -notmatch 'GitHub') {
            Add-Finding -Category $c -Title "Running '$($p.Name)' (PID $($p.ProcessId)) is not signed by Microsoft or GitHub" -Severity High -Classification Suspicious -Evidence $sig `
                -Detail 'A process using the Copilot name without a Microsoft signature.' -Tags 'Copilot', 'Execution'
        }
    }
    foreach ($up in Get-UserProfilePaths) {
        foreach ($d in 'Downloads', 'Desktop', 'AppData\Local\Temp', 'AppData\Roaming') {
            $dir = Join-Path $up $d
            if (-not (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue)) { continue }
            foreach ($f in Get-ChildItem -LiteralPath $dir -Recurse -Depth 2 -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)copilot' -and $_.Extension -match '(?i)^\.(exe|msi|bat|cmd|ps1|vbs|js|hta|scr)$' } | Select-Object -First 20) {
                $sig = Get-FileSignatureInfo $f.FullName
                if ($sig.IsMicrosoft -or $sig.Signer -match 'GitHub') { continue }
                Add-Finding -Category $c -Title "Copilot-named file not signed by Microsoft: $($f.FullName)" -Severity Medium -Classification Suspicious `
                    -Detail 'Copilot comes from the Microsoft Store or Windows itself, never as a downloaded installer or script. Fake "Copilot" downloads are a known malware lure.' `
                    -Evidence ([pscustomobject]@{ Path = $f.FullName; Created = $f.CreationTime; Size = $f.Length; Signature = $sig.Status; Signer = $sig.Signer; SHA256 = (Get-Sha256 $f.FullName) }) `
                    -Recommendation 'Do not run it. Check the SHA256 on VirusTotal and delete it if it is not what you expected.' -Tags 'Copilot', 'Files'
            }
        }
    }

    # Copilot in Edge: Copilot Mode lets Copilot read open tabs and act on websites
    $state = foreach ($pr in $profiles) {
        $modeOn = Get-JsonValue (Get-JsonValue (Get-JsonValue $pr.LocalState 'edge_copilot_mode_enabled_state') $pr.Profile) 'enabled'
        $pinned = Get-JsonValue (Read-JsonFile (Join-Path $pr.Dir 'Preferences')) 'edge.copilot.is_pinned'
        [pscustomobject]@{ Profile = $pr.Label; CopilotMode = $(if ($null -eq $modeOn) { 'not set' } elseif ($modeOn) { 'ON' } else { 'off' }); SidebarPinned = $(if ($null -eq $pinned) { '' } else { [bool]$pinned }) }
    }
    if (@($state).Count) {
        $on = @($state | Where-Object { $_.CopilotMode -eq 'ON' }).Count
        Add-Finding -Category $c -Title "Copilot in Edge: Copilot Mode is on in $on of $(@($state).Count) profile(s)" -Classification Info -Evidence (@($state) | Format-Table -AutoSize | Out-String -Width 300) `
            -Detail 'Copilot Mode lets Copilot see your open tabs and take actions on websites for you. That is its purpose; it also means extensions that target Copilot pages (see above) can see what you ask it.'
    }
}

# ===========================================================================
Invoke-Check -Name 'AI agent connectors (MCP servers, actions, plugins)' -ScriptBlock {
    $c = 'AI connectors'
    $rows = New-Object System.Collections.Generic.List[object]
    $flagged = 0
    foreach ($p in Get-AppPackages) {
        if (-not $p.InstallLocation) { continue }
        $raw = $null; try { $raw = [IO.File]::ReadAllText((Join-Path $p.InstallLocation 'AppxManifest.xml')) } catch { continue }
        if ($raw -notmatch 'com\.microsoft\.windows\.ai\.') { continue }
        $xml = $null; try { $xml = [xml]$raw } catch { continue }
        foreach ($e in $xml.SelectNodes("//*[local-name()='AppExtension']")) {
            $kind = [string]$e.GetAttribute('Name')
            if ($kind -notlike 'com.microsoft.windows.ai.*') { continue }
            $type = $kind -replace '^com\.microsoft\.windows\.ai\.', ''
            $reg = $e.SelectSingleNode(".//*[local-name()='Registration' or local-name()='AISettings']")
            $regRel = if ($reg) { if ($reg.GetAttribute('Path')) { $reg.GetAttribute('Path') } else { $reg.InnerText.Trim() } } else { '' }
            $regFile = $null
            if ($regRel) {
                foreach ($cand in [IO.Path]::Combine($p.InstallLocation, [string]$e.GetAttribute('PublicFolder'), $regRel), [IO.Path]::Combine($p.InstallLocation, $regRel)) {
                    if (Test-Path -LiteralPath $cand) { $regFile = $cand; break }
                }
            }
            $runs = ''; $desc = ''
            if ($regFile -and $type -eq 'mcpServer') {
                $m = Read-JsonFile $regFile
                $desc = [string](Get-JsonValue $m 'description')
                $cfg = Get-JsonValue $m 'server.mcp_config'
                $runs = (@([string](Get-JsonValue $cfg 'command')) + @(Get-JsonValue $cfg 'args') | Where-Object { $_ }) -join ' '
                $url = [string](Get-JsonValue $m 'server.url'); if (-not $url) { $url = [string](Get-JsonValue $cfg 'url') }
                if ($url) { $runs = $url }
            }
            $sigKind = [string]$p.SignatureKind
            $isMs = Test-MicrosoftPackage $p
            $name = [string]$e.GetAttribute('DisplayName'); if (-not $name -or $name -like 'ms-resource:*') { $name = [string]$e.GetAttribute('Id') }
            $row = [pscustomobject][ordered]@{ Type = $type; Connector = $name; Package = $p.Name; Publisher = ($p.Publisher -replace '^CN=([^,]+).*$', '$1'); Signature = $sigKind; Runs = $runs; Description = $desc }
            $rows.Add($row)
            if ($isMs) { continue }

            $score = 1; $reasons = @("Third-party $type connector: Copilot and other agents can call it to act for you")
            if ($sigKind -in 'Developer', 'None') { $score += 3; $reasons += "the package is side-loaded ($sigKind signature) and skipped Store review" }
            $cr = @(Get-CommandLineRisk $runs)
            foreach ($r in $cr) { $score += $r.Weight; $reasons += $r.Reason }
            if ($runs -match '^(?i)http://(?!localhost|127\.|\[::1\])') { $score += 2; $reasons += 'talks to a remote server without encryption' }
            if ($runs -match '^(?i)https?://\d{1,3}(\.\d{1,3}){3}' -and $runs -notmatch '^(?i)https?://127\.') { $score += 2; $reasons += 'remote server is a raw IP address' }
            $sev = if ($score -ge 5) { 'High' } elseif ($score -ge 3) { 'Medium' } else { 'Low' }
            $cls = if ($score -ge 3) { 'Suspicious' } else { 'Ambiguous' }
            $flagged++
            Add-Finding -Category $c -Title "Agent connector '$name' from $($row.Publisher)" -Severity $sev -Classification $cls -Detail (($reasons -join '; ') + '.') -Evidence $row `
                -Recommendation 'Make sure you installed this app on purpose and trust its publisher; review it in Settings > System > AI components / Agent connectors. Uninstall the app to remove the connector.' -Tags 'Copilot', 'Connector'
        }
    }
    Add-Finding -Category $c -Title "$($rows.Count) Windows AI connector(s)/action(s) registered ($flagged from third parties)" -Classification $(if ($flagged) { 'Info' } else { 'OK' }) `
        -Detail 'Windows lets Copilot and other agents call MCP servers ("agent connectors"), app actions and plugins that apps register. Microsoft''s own are listed for reference.' `
        -Evidence ($rows | Sort-Object Publisher, Type, Connector | Format-Table Type, Connector, Package, Publisher, Signature, Runs -AutoSize -Wrap | Out-String -Width 400)

    # GitHub Copilot (VS Code, Visual Studio, JetBrains) MCP servers. Env values are never shown (they often hold API keys).
    $mcp = New-Object System.Collections.Generic.List[object]
    foreach ($up in Get-UserProfilePaths) {
        $files = @(
            @{ P = 'AppData\Roaming\Code\User\mcp.json'; K = 'servers' }, @{ P = 'AppData\Roaming\Code - Insiders\User\mcp.json'; K = 'servers' },
            @{ P = 'AppData\Roaming\Code\User\settings.json'; K = 'mcp.servers' }, @{ P = 'AppData\Roaming\Code - Insiders\User\settings.json'; K = 'mcp.servers' },
            @{ P = '.mcp.json'; K = 'servers' }, @{ P = 'AppData\Local\github-copilot\intellij\mcp.json'; K = 'servers' }, @{ P = 'AppData\Local\github-copilot\mcp.json'; K = 'servers' }
        )
        foreach ($f in $files) {
            $path = Join-Path $up $f.P
            if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) { continue }
            $j = Read-JsonFile $path -Lenient
            $servers = Get-JsonValue $j $f.K; if (-not $servers) { $servers = Get-JsonValue $j 'mcpServers' }
            if ($servers -isnot [Collections.IDictionary]) { continue }
            foreach ($sn in $servers.Keys) {
                $sv = $servers[$sn]
                $cmd = [string](Get-JsonValue $sv 'command')
                $runs = (@($cmd) + @(Get-JsonValue $sv 'args') | Where-Object { $_ }) -join ' '
                $url = [string](Get-JsonValue $sv 'url'); if ($url) { $runs = $url }
                $envKeys = @(); $envObj = Get-JsonValue $sv 'env'; if ($envObj -is [Collections.IDictionary]) { $envKeys = @($envObj.Keys) }
                $score = 0; $reasons = @()
                foreach ($r in @(Get-CommandLineRisk $runs)) { $score += $r.Weight; $reasons += $r.Reason }
                if ($url -match '^(?i)http://(?!localhost|127\.|\[::1\])') { $score += 2; $reasons += 'remote server without encryption' }
                if ($url -match '^(?i)https?://\d{1,3}(\.\d{1,3}){3}' -and $url -notmatch '^(?i)https?://127\.') { $score += 2; $reasons += 'remote server is a raw IP address' }
                $exe = if ($cmd) { Resolve-CommandPath $cmd } else { $null }
                if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf) -and (Test-UserWritablePath $exe)) {
                    $sig = Get-FileSignatureInfo $exe
                    if ($sig.Status -ne 'Valid' -and $exe -notmatch '(?i)\.(cmd|bat|ps1|js|py)$') { $score += 2; $reasons += "unsigned program in a user-writable folder ($exe)" }
                }
                $mcp.Add([pscustomobject][ordered]@{ Server = $sn; Config = $path; Runs = $runs; EnvVariables = ($envKeys -join ', ') })
                if ($score -lt 2) { continue }
                Add-Finding -Category $c -Title "GitHub Copilot MCP server '$sn' looks risky" -Severity $(if ($score -ge 4) { 'High' } else { 'Medium' }) -Classification Suspicious `
                    -Detail "$($reasons -join '; '). MCP servers run with your permissions whenever Copilot agent mode uses them." -Evidence $mcp[$mcp.Count - 1] -Tags 'Copilot', 'Connector'
            }
        }
    }
    if ($mcp.Count) {
        Add-Finding -Category $c -Title "$($mcp.Count) GitHub Copilot MCP server(s) configured" -Classification Info `
            -Detail 'Each runs code on this PC (or connects to a remote service) when Copilot agent mode calls its tools. Servers started with npx/uvx download the latest package version each time; pin versions you trust.' `
            -Evidence ($mcp | Format-List | Out-String -Width 400)
    }
}

# ===========================================================================
Invoke-Check -Name 'Edge and Copilot network connections' -ScriptBlock {
    $c = 'Edge network'
    $procs = @{}; Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
    $dns = @{}
    try { Get-DnsClientCache -ErrorAction Stop | Where-Object { $_.Data -and $_.Type -in 1, 28 } | ForEach-Object { if (-not $dns.ContainsKey([string]$_.Data)) { $dns[[string]$_.Data] = [string]$_.Entry } } } catch {}
    $ratPorts = @(4444, 4445, 1337, 31337, 6666, 6667, 6668, 6669, 6697, 5552, 1604, 2404, 7777, 9999, 1177, 8848)
    $rows = foreach ($cn in Get-NetTCPConnection -State Established -ErrorAction Stop) {
        $p = $procs[[int]$cn.OwningProcess]
        if (-not $p) { continue }
        $isEdge = $p.Name -in 'msedge.exe', 'msedgewebview2.exe'
        $isCopilot = "$($p.Name) $($p.ExecutablePath)" -match '(?i)copilot|ShellMcpServers|WindowsSkillsHost'
        if (-not ($isEdge -or $isCopilot)) { continue }
        $ip = [string]$cn.RemoteAddress
        if (-not (Test-PublicIP $ip)) { continue }
        # WebView2 belongs to whichever app hosts it; walk up to find that app
        $app = $p; $guard = 0
        while ($app -and $app.Name -eq 'msedgewebview2.exe' -and $guard -lt 6) { $app = $procs[[int]$app.ParentProcessId]; $guard++ }
        $appName = if ($app) { $app.Name } else { $p.Name }
        if ($appName -match '(?i)copilot') { $isCopilot = $true }
        [pscustomobject]@{ App = $appName; Process = $p.Name; PID = $p.ProcessId; IP = $ip; Remote = "$($ip):$($cn.RemotePort)"; Name = $dns[$ip]; Port = [int]$cn.RemotePort
                           Microsoft = $false; Copilot = $isCopilot }
    }
    $rows = @($rows)
    # Edge's secure DNS bypasses the Windows DNS cache, so fall back to reverse lookups (capped, short timeouts)
    $ptr = @{}
    foreach ($ip in @($rows | Where-Object { -not $_.Name } | Select-Object -ExpandProperty IP -Unique | Select-Object -First 40)) {
        try { $ptr[$ip] = [string](Resolve-DnsName -Name $ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1 -ExpandProperty NameHost) } catch {}
    }
    foreach ($row in $rows) {
        if (-not $row.Name -and $ptr[$row.IP]) { $row.Name = $ptr[$row.IP] }
        $row.Microsoft = [bool]($row.Name -and $row.Name -match $msDomains)
    }
    $copOdd = @($rows | Where-Object { $_.Copilot -and -not $_.Microsoft })
    if ($copOdd.Count) {
        Add-Finding -Category $c -Title "Copilot components have $($copOdd.Count) connection(s) to non-Microsoft or unresolved addresses" -Severity Low -Classification Ambiguous `
            -Detail 'Copilot itself only talks to Microsoft services. "Unresolved" usually just means the name is not in the DNS cache (CDNs); a named non-Microsoft site deserves a look, as do agent connectors that call outside services.' `
            -Evidence ($copOdd | Format-Table App, Process, PID, Remote, Name -AutoSize | Out-String -Width 300) -Tags 'Copilot', 'Network'
    }
    $odd = @($rows | Where-Object { $_.Port -in $ratPorts -or (-not $_.Name -and $_.Port -notin 80, 443, 8080, 8443) })
    if ($odd.Count) {
        Add-Finding -Category $c -Title "$($odd.Count) Edge/WebView2 connection(s) to unnamed addresses on unusual ports" -Severity Low -Classification Ambiguous `
            -Detail 'Web pages and extensions normally use ports 80/443. Look up the addresses (AbuseIPDB, VirusTotal) if you do not recognize them.' `
            -Evidence ($odd | Format-Table App, Process, PID, Remote -AutoSize | Out-String -Width 300) -Tags 'Browser', 'Network'
    }
    $summary = $rows | Group-Object App | ForEach-Object { [pscustomobject]@{ App = $_.Name; Connections = $_.Count; NonMicrosoft = @($_.Group | Where-Object { -not $_.Microsoft }).Count
                                                                             Sites = (($_.Group | ForEach-Object { if ($_.Name) { $_.Name } else { $_.Remote } } | Select-Object -Unique -First 25) -join ', ') } }
    Add-Finding -Category $c -Title "$($rows.Count) internet connection(s) from Edge, WebView2 apps and Copilot" -Classification Info -Evidence ($summary | Format-List | Out-String -Width 400)
}

# ===========================================================================
$findings = @(Get-Findings)
$verdict = Get-WinDiagVerdict $findings
if (-not $Quiet) { Write-WinDiagSummary -Findings $findings -Verdict $verdict }
if (-not $NoReport) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $paths = Export-WinDiagReport -Findings $findings -OutputDir $OutputDir -BaseName "EdgeCopilot-$env:COMPUTERNAME-$stamp" -Title "Edge and Copilot review - $env:COMPUTERNAME" -Verdict $verdict -Inventory (Get-Inventory)
    if (-not $Quiet) { Write-Host "`nReport: $($paths.Html)" -ForegroundColor Green }
}
if ($PassThru) { return @($findings) + @(Get-Inventory) }
