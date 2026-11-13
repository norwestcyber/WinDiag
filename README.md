# WinDiag: Windows Update and compromise triage

A read-only PowerShell toolkit that answers two questions:

1. **Why is Windows Update failing?** Is it an ordinary problem (disk, network, corruption, reboot) or has something deliberately broken it?
2. **Are there signs this machine is compromised?**
3. **Is anything abusing Edge or Copilot?** That covers malicious extensions, hijacked settings, remote debugging, and rogue agent connectors.

It then correlates them. A broken update on its own is usually environmental. A broken update *plus* weakened antivirus, new persistence or rogue accounts is the classic pattern of malware protecting itself.

**Nothing is changed on the machine.** Every check only reads. `-CollectLogs` writes copies into the output folder only.

## Files

| File | Purpose |
|---|---|
| `Run-WinDiag.cmd` | Double-click launcher. Elevates and runs everything. |
| `Invoke-WinDiag.ps1` | Runs both diagnostics, correlates them, writes one combined report. |
| `Test-WindowsUpdateHealth.ps1` | Windows Update diagnosis. Can run on its own. |
| `Test-CompromiseIndicators.ps1` | Compromise-indicator sweep. Can run on its own. |
| `Test-EdgeCopilot.ps1` | Edge and Copilot review: extensions, policies, launch flags, native messaging, Copilot apps, AI agent connectors. Can run on its own. |
| `Common.ps1` | Shared helpers (scoring, signatures, report). Not run directly. |

Hardening (firewall cleanup, bloatware removal, services, security settings) lives in the separate [WinHarden](https://github.com/norwestcyber/WinHarden) repository (`Set-WindowsHardening.ps1`). It changes the system, so it is kept apart from this read-only toolkit.

Keep all files in the same folder. Requires Windows 10/11 or Server 2016+ with Windows PowerShell 5.1 (built in) or PowerShell 7.

## Running it

Easiest: double-click `Run-WinDiag.cmd` (it asks for admin rights).

From PowerShell:

```powershell
# Full triage, elevating if needed
powershell -ExecutionPolicy Bypass -File .\Invoke-WinDiag.ps1 -Elevate

# Thorough: adds DISM ScanHealth + SFC verify (5-20 min) and an evidence zip
.\Invoke-WinDiag.ps1 -DeepScan -CollectLogs

# Just one part
.\Test-WindowsUpdateHealth.ps1
.\Test-CompromiseIndicators.ps1 -Days 60
.\Test-EdgeCopilot.ps1
.\Invoke-WinDiag.ps1 -Mode EdgeCopilot
```

If Windows blocks the scripts because they were downloaded, run `Get-ChildItem .\*.ps1 | Unblock-File` once (the `.cmd` launcher does this for you).

Run as Administrator. Without elevation, event logs, Defender exclusions, WMI, BITS, DISM and other users' data are skipped and the report says so.

### Options

| Option | Script | Effect |
|---|---|---|
| `-Mode All\|Update\|Compromise\|EdgeCopilot` | Invoke | Which parts to run (default All). |
| `-OutputDir <path>` | all | Report location (default `Desktop\WinDiag-Reports`). |
| `-Days <n>` | Invoke, Compromise, EdgeCopilot | Event-log look-back / "recently installed" window (default 30). |
| `-UpdateHistoryDays <n>` / `-Days` | Invoke / Update | Update history look-back (default 90). |
| `-DeepScan` | Invoke, Update | DISM `/ScanHealth` + `sfc /verifyonly`. |
| `-SkipNetwork` | Invoke, Update, Compromise | Skip DNS/TCP/TLS tests (offline machines). |
| `-SkipFileScan` | Invoke, Compromise | Skip the dropped-file sweep, the unsigned-DLL scan (about a minute) and the extension code scan (faster). |
| `-SkipCodeScan` | EdgeCopilot | Skip scanning extension code for exfiltration patterns. |
| `-FileScanDays <n>` | Compromise | Age window for dropped files (default 14). |
| `-CollectLogs` | Invoke | Export event logs, CBS/DISM logs, decoded WindowsUpdate.log, gpresult, process/service lists into a zip. |
| `-Elevate` | Invoke | Relaunch as Administrator. |
| `-Quiet`, `-NoOpen` | Invoke | Less console output; don't open the report. |

### Exit codes (for RMM / scripting)

`0` no significant issues · `1` environmental problems only · `2` suspicious, investigate · `3` compromise indicators found

## Reading the report

Each finding has a **severity** (how much it matters) and a **type** (what it most likely means):

| Type | Meaning |
|---|---|
| **Benign** | An ordinary cause: low disk, no internet, clock skew, component-store corruption, pending reboot, TLS 1.2 disabled. Fix it normally. |
| **Ambiguous** | Could be either (e.g. access-denied errors, stale Defender signatures). Decided by what else is found. |
| **Suspicious** | Looks deliberate. Legitimate explanations exist (domain/Intune policy, WSUS, corporate proxy, debloat or update-blocker tools), so confirm who made the change. |
| **Malicious** | Rarely legitimate: replaced system binaries, sticky-keys backdoors, hidden scheduled tasks, broad Defender exclusions on unmanaged PCs, WDigest plaintext passwords, servicing-rollback tampering. |
| **OK / Info** | Passed checks (hidden by default; tick "Show passed checks") and context. |

After the findings, the report has full **inventory tables**. Each table can be filtered, sorted by clicking a column, and switched to "Flagged only"; rows behind a finding are highlighted. Each table is also saved as its own CSV next to the report:
- **Services:** every service with its status, start type, the account it runs as, PID, file path, signer and command line. For services hosted in `svchost.exe`, the file path is the DLL actually loaded.
- **Unsigned DLLs:** every unsigned DLL loaded by a running process, and which processes have it.

The update script ends with a **Diagnosis** line, and the combined report has **Correlation notes** at the top explaining the overall picture.

### How "real problem vs. attacker" is decided

The scripts know whether the machine is **managed** (domain-joined, Azure AD/Intune, SCCM, WSUS). On a managed PC, update policies and proxies are expected and are scored low. On a home PC, nothing legitimate sets them.

They also look for **update-blocking/debloat tools** (Windows Update Blocker, StopUpdates10, Wu10Man, O&O ShutUp10, WinUtil, AtlasOS/ReviOS markers and similar). These do exactly what malware does to updates, on purpose, so if one is present the tampering findings are probably its doing. Check the Event 7040 timestamps in the report against when the tool was run.

Network tests compare **Microsoft endpoints against control sites** (Google, Cloudflare, Wikipedia). Everything failing is a connectivity problem; only Microsoft failing is selective blocking. Black-hole DNS answers or a hosts file that disagrees with public DNS point to tampering. Router-level blockers (Pi-hole, NextDNS, parental controls) can produce the same result.

**Error codes from update history are mapped to likely causes.** For example, `0x80070070` (disk full) and `0x800F081F` (corruption) are environmental. `0x80070422` (service disabled) and `0x8024002E` (blocked by policy) only happen when something changed the configuration.

## What is checked

**Windows Update** (`Test-WindowsUpdateHealth.ps1`)
- Update services (wuauserv, BITS, UsoSvc, WaaSMedicSvc, CryptSvc, TrustedInstaller, DoSvc): start type, binary path and signature, deny-ACEs on the service and its registry key, Event 7040 history
- Policies: WSUS redirection (and whether the server is reachable), access-blocking policies, NoAutoUpdate, pauses beyond the 35-day UI limit
- Hosts file entries for Microsoft or security domains; a redirected hosts-file location
- WinHTTP/user proxy and PAC scripts
- Outbound firewall rules blocking update or Defender binaries
- DNS/TCP reachability (Microsoft vs. control), TLS interception (who signed the certificate), clock skew, TLS 1.2 disabled
- Update history with error-code attribution, repeated failures, uninstalled security updates, time since last success
- Signatures of update/servicing/kernel binaries; patch-rollback ("Windows Downdate") indicators
- SoftwareDistribution/catroot2 redirection or deny ACLs
- DISM health, SFC (with `-DeepScan`), CBS.log errors
- Pending reboot, queued boot-time deletions of security files, uptime, disk space, WinRE state
- Debloat/update-blocker tools; disabled update scheduled tasks; third-party AV

**Compromise indicators** (`Test-CompromiseIndicators.ps1`)
- Defender: disabled components, Tamper Protection, stale signatures, disabling policies, broad exclusions, recent detections, 5001/5007/5013 events
- Accounts: hidden or `$`-suffixed users, Guest enabled, passwordless admins, accounts created or added to Administrators recently
- Event logs: cleared logs, brute-force and internet logons (incl. RDP), suspicious new services, PowerShell flagged script blocks, PowerShell 2.0 downgrade, audit policy changes
- Persistence: Run/RunOnce (all loaded user hives), Winlogon, BootExecute, IFEO debuggers and SilentProcessExit, AppInit/AppCert DLLs, LSA packages, WDigest, netsh helpers, print monitors, accessibility-binary backdoors, scheduled tasks (incl. SD-less hidden tasks), services, ServiceDlls, unsigned/vulnerable/odd drivers, WMI subscriptions, BITS notify jobs, startup folders, PowerShell profiles
- Processes: system-name masquerades, wrong parents, Office spawning shells, risky command lines, unsigned programs in user folders, deleted images
- Unsigned DLLs: every DLL loaded by running processes is signature-checked, including inside 32-bit processes, which are read with the 32-bit PowerShell. Flagged:
  - Unsigned DLLs in user-writable folders or the Windows folder.
  - Unsigned DLLs carrying a Windows DLL's name but loaded from elsewhere (DLL side-loading).
  - Unsigned DLLs claiming to be Microsoft's.
  - Unsigned DLLs loaded by Microsoft's own programs or into `lsass.exe`.
  - DLLs altered after signing or deleted after loading.
  - Per-user COM objects that load unsigned DLLs or override a system-wide registration (COM hijacking).
  - Store-app files and .NET native images are skipped; they are never individually signed.
- Network: scripting hosts on the internet, RAT ports, rogue listeners, netsh portproxy
- Hosts files (`hosts`, `hosts.ics`, `lmhosts`, following a redirected `DataBasePath`):
  - **Pharming:** banks, email and major sites sent to another server.
  - **Blocking:** security and update sites blocked.
  - **Redirects** to internet or LAN addresses, and WPAD entries.
  - **Hiding tricks:** entries pushed off-screen with blank lines or spaces, look-alike characters, malformed lines.
  - **Big ad-block lists** recognized as such.
  - **File protection:** read-only/hidden attributes, write access for non-admins, deny ACLs.
  - **lmhosts `#INCLUDE`** from a network share.
- DNS:
  - **Configured servers:** known public resolvers vs unknown ones, static vs DHCP, VPN adapters, plus the hidden system-wide `NameServer` override that DNSChanger-style malware uses.
  - **Encrypted DNS (DoH):** templates pointing at unknown servers.
  - **NRPT rules:** especially rules that cut security vendors' domains off from DNS.
  - **DNS cache and the DNS-Client query log**, if it is enabled: mining pools, Tor gateways, tunnel services, dynamic-DNS hosts (common RAT C2), exfiltration/callback endpoints, paste sites, IP-lookup services, random-looking (DGA) names, DNS tunnelling, WPAD answers, and major sites answered with local or blocking addresses.
  - **Live tests** (skip with `-SkipNetwork`):
    - Does the resolver invent answers for names that don't exist?
    - Do the addresses returned for PayPal, Microsoft and Google sign-in, VirusTotal and Malwarebytes reach servers with valid certificates? A failure here exposes DNS hijacking at the PC or the router.
- Files: unsigned executables, hidden binaries, double extensions and scripts dropped in user-writable folders (with SHA256 for VirusTotal lookups). Shortcuts (`.lnk`) are judged by what they launch rather than where they sit, because Windows creates them constantly (Recent items, taskbar pins, Start menu). A shortcut is flagged when it does any of these:
  - runs PowerShell, cmd, mshta or another script host with a command line;
  - has a risky command line;
  - opens a script, or starts an unsigned program from a user-writable folder;
  - pads its arguments to hide the command;
  - is named like a document (outside Recent items).
- Root certificates outside Microsoft's program
- Posture: UAC, firewall, SmartScreen, RDP/NLA, SMBv1, LSA protection, HVCI, Secure Boot, test-signing, disabled boot recovery, shadow-copy deletion, System Restore policy
- Remote-access tools (AnyDesk, TeamViewer, ScreenConnect, RustDesk and ~30 others)

**Edge and Copilot** (`Test-EdgeCopilot.ps1`)
- Extensions in every Edge profile and channel (Stable/Beta/Dev/Canary). Each one is scored on:
  - **Install source:** store, unpacked/developer mode, command line, registry side-load, or policy force-install.
  - **Off-store update servers.**
  - **Risky permissions:** debugger, proxy, cookies, native messaging, WebAuthn proxy, and access to every site.
  - **Targeting of AI assistant pages:** Copilot, ChatGPT, Gemini, Claude, Perplexity (prompt and chat harvesting).
  - **Settings takeover:** search, homepage, new tab.
  - **Microsoft-name masquerades.**
  - **Edge's own corrupted/blocklisted flags.**
  - **Code patterns:** Telegram/Discord exfiltration, raw-IP endpoints, cookie dumping.
- Search engine, homepage, startup pages and new-tab overrides
- Edge policies: force-installed extensions, SmartScreen off, DevTools blocked, proxies, forced search/homepage, DNS-over-HTTPS, plus Copilot/Windows AI policies for context
- Launch tampering:
  - Edge started with remote debugging, headless mode or `--load-extension`, plus open debugging ports (how info-stealers dump cookies).
  - Fake `msedge.exe` binaries, edited Edge shortcuts and protocol handlers.
  - WebView2 argument and browser-folder overrides.
- Native messaging hosts (Edge and Chrome registrations): programs an extension can launch, with signature and location checks
- Copilot apps, installers and processes that use the Copilot name but are not Microsoft-signed; Copilot Mode state per profile
- Windows AI agent connectors (MCP servers, app actions, plugins) registered by installed apps, flagging third-party and side-loaded ones; GitHub Copilot MCP servers configured in VS Code, Visual Studio and JetBrains
- Internet connections from Edge, WebView2 apps and Copilot components

## Limitations

- This is triage, not a guarantee. A clean report means these common signals are absent. Kernel rootkits can hide from any tool running on the infected system; for real assurance run **Microsoft Defender Offline** or a bootable scanner, and reimage if in doubt.
- Heuristics produce false positives, especially on developer, gaming and heavily customized PCs. Every finding explains its legitimate explanations; read those before acting.
- The scripts never remove anything. If you find a compromise, isolate the machine first. Removing items destroys evidence and may not remove the attacker.

## Privacy

Reports and the `-CollectLogs` archive contain sensitive data: account names, IP addresses, DNS history, command lines and the Security event log. Store and share them carefully.

The Edge/Copilot review never reads cookies, saved passwords, browsing history or Copilot conversations. It reads only settings files, extension manifests and extension code. For MCP servers it lists the names of environment variables, never their values, which often hold API keys.

If antivirus blocks one check (its detection code can resemble the technique it detects), the report says "blocked by antivirus (AMSI)" for that check and everything else still runs.
