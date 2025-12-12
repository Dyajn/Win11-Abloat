<#
.SYNOPSIS
    Windows 11 Bloatware Remover with External Configuration
.DESCRIPTION
    Removes pre-installed Windows 11 apps based on config.txt settings.
    Features dry run, logging, restoration, group UI, and system tweaks.
.NOTES
    Version: 4.2
    Author: Dyno
    Requires: Windows 11 (Build 22000+), PowerShell 5.0+, Administrator privileges
#>

[CmdletBinding()]
param (
    [Alias("d")][switch]$DryRun = $false,
    [Alias("r")][switch]$Restore = $false,
    [Alias("ng")][switch]$NoGroups = $false,
    [Alias("f")][switch]$Force = $false,
    [Alias("s")][switch]$Silent = $false,
    [Alias("t")][switch]$ApplyTweaks = $false,
    [Alias("lt")][switch]$ListTweaks = $false,
    [Alias("sl")][switch]$ShowLog = $false,
    [Alias("h","?")][switch]$Help = $false,

    [Alias("x")][switch]$Transcript = $false,
    [string]$LogPath = "",
    [string]$ConfigDir = ""
)

Set-StrictMode -Version Latest

# EXE-Mode Detection
function Get-ExeDirectory {
    try { return [IO.Path]::GetDirectoryName(
                [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) }
    catch  { return $null }
}
$IsExe  = $false
$ExeDir = Get-ExeDirectory
if ($ExeDir) {
    $exePath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ($exePath -match '\.exe$' -and $exePath -notmatch 'powershell\.exe$|pwsh\.exe$') {
        $IsExe = $true
    }
}

# Determine Config Directory
if ([string]::IsNullOrEmpty($ConfigDir)) {
    if ($IsExe) {
        # when shipped as EXE, put configs in a sibling "data" directory
        $ConfigDir = Join-Path $ExeDir 'data'
    }
    elseif ($PSScriptRoot) {
        $ConfigDir = $PSScriptRoot
    }
    elseif ($MyInvocation.MyCommand.Path) {
        $ConfigDir = Split-Path $MyInvocation.MyCommand.Path
    }
    else {
        $ConfigDir = (Get-Location).Path
    }
}
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

# Create subdirectories for logs, transcripts, backups, and restore points
$logsDir = Join-Path $ConfigDir 'logs'
$transcriptsDir = Join-Path $ConfigDir 'transcripts'
$backupsDir = Join-Path $ConfigDir 'backups'
$restoreDir = Join-Path $ConfigDir 'restore'
foreach ($dir in @($logsDir, $transcriptsDir, $backupsDir, $restoreDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

if ($Transcript) {
    $transcriptPath = Join-Path $transcriptsDir "PS-Transcript_$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    Start-Transcript -Path $transcriptPath -Append
}

# Compute the path to config files so help can display it
$configFile   = Join-Path $ConfigDir 'config.txt'
$restoreConfig= Join-Path $restoreDir 'restore_config.txt'

# Known tweaks (for dynamic help listing)
$knownTweaks = @(
    "DisableTelemetry","DisableAdvertisingID","DisableFeedback","DisableCortana",
    "DisableLocation","DisableErrorReporting","DisableWiFiSense","DisableConsumerFeatures",
    "DisableBackgroundApps","DisableLockScreenTips","DisableBingSearch","DisableWebSearch",
    "DisableSuggestions","DisableTimeline","DisableActivityHistory","DisableOneDrive",
    "ShowFileExtensions","ShowHiddenFiles","ShowProtectedFiles","DisableAnimations",
    "DisableTransparency","DisableStartMenuAds","DisableLockScreenAds","DisableEdgePrelaunch",
    "DisableEdgeTabPreload","DisableWindowsTips","DisableSuperfetch","SetPowerPlanHighPerformance",
    "DisableGameBar","DisableXboxGameDVR","DisableDefenderCloud","DisableDefenderSampleSubmission",
    "DisableDefenderMAPS","DisableUAC","DisableFirewall","DisableWindowsUpdate",
    "PauseUpdates","DisableSmartScreen","DisableRemoteAssistance","DisableRemoteDesktop"
)

if ($Help) {
    # Dynamically get known tweaks for help output
    Write-Host @"
Windows 11 Debloater Usage
=========================
Removes pre-installed Windows 11 apps and applies system tweaks based on config.txt.

Parameters (aliases in parentheses):
------------------------------------
    -DryRun (-d)         : Show what would be removed or changed, but make no changes.
    -Restore (-r)        : Restore apps listed in restore_config.txt.
    -NoGroups (-ng)      : Ignore group selection UI, process all apps in config.
    -Force (-f)          : Allow removal of critical apps (use with caution).
    -Silent (-s)         : Suppress prompts for automation.
    -LogPath <path>      : Specify custom log file path.
    -ConfigDir <dir>     : Specify custom config directory.
    -ApplyTweaks (-t)    : Apply Windows tweaks as defined in the [Tweaks] section of config.txt.
    -Help (-h, -?)       : Show this help message.

How to Use:
-----------
1. Edit config.txt to control which apps are removed or protected.
2. Optionally, edit the [Tweaks] section to enable/disable system tweaks.
3. Run this script as Administrator.

Examples:
---------
    .\Win11Debloater.ps1 -d
    .\Win11Debloater.ps1 -t
    .\Win11Debloater.ps1 -f -s

Config file location: $configFile

Tweaks Usage:
-------------
    -ApplyTweaks (-t)         : Apply Windows tweaks as defined in the [Tweaks] section of config.txt.
    -ApplyTweaks -DryRun      : Simulate tweaks without making changes.

[Tweaks] section example in config.txt:
---------------------------------------
[Tweaks]
DisableTelemetry,1           # 1 = enable tweak, 0 = disable tweak
DisableAdvertisingID,1
ShowFileExtensions,1
DisableWindowsUpdate,0       # 0 = do not apply this tweak

Available Tweaks:
-----------------
$($knownTweaks -join ", ")

Set 1 to enable, 0 to disable each tweak.
All tweaks support dry run mode.

Notes:
------
- Critical apps are protected unless -Force is specified.
- Use -Restore to attempt to restore previously removed apps.
- Log files are rotated (last 5 kept) and detailed logs are available at the specified or default log path.
- For more information, review the comments in config.txt and the script source.
- If possible, test/run this first in a VM for confirmation.

"@
    exit 0
}

$LogShown = $false

if ($ListTweaks) {
    Write-Host "`nAvailable Tweaks:" -ForegroundColor Cyan
    foreach ($t in $knownTweaks) {
        Write-Host "  $t"
    }
    exit 0
}

# Helper function to escape regex except *
function ConvertTo-RegexWildcard {
    param([string]$pattern)
    # Escape all regex special characters, then convert the escaped wildcard back to a regex wildcard
    $escaped = [Regex]::Escape($pattern) -replace '\\\*', '.*'
    return "^$escaped$" # Anchor the pattern for exact matching
}

# Log rotation: keep last 5 logs
function Remove-OldLogs {
    param(
        [string]$Dir,
        [string]$Pattern = "Windows11Debloater_*.log",
        [int]$MaxLogs    = 5
    )
    try {
        # Force $logs into an array even if there's only one file
        $logs = @(Get-ChildItem -Path $Dir -Filter $Pattern -ErrorAction SilentlyContinue |
                  Sort-Object LastWriteTime -Descending)
        if ($logs.Count -gt $MaxLogs) {
            $logs |
              Select-Object -Skip $MaxLogs |
              Remove-Item -Force
        }
    } catch {
        Write-Host "Log rotation failed: $_" -ForegroundColor Yellow
    }
}
Remove-OldLogs -Dir $logsDir

if ($LogPath -eq "") {
    $LogPath = Join-Path $logsDir "Windows11Debloater_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
}

# Elevation: Relaunch as Admin if Needed
function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
    if (-not (Test-IsAdmin)) {
        try {
            # Build argument list
            $scriptPath = if ($IsExe) {
                [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
            } elseif ($PSScriptRoot) {
                Join-Path $PSScriptRoot $MyInvocation.MyCommand.Name
            } elseif ($MyInvocation.MyCommand.Path) {
                $MyInvocation.MyCommand.Path
            } else {
                $null
            }
            # Build elevation argument array
            $elevArgs = @()
            if (-not $IsExe) {
                $elevArgs += '-NoProfile'
                $elevArgs += '-ExecutionPolicy'; $elevArgs += 'RemoteSigned'
                $elevArgs += '-File';           $elevArgs += $scriptPath
            }

            # Preserve original switches
            if ($DryRun)      { $elevArgs += '-DryRun' }
            if ($Restore)     { $elevArgs += '-Restore' }
            if ($NoGroups)    { $elevArgs += '-NoGroups' }
            if ($Force)       { $elevArgs += '-Force' }
            if ($Silent)      { $elevArgs += '-Silent' }
            if ($ApplyTweaks) { $elevArgs += '-ApplyTweaks' }
            if ($ListTweaks)  { $elevArgs += '-ListTweaks' }
            if ($ShowLog)     { $elevArgs += '-ShowLog' }
            if ($LogPath)     { $elevArgs += '-LogPath';     $elevArgs += $LogPath }
            if ($ConfigDir)   { $elevArgs += '-ConfigDir';   $elevArgs += $ConfigDir }

            # Relaunch with elevation
            if ($IsExe) {
                Start-Process -FilePath $scriptPath -ArgumentList $elevArgs -Verb RunAs
            } else {
                $hostExe = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh" } else { "powershell.exe" }
                Start-Process -FilePath $hostExe -ArgumentList $elevArgs -Verb RunAs
            }
            if (-not $Silent -and $Host.Name -eq "ConsoleHost") {
                Write-Host "Elevating... Press any key to exit."
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            }
            exit
        } catch {
            Write-Host "Failed to elevate: $_" -ForegroundColor Red
            if (-not $Silent) {
                Write-Host "Please run this script as Administrator" -ForegroundColor Yellow
                if ($Host.Name -eq "ConsoleHost") {
                    Write-Host "Press any key to exit..."
                    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                }
            }
            exit 1
        }
    }
#endregion

#region Windows Version and PowerShell Checks
# Grab OS info up front
$os = Get-CimInstance Win32_OperatingSystem

# Only allow Windows 11 (build 22000 or newer)
if ([int]$os.BuildNumber -lt 22000) {
    Write-Warning "This script requires Windows 11 (build 22000+). Detected build $($os.BuildNumber)."
    if (-not $Silent) {
        Write-Host "Press any key to exit..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit 1
}   
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Warning "This script requires PowerShell 5.0 or higher."
    if (-not $Silent) {
        Write-Host "Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }
    exit 1
}
if ($PSVersionTable.PSEdition -eq "Core") {
    Write-Warning "Warning: Running under PowerShell Core (pwsh)"
    Write-Warning "Some features may not work as expected. For best results, use Windows PowerShell (powershell.exe)"
    if (-not $Silent) {
        $continue = Read-Host "Continue anyway? (Y/N)"
        if ($continue -notmatch "^[yY]") { exit }
    }
}
#endregion

#region Logging
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $line      = "[$timestamp] [$Level] $Message"
    # 1) echo to console
    Write-Host $line
    # 2) append to disk with explicit UTF8
    Add-Content -Path $LogPath -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
}
#endregion

function Remove-AppxWithSettings {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $app,

        [Parameter(Mandatory = $true)]
        [ref]$removalTracker,

        [Parameter(Mandatory = $true)]
        [ref]$removedApps,

        [Parameter(Mandatory = $true)]
        [ref]$skippedApps,

        [switch]$DryRun
    )

    Write-Log "Processing: $($app.Name) - User: $($app.RemoveUser), Provisioned: $($app.RemoveProvisioned)" -Level "INFO"
    $appNamePattern = "*$($app.Name)*"
    $actionTaken = $false

    # --- 1. Handle User Package Removal ---
    if ($app.RemoveUser -eq 1) {
        try {
            # PERFORMANCE: Use the -Name parameter for fast, native filtering.
            $userPackages = Get-AppxPackage -AllUsers -Name $appNamePattern -ErrorAction SilentlyContinue

            if ($userPackages) {
                $actionTaken = $true
                foreach ($pkg in $userPackages) {
                    $userInfo = if ($pkg.PackageUserInformation) { "for user $($pkg.PackageUserInformation.UserSecurityId.Value)" } else { "(All Users)" }
                    Write-Log "  - Found user package: $($pkg.Name) $userInfo" -Level "INFO"
                    if ($DryRun) {
                        Write-Log "    [DRY RUN] Would remove user package." -Level "INFO"
                    } else {
                        Write-Log "    Removing user package..." -Level "INFO"
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                        Write-Log "    ✓ Successfully removed user package." -Level "INFO"
                        $removalTracker.Value.UserSuccess++
                    }
                }
            } else {
                Write-Log "  - No user packages found matching '$($app.Name)'." -Level "INFO"
                $removalTracker.Value.UserSkipped++
            }
        } catch {
            Write-Log "  - ✗ ERROR removing user package for '$($app.Name)': $_" -Level "ERROR"
            $removalTracker.Value.UserFail++
        }
    }

    # --- 2. Handle Provisioned Package Removal ---
    if ($app.RemoveProvisioned -eq 1) {
        try {
            # Get-AppxProvisionedPackage doesn't have -Name, so Where-Object is necessary here, but it's still fast.
            $provisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $appNamePattern }

            if ($provisionedPackages) {
                $actionTaken = $true
                foreach ($pkg in $provisionedPackages) {
                    Write-Log "  - Found provisioned package: $($pkg.DisplayName)" -Level "INFO"
                    if ($DryRun) {
                        Write-Log "    [DRY RUN] Would remove provisioned package." -Level "INFO"
                    } else {
                        Write-Log "    Removing provisioned package..." -Level "INFO"
                        Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction Stop
                        Write-Log "    ✓ Successfully removed provisioned package." -Level "INFO"
                        $removalTracker.Value.ProvSuccess++
                        $removalTracker.Value.AnyProvRemoved = $true
                    }
                }
            } else {
                Write-Log "  - No provisioned package found matching '$($app.Name)'." -Level "INFO"
                $removalTracker.Value.ProvSkipped++
            }
        } catch {
            Write-Log "  - ✗ ERROR removing provisioned package for '$($app.Name)': $_" -Level "ERROR"
            $removalTracker.Value.ProvFail++
        }
    }

    # --- 3. Update Final Tracking Lists ---
    # If any action was taken (even a dry run find), count it as "removed" for the summary.
    # Otherwise, it was truly "skipped" because nothing was found.
    if ($actionTaken) {
        $removedApps.Value.Add($app.Name)
    } else {
        # Only add to skipped if an action was intended but no package was found.
        if ($app.RemoveUser -eq 1 -or $app.RemoveProvisioned -eq 1) {
            $skippedApps.Value.Add($app.Name)
        }
    }
}


#region Config/Backup/Restore Paths
$backupConfig = Join-Path $backupsDir "config_backup_$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$currentStateFile = Join-Path $backupsDir "current_state_$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
#endregion

#region Default Config Template (with optional [CriticalApps] section)
$defaultConfig = @"
# Windows 11 Debloater Configuration
# ==================================
# Format: AppName,RemoveUser,RemoveProvisioned
# RemoveUser: 1 removes for current user, 0 keeps it
# RemoveProvisioned: 1 prevents install for new users, 0 keeps in system image
#
# Critical apps below are protected from removal unless using -Force parameter
# These are core system apps that Windows needs for basic functionality

[CriticalApps]
Microsoft.WindowsStore            # Required for app updates and installations
Microsoft.WindowsCalculator       # System calculator app
Microsoft.MSPaint                 # Basic image editing tool
Microsoft.WindowsNotepad          # Simple text editor
Microsoft.WindowsTerminal         # Modern command line interface
Microsoft.WindowsPhotos           # Default image viewer/editor
Microsoft.WindowsCamera           # Webcam interface
Microsoft.WindowsAlarms           # Alarm & timer functionality
Microsoft.WindowsSoundRecorder    # Audio recording tool
Microsoft.WindowsMaps             # Built-in mapping application
Microsoft.WindowsMail             # Email client (connects to Outlook.com)
Microsoft.WindowsCalendar         # Scheduling app
Microsoft.WindowsClock            # Time/date/timezone management
Microsoft.WindowsSettings         # System settings interface (DO NOT REMOVE)
Microsoft.WindowsSecurity         # Windows Security/Defender interface

# ========================
# Communication Apps
# ========================
Microsoft.SkypeApp,1,1             # Preinstalled Skype (can reinstall from Store)
Microsoft.Teams,1,1                # Consumer version of Teams (work version installs separately)
Microsoft.YourPhone,1,1            # Phone Link (keep as 0,0 if you use Android-Windows integration)
Microsoft.People,1,1               # Contacts management app (redundant with Outlook contacts)
Microsoft.Messaging,1,1            # Legacy SMS app (mostly unused since Phone Link exists)

# ========================
# Xbox & Gaming
# ========================
Microsoft.XboxApp,1,1              # Xbox companion app (keep if you game on Xbox)
Microsoft.XboxGameOverlay,1,1      # Game overlay for screenshots/recording
Microsoft.XboxIdentityProvider,1,1 # Xbox login integration
Microsoft.XboxSpeechToTextOverlay,1,1 # Voice chat transcription
Microsoft.Xbox.TCUI,1,1            # Xbox social features
Microsoft.XboxGamingOverlay,1,1    # Performance monitoring overlay
Microsoft.GamingApp,1,1            # Xbox Game Pass advertisements
Microsoft.GamingServices,1,1       # Backend service for Xbox games (required for some Game Pass titles)
Microsoft.XboxGameCallableUI,1,1   # Xbox game interface components

# ========================
# Media & Entertainment
# ========================
Microsoft.ZuneMusic,1,1            # Groove Music (basic music player)
Microsoft.ZuneVideo,1,1            # Movies & TV (video playback app)
Microsoft.MicrosoftSolitaireCollection,1,1 # Ad-supported solitaire games
SpotifyAB.SpotifyMusic,1,1        # Spotify music client (ad-supported install)
PandoraMediaInc.29680B314EFC2,1,1  # Pandora music streaming
Disney.37853FC22B2CE,1,1           # Disney+ streaming app
Netflix.Netflix,1,1                # Netflix streaming client
Microsoft.MixedReality.Portal,1,1  # Windows Mixed Reality VR interface (remove unless using VR)

# ========================
# Bing & Cortana
# ========================
Microsoft.BingNews,1,1             # News aggregator with ads
Microsoft.BingWeather,1,1          # Weather app (uses Bing services)
Microsoft.BingFinance,1,1          # Stock market tracker
Microsoft.BingSports,1,1           # Sports news/scores
Microsoft.BingTravel,1,1           # Travel booking app
Microsoft.BingFoodAndDrink,1,1     # Recipe app
Microsoft.BingHealthAndFitness,1,1 # Health tracking
Microsoft.549981C3F5F10,1,1        # Cortana voice assistant (mostly deprecated)

# ========================
# Social Media
# ========================
Facebook.Facebook,1,1              # Facebook app (web wrapper)
Instagram.Instagram,1,1            # Instagram client
Twitter.Twitter,1,1                # Twitter application
TikTok.TikTok,1,1                  # TikTok video app
LinkedIn.LinkedIn,1,1              # LinkedIn professional network

# ========================
# Productivity
# ========================
Microsoft.GetHelp,1,1              # Windows troubleshooting app (can be useful)
Microsoft.Getstarted,1,1           # Windows tips/tutorials
Microsoft.MicrosoftOfficeHub,1,1   # Office app with ads/upsells (doesn't remove actual Office)
Microsoft.Print3D,1,1              # 3D printing utility (obsolete)
Microsoft.PowerAutomateDesktop,1,1 # RPA automation tool (advanced users may want to keep)
Microsoft.Whiteboard,1,1           # Digital whiteboard (keep if collaborating)
Microsoft.OneConnect,1,1           # Mobile data connection manager (for cellular PCs)

# ========================
# Utilities & Misc
# ========================
Microsoft.3DBuilder,1,1            # Legacy 3D modeling app (replaced by Paint 3D)
Microsoft.Microsoft3DViewer,1,1    # 3D object viewer (FBX/3MF formats)
Microsoft.Wallet,1,1               # Digital wallet/payment storage
Microsoft.WindowsFeedbackHub,1,1   # Sends diagnostic data to Microsoft
Microsoft.WindowsScan,1,1          # Basic scanning utility
Microsoft.ScreenSketch,1,1         # Snipping Tool alternative (Snip & Sketch)
Microsoft.OneDriveSync,1,1         # OneDrive cloud storage (keep as 0,0 if using OneDrive)

# ========================
# Third-Party Apps
# ========================
AdobeSystemsIncorporated.AdobePhotoshopExpress,1,1 # Light version of Photoshop
DolbyLaboratories.DolbyAccess,1,1  # Dolby Atmos control panel (keep if you use Dolby audio)
Duolingo.Duolingo,1,1              # Language learning app
KeeperSecurityInc.Keeper,1,1       # Password manager trial
McAfeeSecurityScan,1,1             # Security scanner (often trial version)
PicsArt.PicsArt,1,1                # Photo editing app

# ========================
# OEM Bloatware (Examples)
# ========================
# ASUS
ASUS.ArmouryCrate,1,1              # RGB lighting/performance control for ASUS
ASUS.AiSuite,1,1                   # ASUS system monitoring

# Dell
Dell.CommandUpdate,1,1             # Dell driver updater
Dell.DellDigitalDelivery,1,1       # Software download manager
Dell.SupportAssist,1,1             # Diagnostic/help tool

# HP
HP.PrinterAssistant,1,1            # Printer management
HP.HPSupportAssistant,1,1          # HP diagnostics
HP.HPJumpStart,1,1                 # Getting started guide

# Lenovo
LenovoCorporation.LenovoVantage,1,1 # System diagnostics/updates
LenovoCorporation.LenovoUtility,1,1 # Hardware-specific features

# Acer
AcerIncorporated.AcerCareCenter,1,1 # System maintenance
AcerIncorporated.AcerProductRegistration,1,1 # Product registration

# Surface
MicrosoftCorporationII.MicrosoftFamily,1,1 # Family safety features

# Notes:
# 1. Apps marked 1,1 will be removed for current user and prevented from installing for new users
# 2. Critical apps are protected - only remove if you understand the consequences
# 3. Some apps may automatically reinstall after major Windows updates
# 4. OEM apps vary by manufacturer - only include the section relevant to your device

# ========================
# Windows Tweaks Section
# ========================
[Tweaks]
# Format: TweakName,Enable(1)/Disable(0)
DisableTelemetry,1
DisableAdvertisingID,1
DisableFeedback,1
DisableCortana,1
DisableLocation,1
DisableErrorReporting,1
DisableWiFiSense,1
DisableConsumerFeatures,1
DisableBackgroundApps,1
DisableLockScreenTips,1
DisableBingSearch,1
DisableWebSearch,1
DisableSuggestions,1
DisableTimeline,1
DisableActivityHistory,1
DisableOneDrive,0
ShowFileExtensions,1
ShowHiddenFiles,1
ShowProtectedFiles,1
DisableSuperfetch,1
DisableWindowsTips,1
DisableGameBar,1
DisableXboxGameDVR,1
DisableDefenderCloud,1
DisableDefenderSampleSubmission,1
DisableDefenderMAPS,1
DisableWindowsUpdate,0
PauseUpdates,0
SetPowerPlanHighPerformance,1
DisableAnimations,1
DisableTransparency,1
DisableStartMenuAds,1
DisableLockScreenAds,1
DisableEdgePrelaunch,1
DisableEdgeTabPreload,1
DisableSmartScreen,0
DisableRemoteAssistance,1
DisableRemoteDesktop,0
DisableUAC,0
DisableFirewall,0
"@
#endregion

#region App Groups
#region App Groups (Updated for expanded config)
$appGroups = @{
    "Communication" = @(
        "Microsoft.SkypeApp",
        "Microsoft.Teams",
        "Microsoft.YourPhone",
        "Microsoft.People",
        "Microsoft.Messaging"
    )
    "Xbox" = @(
        "Microsoft.XboxApp",
        "Microsoft.XboxGameOverlay",
        "Microsoft.XboxIdentityProvider",
        "Microsoft.XboxSpeechToTextOverlay",
        "Microsoft.Xbox.TCUI",
        "Microsoft.XboxGamingOverlay",
        "Microsoft.GamingApp",
        "Microsoft.GamingServices",
        "Microsoft.XboxGameCallableUI"
    )
    "MediaEntertainment" = @(
        "Microsoft.ZuneMusic",
        "Microsoft.ZuneVideo",
        "Microsoft.MicrosoftSolitaireCollection",
        "SpotifyAB.SpotifyMusic",
        "PandoraMediaInc.29680B314EFC2",
        "Disney.37853FC22B2CE",
        "Netflix.Netflix",
        "Microsoft.MixedReality.Portal"
    )
    "BingCortana" = @(
        "Microsoft.BingNews",
        "Microsoft.BingWeather",
        "Microsoft.BingFinance",
        "Microsoft.BingSports",
        "Microsoft.BingTravel",
        "Microsoft.BingFoodAndDrink",
        "Microsoft.BingHealthAndFitness",
        "Microsoft.549981C3F5F10"
    )
    "SocialMedia" = @(
        "Facebook.Facebook",
        "Instagram.Instagram",
        "Twitter.Twitter",
        "TikTok.TikTok",
        "LinkedIn.LinkedIn"
    )
    "Productivity" = @(
        "Microsoft.GetHelp",
        "Microsoft.Getstarted",
        "Microsoft.MicrosoftOfficeHub",
        "Microsoft.Print3D",
        "Microsoft.PowerAutomateDesktop",
        "Microsoft.Whiteboard",
        "Microsoft.OneConnect"
    )
    "UtilitiesMisc" = @(
        "Microsoft.3DBuilder",
        "Microsoft.Microsoft3DViewer",
        "Microsoft.Wallet",
        "Microsoft.WindowsFeedbackHub",
        "Microsoft.WindowsScan",
        "Microsoft.ScreenSketch",
        "Microsoft.OneDriveSync"
    )
    "ThirdParty" = @(
        "AdobeSystemsIncorporated.AdobePhotoshopExpress",
        "DolbyLaboratories.DolbyAccess",
        "Duolingo.Duolingo",
        "KeeperSecurityInc.Keeper",
        "McAfeeSecurityScan",
        "PicsArt.PicsArt"
    )
    "OEM_ASUS" = @(
        "ASUS.ArmouryCrate",
        "ASUS.AiSuite"
    )
    "OEM_Dell" = @(
        "Dell.CommandUpdate",
        "Dell.DellDigitalDelivery",
        "Dell.SupportAssist"
    )
    "OEM_HP" = @(
        "HP.PrinterAssistant",
        "HP.HPSupportAssistant",
        "HP.HPJumpStart"
    )
    "OEM_Lenovo" = @(
        "LenovoCorporation.LenovoVantage",
        "LenovoCorporation.LenovoUtility"
    )
    "OEM_Acer" = @(
        "AcerIncorporated.AcerCareCenter",
        "AcerIncorporated.AcerProductRegistration"
    )
    "OEM_Surface" = @(
        "MicrosoftCorporationII.MicrosoftFamily"
    )
}
#endregion

#region Group Selection UI
function Invoke-GroupSelection {
    param (
        [array]$allApps
    )

    Write-Host "`n===== App Group Selection =====" -ForegroundColor Cyan

    # Ask the user which groups to remove
    $selectedGroups = @()
    foreach ($group in $appGroups.Keys) {
        $choice = Read-Host "Remove group '$group'? (Y/N)"
        if ($choice -match '^[yY]') { $selectedGroups += $group }
    }

    if ($selectedGroups.Count -eq 0) {
        Write-Host "No groups selected. No apps will be processed." -ForegroundColor Yellow
        return @()
    }

    # REFINEMENT: Build a single, efficient regex from the selected group apps.
    $selectedAppPatterns = @()
    foreach ($g in $selectedGroups) { $selectedAppPatterns += $appGroups[$g] }
    
    # Escape each pattern for regex and join with '|' (OR)
    $regexPattern = ($selectedAppPatterns | ForEach-Object { [Regex]::Escape($_) }) -join '|'

    # Filter the main app list using the single regex
    $filtered = $allApps | Where-Object { $_.Name -match $regexPattern }

    Write-Host "Selected $($filtered.Count) apps from groups: $($selectedGroups -join ', ')" -ForegroundColor Cyan
    return $filtered
}
#endregion

#region Core Functions (with improvements)
# --- inside A.ps1 ---
function Test-ConfigFile {
    param(
        [string]$Path,
        [switch]$DryRun,
        [switch]$Force
    )
    try {
        $content       = Get-Content $Path -ErrorAction Stop
        $appNames      = @{}
        $criticalNames = @{}
        $inCritical    = $false
        $inTweaks      = $false

        foreach ($rawLine in $content) {
            # 1) strip BOM
            $clean       = $rawLine.TrimStart([char]0xFEFF)
            # 2) remove inline comments, then trim whitespace
            $line        = ($clean -split '#', 2)[0].Trim()
            # 3) skip empty lines
            if ($line -eq '') { continue }

            # section headers
            switch -regex ($line) {
                '^\[CriticalApps\]' { $inCritical = $true;  $inTweaks = $false; continue }
                '^\[Tweaks\]'       { $inTweaks   = $true;  $inCritical = $false; continue }
                '^\['               { $inCritical = $inTweaks = $false; continue }
            }

            # skip any actual tweak entries in validation
            if ($inTweaks) { continue }

            # capture critical-apps
            if ($inCritical) {
                if ($line -match ',') { continue }  # not a simple name
                if ($criticalNames.ContainsKey($line)) {
                    throw "Duplicate critical app: $line"
                }
                $criticalNames[$line] = $true
                continue
            }

            # validate a three-column app entry
            $parts = $line -split ',' | ForEach-Object { $_.Trim() }
            if ($parts.Count -ne 3) {
                throw "Invalid line format: $rawLine"
            }
            if ($parts[1] -notmatch '^[01]$' -or $parts[2] -notmatch '^[01]$') {
                throw "Invalid removal flags in line: $rawLine (must be 0 or 1)"
            }
            if ($appNames.ContainsKey($parts[0])) {
                throw "Duplicate app name in config: $($parts[0])"
            }
            $appNames[$parts[0]] = $true
        }

        # overlap warning and prompt remain unchanged…
        $overlap = @($criticalNames.Keys | Where-Object { $appNames.ContainsKey($_) })
        foreach ($name in $overlap) {
            Write-Warning "App '$name' is in both [CriticalApps] and removal list."
        }
        if ($overlap.Count -gt 0 -and -not $Force -and -not $DryRun) {
            if ((Read-Host "Continue anyway? (Y/N)") -notmatch '^[yY]') {
                throw "Aborted due to critical-app overlap."
            }
        }

        return $true
    } catch {
        Write-Log "Config validation error: $_" -Level "ERROR"
        return $false
    }
}
function Read-ConfigFile {
    param ([string]$Path)
    $apps         = @()
    $criticalApps = @{}
    $configLines  = Get-Content $Path
    $inCritical   = $false

    foreach ($line in $configLines) {
    # strip BOM if present, then inline comments
    $clean = $line.TrimStart([char]0xFEFF)
    $lineNoComment = ($clean -split '#',2)[0].Trim()
    if ($lineNoComment -eq '') { continue }
    $trimmed = $lineNoComment
    
    # section switches: start critical on [CriticalApps], stop critical at [Tweaks]
    if ($trimmed -match '^\[CriticalApps\]') {
    $inCritical = $true; continue
    } elseif ($trimmed -match '^\[Tweaks\]') {
    $inCritical = $false; continue
    }
    
    # capture critical apps (only lines without commas)
    if ($inCritical -and $trimmed -notmatch ',') {
    $criticalApps[$trimmed] = $true
    continue
    }
    
    # parse regular app rows (must be exactly 3 fields)
    $parts = $trimmed -split ',' | ForEach-Object { $_.Trim() }
    if ($parts.Count -eq 3) {
    $apps += [PSCustomObject]@{
    Name              = $parts[0]
    RemoveUser        = [int]$parts[1]
    RemoveProvisioned = [int]$parts[2]
    }
    }
    }
    return @($apps, $criticalApps)
}

#region Tweaks Parsing and Application
function Read-TweaksFromConfig {
    param ([string]$Path)
    $configLines = Get-Content $Path -ErrorAction Stop
    $inTweaks    = $false
    $tweaks      = @{}

    foreach ($line in $configLines) {
        # strip BOM, then inline comments
        $clean = $line.TrimStart([char]0xFEFF)
        $text  = ($clean -split '#', 2)[0].Trim()
        if ($text -eq '') { continue }

        if ($text -match '^\[Tweaks\]') {
            $inTweaks = $true
            continue
        }

        # if we’re already in Tweaks and hit another section header, stop parsing
        if ($inTweaks -and $text -match '^\[') {
            break
        }

        if ($inTweaks) {
            $parts = $text -split ',' | ForEach-Object { $_.Trim() }
            if ($parts.Count -eq 2) {
                $tweaks[$parts[0]] = [int]$parts[1]
            }
        }
    }

    return $tweaks
}

function Set-WindowsTweaks {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Tweaks,
        [switch]$DryRun = $false,
        [switch]$Force = $false
    )

    Write-Host "`n===== Applying Windows Tweaks =====" -ForegroundColor Cyan

    # Validation
    if (-not $Tweaks -or $Tweaks.Count -eq 0) {
        Write-Warning "No tweaks specified"
        return
    }

    if (-not (Test-IsAdmin)) {
        Write-Host "Tweaks require administrator privileges. Skipping tweaks." -ForegroundColor Red
        Write-Log "Tweaks skipped: not running as administrator." -Level "ERROR"
        return
    }

    if ($DryRun) {
        Write-Host "`n===== DRY RUN MODE: No system changes will be made. =====" -ForegroundColor Yellow
        Write-Log "DRY RUN: Tweaks will not be applied, only simulated." -Level "INFO"
    }

    $applied = New-Object System.Collections.ArrayList
    $failed  = New-Object System.Collections.ArrayList  
    $unknown = New-Object System.Collections.ArrayList

    # Centralized tweak definitions
    $tweakDefinitions = @{
        DisableTelemetry = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
            Properties    = @(@{Name="AllowTelemetry";Type="DWord";Value=0})
            Message       = "Telemetry disabled"
            RequiresForce = $false
        }
        DisableAdvertisingID = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
            Properties    = @(@{Name="Enabled";Type="DWord";Value=0})
            Message       = "Advertising ID disabled"
            RequiresForce = $false
        }
        DisableFeedback = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Siuf\Rules"
            Properties    = @(@{Name="NumberOfSIUFInPeriod";Type="DWord";Value=0})
            Message       = "Feedback frequency set to never"
            RequiresForce = $false
        }
        DisableCortana = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
            Properties    = @(@{Name="AllowCortana";Type="DWord";Value=0})
            Message       = "Cortana disabled"
            RequiresForce = $false
        }
        DisableLocation = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
            Properties    = @(@{Name="Value";Type="String";Value="Deny"})
            Message       = "Location services disabled"
            RequiresForce = $false
        }
        DisableErrorReporting = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
            Properties    = @(@{Name="Disabled";Type="DWord";Value=1})
            Message       = "Error reporting disabled"
            RequiresForce = $false
        }
        DisableWiFiSense = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
            Properties    = @(@{Name="AutoConnectAllowedOEM";Type="DWord";Value=0})
            Message       = "WiFi Sense disabled"
            RequiresForce = $false
        }
        DisableConsumerFeatures = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
            Properties    = @(@{Name="DisableWindowsConsumerFeatures";Type="DWord";Value=1})
            Message       = "Windows consumer features disabled"
            RequiresForce = $false
        }
        DisableBackgroundApps = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
            Properties    = @(@{Name="GlobalUserDisabled";Type="DWord";Value=1})
            Message       = "Background apps disabled"
            RequiresForce = $false
        }
        DisableLockScreenTips = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
            Properties    = @(@{Name="SoftLandingEnabled";Type="DWord";Value=0})
            Message       = "Lock screen tips disabled"
            RequiresForce = $false
        }
        DisableBingSearch = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
            Properties    = @(@{Name="BingSearchEnabled";Type="DWord";Value=0})
            Message       = "Bing search disabled"
            RequiresForce = $false
        }
        DisableWebSearch = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
            Properties    = @(@{Name="AllowSearchToUseLocation";Type="DWord";Value=0})
            Message       = "Web search disabled"
            RequiresForce = $false
        }
        DisableSuggestions = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
            Properties    = @(@{Name="SystemPaneSuggestionsEnabled";Type="DWord";Value=0})
            Message       = "Suggestions disabled"
            RequiresForce = $false
        }
        DisableTimeline = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
            Properties    = @(@{Name="EnableActivityFeed";Type="DWord";Value=0})
            Message       = "Timeline disabled"
            RequiresForce = $false
        }
        DisableActivityHistory = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
            Properties    = @(
                @{Name="PublishUserActivities";Type="DWord";Value=0},
                @{Name="UploadUserActivities";Type="DWord";Value=0}
            )
            Message       = "Activity history disabled"
            RequiresForce = $false
        }
        DisableOneDrive = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
            Properties    = @(@{Name="DisableFileSyncNGSC";Type="DWord";Value=1})
            Message       = "OneDrive disabled"
            RequiresForce = $false
        }
        ShowFileExtensions = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            Properties    = @(@{Name="HideFileExt";Type="DWord";Value=0})
            Message       = "File extensions shown"
            RequiresForce = $false
        }
        ShowHiddenFiles = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            Properties    = @(@{Name="Hidden";Type="DWord";Value=1})
            Message       = "Hidden files shown"
            RequiresForce = $false
        }
        ShowProtectedFiles = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            Properties    = @(@{Name="ShowSuperHidden";Type="DWord";Value=1})
            Message       = "Protected OS files shown"
            RequiresForce = $false
        }
        DisableAnimations = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
            Properties    = @(@{Name="VisualFXSetting";Type="DWord";Value=2})
            Message       = "Animations disabled"
            RequiresForce = $false
        }
        DisableTransparency = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
            Properties    = @(@{Name="EnableTransparency";Type="DWord";Value=0})
            Message       = "Transparency effects disabled"
            RequiresForce = $false
        }
        DisableStartMenuAds = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
            Properties    = @(@{Name="SubscribedContent-StartMenuRecommendationsEnabled";Type="DWord";Value=0})
            Message       = "Start menu recommendations disabled"
            RequiresForce = $false
        }
        DisableLockScreenAds = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
            Properties    = @(
                @{Name="RotatingLockScreenEnabled";Type="DWord";Value=0},
                @{Name="RotatingLockScreenOverlayEnabled";Type="DWord";Value=0}
            )
            Message       = "Lock screen ads disabled"
            RequiresForce = $false
        }
        DisableEdgePrelaunch = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main"
            Properties    = @(@{Name="AllowPrelaunch";Type="DWord";Value=0})
            Message       = "Edge prelaunch disabled"
            RequiresForce = $false
        }
        DisableEdgeTabPreload = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader"
            Properties    = @(@{Name="AllowTabPreloading";Type="DWord";Value=0})
            Message       = "Edge tab preloading disabled"
            RequiresForce = $false
        }
        DisableWindowsTips = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
            Properties    = @(@{Name="SubscribedContent-338393Enabled";Type="DWord";Value=0})
            Message       = "Windows welcome experience tips disabled"
            RequiresForce = $false
        }
        DisableGameBar = @{
            Type          = "Registry"
            Path          = "HKCU:\Software\Microsoft\GameBar"
            Properties    = @(
                @{Name="AllowAutoGameMode";Type="DWord";Value=0},
                @{Name="ShowStartupPanel";Type="DWord";Value=0}
            )
            Message       = "Game Bar disabled"
            RequiresForce = $false
        }
        DisableXboxGameDVR = @{
            Type          = "Registry"
            Path          = "HKCU:\System\GameConfigStore"
            Properties    = @(@{Name="GameDVR_Enabled";Type="DWord";Value=0})
            AdditionalPaths = @(
                @{
                    Path       = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
                    Properties = @(@{Name="AppCaptureEnabled";Type="DWord";Value=0})
                }
            )
            Message       = "Xbox Game DVR disabled"
            RequiresForce = $false
        }
        DisableSuperfetch = @{
            Type          = "Service"
            ServiceName   = "SysMain"
            StartupType   = "Disabled"
            Message       = "Superfetch (SysMain) disabled"
            RequiresForce = $false
        }
        DisableWindowsUpdate = @{
            Type          = "Service"
            ServiceName   = "wuauserv"
            StartupType   = "Disabled"
            Message       = "Windows Update service disabled"
            RequiresForce = $false
        }
        DisableDefenderCloud = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
            Properties    = @(@{Name="SpynetReporting";Type="DWord";Value=0})
            Message       = "Defender cloud protection disabled"
            RequiresForce = $true
        }
        DisableDefenderSampleSubmission = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
            Properties    = @(@{Name="SubmitSamplesConsent";Type="DWord";Value=2})
            Message       = "Defender sample submission disabled"
            RequiresForce = $true
        }
        DisableDefenderMAPS = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
            Properties    = @(@{Name="DisableBlockAtFirstSeen";Type="DWord";Value=1})
            Message       = "Defender MAPS disabled"
            RequiresForce = $true
        }
        DisableUAC = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Properties    = @(@{Name="EnableLUA";Type="DWord";Value=0})
            Message       = "UAC disabled"
            RequiresForce = $true
        }
        DisableFirewall = @{
            Type          = "Custom"
            ScriptBlock   = {
                param($DryRun)
                if ($DryRun) { return }
                if (Get-Module -ListAvailable NetSecurity) { Import-Module NetSecurity -ErrorAction SilentlyContinue }
                if (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue) {
                    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction Stop
                } else {
                    netsh advfirewall set allprofiles state off
                }
            }
            Message       = "Firewall disabled"
            RequiresForce = $true
        }
        PauseUpdates = @{
            Type        = "Custom"
            ScriptBlock = {
                param($DryRun)
                if ($DryRun) { return }
                $expiry = [int]((Get-Date).AddDays(7).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalSeconds)
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
                New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "PauseUpdatesExpiryTime" -PropertyType DWord -Value $expiry -Force -ErrorAction Stop
            }
            Message       = "Windows Updates paused for 7 days"
            RequiresForce = $false
        }
        SetPowerPlanHighPerformance = @{
            Type        = "Custom"
            ScriptBlock = {
                param($DryRun)
                if ($DryRun) { return }
                $highPerfGuid = '8c5e7fdc-3a73-4d63-9965-e4e51c6a5b8c'
                $currentSchemes = powercfg -l
                if ($currentSchemes -match $highPerfGuid) {
                    powercfg -setactive $highPerfGuid
                    return
                }
                $guid = (powercfg -l |
                        Select-String -Pattern '([0-9A-F\-]{36}).*High performance' |
                        ForEach-Object { 
                            if ($_.Line -match '([0-9A-F\-]{36})') { 
                                $matches[1] 
                            } 
                        })[0]
                if (-not $guid) {
                    try {
                        # Try to duplicate the balanced plan and set it to high performance
                        powercfg -duplicatescheme 381b4222-f694-41f0-9685-ff5bb260df2e $highPerfGuid 2>$null
                        $guid = $highPerfGuid
                    } catch {
                        # If all else fails, use the default balanced scheme
                        $guid = '381b4222-f694-41f0-9685-ff5bb260df2e'
                    }
                }
                powercfg -setactive $guid
            }
            Message       = "Power plan set to High Performance"
            RequiresForce = $false
        }
        DisableSmartScreen = @{
            Type          = "Registry"
            Path          = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
            Properties    = @(@{Name="EnableSmartScreen";Type="DWord";Value=0})
            Message       = "SmartScreen disabled"
            RequiresForce = $false
        }
        DisableRemoteAssistance = @{
            Type          = "Registry"
            Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
            Properties    = @(@{Name="fAllowToGetHelp";Type="DWord";Value=0})
            Message       = "Remote Assistance disabled"
            RequiresForce = $false
        }
        DisableRemoteDesktop = @{
            Type          = "Registry"
            Path          = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
            Properties    = @(@{Name="fDenyTSConnections";Type="DWord";Value=1})
            Message       = "Remote Desktop disabled"
            RequiresForce = $false
        }
    }

    function Invoke-RegistryTweak {
        param($TweakName, $Config, $DryRun, $Applied, $Failed)
        if ($DryRun) {
            Write-Log "[DRY RUN] Would apply $TweakName" -Level "INFO"
            $Applied.Add($TweakName); return
        }
        try {
            New-Item -Path $Config.Path -Force | Out-Null
            foreach ($prop in $Config.Properties) {
                New-ItemProperty -Path $Config.Path -Name $prop.Name -PropertyType $prop.Type -Value $prop.Value -Force -ErrorAction Stop
            }
            if ($Config.AdditionalPaths) {
                foreach ($ap in $Config.AdditionalPaths) {
                    New-Item -Path $ap.Path -Force | Out-Null
                    foreach ($p in $ap.Properties) {
                        New-ItemProperty -Path $ap.Path -Name $p.Name -PropertyType $p.Type -Value $p.Value -Force -ErrorAction Stop
                    }
                }
            }
            Write-Log $Config.Message -Level "INFO"
            $Applied.Add($TweakName)
        } catch {
            Write-Log "Failed to apply $TweakName`: $_" -Level "WARN"
            $Failed.Add($TweakName)
        }
    }

    function Invoke-ServiceTweak {
        param($TweakName, $Config, $DryRun, $Applied, $Failed)
        if ($DryRun) {
            Write-Log "[DRY RUN] Would set $($Config.ServiceName) to $($Config.StartupType)" -Level "INFO"
            $Applied.Add($TweakName); return
        }
        try {
            Stop-Service -Name $Config.ServiceName -ErrorAction SilentlyContinue
            Set-Service  -Name $Config.ServiceName -StartupType $Config.StartupType -ErrorAction Stop
            Write-Log $Config.Message -Level "INFO"
            $Applied.Add($TweakName)
        } catch {
            Write-Log "Failed to configure $($Config.ServiceName): $_" -Level "WARN"
            $Failed.Add($TweakName)
        }
    }

    function Invoke-CustomTweak {
        param($TweakName, $Config, $DryRun, $Applied, $Failed)
        if ($DryRun) {
            Write-Log "[DRY RUN] Would apply $TweakName" -Level "INFO"
            $Applied.Add($TweakName); return
        }
        try {
            & $Config.ScriptBlock -DryRun:$DryRun
            Write-Log $Config.Message -Level "INFO"
            $Applied.Add($TweakName)
        } catch {
            Write-Log "Failed to apply $TweakName`: $_" -Level "WARN"
            $Failed.Add($TweakName)
        }
    }

    # Detect unknown tweaks
    foreach ($t in $Tweaks.Keys) {
        if ($t -notin $knownTweaks) {
            Write-Log "Unknown tweak '$t' in config. Ignored." -Level "WARN"
            $unknown.Add($t)
        }
    }

    $secureSkip = (-not $Force -and -not $DryRun)

    # Apply all requested tweaks
    foreach ($t in $Tweaks.Keys) {
        if ($Tweaks[$t] -ne 1) { continue }
        if ($t -notin $knownTweaks) { continue }

        $cfg = $tweakDefinitions[$t]
        if ($cfg.RequiresForce -and $secureSkip) {
            Write-Host "Skipping '$t' (requires -Force)" -ForegroundColor Yellow
            Write-Log "Skipped $t because -Force was not specified." -Level "WARN"
            continue
        }

        switch ($cfg.Type) {
            "Registry" { Invoke-RegistryTweak -TweakName $t -Config $cfg -DryRun:$DryRun -Applied $applied -Failed $failed }
            "Service"  { Invoke-ServiceTweak  -TweakName $t -Config $cfg -DryRun:$DryRun -Applied $applied -Failed $failed }
            "Custom"   { Invoke-CustomTweak   -TweakName $t -Config $cfg -DryRun:$DryRun -Applied $applied -Failed $failed }
        }
    }

    Write-Host "Tweaks applied. Some may require a reboot to take effect." -ForegroundColor Green
    Write-Log "Windows tweaks applied successfully" -Level "INFO"

    # Summary
    Write-Host "`n===== Tweaks Summary =====" -ForegroundColor Cyan
    if ($applied.Count) { Write-Host "Applied:" -ForegroundColor Green;  $applied | ForEach-Object { Write-Host "  $_" -ForegroundColor Green } }
    if ($failed.Count)  { Write-Host "Failed:"  -ForegroundColor Red;    $failed  | ForEach-Object { Write-Host "  $_" -ForegroundColor Red   } }
    if ($unknown.Count) { Write-Host "Unknown:" -ForegroundColor Yellow; $unknown | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow } }
    if (-not $applied.Count -and -not $failed.Count) {
        Write-Host "No tweaks were applied." -ForegroundColor Yellow
    }

    # Reboot notice
    $rebootTweaks = "DisableSuperfetch","DisableWindowsUpdate","DisableUAC","DisableFirewall","DisableRemoteDesktop"
    if ($applied | Where-Object { $_ -in $rebootTweaks }) {
        Write-Host "`nSome tweaks require a reboot to take full effect." -ForegroundColor Magenta
    }
}
#endregion

function Test-AppNames {
    param(
        [Parameter(Mandatory)]
        [array]$apps
    )

    # REFINEMENT: Use a HashSet for much faster lookups (O(1) vs O(n)).
    $allAppIdentifiers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    
    Get-AppxPackage -AllUsers | ForEach-Object {
        if (-not [string]::IsNullOrEmpty($_.Name)) { $allAppIdentifiers.Add($_.Name) | Out-Null }
        if (-not [string]::IsNullOrEmpty($_.PackageFamilyName)) { $allAppIdentifiers.Add($_.PackageFamilyName) | Out-Null }
    }
    Get-AppxProvisionedPackage -Online | ForEach-Object {
        if (-not [string]::IsNullOrEmpty($_.DisplayName)) { $allAppIdentifiers.Add($_.DisplayName) | Out-Null }
        if (-not [string]::IsNullOrEmpty($_.PackageName)) { $allAppIdentifiers.Add($_.PackageName) | Out-Null }
    }

    foreach ($app in $apps) {
        # Since removal logic uses wildcards, we can't do a direct HashSet lookup.
        # We must iterate, but we can optimize by pre-filtering the HashSet.
        $pattern = "*$($app.Name)*"
        
        # The -like operator is efficient enough here, and this check is a user-friendly feature,
        # not a performance-critical part of the removal loop.
        $found = $false
        foreach($identifier in $allAppIdentifiers) {
            if($identifier -like $pattern) {
                $found = $true
                break
            }
        }

        if (-not $found) {
            Write-Warning "App '$($app.Name)' not found on system. Check for typos or missing packages."
        }
    }
}

function Export-CurrentState {
    param (
        [string]$Path
    )
    try {
        $currentApps = @()
        $userApps = Get-AppxPackage -AllUsers | Select-Object Name, PackageUserInformation
        $provApps = Get-AppxProvisionedPackage -Online | Select-Object DisplayName
        $allApps = ($userApps.Name + $provApps.DisplayName) | Where-Object { $_ -ne $null } | Select-Object -Unique | Sort-Object
        foreach ($app in $allApps) {
            $currentApps += "$app,0,0"
        }
        # Atomic write
        $tmp = "$Path.tmp"
        $currentApps | Out-File $tmp -Encoding UTF8
        Move-Item -Path $tmp -Destination $Path -Force
        Write-Log "Exported current app state to $Path" -Level "INFO"
        Write-Host "Current app state exported to: $Path" -ForegroundColor Green
    } catch {
        Write-Log "Failed to export current state: $_" -Level "ERROR"
    }
}

function Show-CriticalAppWarning {
    param(
        [array] $appsToProcess,
        [hashtable] $criticalApps,
        [switch] $DryRun,
        [switch] $Force
    )
    $warningsShown = 0
    foreach ($app in $appsToProcess) {
        if ($criticalApps.ContainsKey($app.Name)) {
            if ($app.RemoveUser -eq 1 -or $app.RemoveProvisioned -eq 1) {
                Write-Log "WARNING: Attempting to remove critical app: $($app.Name)" -Level "WARN"
                $warningsShown++
            }
        }
    }
    if ($warningsShown -gt 0) {
        Write-Host "`nCritical apps marked for removal:" -ForegroundColor Red
        foreach ($app in $appsToProcess) {
            if ($criticalApps.ContainsKey($app.Name) -and ($app.RemoveUser -eq 1 -or $app.RemoveProvisioned -eq 1)) {
                Write-Host "  $($app.Name)" -ForegroundColor Red
            }
        }
        if (-not $DryRun) {
            if (-not $Force) {
                Write-Host "`nCritical apps are marked for removal. Use -Force to proceed, or edit config.txt to keep them." -ForegroundColor Yellow
                Write-Log "Aborted: Critical apps marked for removal without -Force." -Level "WARN"
                return 1
            }
        }
    }
    return 0
}
function Restore-Apps {
    param (
        [string]$ConfigPath
    )

    if ($PSVersionTable.PSEdition -eq "Core") {
        Write-Host "WARNING: App restoration is not fully supported in PowerShell Core (pwsh). Use Windows PowerShell (powershell.exe) for best results." -ForegroundColor Yellow
        Write-Log "Restore attempted in PowerShell Core; some cmdlets may not be available." -Level "WARN"
    }

    if (-not (Test-Path $ConfigPath)) {
        Write-Log "Restore config file not found: $ConfigPath" -Level "ERROR"
        Write-Host "Restore config file not found: $ConfigPath" -ForegroundColor Red
        Write-Host "Please ensure the restore_config.txt file exists in the script directory" -ForegroundColor Yellow
        return
    }
    try {
        $result = Read-ConfigFile -Path $ConfigPath
        $appsToRestore = $result[0]
        $successCount = 0
        $failCount = 0
        Write-Log "Starting app restoration from $ConfigPath" -Level "INFO"
        Write-Host "`n===== RESTORING APPS =====" -ForegroundColor Cyan
        foreach ($app in $appsToRestore) {
            try {
                Write-Host "Attempting to restore: $($app.Name)" -ForegroundColor Gray
                Write-Log "Attempting to restore: $($app.Name)" -Level "INFO"
                # For provisioned packages (system-wide)
                if ($app.RemoveProvisioned -eq 1) {
                    $packageDirs = @(Get-ChildItem -Path "$env:SystemDrive\Program Files\WindowsApps" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$($app.Name)*" })
                    if ($packageDirs.Count -gt 0) {
                        $latestPackage = $packageDirs | Sort-Object Name -Descending | Select-Object -First 1
                        $appxFile = Get-ChildItem -Path $latestPackage.FullName -Filter "*.appx" -ErrorAction SilentlyContinue
                        if (-not $appxFile) {
                            $appxFile = Get-ChildItem -Path $latestPackage.FullName -Filter "*.msix" -ErrorAction SilentlyContinue
                        }
                        if ($appxFile) {
                            $licenseFile = Get-ChildItem -Path "$($latestPackage.FullName)\AppxMetadata" -Filter "*_license.xml" -ErrorAction SilentlyContinue
                            if ($licenseFile) {
                                Add-AppxProvisionedPackage -Online -PackagePath $appxFile.FullName -LicensePath $licenseFile.FullName -ErrorAction Stop
                                Write-Host "✓ Restored provisioned package: $($app.Name)" -ForegroundColor Green
                                Write-Log "✓ Restored provisioned package: $($app.Name)" -Level "INFO"
                                $successCount++
                            } else {
                                Write-Host "! License file not found for: $($app.Name)" -ForegroundColor Yellow
                                Write-Log "License file not found for: $($app.Name)" -Level "WARN"
                                $failCount++
                            }
                        } else {
                            Write-Host "! Appx/MSIX package not found for: $($app.Name)" -ForegroundColor Yellow
                            Write-Log "Appx/MSIX package not found for: $($app.Name)" -Level "WARN"
                            $failCount++
                        }
                    } else {
                        Write-Host "! Package directory not found for: $($app.Name)" -ForegroundColor Yellow
                        Write-Log "Package directory not found for: $($app.Name)" -Level "WARN"
                        Write-Host "This app may not be restorable from WindowsApps. Try restoring from Microsoft Store or your OEM's website." -ForegroundColor Yellow
                    }
                }
                # For user packages
                if ($app.RemoveUser -eq 1) {
                    $escapedPattern = ConvertTo-RegexWildcard $app.Name
                    $manifestFiles = @(Get-ChildItem -Path "$env:SystemDrive\Program Files\WindowsApps" -Recurse -Filter "AppxManifest.xml" -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match "\\$escapedPattern\\" })
                    if ($manifestFiles.Count -gt 0) {
                        $latestManifest = $manifestFiles | Sort-Object DirectoryName -Descending | Select-Object -First 1
                        Add-AppxPackage -DisableDevelopmentMode -Register $latestManifest.FullName -ErrorAction Stop
                        Write-Host "✓ Restored user package: $($app.Name)" -ForegroundColor Green
                        Write-Log "✓ Restored user package: $($app.Name)" -Level "INFO"
                        $successCount++
                    } else {
                        Write-Host "! Manifest not found for: $($app.Name)" -ForegroundColor Yellow
                        Write-Log "Manifest not found for: $($app.Name)" -Level "WARN"
                        $failCount++
                        Write-Host "Try restoring from Microsoft Store if available." -ForegroundColor Yellow
                    }
                }
            } catch {
                Write-Host "✗ Failed to restore $($app.Name): $_" -ForegroundColor Red
                Write-Log "✗ Failed to restore $($app.Name): $_" -Level "ERROR"
                $failCount++
            }
        }
        Write-Log "Restore completed. Success: $successCount, Failed: $failCount" -Level "INFO"
        Write-Host "`nRestore completed. Success: $successCount, Failed: $failCount" -ForegroundColor Cyan
        Write-Host "(Note: Success/Fail counts are per-restore-attempt, not per-app. If an app has both user and provisioned restore, both are counted.)" -ForegroundColor Gray
        if ($failCount -gt 0) {
            Write-Host "`nFor failed restores:" -ForegroundColor Yellow
            Write-Host "1. Try reinstalling from Microsoft Store" -ForegroundColor Yellow
            Write-Host "2. Some system apps may require manual download" -ForegroundColor Yellow
            Write-Host "3. Check the log file for details: $LogPath" -ForegroundColor Yellow
        }
        Write-Host "`n===== RESTORE LIMITATIONS =====" -ForegroundColor Yellow
        Write-Host "Not all apps can be restored automatically from the WindowsApps folder." -ForegroundColor Yellow
        Write-Host "Some apps (especially third-party, OEM, or system apps) may require manual reinstallation from the Microsoft Store or your device manufacturer's website." -ForegroundColor Yellow
        Write-Host "Note: Accessing 'C:\Program Files\WindowsApps' may require taking ownership or special permissions, even as Administrator." -ForegroundColor Yellow
        Write-Host "If you see access denied errors, see https://docs.microsoft.com/en-us/windows/win32/shell/appx--windows-store-apps- for more info." -ForegroundColor Yellow
        Write-Host "If restoration fails:" -ForegroundColor Yellow
        Write-Host "  1. Open Microsoft Store and search for the app to reinstall." -ForegroundColor Yellow
        Write-Host "  2. For OEM or bundled apps, visit your device manufacturer's support page." -ForegroundColor Yellow
        Write-Host "  3. For system apps, some may only be restored by resetting or repairing Windows." -ForegroundColor Yellow
        Write-Host "Check the log file for details: $LogPath" -ForegroundColor Yellow
    } catch {
        Write-Log "Fatal error during restore: $_" -Level "ERROR"
        Write-Host "Fatal error during restore: $_" -ForegroundColor Red
    }
}
function Show-Summary {
    param (
        $removalTracker,
        $totalApps,
        $removedApps,
        $skippedApps
    )

    Write-Log "===== Summary =====" -Level "INFO"
    Write-Log "User package removals:" -Level "INFO"
    Write-Log "  Successful: $($removalTracker.UserSuccess)" -Level "INFO"
    Write-Log "  Failed: $($removalTracker.UserFail)" -Level $(if ($removalTracker.UserFail -gt 0) { "ERROR" } else { "INFO" })
    Write-Log "Provisioned package removals:" -Level "INFO"
    Write-Log "  Successful: $($removalTracker.ProvSuccess)" -Level "INFO"
    Write-Log "  Failed: $($removalTracker.ProvFail)" -Level $(if ($removalTracker.ProvFail -gt 0) { "ERROR" } else { "INFO" })
    Write-Log "  Skipped: $($removalTracker.ProvSkipped)" -Level "INFO"
    Write-Log "Total apps processed: $totalApps" -Level "INFO"

    Write-Host "`n===== Summary =====" -ForegroundColor Cyan
    Write-Host "User package removals:" -ForegroundColor Cyan
    Write-Host "  Successful: $($removalTracker.UserSuccess)" -ForegroundColor Green
    Write-Host "  Failed: $($removalTracker.UserFail)" -ForegroundColor $(if ($removalTracker.UserFail -gt 0) { "Red" } else { "Gray" })

    Write-Host "`nProvisioned package removals:" -ForegroundColor Cyan
    Write-Host "  Successful: $($removalTracker.ProvSuccess)" -ForegroundColor Green
    Write-Host "  Failed: $($removalTracker.ProvFail)" -ForegroundColor $(if ($removalTracker.ProvFail -gt 0) { "Red" } else { "Gray" })

    $skippedUnique = $skippedApps | Sort-Object -Unique
    $removedUnique = $removedApps | Sort-Object -Unique

    Write-Host "`nTotal skipped or failed: $($skippedUnique.Count)" -ForegroundColor Yellow
    Write-Host "(Skipped = already removed or not found; Failed = removal error)" -ForegroundColor Gray
    Write-Host "`nTotal apps processed: $totalApps" -ForegroundColor Cyan

    # ---------- Removed apps ----------
    Write-Host "`nApps actually removed:" -ForegroundColor Green
    if ($removedUnique.Count -eq 0) {
        Write-Host "  None" -ForegroundColor Gray
    }
    else {
        foreach ($app in $removedUnique) {
            Write-Host "  $app" -ForegroundColor Green
        }
    }

    # ---------- Skipped / failed apps ----------
    Write-Host "`nApps skipped or failed:" -ForegroundColor Yellow
    if ($skippedUnique.Count -eq 0) {
        Write-Host "  None" -ForegroundColor Gray
    }
    else {
        foreach ($app in $skippedUnique) {
            Write-Host "  $app" -ForegroundColor Yellow
        }
    }

    Write-Host "`nNote: Edit config.txt to change removal settings" -ForegroundColor Blue
    Write-Host "Config location: $configFile" -ForegroundColor Blue
    if (Test-Path $backupConfig) {
        Write-Log "Backup created at: $backupConfig" -Level "INFO"
        Write-Host "Backup created at: $backupConfig" -ForegroundColor Blue
    }

    if ($removalTracker.AnyProvRemoved -and -not $DryRun) {
        Write-Host "`nNOTE: Provisioned packages were removed." -ForegroundColor Yellow
        Write-Host "For complete removal, a system reboot is recommended." -ForegroundColor Yellow
    }

    # CSV export ― unchanged
    $csvPath = Join-Path $logsDir "removal_results_$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $results = @()
    foreach ($app in $removedUnique) { $results += [PSCustomObject]@{App=$app;Status="Removed"} }
    foreach ($app in $skippedUnique) { $results += [PSCustomObject]@{App=$app;Status="Skipped/Failed"} }
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nDetailed results exported to: $csvPath" -ForegroundColor Blue
}
#endregion

#region Main Execution
try {
    Write-Log "Starting Windows 11 Debloater" -Level "INFO"
    Write-Log "Parameters - DryRun: $DryRun, Restore: $Restore, NoGroups: $NoGroups, Force: $Force, Silent: $Silent" -Level "INFO"
    if ($Restore) {
        Write-Host "`n===== Windows 11 App Restoration =====" -ForegroundColor Cyan
        Write-Log "Starting restoration process" -Level "INFO"
        Restore-Apps -ConfigPath $restoreConfig
        exit 0
    }
    # Create or backup config file (atomic write)
    if (Test-Path $configFile) {
        Copy-Item $configFile $backupConfig -Force
        Write-Log "Existing config.txt backed up to $backupConfig" -Level "INFO"
    } else {
        $tmp = "$configFile.tmp"
        $defaultConfig | Out-File $tmp -Encoding UTF8
        Move-Item -Path $tmp -Destination $configFile -Force
        Write-Log "Default config.txt created at $configFile" -Level "INFO"
        Write-Host "Default config.txt created at $configFile" -ForegroundColor Green
        Write-Host "Please review the configuration before running again" -ForegroundColor Yellow
        try {
            Start-Process notepad.exe $configFile
            Write-Host "Opened config.txt in Notepad for editing." -ForegroundColor Yellow
        } catch {
            Write-Host "Could not open Notepad automatically. Please open config.txt manually." -ForegroundColor Red
        }
        exit 0
    }
    # Offer to export current state
    if (-not $DryRun -and -not $Silent) {
        $exportChoice = Read-Host "`nExport current app state before making changes? (Y/N)"
        if ($exportChoice -match "^[yY]") {
            Export-CurrentState -Path $currentStateFile
        }
    }
    # Parse config file
    try {
        if (-not (Test-ConfigFile -Path $configFile -DryRun:$DryRun -Force:$Force)) { exit 1 }
        $result = Read-ConfigFile -Path $configFile
        $appsToProcess = $result[0] # This is already an array
        $criticalApps = $result[1]

        if ($appsToProcess.Count -gt 0) {
            Test-AppNames -apps $appsToProcess
        }
        else {
            Write-Log "No apps to validate (appsToProcess is empty)." -Level "INFO"
        }

        $appsCount = $appsToProcess.Count

        Write-Host "`n===== Config Summary =====" -ForegroundColor Cyan
        Write-Host "Apps to process: $appsCount" -ForegroundColor Cyan
        Write-Log "Critical apps protected: $($criticalApps.Count)" -Level "INFO"

    } catch {
        Write-Log "Error reading config: $_" -Level "ERROR"
        exit 1
    }
    # --- Tweaks Section ---
    if ($ApplyTweaks) {
        $tweaks        = Read-TweaksFromConfig -Path $configFile
        $enabledTweaks = $tweaks.Keys | Where-Object { $tweaks[$_] -eq 1 }
        Write-Host "`nTweaks enabled: $($enabledTweaks.Count)" -ForegroundColor White
        if ($enabledTweaks.Count) {
            Write-Host "Enabled tweaks: $($enabledTweaks -join ', ')" -ForegroundColor Gray
        }
        Set-WindowsTweaks -Tweaks $tweaks -DryRun:$DryRun -Force:$Force
    }

    # Interactive group selection
    $useGroups = $false
    if (-not $NoGroups -and -not $Silent) {
        $groupChoice = Read-Host "`nUse group selection UI? (Y/N)"
        if ($groupChoice -match "^[yY]") {
            $appsToProcess = Invoke-GroupSelection $appsToProcess # This returns an array
            $appsCount = $appsToProcess.Count
            $useGroups = $true
        }
    }

    # Show critical app warnings before removal
    $criticalCheck = Show-CriticalAppWarning -appsToProcess $appsToProcess `
                                            -criticalApps $criticalApps `
                                            -DryRun:$DryRun -Force:$Force
    if ($criticalCheck -ne 0) { exit $criticalCheck }

    if ($DryRun) {
        Write-Host "`n===== DRY RUN MODE - No changes will be made =====" -ForegroundColor Yellow
        if ($useGroups) {
            Write-Host "NOTE: Running in dry run mode with group selections" -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n===== Windows 11 Bloatware Removal =====" -ForegroundColor Cyan
        if ($useGroups) {
            Write-Host "NOTE: Using group-based removal selections" -ForegroundColor Cyan
        }
    }

    Write-Host "Found $appsCount apps in configuration" -ForegroundColor Cyan
    Write-Log "Found $appsCount apps in configuration" -Level "INFO"

    $removalTracker = @{
        UserSuccess = 0
        UserFail = 0
        UserSkipped = 0
        ProvSuccess = 0
        ProvFail = 0
        ProvSkipped = 0
        AnyProvRemoved = $false
    }

    $removedApps = New-Object System.Collections.Generic.List[string]
    $skippedApps = New-Object System.Collections.Generic.List[string] 

    # Guard against zero apps (prevents 0/0 in Write-Progress)
    if ($appsToProcess.Count -eq 0) {
        Write-Host "`nNo apps to process. Exiting." -ForegroundColor Yellow
        exit 0
    }

    # Process all apps with progress display
    $progressId = 1
    try {
        $i = 0
        foreach ($app in $appsToProcess) {
            $i++
            $pct = [math]::Round(($i / $appsToProcess.Count) * 100)
            Write-Progress -Id $progressId -Activity "Removing Apps" -Status "$pct%: $($app.Name)" -PercentComplete $pct
            Remove-AppxWithSettings -app $app `
                                    -removalTracker ([ref]$removalTracker) `
                                    -removedApps    ([ref]$removedApps) `
                                    -skippedApps    ([ref]$skippedApps) `
                                    -DryRun:$DryRun
        }
    }
    finally {
        # always clear the bar no matter what
        Write-Progress -Id $progressId -Activity "Removing Apps" -Completed
    }

    $totalApps = $appsToProcess.Count

    # Show final summary
    Show-Summary -removalTracker $removalTracker `
                -totalApps      $totalApps `
                -removedApps    $removedApps `
                -skippedApps    $skippedApps

    # Always show restore guidance
    Write-Host "`nRestore config location: $restoreConfig" -ForegroundColor Blue
    Write-Host "To restore removed apps, run:" -ForegroundColor Blue
    Write-Host "    .\Win11Debloater.ps1 -Restore" -ForegroundColor Yellow

    # Only create the file if not DryRun
    if (-not $DryRun) {
        try {
            $tmp = "$restoreConfig.tmp"
            Copy-Item $configFile $tmp -Force
            Move-Item -Path $tmp -Destination $restoreConfig -Force
            Write-Log "Created restore config at $restoreConfig" -Level "INFO"
        } catch {
            Write-Log "Failed to create restore config: $_" -Level "ERROR"
        }
    }
} catch {
    $errorDetails = if ($_.InvocationInfo) {
        "Error at line $($_.InvocationInfo.ScriptLineNumber): $_"
    } else {
        "Error: $_"
    }
    Write-Log "Fatal error: $errorDetails" -Level "ERROR"
    Write-Host "`nFatal error: $errorDetails" -ForegroundColor Red
    if ($IsExe) {
        try {
            Add-Type -AssemblyName PresentationFramework
            [System.Windows.MessageBox]::Show("Fatal error: $errorDetails`nSee log: $LogPath", "Windows 11 Debloater", "OK", "Error")
        } catch {
            Write-Host "Could not display MessageBox: $_" -ForegroundColor Red
        }
    }
    if ($ShowLog -and -not $LogShown) {
        try {
            Start-Process notepad.exe $LogPath
            $LogShown = $true
        } catch {
            Write-Host "Could not open log file in Notepad." -ForegroundColor Red
        }
    }
} finally {
    if (-not $Silent) {
        if ($Host.Name -eq "ConsoleHost") {
            Write-Host "`nOperation complete. See log for details: $LogPath" -ForegroundColor Cyan
            if ($ShowLog -and -not $LogShown) {
                try {
                    Start-Process notepad.exe $LogPath
                    $LogShown = $true
                } catch {
                    Write-Host "Could not open log file in Notepad." -ForegroundColor Red
                }
            }
            if ($Transcript) { Stop-Transcript }

            Write-Host "Press any key to exit..."            
            $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        }
    }
}
#endregion
