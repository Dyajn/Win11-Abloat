# Win11Debloater

A powerful, configurable Windows 11 bloatware remover and system tweaker designed to optimize your Windows 11 experience by removing unwanted pre-installed applications and applying performance-enhancing system tweaks.

## Features

- **Selective App Removal**: Remove bloatware apps for current user and/or prevent installation for new users
- **System Tweaks**: Apply privacy, performance, and UI tweaks
- **Critical App Protection**: Prevents accidental removal of essential system apps
- **Group Selection**: Interactive UI to select app categories for removal
- **Dry Run Mode**: Preview changes before applying them
- **App Restoration**: Restore previously removed apps
- **Comprehensive Logging**: Detailed logs with rotation
- **Configuration Backup**: Automatic backup of settings
- **Progress Tracking**: Real-time progress display during operations

## System Requirements

- Windows 11 (Build 22000 or higher)
- PowerShell 5.0 or higher
- Administrator privileges

## Quick Start

1. **Download and Extract**: Place `Win11Debloater.ps1` in a folder of your choice
2. **Run as Administrator**: Right-click PowerShell and select "Run as Administrator"
3. **First Run**: Execute `.\Win11Debloater.ps1` to generate the default `config.txt`
4. **Configure**: Edit `config.txt` to customize which apps and tweaks to apply
5. **Execute**: Run the script again with your desired parameters

## Parameters

| Parameter      | Alias    | Description                                 |
|----------------|----------|---------------------------------------------|
| -DryRun        | -d       | Simulate actions without making changes     |
| -Restore       | -r       | Restore apps from restore_config.txt        |
| -NoGroups      | -ng      | Skip interactive group selection UI         |
| -Force         | -f       | Allow removal of critical system apps       |
| -Silent        | -s       | Suppress interactive prompts for automation |
| -ApplyTweaks   | -t       | Apply Windows system tweaks from config.txt |
| -Help          | -h, -?   | Display comprehensive help information      |
| -ShowLog       | -sl      | Open log file in Notepad after execution    |
| -ListTweaks    | -lt      | Display all available system tweaks         |
| -LogPath       |          | Specify custom log file location            |
| -ConfigDir     |          | Specify custom configuration directory      |

## Usage Examples

```powershell
# Preview what would be removed (recommended first step)
.\Win11Debloater.ps1 -DryRun

# Remove apps and apply tweaks
.\Win11Debloater.ps1 -ApplyTweaks

# Use interactive group selection
.\Win11Debloater.ps1 -d

# Force removal of critical apps (use with caution)
.\Win11Debloater.ps1 -Force -Silent

# Restore previously removed apps
.\Win11Debloater.ps1 -Restore

# List all available system tweaks
.\Win11Debloater.ps1 -ListTweaks
```

## Configuration

### App Removal Format
```
AppName,RemoveUser,RemoveProvisioned
```
- **RemoveUser**: `1` removes for current user, `0` keeps it
- **RemoveProvisioned**: `1` prevents installation for new users, `0` keeps in system image

### Critical Apps Protection
Apps listed in the `[CriticalApps]` section are protected from accidental removal unless the `-Force` parameter is used. These include essential system components like Windows Store, Calculator, and Settings.

### System Tweaks
The `[Tweaks]` section allows you to enable/disable various system optimizations:
- Privacy settings (telemetry, advertising ID, feedback)
- Performance tweaks (animations, transparency, superfetch)
- UI modifications (file extensions, hidden files)
- Security settings (Windows Defender, firewall, UAC)

## App Categories

The script organizes apps into logical groups for easier management:

- **Communication**: Skype, Teams, Phone Link, Messaging
- **Xbox & Gaming**: Xbox apps, Game Bar, Gaming services
- **Media & Entertainment**: Music, Video, Solitaire, Streaming apps
- **Bing & Cortana**: Bing-powered apps and Cortana
- **Social Media**: Facebook, Instagram, Twitter, TikTok
- **Productivity**: Office Hub, 3D apps, Whiteboard
- **OEM Bloatware**: Manufacturer-specific apps (ASUS, Dell, HP, Lenovo, etc.)

## Safety Features

- **Dry Run Mode**: Test configurations safely before applying changes
- **Critical App Protection**: Prevents removal of essential system apps
- **Configuration Backup**: Automatic backup of settings before changes
- **Restoration Capability**: Ability to restore removed apps
- **Comprehensive Logging**: Detailed logs for troubleshooting
- **Validation**: Checks for duplicate entries and configuration errors

## Restoration

If you need to restore removed apps:

1. Run `.\Win11Debloater.ps1 -Restore`
2. For apps that can't be restored automatically, visit the Microsoft Store
3. For OEM apps, check your device manufacturer's support website

**Note**: Not all apps can be automatically restored. Some may require manual reinstallation from the Microsoft Store or manufacturer websites.

## Logging

- Logs are automatically rotated (last 5 kept)
- Default location: Script directory
- Use `-ShowLog` to open logs in Notepad after execution
- Use `-LogPath` to specify custom log location

## Important Notes

⚠️ **Before Using**:
1. **Create a system restore point** before running the script
2. **Test in a virtual machine** if possible
3. **Review the configuration** carefully before execution
4. **Use dry run mode** first to preview changes

⚠️ **Limitations**:
- Some apps may reinstall after major Windows updates
- OEM apps vary by manufacturer
- PowerShell Core (pwsh) has limited restoration capabilities
- Administrator privileges required for most operations

## Troubleshooting

**Script won't run**: Ensure you're running as Administrator and PowerShell execution policy allows scripts

**Apps not found**: Check for typos in app names or use wildcard patterns

**Restoration fails**: Try reinstalling from Microsoft Store or manufacturer website

**Permission errors**: Some operations require taking ownership of system files

## Future Development

A .NET MAUI application version is planned to provide a more user-friendly graphical interface.

## License

This project is provided as-is for educational and personal use. Use at your own risk.

---

**Disclaimer**: This tool modifies system settings and removes applications. Always backup your system and test in a safe environment before use on production systems.