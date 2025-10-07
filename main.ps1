<#
.SYNOPSIS
    A PowerShell script to streamline and debloat Windows 11/10.

.DESCRIPTION
    This script provides a user-friendly playbook to optimize a Windows installation.
    It performs the following actions in order:
    1.  Checks for Administrator privileges.
    2.  Creates a System Restore Point as a safety precaution.
    3.  Asks the user to select and install a web browser (Brave, Firefox, or Chrome).
    4.  Asks the user to select and install popular applications using winget.
    5.  Uninstalls a comprehensive list of bloatware and unwanted applications.
    6.  Downloads and launches the ChrisTitusTech/winutil PowerShell script for advanced tweaking.

.AUTHOR
    leizark

.VERSION
    1.1
#>

#=======================================================================================================================
#   ADMINISTRATOR CHECK
#=======================================================================================================================
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator!"
    Write-Host "Please right-click the script and choose 'Run as Administrator'." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    exit
}

#=======================================================================================================================
#   SCRIPT START & RESTORE POINT CREATION
#=======================================================================================================================
Clear-Host
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  Windows Optimizer Playbook by Leizark" -ForegroundColor White
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host

Write-Host "[STEP 1] Creating a System Restore Point..." -ForegroundColor Cyan
Write-Host "This is a safety measure in case you want to revert the changes." -ForegroundColor Gray

try {
    $restorePointDescription = "Pre-Optimization - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Checkpoint-Computer -Description $restorePointDescription -RestorePointType "MODIFY_SETTINGS"
    Write-Host "[SUCCESS] System Restore Point '$restorePointDescription' created successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to create a System Restore Point. $_"
    Write-Warning "Continuing without a restore point is not recommended."
    $confirmation = Read-Host "Do you want to continue anyway? (y/n)"
    if ($confirmation -ne 'y') {
        Write-Host "Exiting script." -ForegroundColor Red
        Start-Sleep -Seconds 5
        exit
    }
}
Write-Host

#=======================================================================================================================
#   BROWSER INSTALLATION
#=======================================================================================================================
Write-Host "[STEP 2] Browser Installation" -ForegroundColor Cyan
Write-Host "Please choose a web browser to install:" -ForegroundColor Yellow
Write-Host "  1: Brave Browser (Privacy-focused)"
Write-Host "  2: Mozilla Firefox (Open-source)"
Write-Host "  3: Google Chrome (Most popular)"
$browserChoice = Read-Host -Prompt "Enter the number of your choice"

try {
    switch ($browserChoice) {
        '1' { Write-Host "Installing Brave Browser..."; winget install -e --id Brave.Brave --accept-package-agreements --accept-source-agreements }
        '2' { Write-Host "Installing Mozilla Firefox..."; winget install -e --id Mozilla.Firefox --accept-package-agreements --accept-source-agreements }
        '3' { Write-Host "Installing Google Chrome..."; winget install -e --id Google.Chrome --accept-package-agreements --accept-source-agreements }
        default { Write-Warning "Invalid selection. No browser will be installed." }
    }
    Write-Host "[SUCCESS] Browser installation task finished." -ForegroundColor Green
}
catch {
    Write-Error "An error occurred during browser installation. It might already be installed or winget failed."
}
Write-Host

#=======================================================================================================================
#   APPLICATION INSTALLATION
#=======================================================================================================================
Write-Host "[STEP 3] Application Installation" -ForegroundColor Cyan
$availableApps = @{
    'Discord' = 'Discord.Discord'
    'Telegram' = 'Telegram.TelegramDesktop'
    'Steam' = 'Valve.Steam'
    '7-Zip' = '7zip.7zip'
    'Spotify' = 'Spotify.Spotify'
    'Modrinth App' = 'Modrinth.ModrinthApp'
    'VLC' = 'VideoLAN.VLC'
    'PowerToys' = 'Microsoft.PowerToys'
    'OBS Studio' = 'OBSProject.OBSStudio'
}

Write-Host "The following applications are available to install via winget:" -ForegroundColor Yellow
$i = 1
$appKeys = $availableApps.Keys | Sort-Object
foreach ($appName in $appKeys) {
    Write-Host "  $i`: $appName"
    $i++
}

$appChoices = Read-Host -Prompt "Enter the numbers of the apps you want to install, separated by commas (e.g., 1,3,5)"
$selectedApps = $appChoices -split ',' | ForEach-Object { $_.Trim() }

foreach ($choice in $selectedApps) {
    if ([int]::TryParse($choice, [ref]$null) -and $choice -ge 1 -and $choice -le $appKeys.Count) {
        $appName = $appKeys[$choice - 1]
        $appId = $availableApps[$appName]
        try {
            Write-Host "Installing $appName..." -ForegroundColor Cyan
            winget install -e --id $appId --accept-package-agreements --accept-source-agreements
            Write-Host "[SUCCESS] Successfully installed $appName." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to install $appName. It might already be installed or winget failed."
        }
    }
    else {
        Write-Warning "Invalid selection '$choice' skipped."
    }
}
Write-Host

#=======================================================================================================================
#   SYSTEM DEBLOAT
#=======================================================================================================================
Write-Host "[STEP 4] System Debloat" -ForegroundColor Cyan
Write-Host "Uninstalling common bloatware. This may take a few minutes." -ForegroundColor Yellow

# --- Uninstall Microsoft Edge ---
try {
    Write-Host "Attempting to uninstall Microsoft Edge..." -ForegroundColor Gray
    $edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application"
    if (Test-Path $edgePath) {
        $versionFolder = Get-ChildItem -Path $edgePath -Directory | Where-Object { $_.Name -match '^\d' } | Sort-Object -Property Name -Descending | Select-Object -First 1
        if ($versionFolder) {
            $installerPath = Join-Path -Path $versionFolder.FullName -ChildPath "Installer\setup.exe"
            if (Test-Path $installerPath) {
                Start-Process -FilePath $installerPath -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait
                Write-Host "[SUCCESS] Microsoft Edge uninstaller executed." -ForegroundColor Green
            }
        }
    } else {
        Write-Warning "Microsoft Edge installation directory not found."
    }
} catch { Write-Error "Could not uninstall Edge. It might have been already removed." }


# --- Uninstall OneDrive ---
try {
    Write-Host "Attempting to uninstall OneDrive..." -ForegroundColor Gray
    Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $oneDrivePath = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    if (-not (Test-Path $oneDrivePath)) { $oneDrivePath = "$env:SystemRoot\System32\OneDriveSetup.exe" }
    if (Test-Path $oneDrivePath) {
        Start-Process -FilePath $oneDrivePath -ArgumentList "/uninstall" -Wait
        Write-Host "[SUCCESS] OneDrive uninstaller executed." -ForegroundColor Green
    }
    # Remove from Explorer
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\*" -Include '{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse -ErrorAction SilentlyContinue
} catch { Write-Error "Could not uninstall OneDrive."}


# --- Uninstall Appx Packages ---
$bloatwarePackages = @(
    # Core Bloat
    "*MicrosoftTeams*"
    "*Outlook*"
    "*Copilot*"
    "*OneDrive*"
    # Xbox & Gaming
    "*Xbox*"
    "*GamingApp*"
    # Widgets & News
    "*WebExperience*" # Windows Widgets
    "*BingWeather*"
    "*BingNews*"
    # Other Pre-installed Apps
    "*Microsoft.549981C3F5F10*" # Cortana
    "*YourPhone*"
    "*WindowsFeedbackHub*"
    "*MicrosoftSolitaireCollection*"
    "*GetHelp*"
    "*ZuneMusic*"
    "*ZuneVideo*"
    "*WindowsMaps*"
    "*People*"
    "*Wallet*"
    "*Todos*"
    "*WindowsAlarms*"
    "*WindowsCommunicationsApps*" # Mail and Calendar
)

Write-Host "Removing modern (Appx) packages..." -ForegroundColor Gray
foreach ($package in $bloatwarePackages) {
    Write-Host "  -> Searching for and removing '$package'..." -ForegroundColor Gray
    # Remove for all current users
    Get-AppxPackage -AllUsers -Name $package | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    # Remove the provisioned package so it doesn't come back for new users
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $package -or $_.PackageName -like $package } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}
Write-Host "[SUCCESS] Debloat process completed." -ForegroundColor Green
Write-Host

#=======================================================================================================================
#   LAUNCH WINUTIL
#=======================================================================================================================
Write-Host "[STEP 5] Launching Winutil for Advanced Tweaks" -ForegroundColor Cyan
Write-Host "Downloading the latest version of the Winutil PowerShell script from ChrisTitusTech's GitHub..." -ForegroundColor Yellow

try {
    $winutilUrl = "https://github.com/ChrisTitusTech/winutil/releases/download/25.09.05/winutil.ps1"
    $winutilPath = "$env:TEMP\winutil.ps1"
    
    Invoke-WebRequest -Uri $winutilUrl -OutFile $winutilPath -UseBasicParsing
    
    Write-Host "[SUCCESS] Download complete. Launching Winutil in a new window..." -ForegroundColor Green
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$winutilPath`""
}
catch {
    Write-Error "Failed to download or launch Winutil. $_"
    Write-Host "You can run it manually by pasting this into a new PowerShell window:" -ForegroundColor Yellow
    Write-Host "iex ((New-Object System.Net.WebClient).DownloadString('https://christitus.com/win'))" -ForegroundColor Yellow
}
Write-Host

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  Optimization Playbook Finished!" -ForegroundColor White
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "The script has completed all automated tasks. Winutil should be running in a new window for further customization." -ForegroundColor Green
Start-Sleep -Seconds 10

