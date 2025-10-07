if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator!"
    Write-Host "Please right-click the script and choose 'Run as Administrator'." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    exit
}

Clear-Host
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  My Own Setup" -ForegroundColor White
Write-Host "  (c) leizark" -ForegroundColor Gray
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host

Write-Host "[STEP 1] Creating a System Restore Point..." -ForegroundColor Cyan
Write-Host "This is a safety measure in case you want to revert the changes." -ForegroundColor Gray

$restorePointCreated = $false
while (-not $restorePointCreated) {
    try {
        $restorePointDescription = "Pre-Optimization - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Checkpoint-Computer -Description $restorePointDescription -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Host "[SUCCESS] System Restore Point '$restorePointDescription' created successfully." -ForegroundColor Green
        $restorePointCreated = $true
    }
    catch {
        if ($_.Exception.Message -like "*the service cannot be started*") {
            Write-Warning "System Restore is currently disabled on your system."
            $enableChoice = Read-Host "Would you like this script to attempt to enable it for you? (y/n)"
            if ($enableChoice -eq 'y') {
                try {
                    Write-Host "Attempting to enable System Restore..." -ForegroundColor Yellow
                    Set-Service -Name VSS -StartupType Automatic -ErrorAction Stop
                    Start-Service -Name VSS -ErrorAction Stop
                    Enable-ComputerRestore -Drive "$($env:SystemDrive)" -ErrorAction Stop
                    Write-Host "[SUCCESS] System Restore has been enabled for drive $($env:SystemDrive)." -ForegroundColor Green
                    Write-Host "Retrying to create the restore point..."
                    Start-Sleep -Seconds 2
                    continue
                } catch {
                    Write-Error "Failed to automatically enable System Restore. You may need to do it manually via System Properties > System Protection."
                    break
                }
            } else {
                 break
            }
        } else {
            Write-Error "An unexpected error occurred while creating the restore point: $($_.Exception.Message)"
            break
        }
    }
}

if (-not $restorePointCreated) {
    Write-Warning "Failed to create a System Restore Point."
    $confirmation = Read-Host "Do you want to continue with the optimization anyway? This is not recommended. (y/n)"
    if ($confirmation -ne 'y') {
        Write-Host "Exiting script." -ForegroundColor Red
        Start-Sleep -Seconds 5
        exit
    }
}
Write-Host

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

Write-Host "[STEP 3] Application Installation" -ForegroundColor Cyan
$spotifyJustInstalled = $false
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
            if ($appName -eq 'Spotify') {
                $spotifyJustInstalled = $true
            }
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

if ($spotifyJustInstalled) {
    Write-Host "[STEP 3.5] Post-Install: Configuring Spicetify for Spotify" -ForegroundColor Cyan
    Write-Host "This will install themes and extensions for Spotify. This may take a moment." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/spicetify/spicetify-cli/master/install.ps1" | Invoke-Expression
        $env:Path += ";$env:APPDATA\spicetify"
        spicetify backup apply
        Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/spicetify/spicetify-marketplace/main/resources/install.ps1" | Invoke-Expression
        spicetify apply
        Write-Host "[SUCCESS] Spicetify and Marketplace have been installed successfully." -ForegroundColor Green
        Write-Host "Open Spotify and you'll find the Marketplace in the left sidebar to browse for themes and extensions." -ForegroundColor Green
    } catch {
        Write-Error "An error occurred during Spicetify installation. $_"
        Write-Warning "You may need to install it manually. See https://spicetify.app for details."
    }
    Write-Host
}

Write-Host "[STEP 4] System Debloat" -ForegroundColor Cyan
Write-Host "Uninstalling common bloatware. This may take a few minutes." -ForegroundColor Yellow

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
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\*" -Include '{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse -ErrorAction SilentlyContinue
} catch { Write-Error "Could not uninstall OneDrive."}

$bloatwarePackages = @(
    "*MicrosoftTeams*","*Outlook*","*Copilot*","*OneDrive*","*Xbox*","*GamingApp*","*WebExperience*","*BingWeather*","*BingNews*","*Microsoft.549981C3F5F10*","*YourPhone*","*WindowsFeedbackHub*","*MicrosoftSolitaireCollection*","*GetHelp*","*ZuneMusic*","*ZuneVideo*","*WindowsMaps*","*People*","*Wallet*","*Todos*","*WindowsAlarms*","*WindowsCommunicationsApps*"
)

Write-Host "Removing modern (Appx) packages..." -ForegroundColor Gray
foreach ($package in $bloatwarePackages) {
    Write-Host "  -> Searching for and removing '$package'..." -ForegroundColor Gray
    Get-AppxPackage -AllUsers -Name $package | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $package -or $_.PackageName -like $package } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}
Write-Host "[SUCCESS] Debloat process completed." -ForegroundColor Green
Write-Host

Write-Host "[STEP 5] Security & Performance Tweaks" -ForegroundColor Cyan
$disableDefender = Read-Host "Would you like to disable Windows Defender? (This can improve performance but reduces security) (y/n)"
if ($disableDefender -eq 'y') {
    Write-Host "Disabling Windows Defender..." -ForegroundColor Yellow
    try {
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force -ErrorAction Stop
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Write-Host "[SUCCESS] Windows Defender has been disabled." -ForegroundColor Green
    } catch {
        Write-Error "Failed to disable Windows Defender. It may be protected by Tamper Protection."
    }
}

$disableMitigations = Read-Host "Would you like to disable CPU Mitigations (Spectre/Meltdown)? (This can improve performance but is a major security risk) (y/n)"
if ($disableMitigations -eq 'y') {
    Write-Host "Disabling CPU Mitigations..." -ForegroundColor Yellow
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Value 3 -PropertyType DWORD -Force -ErrorAction Stop
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Value 3 -PropertyType DWORD -Force -ErrorAction Stop
        Write-Host "[SUCCESS] CPU Mitigations have been disabled. A restart is required for this to take effect." -ForegroundColor Green
    } catch {
        Write-Error "Failed to set registry keys to disable CPU mitigations."
    }
}
Write-Host

Write-Host "[STEP 6] Optional: Launch Winutil for Advanced Tweaks" -ForegroundColor Cyan
$launchWinutil = Read-Host "Would you like to download and launch the Winutil script for further advanced tweaking? (y/n)"

if ($launchWinutil -eq 'y') {
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
}
else {
    Write-Host "Skipping Winutil." -ForegroundColor Yellow
}
Write-Host

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "  Optimization Playbook Finished!" -ForegroundColor White
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "The script has completed all selected tasks. It's recommended to restart your computer." -ForegroundColor Green
Start-Sleep -Seconds 10

