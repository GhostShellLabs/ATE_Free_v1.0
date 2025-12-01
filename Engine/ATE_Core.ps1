# ATE_Core.ps1
# Atlas Tuning Engine - Core Orchestrator
# Version: 1.0.0-Secure Releasen)

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Engine Identity
# (Copy these from your 1.0 script as-is if they differ.)
# ---------------------------------------------------------------------------
$ATE_Name    = "Atlas Tuning Engine (ATE_Free)"
$ATE_Version = "1.0.0"   # Keep as 1.0.0 for now to reflect behavioral baseline.

# ---------------------------------------------------------------------------
# FRONT DOOR UI
# ---------------------------------------------------------------------------
# This is the full Show-ATEFrontDoor implementation brought over from
# legacy ATE_v0.95_Redline. It is now a pure function (no top-level logic), and
# is intended to be called by ATE_Bootstrap.ps1 when no CLI switches are
# provided.
# ---------------------------------------------------------------------------

function Show-ATESafetyInfo {
    Write-Host ""
    Write-Host "=== Atlas Tuning Engine (ATE_Free) - Safety Overview ===" -ForegroundColor Cyan
    Write-Host " ATE_Free is a conservative, trust-first tuning tool." -ForegroundColor White
    Write-Host ""
    Write-Host " - Starts with Read-Only Scan so you can see changes first." -ForegroundColor White
    Write-Host " - Supported tweaks are designed to be reversible via 'Restore Originals'." -ForegroundColor White
    Write-Host " - Does NOT modify BIOS or firmware." -ForegroundColor White
    Write-Host " - Does NOT perform destructive or unrecoverable changes." -ForegroundColor White
    Write-Host " - Performs NO network or telemetry calls; all actions run locally." -ForegroundColor White
    Write-Host " - Logs actions to the local 'Engine\\Logs' folder for review." -ForegroundColor White
    Write-Host ""
    Write-Host "Return to the menu to choose a mode when ready." -ForegroundColor DarkGray
    Write-Host ""
}

function Show-ATEFrontDoor {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host " Atlas Tuning Engine (ATE_Free) - Front Door" -ForegroundColor Cyan
    Write-Host " Version $ATE_Version  |  PS 5.1 Secure Mode" -ForegroundColor DarkGray
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Tip: Start with Read-Only Scan (no changes)." -ForegroundColor DarkGray
    Write-Host "Supported changes are logged and reversible where possible." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Choose a mode:" -ForegroundColor White
    Write-Host "  1) Read-Only Scan (no changes)" -ForegroundColor White
    Write-Host "  2) Apply Safe Tweaks (recommended)" -ForegroundColor White
    Write-Host "  3) Restore Originals (from backups)" -ForegroundColor White
    Write-Host "  4) Apply Safe Tweaks + Rebuild Shader Cache" -ForegroundColor White
    Write-Host "  5) Overlay Cleanup Only (interactive)" -ForegroundColor White
    Write-Host "  S) Safety info" -ForegroundColor White
    Write-Host "  0) Exit" -ForegroundColor White
    Write-Host ""

    while ($true) {
        $choice = Read-Host "Selection"
        switch ($choice.ToUpperInvariant()) {
            '1' { return @{ Apply=$false; Restore=$false; Shader=$false; Overlays=$false } }
            '2' { return @{ Apply=$true;  Restore=$false; Shader=$false; Overlays=$false } }
            '3' { return @{ Apply=$false; Restore=$true;  Shader=$false; Overlays=$false } }
            '4' { return @{ Apply=$true;  Restore=$false; Shader=$true;  Overlays=$false } }
            '5' { return @{ Apply=$false; Restore=$false; Shader=$false; Overlays=$true  } }
            'S' { Show-ATESafetyInfo; continue }
            '0' { return $null }
            default { Write-Host "Invalid selection. Choose 0-5 or S for safety info." -ForegroundColor Yellow }
        }
    }
}

function Normalize-Status {
    param([string]$Status)
    if ([string]::IsNullOrWhiteSpace($Status)) { return 'UNKNOWN' }
    $s = $Status.Trim().ToUpperInvariant()
    switch ($s) {
        'ERROR' { 'ISSUE' }
        'CRIT'  { 'ISSUE' }
        'FAIL'  { 'ISSUE' }
        'PEND'  { 'PENDING' }
        'RO'    { 'READ-ONLY' }
        'READONLY' { 'READ-ONLY' }
        'N/A'   { 'UNSUPPORTED' }
        default {
            if ($global:ATE_Statuses -contains $s) { $s } else { 'UNKNOWN' }
        }
    }
}

function Get-StatusRank {
    param([string]$Status)
    $s = Normalize-Status $Status
    switch ($s) {
        'ISSUE'       { 100 }
        'WARN'        { 90 }
        'POLICY'      { 85 }
        'READ-ONLY'   { 80 }
        'PENDING'     { 70 }
        'DEGRADED'    { 60 }
        'LIMITED'     { 55 }
        'INFO'        { 40 }
        'OK'          { 30 }
        'ALIAS-MISS'  { 25 }
        'UNKNOWN'     { 20 }
        'UNSUPPORTED' { 10 }
        default       { 0 }
    }
}

function Resolve-FinalStatus {
    param([array]$Rungs)
    if (-not $Rungs -or @($Rungs).Count -eq 0) { return 'UNKNOWN' }
    $worst = $Rungs | Sort-Object @{Expression={ Get-StatusRank $_.Status }} -Descending | Select-Object -First 1
    return (Normalize-Status $worst.Status)
}

function Backup-RegKey {
    param([string]$KeyPath, [string]$Tag)
    if ([string]::IsNullOrWhiteSpace($Tag)) { return }

    $stamp   = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $safeTag = $Tag -replace '[^a-zA-Z0-9_-]', '_'
    $file    = Join-Path $backupDir "$stamp-$safeTag.reg"

    $regExePath = "$env:SystemRoot\System32\reg.exe"
    & $regExePath export $KeyPath $file /y | Out-Null
}

function Set-RegistryValueSafe {
    param(
        [string]$HivePath,
        [string]$Name,
        [object]$Value,
        [string]$Type = 'DWord',
        [string]$BackupTag
    )

    if (-not [string]::IsNullOrWhiteSpace($BackupTag)) {
        $regPath = $HivePath -replace 'HKCU:\\', 'HKCU\' -replace 'HKLM:\\', 'HKLM\'
        if ($regPath -match '^(HKCU|HKLM)\\') { Backup-RegKey -KeyPath $regPath -Tag $BackupTag }
    }

    if (-not (Test-Path $HivePath)) { New-Item -Path $HivePath -Force | Out-Null }
    New-ItemProperty -Path $HivePath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

function Restore-OriginalSettings {
    param()

    $tags = @(
        'GameMode',
        'GameDVR-User',
        'GameDVR-AppCapture',
        'GameBar-Overlay',
        'GameDVR-Policy',
        'Storage-FileSystem',
        'Network-Multimedia',
        'GpuTaskPriority',
        'ShaderCache',
        'AudioDucking',
        'USBSelectiveSuspend',
        'NvidiaOverlay'
    )

    $regExe  = "$env:SystemRoot\System32\reg.exe"
    $actions = @()

    foreach ($tag in $tags) {
        $safeTag = $tag -replace '[^a-zA-Z0-9_-]', '_'
        $pattern = "*-$safeTag.reg"

        $file = Get-ChildItem -Path $backupDir -Filter $pattern -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1

        if ($file) {
            try {
                & $regExe import $file.FullName 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $actions += "Restored '$tag' settings from backup '$($file.Name)'."
                } else {
                    $actions += "Failed to restore '$tag' from backup '$($file.Name)' (reg.exe exit code $LASTEXITCODE)."
                }
            } catch {
                $actions += "Failed to restore '$tag' from backup '$($file.Name)': $($_.Exception.Message)"
            }
        } else {
            $actions += "No backup found for tag '$tag'; nothing to restore."
        }
    }

    return $actions
}

function Get-ScoreForStatus {
    param([string]$Status, [int]$Impact)

    $s = Normalize-Status $Status

    $multiplier = switch ($s) {
        'OK'          { 1.0 }
        'INFO'        { 1.0 }
        'PENDING'     { 0.8 }
        'DEGRADED'    { 0.75 }
        'LIMITED'     { 0.75 }
        'READ-ONLY'   { 0.6 }
        'ALIAS-MISS'  { 0.85 }
        'UNKNOWN'     { 0.85 }
        'UNSUPPORTED' { 1.0 }
        'POLICY'      { 0.4 }
        'WARN'        { 0.5 }
        'ISSUE'       { 0.0 }
        default       { 0.7 }
    }
    return [int]([math]::Round($Impact * $multiplier))
}

function Get-Grade {
    param([int]$Score)
    if     ($Score -ge 90) { "Great" }
    elseif ($Score -ge 75) { "Good" }
    elseif ($Score -ge 60) { "Okay" }
    else                   { "Needs work" }
}

function Describe-PerfDelta {
    param([int]$Delta)
    if ($Delta -lt 5) {
        "Expected performance gain: negligible (<2% FPS); improvements mainly in consistency / 1% lows."
    } elseif ($Delta -lt 15) {
        "Expected performance gain: modest (~2-5% average FPS and slightly better 1% lows in CPU-bound moments)."
    } elseif ($Delta -lt 30) {
        "Expected performance gain: noticeable (~5-10% average FPS and clearly smoother 1% lows in many titles)."
    } else {
        "Expected performance gain: significant (10%+ potential in badly misconfigured or CPU-bound systems)."
    }
}

function Get-DiskForDriveLetter {
    param([char]$DriveLetter)
    try {
        $part = Get-Partition -DriveLetter $DriveLetter -ErrorAction Stop
        Get-Disk -Number $part.DiskNumber -ErrorAction Stop
    } catch { $null }
}

function Get-ATEStorageMediaTypeFromDisk {
    <#
        .SYNOPSIS
            Safely retrieves a disk's MediaType (SSD/HDD/Unknown) without throwing if the property is missing.
    #>
    param(
        [Parameter(Mandatory = $true)]
        $Disk
    )

    if (-not $Disk) { return 'Unknown' }

    $mediaTypeProp = $Disk | Get-Member -Name 'MediaType' -MemberType Properties -ErrorAction SilentlyContinue
    if ($mediaTypeProp) {
        $value = $Disk.MediaType
        if ([string]::IsNullOrWhiteSpace([string]$value)) { return 'Unknown' }
        return $value.ToString()
    }

    return 'Unknown'
}

function Invoke-ShaderCacheRebuild {
    param()

    $paths = @(
        "$env:LOCALAPPDATA\D3DSCache",
        "$env:LOCALAPPDATA\NVIDIA\DXCache",
        "$env:LOCALAPPDATA\NVIDIA\GLCache",
        "$env:ProgramData\NVIDIA Corporation\NV_Cache"
    )

    $actions = @()
    foreach ($p in $paths) {
        if (-not (Test-Path $p)) { continue }
        try {
            $before = Get-ChildItem -Path $p -Recurse -ErrorAction SilentlyContinue |
                      Measure-Object -Property Length -Sum
            $beforeBytes = $before.Sum

            Remove-Item -Path (Join-Path $p '*') -Recurse -Force -ErrorAction SilentlyContinue

            $freedMB = 0
            if ($beforeBytes -gt 0) { $freedMB = [math]::Round($beforeBytes / 1MB, 1) }

            if ($freedMB -gt 0) {
                $actions += "Cleared shader cache at '$p' (~${freedMB}MB freed)."
            } else {
                $actions += "Cleared shader cache at '$p' (no significant files found)."
            }
        } catch {
            $actions += "Failed to clear shader cache at '$p': $($_.Exception.Message)"
        }
    }

    if (@($actions).Count -eq 0) { $actions += "No known shader cache directories found to clear." }
    return $actions
}

function Invoke-OverlayCleanup {
    param([ref]$ActionsTaken)

    Write-Host ""
    Write-Host "Overlay Cleanup (Interactive):" -ForegroundColor Cyan
    Write-Host "  1) Close NVIDIA Overlay Helpers (safe)"
    Write-Host "  2) Close Steam / Discord / Xbox Overlays (safe)"
    Write-Host "  3) Strict Mode: close ALL overlay helpers this session (advanced)"
    Write-Host "  0) Return"
    $sel = Read-Host "Selection"
    if ([string]::IsNullOrWhiteSpace($sel)) { return }

    $overlaySafeNv   = @('nvsphelper64','nvshare','NVIDIA Share','shadowplay','NVIDIA Overlay')
    $overlaySafeOther= @('gameoverlayui64','GameOverlayUI','DiscordOverlayHost','DiscordHookHelper','DiscordHookHelper64','GameBar','GameBarFTServer','GameBarPresenceWriter','XboxPcAppFT')

    switch ($sel) {
        '1' {
            foreach ($p in $overlaySafeNv) {
                Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                if ($?) { $ActionsTaken.Value += "OverlayCleanup: Closed $p" }
            }
            Write-Host "Closed NVIDIA overlay helpers (session-only)." -ForegroundColor Green
        }
        '2' {
            foreach ($p in $overlaySafeOther) {
                Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                if ($?) { $ActionsTaken.Value += "OverlayCleanup: Closed $p" }
            }
            Write-Host "Closed non-NVIDIA overlays/hooks (session-only)." -ForegroundColor Green
        }
        '3' {
            $all = $overlaySafeNv + $overlaySafeOther
            foreach ($p in $all) {
                Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                if ($?) { $ActionsTaken.Value += "OverlayCleanup(Strict): Closed $p" }
            }
            Write-Host "Strict overlay cleanup complete. Changes are session-only and revert on reboot." -ForegroundColor Yellow
        }
        default { return }
    }
}

function Get-ModuleScores {
    param([string]$ModuleName)

    $rows = $checkResults | Where-Object { $_.Module -eq $ModuleName }
    if (-not $rows) { return $null }

    $scorableRows = $rows | Where-Object {
        (Normalize-Status $_.PreStatus)  -ne 'READ-ONLY' -and
        (Normalize-Status $_.PostStatus) -ne 'READ-ONLY'
    }
    if (-not $scorableRows) { $scorableRows = $rows }

    $maxScore = ($scorableRows | Measure-Object -Property Impact -Sum).Sum
    if ($maxScore -eq 0) { $maxScore = 1 }

    $preRaw  = 0
    $postRaw = 0
    foreach ($r in $scorableRows) {
        $preRaw  += Get-ScoreForStatus -Status $r.PreStatus  -Impact $r.Impact
        $postRaw += Get-ScoreForStatus -Status $r.PostStatus -Impact $r.Impact
    }

    $prePct  = [int]([math]::Round(($preRaw  / $maxScore) * 100))
    $postPct = [int]([math]::Round(($postRaw / $maxScore) * 100))
    $delta   = $postPct - $prePct

    return [pscustomobject]@{
        Module    = $ModuleName
        PrePct    = $prePct
        PostPct   = $postPct
        DeltaPct  = $delta
        PreGrade  = Get-Grade -Score $prePct
        PostGrade = Get-Grade -Score $postPct
        DeltaDesc = Describe-PerfDelta -Delta $delta
    }
}

function Get-ATERank {
    param([int]$score)
    # Returns a single rank string for a given score. Ranges are mutually exclusive
    # so we never return multiple values (which would display as System.Object[]).
    switch ($score) {
        { $_ -lt 7600 }                                      { "Recruit";            break }
        { $_ -ge 7600 -and $_ -lt 8400 }                     { "Trainee";            break }
        { $_ -ge 8400 -and $_ -lt 9000 }                     { "Soldier";            break }
        { $_ -ge 9000 -and $_ -lt 9400 }                     { "Mercenary";          break }
        { $_ -ge 9400 -and $_ -lt 9650 }                     { "Operator";           break }
        { $_ -ge 9650 -and $_ -lt 9850 }                     { "Special Operations"; break }
        default                                              { "Classified" }
    }
}

function Start-ATECore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Config,

        [switch]$ApplySafeTweaks,
        [switch]$RestoreOriginal,
        [switch]$RebuildShaderCache,
        [switch]$ManageOverlays,

        # Indicates that ATE is running under the interactive Front Door menu loop.
        # When set, Start-ATECore will return control directly to the caller without
        # prompting the user to "Press ENTER to close ATE" at the end of a run.
        [switch]$InteractiveFrontDoorSession
    )


    # =============================================================================
    # OS Info + supporting modules (migrated from v1.0)
    # =============================================================================
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $buildNumber = [int]$os.BuildNumber
        $osCaption   = $os.Caption
        $osVersion   = $os.Version
    } catch {
        $buildNumber = [int]([Environment]::OSVersion.Version.Build)
        $osCaption   = 'Windows (CIM unavailable)'
        $osVersion   = [Environment]::OSVersion.Version.ToString()
    }

    Write-Host ("=== {0} - v{1} ===" -f $ATE_Name, $ATE_Version) -ForegroundColor Cyan
    Write-Host ("OS: {0} ({1}, Build {2})" -f $osCaption, $osVersion, $buildNumber)
    Write-Host ""

    Import-Module ScheduledTasks -ErrorAction SilentlyContinue
    Import-Module NetAdapter     -ErrorAction SilentlyContinue
    Import-Module PnpDevice      -ErrorAction SilentlyContinue

    # =============================================================================
    # Directories for backups + logs (migrated from v1.0)
    # =============================================================================
    # Engine folder is PSScriptRoot; resources live under the product root in 'Resources'.
    $engineDir  = $PSScriptRoot
    if (-not $engineDir) { $engineDir = (Get-Location).Path }
    $productDir   = Split-Path -Parent $engineDir
    $resourcesDir = Join-Path -Path $productDir -ChildPath 'Resources'

    $script:backupDir = Join-Path -Path $resourcesDir -ChildPath 'Backups'
    $script:logDir    = Join-Path -Path $resourcesDir -ChildPath 'Logs'
    $backupDir        = $script:backupDir
    $logDir           = $script:logDir

    foreach ($dir in @($script:backupDir, $script:logDir)) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir | Out-Null
        }
    }

    $checks = @()
    
    # ================================
    # CORE MODULE
    # ================================
    
    # 1) Game Mode
    $checks += [pscustomobject]@{
        Name     = 'Game Mode'
        Module   = 'Core'
        Category = 'GamingFeatures'
        MinBuild = 15063
        Impact   = 15
    
        Detect   = {
            $path = 'HKCU:\Software\Microsoft\GameBar'
            $primaryName = 'AutoGameModeEnabled'
            $legacyName  = 'AllowAutoGameMode'
    
            if (-not (Test-Path $path)) {
                return @{ Status='OK'; Detail='Game Mode enabled (default; key not present).'; Raw=$null }
            }
    
            $props = Get-ItemProperty -Path $path -Name $primaryName,$legacyName -ErrorAction SilentlyContinue
            $primaryVal = $null
            $legacyVal  = $null
            if ($props) {
                if ($props.PSObject.Properties.Match($primaryName).Count -gt 0) {
                    $primaryVal = $props.$primaryName
                }
                if ($props.PSObject.Properties.Match($legacyName).Count -gt 0) {
                    $legacyVal = $props.$legacyName
                }
            }
    
            if ($null -ne $primaryVal) {
                if ([int]$primaryVal -eq 1) {
                    return @{ Status='OK'; Detail="Game Mode enabled [$primaryName=1]."; Raw=$primaryVal }
                } else {
                    return @{ Status='WARN'; Detail="Game Mode disabled [$primaryName=$primaryVal] (recommend ON for gaming)."; Raw=$primaryVal }
                }
            } elseif ($null -ne $legacyVal) {
                if ([int]$legacyVal -eq 1) {
                    return @{ Status='OK'; Detail="Game Mode enabled [$legacyName=1]."; Raw=$legacyVal }
                } else {
                    return @{ Status='WARN'; Detail="Game Mode disabled [$legacyName=$legacyVal] (recommend ON for gaming)."; Raw=$legacyVal }
                }
            } else {
                return @{ Status='OK'; Detail='Game Mode enabled (default; value not explicitly set).'; Raw=$null }
            }
        }
    
        FixSafe = {
            $path = 'HKCU:\Software\Microsoft\GameBar'
            $name = 'AutoGameModeEnabled'
            New-Item -Path $path -Force | Out-Null
    
            $current = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
    
            if ($null -eq $current -or [int]$current -ne 1) {
                Set-RegistryValueSafe -HivePath $path -Name $name -Value 1 -Type 'DWord' -BackupTag 'GameMode'
                return "Set $name=1 (enable Game Mode)."
            } else {
                return 'Game Mode already enabled.'
            }
        }
    }
    
    # 2) Xbox Game Bar / DVR
    $checks += [pscustomobject]@{
        Name     = 'Xbox Game Bar / DVR'
        Module   = 'Core'
        Category = 'GamingFeatures'
        MinBuild = 14393
        Impact   = 20
        Detect   = {
            $rungs = @()
    
            $polPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
            $polName = 'AllowGameDVR'
            $polVal  = $null
            if (Test-Path $polPath) {
                $polVal = (Get-ItemProperty -Path $polPath -Name $polName -ErrorAction SilentlyContinue).$polName
            }
            if ($null -eq $polVal) {
                $rungs += [pscustomobject]@{ Rung=1; Status='INFO'; Detail='No explicit GameDVR policy found (Windows default).'; Raw=$null }
            } elseif ([int]$polVal -eq 0) {
                $rungs += [pscustomobject]@{ Rung=1; Status='OK'; Detail='Policy blocks GameDVR system-wide.'; Raw=$polVal }
            } else {
                $rungs += [pscustomobject]@{ Rung=1; Status='WARN'; Detail='Policy allows GameDVR (may re-enable features).'; Raw=$polVal }
            }
    
            $gbPath = 'HKCU:\Software\Microsoft\GameBar'
            $gbName = 'ShowStartupPanel'
            $gbVal  = $null
            if (Test-Path $gbPath) {
                $gbProps = Get-ItemProperty -Path $gbPath -ErrorAction SilentlyContinue
                if ($gbProps -and $gbProps.PSObject.Properties.Name -contains $gbName) {
                    $gbVal = $gbProps.$gbName
                }
            }
    
            $dvrPath = 'HKCU:\System\GameConfigStore'
            $dvrName = 'GameDVR_Enabled'
            $dvrVal  = $null
            if (Test-Path $dvrPath) {
                $dvrProps = Get-ItemProperty -Path $dvrPath -ErrorAction SilentlyContinue
                if ($dvrProps -and $dvrProps.PSObject.Properties.Name -contains $dvrName) {
                    $dvrVal = $dvrProps.$dvrName
                }
            }
    
            $detail = "GameBar.ShowStartupPanel=$gbVal; GameDVR_Enabled=$dvrVal"
    
            if ($dvrVal -eq 1 -or $gbVal -eq 1) {
                $rungs += [pscustomobject]@{ Rung=2; Status='WARN'; Detail="User DVR/Game Bar enabled. $detail"; Raw=@{ GameBar=$gbVal; DVR=$dvrVal } }
            } elseif ($dvrVal -eq 0 -and ($gbVal -eq 0 -or $null -eq $gbVal)) {
                $rungs += [pscustomobject]@{ Rung=2; Status='OK'; Detail="User DVR/Game Bar disabled. $detail"; Raw=@{ GameBar=$gbVal; DVR=$dvrVal } }
            } else {
                $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail="User DVR/Game Bar state unclear. $detail"; Raw=@{ GameBar=$gbVal; DVR=$dvrVal } }
            }
    
            $rungs += [pscustomobject]@{ Rung=3; Status='INFO'; Detail='Default-profile lock not evaluated in detect-only mode.'; Raw=$null }
            return $rungs
        }
    
        FixSafe = {
            Set-RegistryValueSafe -HivePath 'HKCU:\System\GameConfigStore' -Name 'GameDVR_Enabled' -Value 0 -Type 'DWord' -BackupTag 'GameDVR-User'
            Set-RegistryValueSafe -HivePath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' -Name 'AppCaptureEnabled' -Value 0 -Type 'DWord' -BackupTag 'GameDVR-AppCapture'
            Set-RegistryValueSafe -HivePath 'HKCU:\Software\Microsoft\GameBar' -Name 'ShowStartupPanel' -Value 0 -Type 'DWord' -BackupTag 'GameBar-Overlay'
            Set-RegistryValueSafe -HivePath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Value 0 -Type 'DWord' -BackupTag 'GameDVR-Policy'
    
            $defaultHive = "C:\Users\Default\NTUSER.DAT"
            $regExe      = "$env:SystemRoot\System32\reg.exe"
            $loaded      = $false
    
            if (Test-Path $defaultHive) {
                try {
                    & $regExe load HKU\TempDefault "$defaultHive" 2>$null
                    if ($LASTEXITCODE -eq 0) { $loaded = $true }
    
                    if ($loaded) {
                        New-Item -Path "HKU:\TempDefault\System\GameConfigStore" -Force | Out-Null
                        New-ItemProperty -Path "HKU:\TempDefault\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
    
                        New-Item -Path "HKU:\TempDefault\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Force | Out-Null
                        New-ItemProperty -Path "HKU:\TempDefault\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -PropertyType DWord -Force | Out-Null
                    }
                } catch {
                    # default-profile lock skipped safely on errors
                } finally {
                    if ($loaded) { & $regExe unload HKU\TempDefault 2>$null }
                }
            }
    
            if ($loaded) {
                return 'Disabled DVR + Game Bar for current user, machine policy, and default profile (triple lock). Reboot recommended.'
            } else {
                return 'Disabled DVR + Game Bar for current user + machine policy. (Default-profile lock skipped safely.) Reboot recommended.'
            }
        }
    }
    
    # 3) Power plan
    $checks += [pscustomobject]@{
        Name     = 'Power Plan'
        Module   = 'Core'
        Category = 'Power'
        MinBuild = 10240
        Impact   = 35
        Detect   = {
            $rungs = @()
            $schemeActive = (powercfg /GETACTIVESCHEME) 2>$null
            if (-not $schemeActive) {
                $rungs += [pscustomobject]@{ Rung=1; Status='UNKNOWN'; Detail='Unable to get active power scheme.'; Raw=$null }
                return $rungs
            }
    
            $full       = $schemeActive.Trim()
            $schemeGuid = ($full -split '\s+')[3]
            $status = 'OK'
            $detail = $full
    
            switch ($schemeGuid.ToLower()) {
                "381b4222-f694-41f0-9685-ff5bb260df2e" {
                    $status = 'WARN'
                    $detail = "Balanced plan active (usually fine, but High/Ultimate gives better consistency). $full"
                }
                "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" {
                    $status = 'OK'
                    $detail = "High performance plan active (good). $full"
                }
                "e9a42b02-d5df-448d-aa00-03f14749eb61" {
                    $status = 'OK'
                    $detail = "Ultimate performance plan active (best). $full"
                }
                default {
                    if ($full -match 'power saver') {
                        $status = 'ISSUE'
                        $detail = "Power Saver active (bad for gaming). $full"
                    } elseif ($full -match 'balanced') {
                        $status = 'WARN'
                        $detail = "Balanced plan active (usually fine, but High/Ultimate gives better consistency). $full"
                    } elseif ($full -match 'high performance' -or $full -match 'ultimate performance') {
                        $status = 'OK'
                        $detail = "High/Ultimate Performance active (good for gaming). $full"
                    }
                }
            }
    
            $rungs += [pscustomobject]@{ Rung=1; Status=$status; Detail=$detail; Raw=@{ Guid=$schemeGuid; Text=$full } }
    
            try {
                $avail = (powercfg /a) 2>$null
                if ($avail -match 'S0 Low Power Idle') {
                    $rungs += [pscustomobject]@{ Rung=2; Status='INFO'; Detail='Modern Standby (S0) present; some OEMs may clamp power settings at runtime.'; Raw=$null }
                } else {
                    $rungs += [pscustomobject]@{ Rung=2; Status='OK'; Detail='No Modern Standby override detected.'; Raw=$null }
                }
            } catch {
                $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail='Could not evaluate Modern Standby override state.'; Raw=$null }
            }
    
            return $rungs
        }
        FixSafe = {
            $list     = powercfg /L
            $ultimate = $list | Where-Object { $_ -match 'Ultimate Performance' }
            $highPerf = $list | Where-Object { $_ -match 'High performance' }
    
            if ($ultimate) {
                $guid = ($ultimate -split '\s+')[3]
                powercfg /S $guid | Out-Null
                return 'Switched active power plan to Ultimate Performance.'
            } elseif ($highPerf) {
                $guid = ($highPerf -split '\s+')[3]
                powercfg /S $guid | Out-Null
                return 'Switched active power plan to High Performance.'
            } else {
                return 'High/Ultimate Performance plan not found; no automatic change made.'
            }
        }
    }
    
    # 4) CPU min/max processor state (AC) (detect-only)
    $checks += [pscustomobject]@{
        Name     = 'CPU Min/Max State (AC)'
        Module   = 'Core'
        Category = 'Power'
        MinBuild = 10240
        Impact   = 15
        Detect   = {
            $rungs = @()
    
            try {
                $null = (powercfg /q) 2>$null
                $rungs += [pscustomobject]@{ Rung=1; Status='OK'; Detail='PowerCfg CPU state query available.'; Raw=$null }
            } catch {
                $rungs += [pscustomobject]@{ Rung=1; Status='UNSUPPORTED'; Detail='PowerCfg CPU state query unavailable on this OS.'; Raw=$null }
                return $rungs
            }
    
            $schemeLine = (powercfg /GETACTIVESCHEME) 2>$null
            if (-not $schemeLine) {
                $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail='Could not read active power scheme for CPU states.'; Raw=$null }
                return $rungs
            }
            $schemeGuid = ($schemeLine -split '\s+')[3]
    
            $subProcessor = '54533251-82be-4824-96c1-47b60b740d00'
            $settingMin   = '893dee8e-2bef-41e0-89c6-b55d0929964c'
            $settingMax   = 'bc5038f7-23e0-4960-96da-33abaf5935ec'
    
            $minOut = (powercfg /Q $schemeGuid $subProcessor $settingMin) 2>$null
            $maxOut = (powercfg /Q $schemeGuid $subProcessor $settingMax) 2>$null
    
            if (-not $minOut -or -not $maxOut) {
                $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail='Could not query CPU min/max state.'; Raw=$null }
                return $rungs
            }
    
            $minLine = $minOut | Select-String -Pattern 'Current AC Power Setting Index' | Select-Object -First 1
            $maxLine = $maxOut | Select-String -Pattern 'Current AC Power Setting Index' | Select-Object -First 1
            if (-not $minLine -or -not $maxLine) {
                $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail='CPU min/max AC setting lines not found.'; Raw=@{Min=$minOut;Max=$maxOut} }
                return $rungs
            }
    
            $minVal = $minLine.Line.Split()[-1]
            $maxVal = $maxLine.Line.Split()[-1]
    
            $minPct = [int]("0x$minVal")
            $maxPct = [int]("0x$maxVal")
    
            $status = 'OK'
            $detail = "CPU AC Min=$minPct%, Max=$maxPct%."
            if ($minPct -ne 100 -or $maxPct -ne 100) {
                $status = 'WARN'
                $detail = "CPU AC Min/Max not 100%. Current Min=$minPct%, Max=$maxPct% (recommended 100/100 for gaming consistency)."
            }
    
            $rungs += [pscustomobject]@{ Rung=2; Status=$status; Detail=$detail; Raw=@{ MinAC=$minPct; MaxAC=$maxPct } }
            return $rungs
        }
        FixSafe = $null
    }
    
    # 5) Pagefile sanity (detect-only)
    $checks += [pscustomobject]@{
        Name     = 'Pagefile'
        Module   = 'Core'
        Category = 'Storage'
        MinBuild = 7600
        Impact   = 20
        Detect   = {
            $pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
            if (-not $pf) {
                return @{ Status='ISSUE'; Detail='No pagefile detected. This can cause crashes and stutters in large games.'; Raw=$null }
            }
    
            $totalPFMB = ($pf | Measure-Object -Property AllocatedBaseSize -Sum).Sum
            $cs        = Get-CimInstance Win32_ComputerSystem
            $ramMB     = [math]::Round($cs.TotalPhysicalMemory / 1MB)
    
            if ($ramMB -le 0) {
                return @{ Status='UNKNOWN'; Detail="Pagefile total: $totalPFMB MB. Unable to read RAM size for comparison."; Raw=@{ TotalPFMB=$totalPFMB; RAMMB=$ramMB } }
            }
    
            $pfGB  = [math]::Round($totalPFMB / 1024, 1)
            $ramGB = [int]([math]::Round($ramMB / 1024, 0))
    
            $bucket  = $null
            $okMinGB = $null
            $okMaxGB = $null
    
            if ($ramGB -le 8)      { $bucket=8;   $okMinGB=4; $okMaxGB=8 }
            elseif ($ramGB -le 16) { $bucket=16;  $okMinGB=4; $okMaxGB=16 }
            elseif ($ramGB -le 32) { $bucket=32;  $okMinGB=4; $okMaxGB=12 }
            elseif ($ramGB -le 64) { $bucket=64;  $okMinGB=4; $okMaxGB=8 }
            elseif ($ramGB -le 128){ $bucket=128; $okMinGB=2; $okMaxGB=4 }
    
            $status = 'OK'
            if ($bucket -ne $null) {
                $detail = "Total pagefile: ${pfGB}GB vs RAM: ${ramGB}GB. Recommended range for ${bucket}GB RAM: ${okMinGB}-${okMaxGB}GB."
                if ($pfGB -lt 1)           { $status='ISSUE'; $detail += ' Extremely small pagefile (<1GB) can cause crashes.' }
                elseif ($pfGB -lt $okMinGB){ $status='WARN';  $detail += ' Below recommended range; may cause issues.' }
                elseif ($pfGB -gt $okMaxGB){ $status='WARN';  $detail += ' Above recommended range; wastes disk space.' }
                else                       { $detail += ' Configuration is within recommended range.' }
            } else {
                $ratio  = $totalPFMB / $ramMB
                $detail = ("Total pagefile: ${pfGB}GB vs RAM: ${ramGB}GB (~{0:P1} of RAM)." -f $ratio)
                if ($pfGB -lt 1)         { $status='ISSUE'; $detail += ' Extremely small pagefile (<1GB) can cause crashes.' }
                elseif ($ratio -lt 0.25) { $status='WARN';  $detail += ' Smaller than ~25% of RAM; may cause issues.' }
                elseif ($ratio -gt 4)    { $status='WARN';  $detail += ' Very large pagefile; wastes disk space.' }
                else                     { $detail += ' Pagefile size looks reasonable.' }
            }
    
            return @{ Status=$status; Detail=$detail; Raw=@{ TotalPFMB=$totalPFMB; RAMMB=$ramMB; Bucket=$bucket; RangeGB=@($okMinGB,$okMaxGB) } }
        }
        FixSafe = $null
    }
    
    # 6) Timer Resolution Hardening
    $checks += [pscustomobject]@{
        Name     = 'Timer Resolution Hardening'
        Module   = 'Core'
        Category = 'Timers'
        MinBuild = 10240
        Impact   = 12

        Detect   = {
            $rungs = @()

            if ($buildNumber -lt 10240) {
                $rungs += [pscustomobject]@{
                    Rung   = 1
                    Status = 'UNSUPPORTED'
                    Detail = "OS build $buildNumber does not support modern timer resolution control."
                    Raw    = $buildNumber
                }
                return $rungs
            }

            $rungs += [pscustomobject]@{
                Rung   = 1
                Status = 'OK'
                Detail = "OS build supports modern timer resolution control (build $buildNumber)."
                Raw    = $buildNumber
            }

            try {
                Add-Type -ErrorAction SilentlyContinue -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class AtlasTimers {
  [DllImport("ntdll.dll")]
  public static extern uint NtQueryTimerResolution(
      out uint MinimumResolution,
      out uint MaximumResolution,
      out uint CurrentResolution
  );
}
"@

                $min = 0; $max = 0; $cur = 0
                [void][AtlasTimers]::NtQueryTimerResolution([ref]$min, [ref]$max, [ref]$cur)

                $curMs = [math]::Round($cur / 10000.0, 3)
                $minMs = [math]::Round($min / 10000.0, 3)
                $maxMs = [math]::Round($max / 10000.0, 3)

                if ($cur -le 10000) {
                    $rungs += [pscustomobject]@{
                        Rung   = 2
                        Status = 'OK'
                        Detail = "Timer resolution is already at or near minimum ($curMs ms, min $minMs / max $maxMs)."
                        Raw    = @{ Min = $min; Max = $max; Cur = $cur }
                    }
                } else {
                    $rungs += [pscustomobject]@{
                        Rung   = 2
                        Status = 'WARN'
                        Detail = "Timer resolution is above minimum ($curMs ms, min $minMs / max $maxMs)."
                        Raw    = @{ Min = $min; Max = $max; Cur = $cur }
                    }
                }
            } catch {
                $rungs += [pscustomobject]@{
                    Rung   = 2
                    Status = 'INFO'
                    Detail = 'Failed to query timer resolution via NT API.'
                    Raw    = $null
                }
            }

            $rungs += [pscustomobject]@{
                Rung   = 3
                Status = 'INFO'
                Detail = 'Timer resolution is process-driven; pre-run WARN may oscillate normally.'
                Raw    = $null
            }

            return $rungs
        }

        FixSafe = {
            try {
                Add-Type -ErrorAction SilentlyContinue -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class AtlasTimersSet {
  [DllImport("ntdll.dll")]
  public static extern uint NtSetTimerResolution(
      uint DesiredResolution,
      bool SetResolution,
      out uint CurrentResolution
  );
}
"@

                $curOut = 0
                [void][AtlasTimersSet]::NtSetTimerResolution(10000, $true, [ref]$curOut)
                $curMs = [math]::Round($curOut / 10000.0, 3)

                if ($curOut -le 10000) {
                    return @{
                        Status = 'PENDING'
                        Detail = "Requested 1.0 ms timer resolution via NT API (current $curMs ms). Session-scoped; re-applies each ATE run."
                        Raw    = $curOut
                    }
                } else {
                    return @{
                        Status = 'WARN'
                        Detail = "Attempted to request 1.0 ms timer resolution, but NT API returned $curMs ms; another process may be holding a higher resolution."
                        Raw    = $curOut
                    }
                }
            } catch {
                return @{
                    Status = 'UNKNOWN'
                    Detail = 'Failed to request timer resolution via NT API.'
                    Raw    = $null
                }
            }
        }
    }
    # ================================
    # STORAGE MODULE
    # ================================
    
    $checks += [pscustomobject]@{
        Name     = 'OS Drive Type'
        Module   = 'Storage'
        Category = 'StorageDevices'
        MinBuild = 9600
        Impact   = 15
        Detect   = {
            try {
                $osDriveLetter = ($env:SystemDrive.TrimEnd('\') -replace ':','')[0]
                $disk = Get-DiskForDriveLetter -DriveLetter $osDriveLetter
                if (-not $disk) { return @{ Status='UNKNOWN'; Detail="Unable to map OS drive to physical disk."; Raw=$null } }

                $media = Get-ATEStorageMediaTypeFromDisk -Disk $disk
                $bus   = $disk.BusType.ToString()
                $detail = "OS drive disk: Number $($disk.Number), MediaType: $media, BusType: $bus."

                if ($media -eq 'Unknown') {
                    return @{ Status='UNSUPPORTED'; Detail=$detail + ' MediaType not exposed on this OS/driver; treating OS drive type as Unknown.'; Raw=$disk }
                } elseif ($media -match 'HDD') {
                    return @{ Status='WARN'; Detail=$detail + ' OS installed on HDD; this can hurt load times.'; Raw=$disk }
                } else {
                    return @{ Status='OK'; Detail=$detail + ' OS is on SSD/NVMe or other non-rotational media.'; Raw=$disk }
                }
            } catch {
                return @{ Status='UNSUPPORTED'; Detail="Get-Disk / Get-Partition unavailable or failed: $($_.Exception.Message)"; Raw=$null }
            }
        }
        FixSafe = $null
    }

$checks += [pscustomobject]@{
        Name     = 'Primary Game/Data Drive'
        Module   = 'Storage'
        Category = 'StorageDevices'
        MinBuild = 9600
        Impact   = 10
        Detect   = {
            try {
                $osLetter = $env:SystemDrive.TrimEnd('\') -replace ':',''
                $vols = Get-Volume -ErrorAction Stop |
                        Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter -and $_.DriveLetter -ne $osLetter }

                if (-not $vols) {
                    return @{ Status='UNKNOWN'; Detail='No additional fixed data volumes detected (OS drive only).'; Raw=$null }
                }

                $primary = $vols | Sort-Object -Property Size -Descending | Select-Object -First 1
                $disk    = Get-DiskForDriveLetter -DriveLetter $primary.DriveLetter
                if (-not $disk) {
                    return @{ Status='UNKNOWN'; Detail=("Primary data volume {0}: cannot be mapped to a physical disk." -f $primary.DriveLetter); Raw=$primary }
                }

                $media = Get-ATEStorageMediaTypeFromDisk -Disk $disk
                $bus   = $disk.BusType.ToString()
                $detail = "Primary data volume: $($primary.DriveLetter): ($([math]::Round($primary.Size/1GB,1))GB). Disk $($disk.Number), MediaType: $media, BusType: $bus."

                if ($media -eq 'Unknown') {
                    return @{ Status='UNSUPPORTED'; Detail=$detail + ' MediaType not exposed on this OS/driver; treating game/data drive type as Unknown.'; Raw=@{ Volume=$primary; Disk=$disk } }
                } elseif ($media -match 'HDD') {
                    return @{ Status='WARN'; Detail=$detail + ' May increase load times.'; Raw=@{ Volume=$primary; Disk=$disk } }
                } else {
                    return @{ Status='OK'; Detail=$detail + ' Main data volume is on SSD/NVMe.'; Raw=@{ Volume=$primary; Disk=$disk } }
                }
            } catch {
                return @{ Status='UNSUPPORTED'; Detail="Get-Volume / Get-Disk unavailable or failed: $($_.Exception.Message)"; Raw=$null }
            }
        }
        FixSafe = $null
    }

$checks += [pscustomobject]@{
        Name     = 'SSD TRIM Status'
        Module   = 'Storage'
        Category = 'Filesystem'
        MinBuild = 7600
        Impact   = 15
        Detect   = {
            $rungs = @()
            $out = (& fsutil behavior query DisableDeleteNotify 2>$null)
            if (-not $out) {
                $rungs += [pscustomobject]@{ Rung=1; Status='UNKNOWN'; Detail='Could not query TRIM status.'; Raw=$null }
            } else {
                $values = @()
                foreach ($line in $out) {
                    if ($line -match '=\s*(\d+)') { $values += [long]$matches[1] }
                }
    
                if (@($values).Count -eq 0) {
                    $rungs += [pscustomobject]@{ Rung=1; Status='UNKNOWN'; Detail='No TRIM flags found in fsutil output.'; Raw=$out }
                } else {
                    $hasDisabled = $values | Where-Object { $_ -ne 0 }
                    if (@($hasDisabled).Count -eq 0) {
                        $rungs += [pscustomobject]@{ Rung=1; Status='OK'; Detail='TRIM appears enabled for all supported file systems.'; Raw=$values }
                    } else {
                        $rungs += [pscustomobject]@{ Rung=1; Status='WARN'; Detail='TRIM appears disabled or partially unsupported on at least one filesystem.'; Raw=$values }
                    }
                }
            }
    
            $rungs += [pscustomobject]@{ Rung=2; Status='INFO'; Detail='Per-volume TRIM eligibility not evaluated here.'; Raw=$null }
            return $rungs
        }
        FixSafe = {
            & fsutil behavior set DisableDeleteNotify 0 | Out-Null
            'Enabled TRIM (DisableDeleteNotify set to 0).'
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'NTFS Last Access Time'
        Module   = 'Storage'
        Category = 'Filesystem'
        MinBuild = 6000
        Impact   = 10
        Detect   = {
            $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
            $name = 'NtfsDisableLastAccessUpdate'
    
            if (-not (Test-Path $path)) { return @{ Status='UNKNOWN'; Detail='FileSystem key not found; defaults in use.'; Raw=$null } }
    
            $prop = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
            if (-not $prop) { return @{ Status='UNKNOWN'; Detail='NtfsDisableLastAccessUpdate not set; default behavior applies.'; Raw=$null } }
    
            $val = [long]$prop.$name
            if ($val -eq 0) {
                return @{ Status='WARN'; Detail="NtfsDisableLastAccessUpdate=0 (timestamps fully enabled; small overhead)."; Raw=$val }
            } else {
                return @{ Status='OK'; Detail="NtfsDisableLastAccessUpdate=$val (reduced/disabled; good for perf)."; Raw=$val }
            }
        }
        FixSafe = {
            $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem'
            try {
                Set-RegistryValueSafe -HivePath $path -Name 'NtfsDisableLastAccessUpdate' -Value 1 -Type 'DWord' -BackupTag 'Storage-FileSystem'
                'Set NtfsDisableLastAccessUpdate to 1 (disable last access updates). Reboot recommended.'
            } catch {
                "Failed to set NtfsDisableLastAccessUpdate: $($_.Exception.Message)"
            }
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'Scheduled Defrag/Optimize'
        Module   = 'Storage'
        Category = 'Maintenance'
        MinBuild = 7600
        Impact   = 5
        Detect   = {
            $rungs = @()
    
            try {
                $media = Get-PhysicalDisk | Select-Object FriendlyName, MediaType, Size
                if ($media) {
                    $mix = ($media | ForEach-Object { "$($_.FriendlyName):$($_.MediaType)" }) -join '; '
                    $rungs += [pscustomobject]@{ Rung=1; Status='INFO'; Detail="Detected media types: $mix"; Raw=$media }
                } else {
                    $rungs += [pscustomobject]@{ Rung=1; Status='UNKNOWN'; Detail='Could not enumerate physical disks.'; Raw=$null }
                }
            } catch {
                $rungs += [pscustomobject]@{ Rung=1; Status='UNKNOWN'; Detail='Could not enumerate physical disks.'; Raw=$null }
            }
    
            try {
                $task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction Stop
            } catch {
                $rungs += [pscustomobject]@{ Rung=2; Status='UNSUPPORTED'; Detail='ScheduledDefrag task not found.'; Raw=$null }
                return $rungs
            }
    
            $enabled = $null
            if ($task -and ($task | Get-Member -Name Enabled -ErrorAction SilentlyContinue)) {
                $enabled = $task.Enabled
            }
            $state   = $task.State.ToString()
            $detail  = "ScheduledDefrag task: State=$state, Enabled=$enabled."
    
            if ($enabled -or $state -in @('Ready','Running')) {
                $rungs += [pscustomobject]@{ Rung=2; Status='OK'; Detail=$detail + ' Windows will periodically optimize drives.'; Raw=$task }
            } else {
                $rungs += [pscustomobject]@{ Rung=2; Status='WARN'; Detail=$detail + ' Task not enabled; optimization may not run.'; Raw=$task }
            }
    
            try {
                $svc = Get-Service -Name 'defragsvc' -ErrorAction Stop
                if ($svc.Status -eq 'Running') {
                    $rungs += [pscustomobject]@{ Rung=3; Status='OK'; Detail='Optimize Drives service running.'; Raw=$svc.Status }
                } else {
                    $rungs += [pscustomobject]@{ Rung=3; Status='INFO'; Detail="Optimize Drives service is $($svc.Status)."; Raw=$svc.Status }
                }
            } catch {
                $rungs += [pscustomobject]@{ Rung=3; Status='UNKNOWN'; Detail='Optimize Drives service not found or not queryable.'; Raw=$null }
            }
    
            return $rungs
        }
        FixSafe = {
            try {
                Enable-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction Stop
                'Enabled ScheduledDefrag task so Windows can optimize drives.'
            } catch {
                "Failed to enable ScheduledDefrag: $($_.Exception.Message)"
            }
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'Pagefile Location'
        Module   = 'Storage'
        Category = 'StorageLayout'
        MinBuild = 7600
        Impact   = 10
        Detect   = {
            $pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue
            if (-not $pf) { return @{ Status='ISSUE'; Detail='No pagefile detected.'; Raw=$null } }
    
            $entries = @()
            foreach ($p in $pf) {
                $path  = $p.Name
                if (-not $path) { continue }
                $drive = $path.Substring(0,1)
                $disk  = Get-DiskForDriveLetter -DriveLetter $drive
    
                $mediaType = 'Unknown'
                if ($disk -and $disk.PSObject.Properties.Match('MediaType').Count -gt 0 -and $disk.MediaType) {
                    $mediaType = $disk.MediaType.ToString()
                }

                if ($disk) {
                    $entries += [pscustomobject]@{
                        Path=$path; Drive=$drive; Disk=$disk.Number
                        MediaType= $mediaType
                        BusType=$disk.BusType.ToString()
                    }
                } else {
                    $entries += [pscustomobject]@{ Path=$path; Drive=$drive; Disk=$null; MediaType='Unknown'; BusType='Unknown' }
                }
            }
    
            if (@($entries).Count -eq 0) { return @{ Status='UNKNOWN'; Detail='Pagefile entries could not be resolved.'; Raw=$pf } }
    
            $detailParts = $entries | ForEach-Object {
                "Pagefile at $($_.Path) -> Disk $($_.Disk) MediaType=$($_.MediaType) BusType=$($_.BusType)"
            }
    
            $hasHDD = $entries | Where-Object { $_.MediaType -match 'HDD' }
            if ($hasHDD) {
                return @{ Status='WARN'; Detail=($detailParts -join '; ') + ' Pagefile on HDD can increase stutter.'; Raw=$entries }
            } else {
                return @{ Status='OK'; Detail=($detailParts -join '; ') + ' All pagefiles on SSD/NVMe or unknown media.'; Raw=$entries }
            }
        }
        FixSafe = $null
    }
    
    $checks += [pscustomobject]@{
        Name     = 'Disk Free Space (Key Drives)'
        Module   = 'Storage'
        Category = 'StorageCapacity'
        MinBuild = 7600
        Impact   = 15
        Detect   = {
            $drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue
            if (-not $drives) { return @{ Status='UNKNOWN'; Detail='Could not read disk information.'; Raw=$null } }
    
            $osLetter = $env:SystemDrive.TrimEnd('\')
            $osDrive  = $drives | Where-Object { $_.DeviceID -eq $osLetter }
    
            $dataDrive = $drives | Where-Object { $_.DeviceID -ne $osLetter } |
                Sort-Object -Property Size -Descending | Select-Object -First 1
    
            $detailParts = @()
            $worstPct    = 100
            $rawList     = @()
    
            foreach ($d in @($osDrive, $dataDrive)) {
                if (-not $d) { continue }
                $freePct = [int]([math]::Round(($d.FreeSpace / $d.Size) * 100))
                $sizeGB  = [math]::Round($d.Size / 1GB, 1)
                $freeGB  = [math]::Round($d.FreeSpace / 1GB, 1)
    
                $role = if ($d.DeviceID -eq $osLetter) { 'OS' } else { 'Data' }
                $detailParts += ("{0} drive {1}: {2}GB total, {3}GB free ({4}% free)" -f $role, $d.DeviceID, $sizeGB, $freeGB, $freePct)
    
                if ($freePct -lt $worstPct) { $worstPct = $freePct }
    
                $rawList += [pscustomobject]@{ Drive=$d.DeviceID; Role=$role; SizeGB=$sizeGB; FreeGB=$freeGB; FreePct=$freePct }
            }
    
            if (@($detailParts).Count -eq 0) { return @{ Status='UNKNOWN'; Detail='No OS or fixed data drives found.'; Raw=$null } }
    
            $detail = ($detailParts -join '; ')
            $status = 'OK'
            if ($worstPct -lt 10) {
                $status='ISSUE'; $detail += ' One or more key drives are <10% free; can hurt stability.'
            } elseif ($worstPct -lt 15) {
                $status='WARN';  $detail += ' One or more key drives are <15% free; freeing space recommended.'
            }
    
            return @{ Status=$status; Detail=$detail; Raw=$rawList }
        }
        FixSafe = $null
    }
    
    # ================================
    # NETWORK MODULE
    # ================================
    
    $checks += [pscustomobject]@{
        Name     = 'Active Physical NICs'
        Module   = 'Network'
        Category = 'NetworkStack'
        MinBuild = 9600
        Impact   = 5
        Detect   = {
            try {
                $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
            } catch {
                return @{ Status='UNSUPPORTED'; Detail='Get-NetAdapter is not available on this system.'; Raw=$null }
            }
    
            if (-not $adapters) { return @{ Status='ISSUE'; Detail='No active physical adapters reported.'; Raw=$null } }
            $names = $adapters | Select-Object -ExpandProperty Name
            return @{ Status='OK'; Detail="Active physical adapters: $($names -join ', ')."; Raw=$adapters }
        }
        FixSafe = $null
    }
    
    $checks += [pscustomobject]@{
        Name     = 'NIC Power Management'
        Module   = 'Network'
        Category = 'NICPower'
        MinBuild = 7601
        Impact   = 15
    
        Detect = {
            $active = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }
            if (-not $active) { return @{ Status='UNKNOWN'; Detail='No active physical adapters found.'; Raw=$null } }
    
            $hits = @()
            foreach ($nic in $active) {
                $props = @(Get-NetAdapterAdvancedProperty -Name $nic.Name -ErrorAction SilentlyContinue)
                if (-not $props) { continue }
    
                $eeeProps = $props | Where-Object {
                    ($_.DisplayName     -match '(?i)\bEEE\b|Energy Efficient Ethernet|Green Ethernet|Power Saving|Ultra Low Power|System Idle Power Saver') -or
                    ($_.RegistryKeyword -match '(?i)\bEEE\b|EnergyEfficientEthernet|GreenEthernet|PowerSaving')
                }
    
                foreach ($p in $eeeProps) {
                    $val = ($p.DisplayValue, $p.RegistryValue) -ne $null | Select-Object -First 1
                    $enabled = $false
                    if ($val -is [string]) {
                        if ($val -match '(?i)enable|on|auto') { $enabled = $true }
                    } else {
                        if ($val -ne 0) { $enabled = $true }
                    }
    
                    $hits += [pscustomobject]@{
                        NicName=$nic.Name; PropName=$p.DisplayName; Keyword=$p.RegistryKeyword
                        Value=$val; Enabled=$enabled
                    }
                }
            }
    
            if (-not $hits) {
                return @{ Status='OK'; Detail='No EEE/Power-saving properties exposed by active NIC driver(s).'; Raw=$null }
            }
    
            $stillEnabled = $hits | Where-Object { $_.Enabled }
            if ($stillEnabled) {
                $desc = ($stillEnabled | ForEach-Object { "$($_.NicName): $($_.PropName)=$($_.Value)" }) -join '; '
                return @{ Status='WARN'; Detail="EEE/Power-saving still enabled on NIC(s): $desc"; Raw=$hits }
            }
    
            return @{ Status='OK'; Detail='EEE/Power-saving properties present and already disabled.'; Raw=$hits }
        }
    
        FixSafe = {
            $active = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' }
            if (-not $active) { return "No active physical NICs found; nothing to fix." }
    
            $fixed = @()
            foreach ($nic in $active) {
                $props = @(Get-NetAdapterAdvancedProperty -Name $nic.Name -ErrorAction SilentlyContinue)
                if (-not $props) { continue }
    
                $eeeProps = $props | Where-Object {
                    ($_.DisplayName     -match '(?i)\bEEE\b|Energy Efficient Ethernet|Green Ethernet|Power Saving|Ultra Low Power|System Idle Power Saver') -or
                    ($_.RegistryKeyword -match '(?i)\bEEE\b|EnergyEfficientEthernet|GreenEthernet|PowerSaving')
                }
    
                foreach ($p in $eeeProps) {
                    $tryValues = @('Disabled','Off','0')
                    $success = $false
                    foreach ($tv in $tryValues) {
                        try {
                            Set-NetAdapterAdvancedProperty -Name $nic.Name -RegistryKeyword $p.RegistryKeyword -DisplayValue $tv -NoRestart -ErrorAction Stop
                            $success = $true
                            $fixed += "$($nic.Name): $($p.DisplayName)->$tv"
                            break
                        } catch {}
                    }
    
                    if (-not $success) {
                        try {
                            Set-NetAdapterAdvancedProperty -Name $nic.Name -RegistryKeyword $p.RegistryKeyword -RegistryValue 0 -NoRestart -ErrorAction Stop
                            $fixed += "$($nic.Name): $($p.DisplayName)->0"
                        } catch {}
                    }
                }
            }
    
            if (@($fixed).Count -eq 0) { return "EEE/Power-saving property not exposed OR could not be safely set by driver." }
    
            foreach ($nic in $active) {
                try { Disable-NetAdapter -Name $nic.Name -Confirm:$false -ErrorAction SilentlyContinue } catch {}
                Start-Sleep -Milliseconds 500
                try { Enable-NetAdapter  -Name $nic.Name -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            }
    
            return "Disabled EEE/Power-saving (best-effort) on: " + ($fixed -join '; ')
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'TCP Global (RSS + AutoTuning)'
        Module   = 'Network'
        Category = 'NetworkStack'
        MinBuild = 6000
        Impact   = 20
        Detect   = {
            $rungs = @()
            try { $output = & netsh int tcp show global 2>$null } catch { $output = $null }
            if (-not $output) {
                $rungs += [pscustomobject]@{ Rung=1; Status='UNSUPPORTED'; Detail='netsh TCP globals could not be read.'; Raw=$null }
                return $rungs
            }
    
            $text = ($output | Out-String)
            $rssMatch   = [regex]::Match($text, 'Receive-Side Scaling State\s*:\s*(.+)')
            $autoMatch  = [regex]::Match($text, 'Receive Window Auto-Tuning Level\s*:\s*(.+)')
    
            if (-not $rssMatch.Success -and -not $autoMatch.Success) {
                $rungs += [pscustomobject]@{ Rung=1; Status='UNKNOWN'; Detail='Could not parse TCP global output.'; Raw=$text }
            } else {
                $rss  = $rssMatch.Groups[1].Value.Trim()
                $auto = $autoMatch.Groups[1].Value.Trim()
    
                $issues = @()
                if ($rss -and $rss -notmatch 'enabled') { $issues += "RSS state is '$rss' (recommended: enabled)." }
                if ($auto -and $auto -notmatch 'normal') { $issues += "Auto-Tuning is '$auto' (recommended: normal)." }
    
                if (@($issues).Count -eq 0) {
                    $rungs += [pscustomobject]@{ Rung=1; Status='OK'; Detail="RSS: $rss; Auto-Tuning: $auto."; Raw=$text }
                } else {
                    $rungs += [pscustomobject]@{ Rung=1; Status='WARN'; Detail=($issues -join ' '); Raw=$text }
                }
            }
    
            try {
                $rssCaps = Get-NetAdapterRss -ErrorAction SilentlyContinue
                if (-not $rssCaps) {
                    $rungs += [pscustomobject]@{ Rung=2; Status='LIMITED'; Detail='Adapter RSS capability could not be queried.'; Raw=$null }
                } else {
                    $unsupported = $rssCaps | Where-Object { $_.Enabled -eq $false -and $_.MaxProcessors -le 0 }
                    if ($unsupported) {
                        $rungs += [pscustomobject]@{ Rung=2; Status='LIMITED'; Detail='Detected adapter(s) without RSS capability.'; Raw=$rssCaps }
                    } else {
                        $rungs += [pscustomobject]@{ Rung=2; Status='OK'; Detail='Adapter RSS capability present.'; Raw=$rssCaps }
                    }
                }
            } catch {
                $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail='Could not evaluate adapter RSS capabilities.'; Raw=$null }
            }
    
            return $rungs
        }
        FixSafe = {
            try {
                & netsh int tcp set global rss=enabled autotuninglevel=normal 2>$null | Out-Null
                "Set TCP globals: RSS=enabled, AutoTuningLevel=normal."
            } catch {
                "Failed to set TCP globals: $($_.Exception.Message)"
            }
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'Network Throttling Index'
        Module   = 'Network'
        Category = 'NetworkScheduler'
        MinBuild = 6000
        Impact   = 20
        Detect   = {
            $rungs = @()
            $polPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
            if (Test-Path $polPath) {
                $rungs += [pscustomobject]@{ Rung=1; Status='INFO'; Detail='Policy Multimedia SystemProfile path present; may override NetworkThrottlingIndex.'; Raw=$polPath }
            } else {
                $rungs += [pscustomobject]@{ Rung=1; Status='OK'; Detail='No Multimedia policy override path detected.'; Raw=$null }
            }
    
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
            $name = 'NetworkThrottlingIndex'
            if (-not (Test-Path $path)) {
                $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail='SystemProfile key missing; defaults in use.'; Raw=$null }
                return $rungs
            }
    
            $prop = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
            if (-not $prop) {
                $rungs += [pscustomobject]@{ Rung=2; Status='WARN'; Detail='NetworkThrottlingIndex not set (default throttling may limit bursts).'; Raw=$null }
                return $rungs
            }
    
            $val    = [uint32]$prop.$name
            $hexVal = "{0:X8}" -f $val
            if ($hexVal -eq 'FFFFFFFF') {
                $rungs += [pscustomobject]@{ Rung=2; Status='OK'; Detail='NetworkThrottlingIndex=0xFFFFFFFF (throttling disabled).'; Raw=$val }
            } else {
                $rungs += [pscustomobject]@{ Rung=2; Status='WARN'; Detail="NetworkThrottlingIndex=0x$hexVal (recommended 0xFFFFFFFF)."; Raw=$val }
            }
    
            return $rungs
        }
        FixSafe = {
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
            try {
                Set-RegistryValueSafe -HivePath $path -Name 'NetworkThrottlingIndex' -Value 0xffffffff -Type 'DWord' -BackupTag 'Network-Multimedia'
                'Set NetworkThrottlingIndex to 0xFFFFFFFF (disabled throttling). Reboot recommended.'
            } catch {
                "Failed to set NetworkThrottlingIndex: $($_.Exception.Message)"
            }
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'System Responsiveness'
        Module   = 'Network'
        Category = 'NetworkScheduler'
        MinBuild = 6000
        Impact   = 15
        Detect   = {
            $rungs = @()
            $polPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
            if (Test-Path $polPath) {
                $rungs += [pscustomobject]@{ Rung=1; Status='INFO'; Detail='Policy Multimedia SystemProfile path present; may override SystemResponsiveness.'; Raw=$polPath }
            } else {
                $rungs += [pscustomobject]@{ Rung=1; Status='OK'; Detail='No Multimedia policy override path detected.'; Raw=$null }
            }
    
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
            $name = 'SystemResponsiveness'
            if (-not (Test-Path $path)) {
                $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail='SystemProfile key missing; defaults in use.'; Raw=$null }
                return $rungs
            }
    
            $prop = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
            if (-not $prop) {
                $rungs += [pscustomobject]@{ Rung=2; Status='WARN'; Detail='SystemResponsiveness not set (default ~20 can reserve CPU time).'; Raw=$null }
                return $rungs
            }
    
            $val = [int]$prop.$name
            if ($val -eq 0) {
                $rungs += [pscustomobject]@{ Rung=2; Status='OK'; Detail='SystemResponsiveness=0 (no extra CPU reservation).'; Raw=$val }
            } else {
                $rungs += [pscustomobject]@{ Rung=2; Status='WARN'; Detail="SystemResponsiveness=$val (recommended 0)."; Raw=$val }
            }
    
            return $rungs
        }
        FixSafe = {
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
            try {
                Set-RegistryValueSafe -HivePath $path -Name 'SystemResponsiveness' -Value 0 -Type 'DWord' -BackupTag 'Network-Multimedia'
                'Set SystemResponsiveness to 0. Reboot recommended.'
            } catch {
                "Failed to set SystemResponsiveness: $($_.Exception.Message)"
            }
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'DNS Client Service'
        Module   = 'Network'
        Category = 'Services'
        MinBuild = 6000
        Impact   = 10
        Detect   = {
            try { $svc = Get-Service -Name 'Dnscache' -ErrorAction Stop }
            catch { return @{ Status='UNSUPPORTED'; Detail='DNS Client (Dnscache) service not found.'; Raw=$null } }
    
            if ($svc.Status -ne 'Running' -or $svc.StartType -eq 'Disabled') {
                return @{ Status='ISSUE'; Detail='DNS Client not running or disabled.'; Raw=$svc }
            }
            return @{ Status='OK'; Detail="DNS Client running (StartType: $($svc.StartType))."; Raw=$svc }
        }
        FixSafe = {
            try {
                Set-Service -Name 'Dnscache' -StartupType Automatic -ErrorAction Stop
                Start-Service -Name 'Dnscache' -ErrorAction Stop
                'Set DNS Client to Automatic and started service.'
            } catch {
                "Failed to adjust DNS Client service: $($_.Exception.Message)"
            }
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'NIC Interrupt Moderation'
        Module   = 'Network'
        Category = 'NICPower'
        MinBuild = 9600
        Impact   = 15
        Detect   = {
            try {
                $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
            } catch {
                return @{ Status='UNSUPPORTED'; Detail='Get-NetAdapter not available for advanced NIC props.'; Raw=$null }
            }
    
            $props = foreach ($a in $adapters) {
                Get-NetAdapterAdvancedProperty -Name $a.Name -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -eq 'Interrupt Moderation' -or $_.RegistryKeyword -eq 'InterruptModeration' }
            }
    
            if (-not $props) { return @{ Status='UNSUPPORTED'; Detail='No Interrupt Moderation property exposed.'; Raw=$null } }
    
            $nonDisabled = $props | Where-Object { $_.DisplayValue -and $_.DisplayValue -notmatch 'Disabled' }
            if ($nonDisabled) {
                $details = $nonDisabled | ForEach-Object { "$($_.Name): $($_.DisplayValue)" }
                return @{ Status='WARN'; Detail="Interrupt Moderation not disabled on: $($details -join '; ')."; Raw=$props }
            }
            return @{ Status='OK'; Detail='Interrupt Moderation already disabled.'; Raw=$props }
        }
        FixSafe = {
            try {
                $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
                $changed = @()
    
                foreach ($a in $adapters) {
                    $prop = Get-NetAdapterAdvancedProperty -Name $a.Name -ErrorAction SilentlyContinue |
                            Where-Object { $_.DisplayName -eq 'Interrupt Moderation' -or $_.RegistryKeyword -eq 'InterruptModeration' }
    
                    if ($prop -and $prop.DisplayValue -and $prop.DisplayValue -notmatch 'Disabled') {
                        try {
                            Set-NetAdapterAdvancedProperty -Name $a.Name -DisplayName $prop.DisplayName -DisplayValue 'Disabled' -ErrorAction Stop
                            $changed += $a.Name
                        } catch {}
                    }
                }
    
                if (@($changed).Count -gt 0) {
                    return "Disabled Interrupt Moderation on: $($changed -join ', '). Reconnect/reboot may be required."
                }
                return 'No NICs required Interrupt Moderation changes.'
            } catch {
                return "Failed to adjust Interrupt Moderation: $($_.Exception.Message)"
            }
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'NIC Link Speed & Duplex'
        Module   = 'Network'
        Category = 'NetworkStack'
        MinBuild = 9600
        Impact   = 5
        Detect   = {
            try {
                $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
            } catch {
                return @{ Status='UNSUPPORTED'; Detail='Get-NetAdapter not available to inspect link speed/duplex.'; Raw=$null }
            }
    
            if (-not $adapters) { return @{ Status='UNKNOWN'; Detail='No active physical adapters found.'; Raw=$null } }
    
            $issues = @()
            foreach ($a in $adapters) {
                $speed  = $a.LinkSpeed
                $duplex = $a.FullDuplex
                if ($speed -and $speed -notmatch 'Gbps') { $issues += "$($a.Name): LinkSpeed=$speed (expected >=1Gbps)." }
                if ($duplex -ne $null -and -not $duplex) { $issues += "$($a.Name): FullDuplex=$duplex (half-duplex hurts performance)." }
            }
    
            if (@($issues).Count -eq 0) {
                $summary = $adapters | ForEach-Object { "$($_.Name): $($_.LinkSpeed)" }
                return @{ Status='OK'; Detail="Link speeds: $($summary -join '; ')."; Raw=$adapters }
            }
            return @{ Status='WARN'; Detail=($issues -join ' '); Raw=$adapters }
        }
        FixSafe = $null
    }
    
    # ================================
    # GPU MODULE
    # ================================
    
    $checks += [pscustomobject]@{
        Name     = 'HAGS (Hardware GPU Scheduling)'
        Module   = 'GPU'
        Category = 'GPU'
        MinBuild = 19041
        Impact   = 15
        Detect   = {
            $rungs = @()
            $path = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
            $name = 'HwSchMode'
            if (-not (Test-Path $path)) {
                $rungs += [pscustomobject]@{ Rung=1; Status='UNSUPPORTED'; Detail='GraphicsDrivers key not found; likely no HAGS support.'; Raw=$null }
                return $rungs
            }
            $rungs += [pscustomobject]@{ Rung=1; Status='OK'; Detail='HAGS capability key present.'; Raw=$null }
    
            $val = $null
            if (Test-Path $path) {
                $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                if ($props -and $props.PSObject.Properties.Name -contains $name) {
                    $val = $props.$name
                }
            }
            if ($null -eq $val) {
                $rungs += [pscustomobject]@{ Rung=2; Status='WARN'; Detail='HwSchMode not set (typically off/default).'; Raw=$null }
            } else {
                switch ($val) {
                    1 { $rungs += [pscustomobject]@{ Rung=2; Status='WARN'; Detail='HAGS enabled  -  helps some systems, may increase stutter on others. If stable for you, ignore.'; Raw=$val } }
                    2 { $rungs += [pscustomobject]@{ Rung=2; Status='OK'; Detail='HAGS explicitly disabled (stable default for most gaming systems).'; Raw=$val } }
                    default { $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail="Unexpected HwSchMode value: $val."; Raw=$val } }
                }
            }
    
            $rungs += [pscustomobject]@{ Rung=3; Status='INFO'; Detail='Driver-level HAGS override not evaluated.'; Raw=$null }
            return $rungs
        }
        FixSafe = $null
    }
    
    $checks += [pscustomobject]@{
        Name     = 'GPU Task Priority (Games profile)'
        Module   = 'GPU'
        Category = 'Scheduler'
        MinBuild = 7600
        Impact   = 30
        Detect   = {
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
            if (-not (Test-Path $path)) { return @{ Status='UNKNOWN'; Detail='Games task profile key not found.'; Raw=$null } }
    
            $props    = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $gpuPrio  = $props.'GPU Priority'
            $prio     = $props.'Priority'
            $schedCat = $props.'Scheduling Category'
            $sfio     = $props.'SFIO Priority'
    
            $detail = "GPU Priority=$gpuPrio, Priority=$prio, Scheduling='$schedCat', SFIO='$sfio'."
            $status = 'OK'
    
            $expectedGpu   = 8
            $expectedPrio  = 6
            $expectedSched = 'High'
            $expectedSfio  = 'High'
    
            $mismatch = @()
            if ($gpuPrio  -ne $expectedGpu)   { $mismatch += "GPU Priority != $expectedGpu" }
            if ($prio     -ne $expectedPrio)  { $mismatch += "Priority != $expectedPrio" }
            if ($schedCat -ne $expectedSched) { $mismatch += "Scheduling != '$expectedSched'" }
            if ($sfio     -ne $expectedSfio)  { $mismatch += "SFIO != '$expectedSfio'" }
    
            if (@($mismatch).Count -gt 0) {
                $status='WARN'
                $detail += " Recommended: GPU Priority=$expectedGpu, Priority=$expectedPrio, Scheduling='$expectedSched', SFIO='$expectedSfio'."
            }
    
            return @{ Status=$status; Detail=$detail; Raw=$props }
        }
        FixSafe = {
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
            Set-RegistryValueSafe -HivePath $path -Name 'GPU Priority'        -Value 8      -Type 'DWord'  -BackupTag 'GpuTaskPriority'
            Set-RegistryValueSafe -HivePath $path -Name 'Priority'            -Value 6      -Type 'DWord'  -BackupTag 'GpuTaskPriority'
            Set-RegistryValueSafe -HivePath $path -Name 'Scheduling Category' -Value 'High' -Type 'String' -BackupTag 'GpuTaskPriority'
            Set-RegistryValueSafe -HivePath $path -Name 'SFIO Priority'       -Value 'High' -Type 'String' -BackupTag 'GpuTaskPriority'
            "Set Games task profile to GPU Priority=8, Priority=6, Scheduling='High', SFIO='High'."
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'PCIe Link State (AC)'
        Module   = 'GPU'
        Category = 'Power'
        MinBuild = 7600
        Impact   = 25
        Detect   = {
            $schemeLine = (powercfg /GETACTIVESCHEME) 2>$null
            if (-not $schemeLine) { return @{ Status='UNKNOWN'; Detail='Unable to get active power scheme for PCIe link state.'; Raw=$null } }
    
            $schemeGuid = ($schemeLine -split '\s+')[3]
            $subGuid    = '501a4d13-42af-4429-9fd1-a8218c268e20'
            $setGuid    = 'ee12f906-d277-404b-b6da-e5fa1a576df5'
    
            $out = (powercfg /Q $schemeGuid $subGuid $setGuid) 2>$null
            if (-not $out) { return @{ Status='UNKNOWN'; Detail='Could not query PCIe link state.'; Raw=$null } }
    
            $acLine = ($out | Select-String -Pattern 'Current AC Power Setting Index').ToString()
            if (-not $acLine) { return @{ Status='UNKNOWN'; Detail='AC setting index not found in PCIe section.'; Raw=$out } }
    
            $hex  = $acLine.Split()[-1]
            $val  = [int]("0x$hex")
            $desc = switch ($val) {
                0 { 'Off (best for gaming stability/latency).' }
                1 { 'Moderate power savings.' }
                2 { 'Maximum power savings (can hurt latency).' }
                default { "Unknown mode ($val)." }
            }
    
            $detail = "PCIe Link State (AC): $desc"
            $status = 'OK'
    
            if ($val -eq 1) { $status='WARN';  $detail += ' Recommended: Off (0).' }
            elseif ($val -eq 2) { $status='ISSUE'; $detail += ' Maximum savings can cause micro-stutter; Off recommended.' }
    
            return @{ Status=$status; Detail=$detail; Raw=@{ Scheme=$schemeGuid; Value=$val } }
        }
        FixSafe = {
            $schemeLine = (powercfg /GETACTIVESCHEME) 2>$null
            if (-not $schemeLine) { return "Unable to get active power scheme; no change made." }
    
            $schemeGuid = ($schemeLine -split '\s+')[3]
            $subGuid    = '501a4d13-42af-4429-9fd1-a8218c268e20'
            $setGuid    = 'ee12f906-d277-404b-b6da-e5fa1a576df5'
    
            powercfg /SETACVALUEINDEX $schemeGuid $subGuid $setGuid 0 | Out-Null
            powercfg /S $schemeGuid | Out-Null
            "Set PCIe Link State Power Management (AC) to Off (0)."
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'NVIDIA Shader Cache Config'
        Module   = 'GPU'
        Category = 'GPU'
        MinBuild = 7600
        Impact   = 15
        Detect   = {
            $path = 'HKLM:\SOFTWARE\NVIDIA Corporation\Global\ShaderCache'
            if (-not (Test-Path $path)) {
                return @{ Status='OK'; Detail='NVIDIA shader cache key not found (common on DCH drivers). Skipping with no penalty.'; Raw=$null }
            }
    
            $props   = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $maxSize = $props.MaxSize
            if ($null -eq $maxSize) {
                return @{ Status='OK'; Detail='MaxSize not set; driver default shader cache size in use.'; Raw=$props }
            }
    
            $maxGB  = [math]::Round(($maxSize / 1024), 1)
            $status = 'OK'
            $detail = "NVIDIA shader cache MaxSize=${maxGB}GB. Recommended range: 4-8GB."
            if ($maxGB -lt 2)       { $status='WARN'; $detail += ' Very small cache can cause shader recompiles.' }
            elseif ($maxGB -gt 16)  { $status='WARN'; $detail += ' Extremely large cache wastes disk.' }
    
            return @{ Status=$status; Detail=$detail; Raw=$props }
        }
        FixSafe = {
            $path = 'HKLM:\SOFTWARE\NVIDIA Corporation\Global\ShaderCache'
            if (-not (Test-Path $path)) { return "NVIDIA shader cache key not found; no change made." }
    
            $recommendedMB = 5120
            Set-RegistryValueSafe -HivePath $path -Name 'MaxSize' -Value $recommendedMB -Type 'DWord' -BackupTag 'ShaderCache'
            "Set NVIDIA shader cache MaxSize to 5GB (${recommendedMB}MB)."
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'MPO (Multiplane Overlay) State'
        Module   = 'GPU'
        Category = 'Display'
        MinBuild = 10240
        Impact   = 10
        Detect   = {
            $rungs = @()
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows\Dwm'
            if (-not (Test-Path $path)) {
                $rungs += [pscustomobject]@{ Rung=1; Status='UNKNOWN'; Detail='DWM key not found; MPO status unknown.'; Raw=$null }
                return $rungs
            }
            $rungs += [pscustomobject]@{ Rung=1; Status='OK'; Detail='DWM key present.'; Raw=$null }
    
            $props       = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            $overlayTest = $null
            if ($props -and $props.PSObject.Properties.Match('OverlayTestMode').Count -gt 0) {
                $overlayTest = $props.OverlayTestMode
            }
    
            if ($null -eq $overlayTest) {
                $rungs += [pscustomobject]@{ Rung=2; Status='OK'; Detail='OverlayTestMode not set; MPO default behavior.'; Raw=$props }
            } elseif ($overlayTest -eq 5) {
                $rungs += [pscustomobject]@{ Rung=2; Status='OK'; Detail='OverlayTestMode=5 (MPO disabled). Leave if stable.'; Raw=$props }
            } else {
                $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail="OverlayTestMode=$overlayTest nonstandard (0=default,5=disabled)."; Raw=$props }
            }
    
            $rungs += [pscustomobject]@{ Rung=3; Status='INFO'; Detail='Driver-level MPO override not evaluated.'; Raw=$null }
            return $rungs
        }
        FixSafe = $null
    }
    
    $checks += [pscustomobject]@{
        Name     = 'Overlay / Hook Stack'
        Module   = 'GPU'
        Category = 'Overlay'
        MinBuild = 10240
        Impact   = 10
    
        Detect = {
            $procs = Get-Process -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '(?i)nvsphelper64|nvshare|nvidia share|shadowplay|nvidia overlay|gameoverlayui|discordoverlay|xboxpcappft|gamebar' }
    
            if (-not $procs) { return @{ Status='OK'; Detail='No common overlay helpers detected.'; Raw=$null } }
    
            $nvidiaHelpers = $procs | Where-Object { $_.Name -match '(?i)^nvsphelper64$|^nvshare$|nvidia share|shadowplay|nvidia overlay' }
            $otherHelpers  = $procs | Where-Object { $_ -notin $nvidiaHelpers }
    
            $namesNv    = ($nvidiaHelpers | Select-Object -ExpandProperty Name -Unique) -join ', '
            $namesOther = ($otherHelpers  | Select-Object -ExpandProperty Name -Unique) -join ', '
    
            if (@($nvidiaHelpers).Count -gt 0) {
                return @{ Status='WARN'; Detail="Active NVIDIA overlay helpers detected (x$(@($nvidiaHelpers).Count)): $namesNv. Other hooks: $namesOther"; Raw=@{ Nvidia=$namesNv; Other=$namesOther } }
            }
    
            return @{ Status='INFO'; Detail=("Non-NVIDIA overlays/hooks detected (x{0}): {1}" -f (@($otherHelpers).Count), $namesOther); Raw=$namesOther }
        }
    
        FixSafe = {
            $changes = @()
    
            $legacyKey = 'HKCU:\Software\NVIDIA Corporation\NVIDIA GeForce Experience\InGameOverlay'
            if (Test-Path $legacyKey) {
                try {
                    Set-RegistryValueSafe -HivePath $legacyKey -Name 'Enabled' -Value 0 -Type 'DWord' -BackupTag 'NvidiaOverlay'
                    $changes += "Legacy GFE overlay disabled."
                } catch {}
            }
    
            $newKey = 'HKCU:\Software\NVIDIA Corporation\NVIDIA App\InGameOverlay'
            if (Test-Path $newKey) {
                try {
                    Set-RegistryValueSafe -HivePath $newKey -Name 'Enabled' -Value 0 -Type 'DWord' -BackupTag 'NvidiaOverlay'
                    $changes += "NVIDIA App overlay disabled."
                } catch {}
            }
    
            $nvKill = @('nvsphelper64','nvshare','NVIDIA Share','shadowplay','NVIDIA Overlay')
            foreach ($kn in $nvKill) {
                Get-Process -Name $kn -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            }
            $changes += "NVIDIA overlay helper processes terminated."
    
            if (@($changes).Count -eq 0) { return "No NVIDIA overlay keys found; terminated helper processes only." }
            return ($changes -join ' ')
        }
    
        FixStrict = {
            $targets = @('nvsphelper64','nvshare','NVIDIA Share','shadowplay','NVIDIA Overlay','gameoverlayui64','DiscordOverlayHost','GameBarFTServer','GameBar')
            $stopped = @()
            foreach ($t in $targets) {
                Get-Process -Name $t -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                if ($?) { $stopped += $t }
            }
            if (@($stopped).Count -eq 0) { return "Strict overlay cleanup: no targets stopped (none running)." }
            return ("Strict overlay cleanup stopped: " + ($stopped -join ', '))
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'Background GPU / Compute Workloads'
        Module   = 'GPU'
        Category = 'GPUBackground'
        MinBuild = 7600
        Impact   = 20
        Detect   = {
            $procs = Get-Process -ErrorAction SilentlyContinue
    
            $heavyMap = @(
                @{ Label='OBS / screen capture';    Names=@('obs64') },
                @{ Label='Video encoding';         Names=@('ffmpeg', 'HandBrake') },
                @{ Label='Local AI / Python jobs'; Names=@('python', 'python3') },
                @{ Label='Media players';          Names=@('vlc', 'mpv') },
                @{ Label='NVIDIA Share recording'; Names=@('NVIDIA Share') }
            )
    
            $lightMap = @(
                @{ Label='Browsers';     Names=@('chrome', 'msedge') },
                @{ Label='Discord';      Names=@('Discord') },
                @{ Label='Steam helper'; Names=@('steamwebhelper') }
            )
    
            $heavyHits = @()
            $lightHits = @()
    
            foreach ($entry in $heavyMap) {
                $found = $procs | Where-Object { $entry.Names -contains $_.ProcessName } |
                         Select-Object -ExpandProperty ProcessName -Unique
                if ($found) { $heavyHits += ("{0}: {1}" -f $entry.Label, ($found -join ', ')) }
            }
    
            foreach ($entry in $lightMap) {
                $found = $procs | Where-Object { $entry.Names -contains $_.ProcessName } |
                         Select-Object -ExpandProperty ProcessName -Unique
                if ($found) { $lightHits += ("{0}: {1}" -f $entry.Label, ($found -join ', ')) }
            }
    
            if (@($heavyHits).Count -eq 0 -and @($lightHits).Count -eq 0) {
                return @{ Status='OK'; Detail='No obvious background GPU workloads detected.'; Raw=$null }
            }
    
            if (@($heavyHits).Count -gt 0) {
                $detail = "Potential GPU/compute workloads: " + ($heavyHits -join '; ')
                if (@($lightHits).Count -gt 0) { $detail += ". Lighter apps: " + ($lightHits -join '; ') }
                $detail += ". Close these for latency-critical sessions if not needed."
                return @{ Status='WARN'; Detail=$detail; Raw=@{ Heavy=$heavyHits; Light=$lightHits } }
            }
    
            $detail = "Common background apps detected: " + ($lightHits -join '; ') + ". Usually fine unless under heavy use."
            return @{ Status='OK'; Detail=$detail; Raw=@{ Heavy=$heavyHits; Light=$lightHits } }
        }
        FixSafe = $null
    }
    
    $checks += [pscustomobject]@{
        Name     = 'Display Refresh / VRR Readiness'
        Module   = 'GPU'
        Category = 'Display'
        MinBuild = 7600
        Impact   = 10
        Detect   = {
            $rungs = @()
    
            try {
                $activeModes = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorCurrentMode -ErrorAction SilentlyContinue
                if (-not $activeModes) {
                    $rungs += [pscustomobject]@{ Rung=1; Status='UNKNOWN'; Detail='Could not read active monitor mode via WMI.'; Raw=$null }
                } else {
                    foreach ($m in $activeModes) {
                        $hz = if ($m.CurrentRefreshRate) { [int]$m.CurrentRefreshRate } else { 0 }
                        $rungs += [pscustomobject]@{ Rung=1; Status='INFO'; Detail="Active refresh reported: ${hz}Hz."; Raw=$m }
                    }
                }
            } catch {
                $rungs += [pscustomobject]@{ Rung=1; Status='UNKNOWN'; Detail='Active refresh query failed.'; Raw=$null }
            }
    
            try {
                $supported = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorListedSupportedSourceModes -ErrorAction SilentlyContinue
                if (-not $supported) {
                    $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail='Could not read supported modes via WMI.'; Raw=$null }
                } else {
                    $maxHz = 0
                    foreach ($s in $supported) {
                        foreach ($mode in $s.MonitorSourceModes) {
                            if ($mode.RefreshRate -gt $maxHz) { $maxHz = $mode.RefreshRate }
                        }
                    }
                    if ($maxHz -gt 0) {
                        $rungs += [pscustomobject]@{ Rung=2; Status='INFO'; Detail="Max supported refresh (any mode): ${maxHz}Hz."; Raw=$maxHz }
                    } else {
                        $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail='Supported modes present but max refresh could not be derived.'; Raw=$null }
                    }
                }
            } catch {
                $rungs += [pscustomobject]@{ Rung=2; Status='UNKNOWN'; Detail='Supported mode query failed.'; Raw=$null }
            }
    
            $rungs += [pscustomobject]@{ Rung=3; Status='READ-ONLY'; Detail='Preferred driver refresh not universally queryable; verify in GPU control panel if needed.'; Raw=$null }
    
            $activeSample = ($rungs | Where-Object Rung -eq 1 | Select-Object -First 1).Raw
            $activeHz = if ($activeSample -and $activeSample.CurrentRefreshRate) { [int]$activeSample.CurrentRefreshRate } else { $null }
            $maxHzAny = ($rungs | Where-Object Rung -eq 2 | Select-Object -First 1).Raw
    
            if ($activeHz -and $maxHzAny -and ($activeHz -lt $maxHzAny)) {
                $rungs += [pscustomobject]@{
                    Rung=9; Status='DEGRADED'
                    Detail="Active ${activeHz}Hz below max ${maxHzAny}Hz. Likely constrained by resolution, HDR/10-bit, VRR, cable/port, or multi-monitor negotiation."
                    Raw=$null
                }
            } elseif ($activeHz -and $maxHzAny) {
                $rungs += [pscustomobject]@{ Rung=9; Status='OK'; Detail='Active refresh aligned with expected capability.'; Raw=$null }
            }
    
            return $rungs
        }
        FixSafe = { "No safe automatic fix for refresh/VRR in PS 5.1; leaving read-only." }
    }
    
    # ================================
    # AUDIO MODULE
    # ================================
    
    $checks += [pscustomobject]@{
        Name     = 'Audio Endpoint Health'
        Module   = 'Audio'
        Category = 'Endpoints'
        MinBuild = 7600
        Impact   = 15
        Detect   = {
            try { $endpoints = Get-PnpDevice -Class AudioEndpoint -ErrorAction Stop }
            catch { return @{ Status='UNSUPPORTED'; Detail='Get-PnpDevice not available on this OS/PS build.';Raw=$null } }
    
            if (-not $endpoints) { return @{ Status='UNKNOWN'; Detail='No audio endpoints returned by PnP query.'; Raw=$null } }
    
            $bad    = $endpoints | Where-Object { $_.Status -ne 'OK' }
            $playOk = $endpoints | Where-Object { $_.FriendlyName -match 'Speakers|Headphones|Digital Output|HDMI' }
            $recOk  = $endpoints | Where-Object { $_.FriendlyName -match 'Microphone|Mic' }
    
            $detail = "Detected endpoints: $($endpoints.Count). "
            if ($playOk) { $detail += "Playback-capable: $((($playOk | Select-Object -ExpandProperty FriendlyName) -join ', ')). " }
            if ($recOk)  { $detail += "Recording-capable: $((($recOk  | Select-Object -ExpandProperty FriendlyName) -join ', ')). " }
    
            if ($bad) {
                $detail += "Non-OK endpoints: $((($bad | ForEach-Object { "$($_.FriendlyName)[$($_.Status)]" }) -join '; '))."
                return @{ Status='INFO'; Detail=$detail; Raw=$endpoints }
            }
    
            $detail += "All endpoints OK."
            return @{ Status='OK'; Detail=$detail; Raw=$endpoints }
        }
        FixSafe = $null
    }
    
    $checks += [pscustomobject]@{
        Name     = 'Default Audio Device'
        Module   = 'Audio'
        Category = 'DefaultDevice'
        MinBuild = 7600
        Impact   = 15
        Detect   = {
            $mapper = 'HKCU:\Software\Microsoft\Multimedia\Sound Mapper'
            if (-not (Test-Path $mapper)) {
                return @{ Status='OK'; Detail='Modern audio routing active. Verify defaults in Settings -> System -> Sound.'; Raw=$null }
            }
    
            $props     = Get-ItemProperty -Path $mapper -ErrorAction SilentlyContinue
            $playback  = $props.Playback
            $recording = $props.Record
    
            $playName = if ([string]::IsNullOrWhiteSpace($playback))  { 'Unknown' } else { $playback }
            $recName  = if ([string]::IsNullOrWhiteSpace($recording)) { 'Unknown' } else { $recording }
    
            $status='OK'
            $detail="Legacy defaults found. Default playback: $playName; Default recording: $recName."
            if ($playName -eq 'Unknown' -or $recName -eq 'Unknown') {
                $status='WARN'
                $detail += ' One or more legacy defaults missing; verify in Sound settings.'
            }
    
            return @{ Status=$status; Detail=$detail; Raw=$props }
        }
        FixSafe = $null
    }
    
    $checks += [pscustomobject]@{
        Name     = 'Audio Enhancements / Loudness EQ'
        Module   = 'Audio'
        Category = 'Enhancements'
        MinBuild = 7600
        Impact   = 10
        Detect   = {
            $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Audio'
            $val = $null
            if (Test-Path $key) {
                $val = $null
                $k = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($k -and $k.PSObject.Properties.Match('DisableEnhancements').Count -gt 0) {
                    $val = $k.DisableEnhancements
                }
            }
    
            if ($null -eq $val) {
                return @{ Status='OK'; Detail='Enhancements policy not forced; defaults in use.'; Raw=$null }
            }
    
            if ($val -eq 1) {
                return @{ Status='OK'; Detail='DisableEnhancements=1 (forced OFF). Good for latency/stability.'; Raw=$val }
            }
    
            return @{ Status='INFO'; Detail=("DisableEnhancements=$val nonstandard. If crackle/latency, disable enhancements in device properties.") ; Raw=$val }
        }
        FixSafe = $null
    }
    
    $checks += [pscustomobject]@{
        Name     = 'Communications Ducking'
        Module   = 'Audio'
        Category = 'Ducking'
        MinBuild = 7600
        Impact   = 10
        Detect   = {
            $key = 'HKCU:\Software\Microsoft\Multimedia\Audio'
            $val = $null
            if (Test-Path $key) {
                $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if ($props -and $props.PSObject.Properties.Name -contains 'UserDuckingPreference') {
                    $val = $props.UserDuckingPreference
                }
            }
    
            if ($null -eq $val) { return @{ Status='OK'; Detail='UserDuckingPreference not set; default ducking behavior.'; Raw=$null } }
            if ($val -eq 3)     { return @{ Status='OK'; Detail='Communications ducking disabled (UserDuckingPreference=3).'; Raw=$val } }
    
            return @{ Status='WARN'; Detail=("Communications ducking enabled (UserDuckingPreference=$val)."); Raw=$val }
        }
        FixSafe = {
            $key = 'HKCU:\Software\Microsoft\Multimedia\Audio'
            Set-RegistryValueSafe -HivePath $key -Name 'UserDuckingPreference' -Value 3 -Type 'DWord' -BackupTag 'AudioDucking'
            "Set UserDuckingPreference=3 (disable communications ducking)."
        }
    }
    
    $checks += [pscustomobject]@{
        Name     = 'User Audio Services'
        Module   = 'Audio'
        Category = 'Services'
        MinBuild = 7600
        Impact   = 10
        Detect   = {
            $svcNames = @('Audiosrv','AudioEndpointBuilder')
            $svcs = $svcNames | ForEach-Object { Get-Service $_ -ErrorAction SilentlyContinue }
            if ($svcs | Where-Object { $_.Status -ne 'Running' }) {
                return @{ Status='WARN'; Detail=("One or more audio services not running: " + (($svcs | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join ', ')); Raw=$svcs }
            }
            return @{ Status='OK'; Detail='Core audio services running.'; Raw=$svcs }
        }
        FixSafe = $null
    }
    
    $checks += [pscustomobject]@{
        Name     = 'USB Selective Suspend (Audio)'
        Module   = 'Audio'
        Category = 'USBPower'
        MinBuild = 7600
        Impact   = 5
        Detect   = {
            $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\USB'
            $val = $null
            if (Test-Path $key) {
                $val = (Get-ItemProperty -Path $key -ErrorAction SilentlyContinue).DisableSelectiveSuspend
            }
    
            if ($val -eq 1) {
                return @{ Status='OK'; Detail='USB selective suspend disabled (best for USB audio stability).'; Raw=$val }
            }
            return @{ Status='INFO'; Detail='USB selective suspend not explicitly disabled. If DAC/headset dropouts, consider disabling.'; Raw=$val }
        }
        FixSafe = {
            $key = 'HKLM:\SYSTEM\CurrentControlSet\Services\USB'
            Set-RegistryValueSafe -HivePath $key -Name 'DisableSelectiveSuspend' -Value 1 -Type 'DWord' -BackupTag 'USBSelectiveSuspend'
            "Disabled USB selective suspend (DisableSelectiveSuspend=1)."
        }
    }
    
    # =============================================================================
    # Restore mode
    # =============================================================================
    $actionsTaken = @()
    if ($DoRestoreOriginal) {
        Write-Host "Restoring from registry backups..." -ForegroundColor Cyan
        $restoreActions = Restore-OriginalSettings
        foreach ($a in $restoreActions) { Write-Host " - $a" }
        $actionsTaken += $restoreActions
        Write-Host ""
    }
    
    # =============================================================================
    # Run checks
    # =============================================================================
    Write-Host "Running integrated checks..." -ForegroundColor Cyan
    Write-Host ""
    
    $checkResults  = @()
    $currentModule = $null
    
    $checks |
        Where-Object { $buildNumber -ge $_.MinBuild } |
        ForEach-Object {
            $check = $_
    
            if ($currentModule -ne $check.Module) {
                $currentModule = $check.Module
                Write-Host ""
                Write-Host ("=" * 22) -ForegroundColor DarkGray
                Write-Host ("MODULE: {0}" -f $currentModule) -ForegroundColor White
                Write-Host ("=" * 22) -ForegroundColor DarkGray
            }
    
            $preResult = & $check.Detect
            $preRungs = if ($preResult -is [array]) { $preResult } else { @([pscustomobject]@{ Rung=0; Status=$preResult.Status; Detail=$preResult.Detail; Raw=$preResult.Raw }) }
    
            $preFinal  = Resolve-FinalStatus $preRungs
            $preWorst  = $preRungs | Sort-Object @{Expression={ Get-StatusRank $_.Status }} -Descending | Select-Object -First 1
            $preDetail = $preWorst.Detail
    
            $displayName = ("{0} :: {1}" -f $check.Module, $check.Name).Replace("`t"," ").Trim()
            Write-Status -Name $displayName -Status $preFinal -Detail $preDetail
    
            if (@($preRungs).Count -gt 1) {
                $childPrefix = (" " * $global:ATE_MessageStartColumn)
                foreach ($r in ($preRungs | Sort-Object Rung)) {
                    $rs = Normalize-Status $r.Status
                    Write-Host ("{0}- Rung {1}: {2}  -  {3}" -f $childPrefix, $r.Rung, $rs, $r.Detail)
                }
            }
    
            $record = [pscustomobject]@{
                Name        = $check.Name
                Module      = $check.Module
                Category    = $check.Category
                Impact      = $check.Impact
                PreStatus   = $preFinal
                PostStatus  = $preFinal
                Detail      = $preDetail
            }
    
            if ($DoApplySafeTweaks -and $check.FixSafe -ne $null -and ($preFinal -in @('WARN','ISSUE','POLICY','READ-ONLY'))) {
                try {
                    $fixOut = & $check.FixSafe
    
                    if ($fixOut -is [hashtable] -and $fixOut.ContainsKey('Status')) {
                        $actionsTaken += "{0} :: {1}: {2}" -f $check.Module, $check.Name, $fixOut.Detail
                    } else {
                        $actionsTaken += "{0} :: {1}: {2}" -f $check.Module, $check.Name, $fixOut
                    }
    
                    $postResult = & $check.Detect
                    $postRungs = if ($postResult -is [array]) { $postResult } else { @([pscustomobject]@{ Rung=0; Status=$postResult.Status; Detail=$postResult.Detail; Raw=$postResult.Raw }) }
    
                    $postFinal  = Resolve-FinalStatus $postRungs
                    $postWorst  = $postRungs | Sort-Object @{Expression={ Get-StatusRank $_.Status }} -Descending | Select-Object -First 1
                    $postDetail = $postWorst.Detail
    
                    $record.PostStatus = $postFinal
                    $record.Detail     = $postDetail
    
                    if ($postFinal -ne $preFinal) {
                        Write-Status -Name ($displayName + " (after apply)") -Status $postFinal -Detail $postDetail
                    }
    
                    if (@($postRungs).Count -gt 1) {
                        $childPrefix = (" " * $global:ATE_MessageStartColumn)
                        foreach ($r in ($postRungs | Sort-Object Rung)) {
                            $rs = Normalize-Status $r.Status
                            Write-Host ("{0}- Rung {1}: {2}  -  {3}" -f $childPrefix, $r.Rung, $rs, $r.Detail)
                        }
                    }
                } catch {
                    $actionsTaken += "{0} :: {1}: Failed to apply safe fix - {2}" -f $check.Module, $check.Name, $_.Exception.Message
                    $record.PostStatus = 'WARN'
                }
            }
    
            $checkResults += $record
        }
    
    # =============================================================================
    # GPU optional add-ons (post-check)
    # =============================================================================
    if ($DoApplySafeTweaks -and $DoRebuildShaderCache) {
        Write-Host ""
        Write-Host "Rebuilding shader caches (safe cleanup)..." -ForegroundColor Cyan
        try {
            $scActions = Invoke-ShaderCacheRebuild
            foreach ($a in $scActions) { Write-Host " - $a" }
            $actionsTaken += $scActions
        } catch {
            $actionsTaken += "ShaderCache: Failed to rebuild caches - $($_.Exception.Message)"
            Write-Host " - Shader cache rebuild failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    if ($DoManageOverlays) {
        Write-Host ""
        Write-Host "Interactive overlay cleanup (optional per provider)..." -ForegroundColor Cyan
        try { Invoke-OverlayCleanup -ActionsTaken ([ref]$actionsTaken) }
        catch { Write-Host "Overlay cleanup failed: $($_.Exception.Message)" -ForegroundColor Red }
    }
    
    # =============================================================================
    # Scoring by module + total
    # =============================================================================
    
    
    $modules = @('Core','Storage','Network','GPU','Audio')
    
    if ($DoRestoreOriginal) {
        $runMode        = "Restore"
        $runModeSummary = "Restore Originals"
    } elseif ($DoApplySafeTweaks) {
        $runMode        = "SafeTweaks"
        $runModeSummary = "Safe Tweaks"
    } else {
        $runMode        = "ReadOnly"
        $runModeSummary = "Read-Only"
    }
    
    # Build recommendations (unified list)
    $recommendations = @()
    foreach ($r in $checkResults) {
        if ($r.PreStatus -in @('INFO','WARN','ISSUE')) {
            if ($r.Detail) { $recommendations += ("[{0}] {1}" -f $r.Module, $r.Detail) }
        }
    }
    $recommendations = $recommendations | Select-Object -Unique
    
    Write-Host ""
    Write-Host "========= ATE Recommendations =========" -ForegroundColor Cyan
    if (@($recommendations).Count -gt 0) {
        foreach ($rec in $recommendations) { Write-Host (" - {0}" -f $rec) -ForegroundColor DarkGray }
    } else {
        Write-Host " - None (all checks OK)." -ForegroundColor DarkGray
    }
    
    # Module scores
    $moduleScores = @()
    foreach ($m in $modules) {
        $scoreObj = Get-ModuleScores -ModuleName $m
        if ($scoreObj) { $moduleScores += $scoreObj }
    }
    
    # Total scores
    $maxTotal = ($checkResults | Measure-Object -Property Impact -Sum).Sum
    if ($maxTotal -le 0) { $maxTotal = 1 }
    
    $totalPreRaw  = 0
    $totalPostRaw = 0
    foreach ($r in $checkResults) {
        $totalPreRaw  += Get-ScoreForStatus -Status $r.PreStatus  -Impact $r.Impact
        $totalPostRaw += Get-ScoreForStatus -Status $r.PostStatus -Impact $r.Impact
    }
    
    $totalPrePct     = [int]([math]::Round(($totalPreRaw  / $maxTotal) * 100))
    $totalPostPct    = [int]([math]::Round(($totalPostRaw / $maxTotal) * 100))
    $totalDelta      = $totalPostPct - $totalPrePct
    $totalDesc       = Describe-PerfDelta -Delta $totalDelta
    $totalPreGrade   = Get-Grade -Score $totalPrePct
    $totalPostGrade  = Get-Grade -Score $totalPostPct
    
    # Rank ladder
    
    
    # Leaderboard score
    $gamma          = 1.7
    $norm           = $totalPostRaw / $maxTotal
    $normPre        = $totalPreRaw  / $maxTotal
    
    $ATE_Score      = [int][math]::Round(([math]::Pow($norm,    $gamma)) * 10000)
    $ATE_Score_Pre  = [int][math]::Round(([math]::Pow($normPre, $gamma)) * 10000)
    $ATE_DeltaScore = $ATE_Score - $ATE_Score_Pre
    
    $Rank_Pre       = Get-ATERank $ATE_Score_Pre
    $Rank_Post      = Get-ATERank $ATE_Score
    
    # Scorecard
    Write-Host ""
    Write-Host "=== ATE Scorecard ===" -ForegroundColor Cyan
    foreach ($ms in $moduleScores) {
        Write-Host (" - {0,-8}: {1,3}% ({2})" -f $ms.Module, $ms.PostPct, $ms.PostGrade) -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host ("Overall Health: {0,3}% ({1})" -f $totalPostPct, $totalPostGrade) -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "=== ATE Score (GhostShell Labs Index) ===" -ForegroundColor Cyan
    if ($runMode -eq "ReadOnly") {
        Write-Host ("Current  : {0:N0}  Rank: {1}" -f $ATE_Score, $Rank_Post)
    } else {
        Write-Host ("Current  : {0:N0}  Rank: {1}" -f $ATE_Score_Pre, $Rank_Pre)
        Write-Host ("Potential: {0:N0}  Rank: {1}" -f $ATE_Score, $Rank_Post)
        Write-Host ("Delta    : {0:+#;-#;0}" -f $ATE_DeltaScore)
    }
    
    Write-Host ""
    if ($runMode -eq "ReadOnly") {
        Write-Host "This was a read-only scan. Run again with -ApplySafeTweaks or -RestoreOriginal to apply/restore changes." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Optional add-ons:" -ForegroundColor DarkGray
        Write-Host "  -ApplySafeTweaks -RebuildShaderCache   (safe shader cache cleanup)" -ForegroundColor DarkGray
        Write-Host "  -ManageOverlays                       (interactive overlay closing)" -ForegroundColor DarkGray
    }
    
    # =============================================================================
    # Run logging (JSON + TXT)
    # =============================================================================
    $timestamp = Get-Date
    
    $runMeta = [pscustomobject]@{
        EngineName   = $ATE_Name
        Version      = $ATE_Version
        Timestamp    = $timestamp.ToString("o")
        OS           = @{
            Caption = $osCaption
            Version = $osVersion
            Build   = $buildNumber
        }
        Mode         = $runMode
        Checks       = $checkResults
        ModuleScores = $moduleScores
        TotalScore   = @{
            Pre   = $totalPrePct
            Post  = $totalPostPct
            Delta = $totalDelta
        }
        ATE_Score    = @{
            Pre   = $ATE_Score_Pre
            Post  = $ATE_Score
            Delta = $ATE_DeltaScore
            Gamma = $gamma
            Scale = 10000
            Rank  = @{
                Pre  = $Rank_Pre
                Post = $Rank_Post
            }
        }
        Actions      = $actionsTaken
    }
    
    $logBaseName = "ATE_Free-ALL-{0:yyyyMMdd-HHmmss}" -f $timestamp
    $logJsonPath = Join-Path $logDir ($logBaseName + ".json")
    $runMeta | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $logJsonPath -Encoding UTF8
    
    $summaryPath  = Join-Path $logDir ($logBaseName + "-summary.txt")
    $summaryLines = @()
    
    $summaryLines += "$ATE_Name - v$ATE_Version"
    $summaryLines += ("Timestamp : {0}" -f $timestamp.ToString("yyyy-MM-dd HH:mm:ss"))
    $summaryLines += ("Mode      : {0}" -f $runModeSummary)
    $summaryLines += ("OS        : {0} ({1}, Build {2})" -f $osCaption, $osVersion, $buildNumber)
    $summaryLines += ""
    
    $summaryLines += "ATE Scorecard:"
    foreach ($ms in $moduleScores) {
        $gradeOut = if ($ms.PostPct -eq 100) { "" } else { " ({0})" -f $ms.PostGrade }
        $summaryLines += ("  - {0,-8}: {1,3}%{2}" -f $ms.Module, $ms.PostPct, $gradeOut)
    }
    $summaryLines += ""
    $summaryLines += ("Overall Health: {0,3}% ({1})" -f $totalPostPct, $totalPostGrade)
    $summaryLines += ""
    
    $summaryLines += "ATE Score (GhostShell Labs Index):"
    if ($runMode -eq "ReadOnly") {
        $summaryLines += ("  Current  : {0:N0} Rank: {1}" -f $ATE_Score, $Rank_Post)
    } else {
        $summaryLines += ("  Current  : {0:N0} Rank: {1}" -f $ATE_Score_Pre, $Rank_Pre)
        $summaryLines += ("  Potential: {0:N0} Rank: {1}" -f $ATE_Score, $Rank_Post)
        $summaryLines += ("  Delta    : {0:+#;-#;0}" -f $ATE_DeltaScore)
    }
    $summaryLines += ("  Gamma    : {0}" -f $gamma)
    $summaryLines += ""
    
    $summaryLines += "ATE Recommendations:"
    if (@($recommendations).Count -gt 0) {
        foreach ($rec in $recommendations) { $summaryLines += ("  - {0}" -f $rec) }
    } else {
        $summaryLines += "  - None (all checks OK)."
    }
    $summaryLines += ""
    
    $summaryLines += "Check Results:"
    foreach ($r in $checkResults) {
        $summaryLines += ("  - {0} [{1} -> {2}]" -f $r.Name, $r.PreStatus, $r.PostStatus)
    }
    $summaryLines += ""
    
    if (@($actionsTaken).Count -gt 0) {
        $summaryLines += "Actions Taken:"
        foreach ($a in $actionsTaken) { $summaryLines += ("  - {0}" -f $a) }
        $summaryLines += ""
    }
    
    $summaryLines += "Notes:"
    $summaryLines += "  - Performance estimates are approximate; gains depend on game/hardware."
    $summaryLines += "  - JSON log:  $logJsonPath"
    $summaryLines += "  - Summary:   $summaryPath"
    
    $summaryLines | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    
    Write-Host ""
    Write-Host "Run logged to:" -ForegroundColor Cyan
    Write-Host "  JSON   : $logJsonPath"
    Write-Host "  Summary: $summaryPath"
    
    if (-not $InteractiveFrontDoorSession) {
        if (-not $ApplySafeTweaks -and -not $RestoreOriginal -and -not $RebuildShaderCache -and -not $ManageOverlays) {
            Write-Host ""
            Read-Host "Press ENTER to close ATE"
        }
        Read-Host "Press ENTER to close ATE"
    }
}