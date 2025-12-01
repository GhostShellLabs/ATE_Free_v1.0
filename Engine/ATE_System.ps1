# ATE_System.ps1
# Auto-generated domain module from Holy Shit Atlas v1.1 refactor
# Domain: System

Set-StrictMode -Version Latest

function Get-ATESystemChecks {
    [CmdletBinding()]
    param()

    $checks = @()

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
        
                $current = $null
                try {
                    $item = Get-ItemProperty -Path $path -Name $name -ErrorAction Stop
                    $current = $item.$name
                } catch {
                    $current = $null
                }
        
                if ($null -eq $current -or [int]$current -ne 1) {
                    Set-RegistryValueSafe -HivePath $path -Name $name -Value 1 -Type 'DWord' -BackupTag 'GameMode'
                    return "Set $name=1 (enable Game Mode)."
                } else {
                    return 'Game Mode already enabled.'
                }
            }
        }

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
                    $gbVal = (Get-ItemProperty -Path $gbPath -Name $gbName -ErrorAction SilentlyContinue).$gbName
                }
        
                $dvrPath = 'HKCU:\System\GameConfigStore'
                $dvrName = 'GameDVR_Enabled'
                $dvrVal  = $null
                if (Test-Path $dvrPath) {
                    $dvrVal = (Get-ItemProperty -Path $dvrPath -Name $dvrName -ErrorAction SilentlyContinue).$dvrName
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

    return $checks
}
