# ATE_GPU.ps1
# Auto-generated domain module from Holy Shit Atlas v1.1 refactor
# Domain: GPU

Set-StrictMode -Version Latest

function Get-ATEGPUChecks {
    [CmdletBinding()]
    param()

    $checks = @()

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
        
                $val = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
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

    return $checks
}
