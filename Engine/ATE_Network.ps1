# ATE_Network.ps1
# Auto-generated domain module from Holy Shit Atlas v1.1 refactor
# Domain: Network

Set-StrictMode -Version Latest

function Get-ATENetworkChecks {
    [CmdletBinding()]
    param()

    $checks = @()

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

    return $checks
}
