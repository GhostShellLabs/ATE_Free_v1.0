# ATE_Storage.ps1
# Auto-generated domain module from Holy Shit Atlas v1.1 refactor
# Domain: Storage

Set-StrictMode -Version Latest

function Get-ATEStorageChecks {
    [CmdletBinding()]
    param()

    $checks = @()

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

    return $checks
}
