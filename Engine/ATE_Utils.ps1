# ATE_Utils.ps1
# Atlas Tuning Engine - Utility Functions
# Version: 1.0.0

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Global engine state (migrated from ATE v1.0)
# These are used across Core/checks for status ranking and column alignment.
# ---------------------------------------------------------------------------
if (-not (Get-Variable -Name ATE_Statuses -Scope Global -ErrorAction SilentlyContinue)) {
    $global:ATE_Statuses = @(
        'OK',
        'WARN',
        'INFO',
        'ISSUE',
        'UNKNOWN',
        'POLICY',
        'DEGRADED',
        'PENDING',
        'LIMITED',
        'UNSUPPORTED',
        'READ-ONLY',
        'ALIAS-MISS'
    )
}

if (-not (Get-Variable -Name ATE_MessageStartColumn -Scope Global -ErrorAction SilentlyContinue)) {
    $global:ATE_MessageStartColumn = 20
}



# ---------------------------------------------------------------------------
# Wrap-ATEText
# - Wraps text to the host window width with a given indent, for nice status.
# ---------------------------------------------------------------------------
function Wrap-ATEText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Text,
        [int]$Indent = 20
    )

    $width = 120
    try {
        $width = $Host.UI.RawUI.WindowSize.Width
        if ($width -lt 60) { $width = 80 }
    } catch {
        # If host UI isn't available, fall back to default.
    }

    $usable = [Math]::Max(20, $width - $Indent - 1)

    $words = ($Text -replace '\s+', ' ').Trim().Split(' ')
    if ($words.Count -eq 0) {
        return @('')
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $current = ''

    foreach ($word in $words) {
        if ($current.Length + 1 + $word.Length -gt $usable) {
            if ($current.Length -gt 0) {
                $lines.Add($current)
            }
            $current = $word
        } else {
            if ($current.Length -eq 0) {
                $current = $word
            } else {
                $current += " $word"
            }
        }
    }

    if ($current.Length -gt 0) {
        $lines.Add($current)
    }

    return $lines.ToArray()
}

# ---------------------------------------------------------------------------
# Write-Status
# - Pretty, color-coded status line for ATE operations.
# ---------------------------------------------------------------------------
function Write-Status {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Status,
        [string]$Detail
    )

    $color = switch ($Status) {
        'OK'          { 'Green' }
        'WARN'        { 'Yellow' }
        'INFO'        { 'Cyan' }
        'ISSUE'       { 'Red' }
        'READ-ONLY'   { 'DarkGray' }
        'UNKNOWN'     { 'DarkGray' }
        'UNSUPPORTED' { 'DarkGray' }
        'PENDING'     { 'Magenta' }
        'DEGRADED'    { 'DarkYellow' }
        'LIMITED'     { 'DarkCyan' }
        'POLICY'      { 'DarkRed' }
        'ALIAS-MISS'  { 'DarkYellow' }
        default       { 'White' }
    }

    $statusBlock = "[{0}]" -f $Status
    $padStatus   = $statusBlock.PadRight(18)
    $prefix      = "$padStatus $Name  -  "

    if ([string]::IsNullOrWhiteSpace($Detail)) {
        Write-Host $prefix -ForegroundColor $color
        return
    }

    $indent = ($padStatus.Length + 1)
    $lines  = Wrap-ATEText -Text $Detail -Indent $indent

    if ($null -eq $lines) {
        Write-Host $prefix -ForegroundColor $color
        return
    }

    $lines = @($lines)

    Write-Host ($prefix + $lines[0]) -ForegroundColor $color
    for ($i = 1; $i -lt $lines.Count; $i++) {
        Write-Host ((" " * $indent) + $lines[$i]) -ForegroundColor $color
    }
}

# ---------------------------------------------------------------------------
# Test-IsAdmin
# - Checks current process token for local Administrator membership.
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    [CmdletBinding()]
    param()

    try {
        $principal = New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        )
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# Relaunch-ElevatedIfNeeded
# - If not admin, offers to relaunch ATE with elevation.
# - Returns $true if caller should continue, $false to exit.
# ---------------------------------------------------------------------------
function Relaunch-ElevatedIfNeeded {
    [CmdletBinding()]
    param(
        [string[]]$ArgsToPass
    )

    if (Test-IsAdmin) { return $true }

    Write-Host ""
    Write-Host "This mode requires Administrator rights." -ForegroundColor Yellow
    $resp = Read-Host "Relaunch ATE as Administrator now? (Y/N)"
    if ($resp -notmatch '^[Yy]') {
        Write-Host "Cancelled. Re-run ATE as Administrator to apply/restore changes." -ForegroundColor Yellow
        return $false
    }

    $scriptPath = $MyInvocation.MyCommand.Path
    $childArgs  = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$scriptPath`""
    ) + $ArgsToPass

    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $childArgs -Verb RunAs
        return $false
    } catch {
        Write-Host "Elevation failed or was cancelled." -ForegroundColor Yellow
        return $false
    }
}