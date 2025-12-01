# ATE_Logging.ps1
# Atlas Tuning Engine - Logging Subsystem
# Version: 1.0.0

Set-StrictMode -Version Latest

# Default root + resources directories.
# PSScriptRoot points at the Engine folder; resources live at the product root under 'Resources'.
$script:ATE_EngineRoot    = $PSScriptRoot
$script:ATE_ProductRoot   = Split-Path -Parent $script:ATE_EngineRoot
$script:ATE_ResourcesRoot = Join-Path -Path $script:ATE_ProductRoot -ChildPath 'Resources'
$script:ATE_LogRoot       = Join-Path -Path $script:ATE_ResourcesRoot -ChildPath 'Logs'

if (-not (Test-Path $script:ATE_LogRoot)) {
    New-Item -Path $script:ATE_LogRoot -ItemType Directory -Force | Out-Null
}

function Get-ATELogFilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $Name.EndsWith(".log")) {
        $Name = "$Name.log"
    }

    $path = Join-Path -Path $script:ATE_LogRoot -ChildPath $Name
    if (-not (Test-Path $path)) {
        New-Item -Path $path -ItemType File -Force | Out-Null
    }

    return $path
}

function Write-ATELogJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FileName,

        [Parameter(Mandatory)]
        [object]$Data
    )

    $path = Get-ATELogFilePath -Name $FileName
    $json = $Data | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $path -Value $json -Encoding UTF8
}

function Write-ATELogLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO','WARN','ERROR','FATAL')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$Module = 'ATE-Core',

        [string]$LogFileName = "ATE_Run.log"
    )

    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $path = Get-ATELogFilePath -Name $LogFileName

    # Write a one-time header when the log file is first created or empty.
    if (-not (Test-Path -LiteralPath $path) -or (Get-Item -LiteralPath $path).Length -eq 0) {
        $header = "Atlas Tuning Engine (ATE_Free) v1.0.0 - Secure Release. " +
                  "Local-only execution: no network or telemetry calls. All actions are logged."
        Add-Content -LiteralPath $path -Value $header
    }

    $line = "{0} [{1}] [{2}] {3}" -f $ts, $Level, $Module, $Message
    Add-Content -LiteralPath $path -Value $line
}