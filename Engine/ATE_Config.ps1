# ATE_Config.ps1
# Atlas Tuning Engine - Configuration Subsystem
# Version: 1.0.0

Set-StrictMode -Version Latest

$script:ATE_Config      = $null

# PSScriptRoot points at the Engine folder; configuration now lives under Resources\Config at the product root.
$engineRoot    = $PSScriptRoot
$productRoot   = Split-Path -Parent $engineRoot
$resourcesRoot = Join-Path -Path $productRoot -ChildPath 'Resources'
$script:ATE_ConfigPath = Join-Path -Path $resourcesRoot -ChildPath "Config\ATE_Config.json"

if (-not (Test-Path (Split-Path $script:ATE_ConfigPath))) {
    New-Item -Path (Split-Path $script:ATE_ConfigPath) -ItemType Directory -Force | Out-Null
}

function Get-ATEDefaultConfig {
    [CmdletBinding()]
    param()

    # Minimal defaults for now. Expand later as needed.
    [pscustomobject]@{
        ConfigVersion  = '1.0.0'
        EnableSplash   = $true
        RunSafeMode    = $true
        Created        = (Get-Date)
        LastModified   = (Get-Date)
    }
}

function Get-ATEConfig {
    [CmdletBinding()]
    param()

    if ($null -ne $script:ATE_Config) {
        return $script:ATE_Config
    }

    if (Test-Path $script:ATE_ConfigPath) {
        try {
            $json = Get-Content -LiteralPath $script:ATE_ConfigPath -Raw
            $script:ATE_Config = $json | ConvertFrom-Json
        } catch {
            # If config is corrupt, rebuild from defaults.
            $script:ATE_Config = Get-ATEDefaultConfig
        }
    } else {
        $script:ATE_Config = Get-ATEDefaultConfig
    }

    return $script:ATE_Config
}

function Save-ATEConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Config
    )

    $Config.LastModified = Get-Date
    $json = $Config | ConvertTo-Json -Depth 5
    $json | Set-Content -LiteralPath $script:ATE_ConfigPath -Encoding UTF8
    $script:ATE_Config = $Config
}
