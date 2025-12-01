# ATE_Bootstrap.ps1
# Atlas Tuning Engine - Bootstrap Entry Point
# Version: 1.0.0-Secure Releasen)

[CmdletBinding()]
param(
    [switch]$ApplySafeTweaks,
    [switch]$RestoreOriginal,
    [switch]$RebuildShaderCache,
    [switch]$ManageOverlays
)

Set-StrictMode -Version Latest

# Resolve paths
$script:EngineRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:ModuleRoot = Join-Path -Path $script:EngineRoot -ChildPath "Modules"

# If a dedicated Modules folder does not exist, default to EngineRoot
if (-not (Test-Path -LiteralPath $script:ModuleRoot)) {
    $script:ModuleRoot = $script:EngineRoot
}


# Load core infrastructure modules (Phase 1)
. (Join-Path $script:ModuleRoot 'ATE_Utils.ps1')
. (Join-Path $script:ModuleRoot 'ATE_Logging.ps1')
. (Join-Path $script:ModuleRoot 'ATE_Config.ps1')

# Best-effort load of Splash module (non-fatal if missing)
$splashModulePath = Join-Path -Path $script:ModuleRoot -ChildPath 'ATE_Splash.ps1'
if (Test-Path -LiteralPath $splashModulePath) {
    . $splashModulePath
} else {
    Write-Verbose "ATE_Bootstrap: ATE_Splash.ps1 not found. Skipping splash module."
}

# Load Core engine
. (Join-Path $script:EngineRoot 'ATE_Core.ps1')

# Show splash (if available) - cosmetic only, must never be fatal
if (Get-Command -Name Show-ATESplash -ErrorAction SilentlyContinue) {
    try {
        # In release, we don't spam console; this is verbose/log-level only
        Write-Verbose "ATE_Bootstrap: Displaying Master Splash Screen..."
        Show-ATESplash -TimeoutMs 3500
    }
    catch {
        Write-Warning ("[WARN] Splash failed: {0}. Continuing without splash." -f $_.Exception.Message)
    }
}
else {
    Write-Verbose "ATE_Bootstrap: Show-ATESplash not available. Skipping splash."
}

# -------------------------
# Internal run flags and mode selection
# (mirrors original 1.0 semantics for CLI switches; adds Front Door menu loop)
# -------------------------

# Detect whether we were invoked with explicit CLI switches.
$HasCliSwitches = $ApplySafeTweaks.IsPresent -or
                  $RestoreOriginal.IsPresent -or
                  $RebuildShaderCache.IsPresent -or
                  $ManageOverlays.IsPresent

if ($HasCliSwitches) {
    # One-shot CLI mode: preserve original behavior for scripted use.
    $DoApplySafeTweaks    = $ApplySafeTweaks.IsPresent
    $DoRestoreOriginal    = $RestoreOriginal.IsPresent
    $DoRebuildShaderCache = $RebuildShaderCache.IsPresent
    $DoManageOverlays     = $ManageOverlays.IsPresent

    # Retrieve config (not heavily used yet, but ready)
    $config = Get-ATEConfig

    # Call into Core (this function will host your main 1.0 run logic)
    Start-ATECore -Config $config `
                  -ApplySafeTweaks:$DoApplySafeTweaks `
                  -RestoreOriginal:$DoRestoreOriginal `
                  -RebuildShaderCache:$DoRebuildShaderCache `
                  -ManageOverlays:$DoManageOverlays
}
else {
    # Interactive Front Door loop: allow multiple modes in a single session.
    while ($true) {
        $sel = Show-ATEFrontDoor
        if ($null -eq $sel) {
            Write-Host "ATE exiting." -ForegroundColor DarkGray
            break
        }

        $DoApplySafeTweaks    = $sel.Apply
        $DoRestoreOriginal    = $sel.Restore
        $DoRebuildShaderCache = $sel.Shader
        $DoManageOverlays     = $sel.Overlays

        # Retrieve config for this run
        $config = Get-ATEConfig

        # Run Core in interactive-session mode so it returns cleanly
        # to this loop without prompting to close the console.
        Start-ATECore -Config $config `
                      -ApplySafeTweaks:$DoApplySafeTweaks `
                      -RestoreOriginal:$DoRestoreOriginal `
                      -RebuildShaderCache:$DoRebuildShaderCache `
                      -ManageOverlays:$DoManageOverlays `
                      -InteractiveFrontDoorSession

        Write-Host ""
        $loopChoice = Read-Host "Press ENTER to return to the main menu or type Q to exit"
        if ($loopChoice -match '^(?i:q|x)$') {
            Write-Host "ATE exiting." -ForegroundColor DarkGray
            break
        }
    }
}
