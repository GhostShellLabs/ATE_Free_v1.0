# ATE_Splash.ps1
# Atlas Tuning Engine - WPF Splash
# Centered on primary monitor, DPI-aware, non-fatal cosmetic module only.

Set-StrictMode -Version Latest

function Show-ATESplash {
    [CmdletBinding()]
    param(
        [int]$TimeoutMs = 3500
    )

    # Cosmetic only; never fail the engine.
    try {
        Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

        # Best-effort DPI awareness for accurate centering.
        try {
            Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class DpiHelper
{
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
}
"@
            [DpiHelper]::SetProcessDPIAware() | Out-Null
        }
        catch {
            # If DPI awareness cannot be set, continue without failing splash
        }

        # XAML window definition
        $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        WindowStyle="None"
        ResizeMode="NoResize"
        AllowsTransparency="True"
        Background="Transparent"
        ShowInTaskbar="False"
        Topmost="True"
        WindowStartupLocation="Manual">
    <Grid SnapsToDevicePixels="True">
        <Border Background="Black">
            <Image x:Name="SplashImage"
                   Stretch="None"
                   HorizontalAlignment="Center"
                   VerticalAlignment="Center"
                   SnapsToDevicePixels="True"/>
        </Border>
    </Grid>
</Window>
"@

        $xml    = [xml]$xaml
        $reader = New-Object System.Xml.XmlNodeReader $xml
        $window = [Windows.Markup.XamlReader]::Load($reader)

        $imgCtrl = $window.FindName('SplashImage')

        # Resolve splash image path from Resources\Assets\Splash
        $imagePath = $null
        try {
            $candidate1 = Join-Path -Path $PSScriptRoot -ChildPath '..\Resources\Assets\Splash\ATE_Splash.png'
            if (Test-Path -LiteralPath $candidate1) {
                $imagePath = (Resolve-Path -LiteralPath $candidate1).Path
            }
        }
        catch {
            $imagePath = $null
        }

        if (-not $imagePath) {
            Write-Verbose "ATE_Splash: Splash image not found. Skipping splash."
            return
        }

        $bitmap = New-Object System.Windows.Media.Imaging.BitmapImage
        $bitmap.BeginInit()
        $bitmap.UriSource   = New-Object System.Uri($imagePath, [System.UriKind]::Absolute)
        $bitmap.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $bitmap.EndInit()

        $imgCtrl.Source = $bitmap
        $window.SizeToContent = "WidthAndHeight"

        # Center on primary monitor once layout is ready
        $window.Add_Loaded({
            param($sender, $e)
            try {
                $workArea = [System.Windows.SystemParameters]::WorkArea
                $sender.Left = $workArea.X + ($workArea.Width  - $sender.ActualWidth)  / 2
                $sender.Top  = $workArea.Y + ($workArea.Height - $sender.ActualHeight) / 2
            }
            catch {
                # Fallback: let WPF decide if WorkArea is unavailable
            }
        })

        # Show the splash window with a DispatcherTimer for lifetime.
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds($TimeoutMs)
        $timer.Add_Tick({
            $timer.Stop()
            $window.Close()
        })
        $timer.Start()

        $window.ShowDialog() | Out-Null
    }
    catch {
        Write-Warning ("ATE_Splash: An error occurred while showing WPF splash: {0}" -f $_.Exception.Message)
    }
}
