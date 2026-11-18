param(
    [string] $OutputPath = (Join-Path $env:TEMP 'Roblox-VM-Compatibility-Audit.txt')
)

$ErrorActionPreference = 'Continue'
$report = New-Object System.Collections.Generic.List[string]
function Add-Line([string] $Line = '') { [void] $report.Add($Line) }
function Safe-Info([string] $Title, [scriptblock] $Query) {
    Add-Line ''
    Add-Line ('=== ' + $Title + ' ===')
    try {
        $result = & $Query
        if ($null -eq $result) { Add-Line '(no data returned)'; return }
        $formatted = $result | Format-List * | Out-String -Width 180
        foreach ($line in ($formatted -split "`r?`n")) { Add-Line $line }
    } catch {
        Add-Line ('Query unavailable: ' + $_.Exception.GetType().Name)
    }
}

Add-Line 'ROBLOX / VM COMPATIBILITY AUDIT (non-invasive)'
Add-Line ('Collected: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Add-Line 'Scope: virtual hardware, Windows and display-driver information only.'
Add-Line 'No Roblox executables or DLLs were executed, changed, or loaded.'
Add-Line 'No guest security settings were modified.'

Safe-Info 'Windows version' {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, OSArchitecture, BuildNumber
}

Safe-Info 'Virtual computer' {
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Manufacturer, Model, HypervisorPresent,
            @{Name='MemoryGB';Expression={[math]::Round($_.TotalPhysicalMemory / 1GB, 1)}}
}

Safe-Info 'Virtual CPU' {
    Get-CimInstance Win32_Processor |
        Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors
}

Safe-Info 'Display controllers' {
    Get-CimInstance Win32_VideoController |
        Select-Object Name, DriverVersion, DriverDate, VideoProcessor,
            ConfigManagerErrorCode, CurrentHorizontalResolution, CurrentVerticalResolution
}

Safe-Info 'Display device state' {
    if (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) {
        Get-PnpDevice -Class Display -ErrorAction Stop |
            Select-Object FriendlyName, Status, Problem
    } else {
        'Get-PnpDevice is not available on this Windows edition.'
    }
}

Safe-Info 'Virtual firmware mode' {
    $pe = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction SilentlyContinue
    $mode = switch ($pe.PEFirmwareType) { 1 {'Legacy BIOS'} 2 {'UEFI'} default {'Not available'} }
    [pscustomobject]@{FirmwareMode=$mode}
}

Safe-Info 'Recent Roblox log metadata (names only)' {
    $path = Join-Path $env:LOCALAPPDATA 'Roblox\logs'
    if (Test-Path -LiteralPath $path -PathType Container) {
        Get-ChildItem -LiteralPath $path -File -ErrorAction Stop |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 8 Name, Length, LastWriteTime
    } else {
        'No Roblox logs directory found for the current Windows user.'
    }
}

Add-Line ''
Add-Line 'INTERPRETATION'
Add-Line '- VMware SVGA 3D means Windows is using a VMware virtual graphics adapter, not full GPU passthrough.'
Add-Line '- A working display adapter does not prove a particular game allows VM execution.'
Add-Line '- A hypervisor flag alone does not identify the exact reason for a launch failure.'
Add-Line '- This report does not test anti-cheat or bypass client checks.'
Add-Line '- The report may contain your computer model and log filenames. Review before sharing.'

try {
    $parent = Split-Path -Path $OutputPath -Parent
    if ($parent -and !(Test-Path -LiteralPath $parent)) {
        throw 'Output folder does not exist.'
    }
    $report | Set-Content -LiteralPath $OutputPath -Encoding UTF8 -ErrorAction Stop
    Write-Host ('Report saved to: ' + $OutputPath)
    Write-Host 'No changes were made to Roblox or VMware configuration.'
} catch {
    Write-Warning ('Unable to write report: ' + $_.Exception.Message)
    $report | ForEach-Object { Write-Output $_ }
}
