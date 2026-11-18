# Untested
# Created by OpenAI
<# 1.0.0 #>

[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9-]{3,15}$')]
    [string] $ProfileId
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not $ProfileId) {
    $ProfileId = 'LAB-' + ([guid]::NewGuid().ToString('N').Substring(0, 8).ToUpperInvariant())
}
$stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
if ([string]::IsNullOrWhiteSpace($desktop) -or -not (Test-Path -LiteralPath $desktop -PathType Container)) {
    throw 'Windows could not resolve the current user Desktop folder. Run as your ordinary Windows VM account.'
}
$reportPath = Join-Path $desktop ("VM_Hardware_Audit_{0}.txt" -f $stamp)

$script:lines = New-Object 'System.Collections.Generic.List[string]'
$script:observations = New-Object 'System.Collections.Generic.List[object]'
$script:markers = New-Object 'System.Collections.Generic.List[object]'
$script:errors = New-Object 'System.Collections.Generic.List[string]'
$script:markRegex = '(?i)vmware|vmxnet|vmci|vmhgfs|svga|virtualbox|vbox|hyper-v|vmbus|qemu|virtio|kvm|bochs|xen|parallels|VEN_15AD|VEN_80EE|VEN_1AF4'
$script:syntheticUuid = [guid]::NewGuid().ToString()
$script:shortId = ($ProfileId.ToUpperInvariant() -replace '[^A-Z0-9]', '')
if ($script:shortId.Length -gt 10) { $script:shortId = $script:shortId.Substring(0, 10) }

function Line {
    param([AllowEmptyString()][string]$Text = '')
    [void]$script:lines.Add($Text)
}
function Heading {
    param([string]$Title)
    Line
    Line ('=' * 79)
    Line $Title
    Line ('=' * 79)
}
function Clean {
    param($Value)
    if ($null -eq $Value) { return '(not reported)' }
    $valueString = (@($Value) | ForEach-Object { [string]$_ }) -join ', '
    $valueString = $valueString -replace '[\r\n\t]+', ' '
    if ([string]::IsNullOrWhiteSpace($valueString)) { return '(not reported)' }
    return $valueString.Trim()
}
function Record {
    param(
        [string] $Layer,
        [string] $Field,
        $Value,
        [string] $Proposal = '',
        [string] $Limitation = ''
    )
    $observed = Clean $Value
    Line ('{0,-29}: {1}' -f $Field, $observed)
    [void]$script:observations.Add([pscustomobject]@{
        Layer=$Layer; Field=$Field; Observed=$observed
    })
    if ($observed -match $script:markRegex) {
        [void]$script:markers.Add([pscustomobject]@{
            Layer=$Layer; Field=$Field; Observed=$observed;
            Proposal=$Proposal; Limitation=$Limitation
        })
    }
}
function Cim {
    param([string]$Class)
    try {
        return @(Get-CimInstance -ClassName $Class -ErrorAction Stop)
    }
    catch {
        $msg = ('{0}: {1}' -f $Class, $_.Exception.Message)
        [void]$script:errors.Add($msg)
        Line ('[QUERY FAILED] ' + $msg)
        return @()
    }
}
function Get-Info {
    param([string]$Path)
    try { return Get-ItemProperty -LiteralPath $Path -ErrorAction Stop }
    catch {
        [void]$script:errors.Add(('Registry {0}: {1}' -f $Path, $_.Exception.Message))
        return $null
    }
}

$lab = [ordered]@{
    ComputerName = $ProfileId.ToUpperInvariant()
    Manufacturer = 'LAB SYSTEMS'
    SystemModel = 'LAB-PC-' + $script:shortId
    BoardModel = 'LAB-BOARD-' + $script:shortId
    BoardSerial = 'LB-' + $script:shortId
    BiosLabel = 'LAB-FW-' + $script:shortId
    BiosSerial = 'LF-' + $script:shortId
    SystemUUID = $script:syntheticUuid
    CpuLabel = 'LAB-CPU-' + $script:shortId
    GpuLabel = 'LAB-GPU-' + $script:shortId
    DiskSerial = 'LD-' + $script:shortId
    NetworkLabel = 'LAB-NIC-' + $script:shortId
}

Line 'WINDOWS VIRTUAL HARDWARE AUDIT -- READ ONLY'
Line ('Generated          : ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
Line ('Computer           : ' + $env:COMPUTERNAME)
Line ('Account            : ' + $env:USERNAME)
Line ('Profile            : ' + $ProfileId)
Line ('Report             : ' + $reportPath)
Line 'Scope              : Windows-reported identifiers, not firmware extraction'
Line 'Actions            : READ ONLY. No device identifiers changed.'
Line 'Privacy            : Contains actual MACs, system UUID and possibly serials.'
Line 'Interpretation     : A marker indicates a possible VM fingerprint, not proof'
Line '                     that Roblox or any other game uses or blocks on it.'

Heading '1. OPERATING SYSTEM AND COMPUTER IDENTITY'
foreach ($os in @(Cim 'Win32_OperatingSystem')) {
    Record 'OS' 'Caption' $os.Caption
    Record 'OS' 'Version' $os.Version
    Record 'OS' 'BuildNumber' $os.BuildNumber
    Record 'OS' 'OSArchitecture' $os.OSArchitecture
}
foreach ($cs in @(Cim 'Win32_ComputerSystem')) {
    Record 'System' 'ComputerName' $cs.Name $lab.ComputerName 'Windows hostname label only'
    Record 'System' 'Manufacturer' $cs.Manufacturer $lab.Manufacturer 'SMBIOS/VM platform controlled'
    Record 'System' 'Model' $cs.Model $lab.SystemModel 'SMBIOS/VM platform controlled'
    Record 'System' 'HypervisorPresent' $cs.HypervisorPresent '' 'Not a string identity'
    if ($cs.HypervisorPresent -eq $true) {
        [void]$script:markers.Add([pscustomobject]@{
            Layer='System'; Field='HypervisorPresent'; Observed='True';
            Proposal='(no text replacement)';
            Limitation='Hypervisor presence may also be reported by physical Windows systems using Hyper-V/VBS'
        })
    }
    Record 'System' 'LogicalProcessors' $cs.NumberOfLogicalProcessors
    Record 'System' 'TotalMemoryBytes' $cs.TotalPhysicalMemory
}
foreach ($csp in @(Cim 'Win32_ComputerSystemProduct')) {
    Record 'SMBIOS System' 'Vendor' $csp.Vendor $lab.Manufacturer 'SMBIOS/VM platform controlled'
    Record 'SMBIOS System' 'Name' $csp.Name $lab.SystemModel 'SMBIOS/VM platform controlled'
    Record 'SMBIOS System' 'Version' $csp.Version
    Record 'SMBIOS System' 'IdentifyingNumber' $csp.IdentifyingNumber ('LS-' + $script:shortId) 'SMBIOS serial; not settable by ordinary PowerShell'
    Record 'SMBIOS System' 'UUID' $csp.UUID $lab.SystemUUID 'Firmware UUID; proposal only'
}

Heading '2. MOTHERBOARD, BIOS AND FIRMWARE'
foreach ($board in @(Cim 'Win32_BaseBoard')) {
    Record 'Baseboard' 'Manufacturer' $board.Manufacturer $lab.Manufacturer 'SMBIOS platform field'
    Record 'Baseboard' 'Product' $board.Product $lab.BoardModel 'SMBIOS platform field'
    Record 'Baseboard' 'Version' $board.Version
    Record 'Baseboard' 'SerialNumber' $board.SerialNumber $lab.BoardSerial 'SMBIOS board serial; proposal only'
}
foreach ($bios in @(Cim 'Win32_BIOS')) {
    Record 'BIOS' 'Manufacturer' $bios.Manufacturer $lab.Manufacturer 'Firmware identity; proposal only'
    Record 'BIOS' 'Name' $bios.Name $lab.BiosLabel 'Firmware identity; proposal only'
    Record 'BIOS' 'SMBIOSBIOSVersion' $bios.SMBIOSBIOSVersion $lab.BiosLabel 'Firmware version; proposal only'
    Record 'BIOS' 'Version' $bios.Version
    Record 'BIOS' 'SerialNumber' $bios.SerialNumber $lab.BiosSerial 'BIOS serial; proposal only'
}
foreach ($enclosure in @(Cim 'Win32_SystemEnclosure')) {
    Record 'Chassis' 'Manufacturer' $enclosure.Manufacturer $lab.Manufacturer 'SMBIOS platform field'
    Record 'Chassis' 'SerialNumber' $enclosure.SerialNumber ('LC-' + $script:shortId) 'SMBIOS chassis serial; proposal only'
}
$firmwareRegistry = Get-Info 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS'
if ($null -ne $firmwareRegistry) {
    Line '-- Additional Windows firmware registry view --'
    foreach ($property in @('SystemManufacturer','SystemProductName','SystemVersion','BaseBoardManufacturer','BaseBoardProduct','BaseBoardVersion','BIOSVendor','BIOSVersion')) {
        $value = $firmwareRegistry.PSObject.Properties[$property]
        if ($null -ne $value) { Record 'FirmwareRegistry' $property $value.Value $lab.SystemModel 'Firmware-derived registry view; proposal only' }
    }
}

Heading '3. CPU INFORMATION'
foreach ($cpu in @(Cim 'Win32_Processor')) {
    Record 'CPU' 'Name' $cpu.Name $lab.CpuLabel 'CPUID/CPU behavior cannot be altered by renaming'
    Record 'CPU' 'Manufacturer' $cpu.Manufacturer
    Record 'CPU' 'ProcessorId' $cpu.ProcessorId
    Record 'CPU' 'Cores' $cpu.NumberOfCores
    Record 'CPU' 'LogicalProcessors' $cpu.NumberOfLogicalProcessors
    Record 'CPU' 'Architecture' $cpu.Architecture
    Record 'CPU' 'VirtualizationFirmwareEnabled' $cpu.VirtualizationFirmwareEnabled
    Record 'CPU' 'VMMonitorModeExtensions' $cpu.VMMonitorModeExtensions
}
Line 'NOTE: ProcessorId is not a universally available or unique CPU serial number.'
Line 'NOTE: HypervisorPresent=True is not proof that Microsoft Hyper-V is installed.'

Heading '4. GRAPHICS ADAPTERS'
foreach ($gpu in @(Cim 'Win32_VideoController')) {
    Record 'GPU' 'Name' $gpu.Name $lab.GpuLabel 'Display alias only; not a GPU implementation'
    Record 'GPU' 'VideoProcessor' $gpu.VideoProcessor $lab.GpuLabel 'Driver/virtual GPU implementation'
    Record 'GPU' 'PNPDeviceID' $gpu.PNPDeviceID 'Synthetic PCI ID not generated' 'PCI IDs require a matching virtual device and driver'
    Record 'GPU' 'DriverVersion' $gpu.DriverVersion
    Record 'GPU' 'VideoModeDescription' $gpu.VideoModeDescription
    Record 'GPU' 'Status' $gpu.Status
    Line '-- Next GPU --'
}

Heading '5. VIRTUAL STORAGE AND SERIALS'
foreach ($disk in @(Cim 'Win32_DiskDrive')) {
    Record 'Disk' 'Model' $disk.Model ('LAB-DISK-' + $script:shortId) 'Driver/device identity; proposal only'
    Record 'Disk' 'Manufacturer' $disk.Manufacturer
    Record 'Disk' 'SerialNumber' $disk.SerialNumber $lab.DiskSerial 'Virtual disk identity; proposal only'
    Record 'Disk' 'InterfaceType' $disk.InterfaceType
    Record 'Disk' 'PNPDeviceID' $disk.PNPDeviceID 'Synthetic storage ID not generated' 'Not a cosmetic name'
    Record 'Disk' 'SizeBytes' $disk.Size
    Line '-- Next disk --'
}

Heading '6. NETWORK ADAPTERS AND MAC ADDRESSES'
$network = @(Cim 'Win32_NetworkAdapter')
foreach ($nic in $network) {
    # Some virtual NICs do not report PhysicalAdapter=True. Keep those with a MAC or matching virtual-device name.
    if (-not $nic.PhysicalAdapter -and -not $nic.MACAddress -and ($nic.Name -notmatch $script:markRegex)) { continue }
    Record 'NIC' 'Name' $nic.Name $lab.NetworkLabel 'Name change does not change virtual NIC type'
    Record 'NIC' 'Manufacturer' $nic.Manufacturer
    Record 'NIC' 'MACAddress' $nic.MACAddress '02-xx-xx-xx-xx-xx (LAA template)' 'No actual MAC is generated or applied'
    Record 'NIC' 'PNPDeviceID' $nic.PNPDeviceID 'Synthetic NIC PCI ID not generated' 'NIC PCI identity requires virtual device support'
    Record 'NIC' 'NetConnectionID' $nic.NetConnectionID $lab.NetworkLabel 'Windows connection label only'
    Line '-- Next NIC --'
}

Heading '7. PLUG AND PLAY VIRTUALIZATION MARKERS'
Line 'Filtering Plug and Play names, manufacturers, IDs and services for common VM markers.'
$pnpCount = 0
$pnpTotal = 0
foreach ($dev in @(Cim 'Win32_PnPEntity')) {
    $textToMatch = @($dev.Name, $dev.Manufacturer, $dev.PNPDeviceID, $dev.Service) -join ' | '
    if ($textToMatch -notmatch $script:markRegex) { continue }
    $pnpTotal++
    if ($pnpCount -ge 100) { continue }
    $pnpCount++
    Line ('[{0:D3}] {1}' -f $pnpCount, (Clean $dev.Name))
    Record 'PnP' 'Manufacturer' $dev.Manufacturer 'Lab device alias (not functional)' 'Driver or device implementation remains unchanged'
    Record 'PnP' 'PNPDeviceID' $dev.PNPDeviceID 'Synthetic PCI ID not generated' 'Requires actual virtual hardware support'
    Record 'PnP' 'Service' $dev.Service
    Record 'PnP' 'Status' $dev.Status
    Line
}
Line ('Total matching PnP devices: {0}. Listed: {1}.' -f $pnpTotal, $pnpCount)

Heading '8. PROPOSED SYNTHETIC LAB LABELS (NOT APPLIED)'
Line 'These are internally consistent naming placeholders, NOT real OEM hardware identities.'
foreach ($entry in $lab.GetEnumerator()) {
    Line ('{0,-19} -> {1}' -f $entry.Key, $entry.Value)
}
Line 'The entries below are WINDOWS-REPORTED virtualization markers and possible'
Line 'lab labels. No serial, CPUID, PCI vendor/device ID or driver is changed.'
if ($script:markers.Count -eq 0) {
    Line 'No exact keyword matches in the inspected Windows views.'
    Line 'This does not prove the environment is physical or undetectable.'
} else {
    $n = 0
    foreach ($marker in $script:markers) {
        $n++
        Line
        Line ('[{0:D3}] {1} / {2}' -f $n, $marker.Layer, $marker.Field)
        Line ('  Detected  : ' + $marker.Observed)
        if ($marker.Proposal) { Line ('  Candidate : ' + $marker.Proposal) }
        else { Line '  Candidate : No safe textual replacement proposed' }
        if ($marker.Limitation) { Line ('  Limitation: ' + $marker.Limitation) }
    }
}

Heading '9. INTERPRETATION AND LIMITATIONS'
Line ('Virtualization markers found: {0}' -f $script:markers.Count)
Line ('Fields inventoried       : {0}' -f $script:observations.Count)
Line ('PnP matches              : {0}' -f $pnpTotal)
Line 'A proposed name/serial here is a planning placeholder, not an applied spoof.'
Line 'Changing a name does not change PCI vendor IDs, CPUID behavior, drivers or firmware.'
Line 'VMware Workstation does not expose arbitrary GPU/CPU/motherboard emulation in its GUI.'
Line 'Windows CIM/registry views are not exhaustive; kernel/driver checks may differ.'
Line 'No claim is made about which checks Roblox/Hyperion uses.'
Line 'Do not post this report publicly without redacting identifying data.'
if ($script:errors.Count -gt 0) {
    Heading '10. QUERIES THAT COULD NOT BE COMPLETED'
    foreach ($err in $script:errors) { Line ('- ' + $err) }
}

try {
    [System.IO.File]::WriteAllLines($reportPath, $script:lines.ToArray(), [System.Text.UTF8Encoding]::new($true))
}
catch {
    throw ('Failed to save Desktop audit report: ' + $_.Exception.Message)
}
Write-Host ''
Write-Host 'Read-only VM hardware audit completed.' -ForegroundColor Green
Write-Host ('Fields inspected: {0}; virtualization marker matches: {1}' -f $script:observations.Count, $script:markers.Count)
Write-Host ('Desktop report: ' + $reportPath) -ForegroundColor Cyan
Write-Host 'No identifiers, firmware, drivers or binaries were changed.'
