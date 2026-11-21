<#
.SYNOPSIS
    Optimized Native .NET Scanner (Bypasses PowerShell memory limits)
#>

param (
    [string]$ExePath = "C:\Users\$env:USERNAME\AppData\Local\Roblox\Versions\version-2c6fd5e09aaf4cfa\RobloxPlayerBeta.exe"
)

if (-not (Test-Path $ExePath)) {
    Write-Host "[X] File not found at $ExePath" -ForegroundColor Red
    exit
}

Write-Host "[*] Reading $ExePath..." -ForegroundColor Cyan
$bytes = [System.IO.File]::ReadAllBytes($ExePath)
$peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
$numSections = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
$optHeaderSize = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
$sectionsStart = $peOffset + 24 + $optHeaderSize

$sections = @()
for ($i = 0; $i -lt $numSections; $i++) {
    $offset = $sectionsStart + ($i * 40)
    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $offset, 8).TrimEnd([char]0)
    $sections += @{
        Name = $name
        VAddr = [BitConverter]::ToUInt32($bytes, $offset + 12)
        RawSize = [BitConverter]::ToUInt32($bytes, $offset + 16)
        RawPtr = [BitConverter]::ToUInt32($bytes, $offset + 20)
    }
}

$targets = @(
    "D3DKMT", "EnumDisplayDevices", "GetDeviceCaps", "dxgi", "nvapi", 
    "VMware", "VirtualBox", "QEMU", "Hyper-V", "tempest", 
    "SetupDi", "GetAdaptersInfo", "GetSystemFirmwareTable", "RDTSC"
)

Write-Host "`n[*] Scanning 130MB of .text and .rdata safely..." -ForegroundColor Yellow

foreach ($sec in ($sections | Where-Object { $_.Name -eq ".rdata" -or $_.Name -eq ".text" })) {
    Write-Host "`n--- Scanning $($sec.Name) ($([Math]::Round($sec.RawSize/1MB, 2)) MB) ---" -ForegroundColor Cyan
    
    # Convert the ENTIRE section to an ASCII string using .NET (lightning fast, memory safe)
    $asciiString = [System.Text.Encoding]::ASCII.GetString($bytes, $sec.RawPtr, $sec.RawSize)
    
    # Convert the ENTIRE section to a UTF-16 (Unicode) string
    $utf16String = [System.Text.Encoding]::Unicode.GetString($bytes, $sec.RawPtr, $sec.RawSize)

    foreach ($target in $targets) {
        # Check ASCII
        $idx = $asciiString.IndexOf($target)
        if ($idx -ge 0) {
            Write-Host "  [+] Found ASCII '$target' at RVA: 0x$(($sec.VAddr + $idx).ToString('X'))" -ForegroundColor Green
        }

        # Check UTF-16 (WideChar)
        $idx16 = $utf16String.IndexOf($target)
        if ($idx16 -ge 0) {
            # Multiply index by 2 because UTF-16 uses 2 bytes per char
            Write-Host "  [+] Found UTF-16 '$target' at RVA: 0x$(($sec.VAddr + ($idx16 * 2)).ToString('X'))" -ForegroundColor Magenta
        }
    }
}

Write-Host "`n[*] Scan Complete." -ForegroundColor Cyan
