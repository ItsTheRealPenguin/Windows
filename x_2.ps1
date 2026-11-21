<#
.SYNOPSIS
    Deep Scan: UTF-16 API Search + Assembly Signatures + Stub Hexdump
#>

param (
    [string]$ExePath = "C:\Users\$env:USERNAME\AppData\Local\Roblox\Versions\version-2c6fd5e09aaf4cfa\RobloxPlayerBeta.exe"
)

if (-not (Test-Path $ExePath)) {
    Write-Host "[X] File not found at $ExePath" -ForegroundColor Red
    exit
}

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

# =====================================================================
# 1. DUMP STUBS (.byfron and tempest)
# =====================================================================
Write-Host "`n[*] Dumping Trampoline Stubs..." -ForegroundColor Cyan
foreach ($sec in ($sections | Where-Object { $_.Name -eq ".byfron" -or $_.Name -eq "tempest" })) {
    Write-Host "`n--- $($sec.Name) (RawSize: $($sec.RawSize)) ---" -ForegroundColor Yellow
    
    # Extract up to 256 bytes for hexdump to prevent console spam
    $dumpSize = [Math]::Min($sec.RawSize, 256)
    $secBytes = $bytes[$sec.RawPtr..($sec.RawPtr + $dumpSize - 1)]
    
    # Format as Hex
    $hexString = ($secBytes | ForEach-Object { $_.ToString("X2") }) -join " "
    Write-Host $hexString -ForegroundColor Gray
}

# =====================================================================
# 2. UTF-16 (WideChar) API STRING SEARCH
# =====================================================================
Write-Host "`n[*] Searching .rdata and .text for UTF-16 API Strings..." -ForegroundColor Cyan

$targetStrings = @(
    "D3DKMT", "EnumDisplayDevices", "GetDeviceCaps", "dxgi", "nvapi", 
    "VMware", "VirtualBox", "QEMU", "Hyper-V", "tempest", 
    "SetupDi", "GetAdaptersInfo", "GetSystemFirmwareTable"
)

$dataSections = $sections | Where-Object { $_.Name -eq ".rdata" -or $_.Name -eq ".text" }

foreach ($target in $targetStrings) {
    # Convert string to UTF-16 (Unicode) byte array
    $targetBytes = [System.Text.Encoding]::Unicode.GetBytes($target)
    $found = $false

    foreach ($sec in $dataSections) {
        $secBytes = $bytes[$sec.RawPtr..($sec.RawPtr + $sec.RawSize - 1)]
        
        # Simple Boyer-Moore-ish search
        for ($i = 0; $i -le ($secBytes.Length - $targetBytes.Length); $i++) {
            if ($secBytes[$i] -eq $targetBytes[0] -and $secBytes[$i+1] -eq $targetBytes[1]) {
                $match = $true
                for ($j = 2; $j -lt $targetBytes.Length; $j++) {
                    if ($secBytes[$i + $j] -ne $targetBytes[$j]) {
                        $match = $false; break
                    }
                }
                if ($match) {
                    Write-Host "  [+] Found '$target' in $($sec.Name) at RVA: 0x$(($sec.VAddr + $i).ToString('X'))" -ForegroundColor Green
                    $found = $true
                    break
                }
            }
        }
        if ($found) { break }
    }
    if (-not $found) { Write-Host "  [-] '$target' not found in plaintext." -ForegroundColor DarkGray }
}

# =====================================================================
# 3. ASSEMBLY INSTRUCTION SCAN (RDTSC / CPUID)
# =====================================================================
Write-Host "`n[*] Scanning .text for Hardware Check Instructions..." -ForegroundColor Cyan
$textSec = $sections | Where-Object { $_.Name -eq ".text" }
$textBytes = $bytes[$textSec.RawPtr..($textSec.RawPtr + $textSec.RawSize - 1)]

$opcodes = @{
    "RDTSC (0F 31)" = @(0x0F, 0x31)
    "CPUID (0F A2)" = @(0x0F, 0xA2)
    "IN (EDX) (ED)" = @(0xED)
}

foreach ($op in $opcodes.Keys) {
    $sig = $opcodes[$op]
    $count = 0
    $firstOffset = -1

    for ($i = 0; $i -le ($textBytes.Length - $sig.Length); $i++) {
        $match = $true
        for ($j = 0; $j -lt $sig.Length; $j++) {
            if ($textBytes[$i + $j] -ne $sig[$j]) { $match = $false; break }
        }
        if ($match) {
            $count++
            if ($firstOffset -eq -1) { $firstOffset = $i }
        }
    }
    
    if ($count -gt 0) {
        Write-Host "  [+] Found $op $count times." -ForegroundColor Magenta
        Write-Host "      First instance at RVA: 0x$(($textSec.VAddr + $firstOffset).ToString('X'))" -ForegroundColor Gray
    } else {
        Write-Host "  [-] $op not found in .text" -ForegroundColor DarkGray
    }
}

Write-Host "`n[*] Scan Complete." -ForegroundColor Cyan
