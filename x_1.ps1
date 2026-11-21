<#
.SYNOPSIS
    Deep static PE analysis of RobloxPlayerBeta.exe
#>

param (
    [string]$ExePath = "C:\Users\$env:USERNAME\AppData\Local\Roblox\Versions\version-2c6fd5e09aaf4cfa\RobloxPlayerBeta.exe"
)

if (-not (Test-Path $ExePath)) {
    Write-Host "[X] File not found at $ExePath. Please verify the path." -ForegroundColor Red
    exit
}

Write-Host "[*] Reading $ExePath..." -ForegroundColor Cyan
$bytes = [System.IO.File]::ReadAllBytes($ExePath)

# 1. Parse DOS Header
if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    Write-Host "[X] Invalid DOS Header (Not MZ)." -ForegroundColor Red
    exit
}

$peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45) {
    Write-Host "[X] Invalid NT Header (Not PE)." -ForegroundColor Red
    exit
}

# 2. Parse File Header
$numSections = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
$optHeaderSize = [BitConverter]::ToUInt16($bytes, $peOffset + 20)

# 3. Parse Sections
$sectionsStart = $peOffset + 24 + $optHeaderSize

Write-Host "`n[+] PE Sections Found:" -ForegroundColor Green
Write-Host ("{0,-10} {1,-12} {2,-12} {3,-12}" -f "Name", "VirtualAddr", "RawSize", "RawPtr")
Write-Host ("-" * 50)

$targetSection = $null
$sections = @()

for ($i = 0; $i -lt $numSections; $i++) {
    $offset = $sectionsStart + ($i * 40)
    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $offset, 8).TrimEnd([char]0)
    $vSize = [BitConverter]::ToUInt32($bytes, $offset + 8)
    $vAddr = [BitConverter]::ToUInt32($bytes, $offset + 12)
    $rawSize = [BitConverter]::ToUInt32($bytes, $offset + 16)
    $rawPtr = [BitConverter]::ToUInt32($bytes, $offset + 20)
    
    Write-Host ("{0,-10} 0x{1:X8}   0x{2:X8}   0x{3:X8}" -f $name, $vAddr, $rawSize, $rawPtr)
    
    if ($name -eq ".byfron" -or $name -eq "tempest") {
        $targetSection = @{
            Name = $name
            RawPtr = $rawPtr
            RawSize = $rawSize
        }
    }
}

if (-not $targetSection) {
    Write-Host "`n[X] Could not find .byfron or tempest section." -ForegroundColor Red
    exit
}

# 4. Extract and Analyze .byfron
Write-Host "`n[*] Extracting $($targetSection.Name) section..." -ForegroundColor Cyan
$byfronBytes = New-Object byte[] $targetSection.RawSize
[Array]::Copy($bytes, $targetSection.RawPtr, $byfronBytes, 0, $targetSection.RawSize)

# Calculate Entropy (Shannon Entropy)
$frequencies = New-Object int[] 256
foreach ($b in $byfronBytes) { $frequencies[$b]++ }
$entropy = 0.0
foreach ($freq in $frequencies) {
    if ($freq -gt 0) {
        $p = $freq / $byfronBytes.Length
        $entropy -= $p * [Math]::Log($p, 2)
    }
}

Write-Host "`n[+] Section Analysis for '$($targetSection.Name)':" -ForegroundColor Green
Write-Host "    Size: $($targetSection.RawSize) bytes"
Write-Host "    Shannon Entropy: $([Math]::Round($entropy, 4)) / 8.0"
if ($entropy -gt 7.5) {
    Write-Host "    [!] High entropy detected. This section is heavily encrypted or compressed." -ForegroundColor Yellow
    Write-Host "    [!] On-disk patching is mathematically impossible without the decryption key." -ForegroundColor Yellow
}

# 5. Search for known Byte Patterns (Signatures)
Write-Host "`n[*] Searching for known anti-VM signatures in encrypted payload..." -ForegroundColor Cyan

# Hex signatures for CPUID (0x0F 0xA2), RDTSC (0x0F 0x31)
# Even if encrypted, sometimes the compiler leaves the instructions unencrypted in small stubs.
$signatures = @{
    "CPUID (0F A2)" = @(0x0F, 0xA2)
    "RDTSC (0F 31)" = @(0x0F, 0x31)
    "HLT (F4)" = @(0xF4)
}

foreach ($sigName in $signatures.Keys) {
    $sig = $signatures[$sigName]
    $found = $false
    
    for ($i = 0; $i -le ($byfronBytes.Length - $sig.Length); $i++) {
        $match = $true
        for ($j = 0; $j -lt $sig.Length; $j++) {
            if ($byfronBytes[$i + $j] -ne $sig[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            Write-Host "    [+] Found $sigName at offset 0x$($i.ToString('X'))" -ForegroundColor Magenta
            $found = $true
            # Break after finding one to avoid spamming thousands of hits
            break
        }
    }
    if (-not $found) {
        Write-Host "    [-] Did not find $sigName in clear text." -ForegroundColor Gray
    }
}

Write-Host "`n[*] Analysis complete." -ForegroundColor Cyan
