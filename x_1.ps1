$exe = "C:\path\to\RobloxPlayerBeta.exe"
$bytes = [System.IO.File]::ReadAllBytes($exe)
$peOff = [BitConverter]::ToInt32($bytes, 0x3C)
$numSections = [BitConverter]::ToUInt16($bytes, $peOff + 6)
$optHeaderSize = [BitConverter]::ToUInt16($bytes, $peOff + 20)
$sectionsStart = $peOff + 24 + $optHeaderSize

$sections = @()
for ($i = 0; $i -lt $numSections; $i++) {
    $off = $sectionsStart + ($i * 40)
    $name = [System.Text.Encoding]::ASCII.GetString($bytes, $off, 8).TrimEnd([char]0)
    $rawSize = [BitConverter]::ToUInt32($bytes, $off + 16)
    $rawPtr  = [BitConverter]::ToUInt32($bytes, $off + 20)
    $sections += [pscustomobject]@{Name=$name; Size=$rawSize; Ptr=$rawPtr}
}

# Scan ONLY plaintext sections
$targets = $sections | Where-Object { $_.Name -match '^\.(rdata|rodata|didat)$' }

foreach ($sec in $targets) {
    Write-Host "`n=== Section $($sec.Name) ($($sec.Size) bytes) ===" -ForegroundColor Cyan
    $chunk = $bytes[$sec.Ptr..($sec.Ptr + $sec.Size - 1)]
    # Extract printable runs >= 6 chars
    $sb = New-Object System.Text.StringBuilder
    $strings = @()
    foreach ($b in $chunk) {
        if ($b -ge 0x20 -and $b -le 0x7E) {
            [void]$sb.Append([char]$b)
        } else {
            if ($sb.Length -ge 6) { $strings += $sb.ToString() }
            [void]$sb.Clear()
        }
    }
    if ($sb.Length -ge 6) { $strings += $sb.ToString() }

    # Print only strings that look "interesting"
    $strings | Where-Object {
        $_ -match 'VMware|VirtualBox|QEMU|KVM|Hyper-?V|hypervisor|D3DKMT|DXGI|d3d|nvapi|nvml|ADL|EnumDisplay|GetDeviceCaps|GetAdapters|SetupDi|CM_Get_Device|RDTSC|CPUID|NtQuery|SMBIOS|\.dll$|\.sys$|GetProcAddress|LoadLibrary'
    } | Sort-Object -Unique | ForEach-Object { "  $_" }
}
