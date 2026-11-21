<#
.SYNOPSIS
    Dumps the decrypted .byfron section from a running Roblox process.
#>

# --- P/Invoke Definitions ---
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class MemDumper {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;

    public static byte[] ReadMemory(IntPtr hProcess, IntPtr address, int size) {
        byte[] buffer = new byte[size];
        IntPtr bytesRead;
        if (ReadProcessMemory(hProcess, address, buffer, (uint)size, out bytesRead)) {
            return buffer;
        }
        return null;
    }
}
"@

Write-Host "[*] Searching for RobloxPlayerBeta.exe..." -ForegroundColor Cyan
$proc = Get-Process -Name "RobloxPlayerBeta" -ErrorAction SilentlyContinue
if (-not $proc) {
    Write-Host "[X] RobloxPlayerBeta.exe is not running!" -ForegroundColor Red
    exit
}

$pidToAttach = $proc.Id
Write-Host "[+] Found process PID: $pidToAttach" -ForegroundColor Green

# Get Base Address of the main module
$baseAddress = $proc.MainModule.BaseAddress
Write-Host "[+] Base Address: 0x$($baseAddress.ToString('X'))" -ForegroundColor Green

# Open the process with read access
Write-Host "[*] Attaching to process memory..." -ForegroundColor Cyan
$hProcess = [MemDumper]::OpenProcess([MemDumper]::PROCESS_VM_READ -bor [MemDumper]::PROCESS_QUERY_INFORMATION, $false, $pidToAttach)

if ($hProcess -eq [IntPtr]::Zero) {
    Write-Host "[X] Failed to open process. Hyperion blocked the handle. (Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error()))" -ForegroundColor Red
    exit
}
Write-Host "[+] Process handle acquired." -ForegroundColor Green

try {
    # 1. Read DOS Header to get PE Header offset (e_lfanew)
    $dosHeader = [MemDumper]::ReadMemory($hProcess, $baseAddress, 0x40)
    if (-not $dosHeader) { throw "Failed to read DOS header." }
    $e_lfanew = [BitConverter]::ToInt32($dosHeader, 0x3C)

    # 2. Read NT Headers (File Header + Optional Header)
    $ntHeaders = [MemDumper]::ReadMemory($hProcess, [IntPtr]($baseAddress.ToInt64() + $e_lfanew), 0x108)
    if (-not $ntHeaders) { throw "Failed to read NT headers." }
    
    $numSections = [BitConverter]::ToUInt16($ntHeaders, 0x06)
    $optHeaderSize = [BitConverter]::ToUInt16($ntHeaders, 0x14)

    # 3. Read Section Headers
    $sectionStartOffset = $e_lfanew + 0x18 + $optHeaderSize
    $sectionsRaw = [MemDumper]::ReadMemory($hProcess, [IntPtr]($baseAddress.ToInt64() + $sectionStartOffset), $numSections * 40)
    
    $byfronFound = $false
    for ($i = 0; $i -lt $numSections; $i++) {
        $offset = $i * 40
        $secName = [System.Text.Encoding]::ASCII.GetString($sectionsRaw, $offset, 8).TrimEnd([char]0)
        
        if ($secName -eq ".byfron" -or $secName -eq "tempest") {
            $virtualSize = [BitConverter]::ToUInt32($sectionsRaw, $offset + 8)
            $virtualAddress = [BitConverter]::ToUInt32($sectionsRaw, $offset + 12)
            $absoluteAddr = [IntPtr]($baseAddress.ToInt64() + $virtualAddress)
            
            Write-Host "[+] Found target section: $secName" -ForegroundColor Yellow
            Write-Host "    Virtual Size: $virtualSize bytes" -ForegroundColor Gray
            Write-Host "    Memory Addr: 0x$($absoluteAddr.ToString('X'))" -ForegroundColor Gray
            
            Write-Host "[*] Dumping memory (this may take a second)..." -ForegroundColor Cyan
            $dumpBytes = [MemDumper]::ReadMemory($hProcess, $absoluteAddr, $virtualSize)
            
            if ($dumpBytes) {
                $outFile = "C:\byfron_dump_$secName.bin"
                [System.IO.File]::WriteAllBytes($outFile, $dumpBytes)
                Write-Host "[+] SUCCESS! Dumped $($dumpBytes.Length) bytes to $outFile" -ForegroundColor Green
                $byfronFound = $true
            } else {
                Write-Host "[X] ReadProcessMemory failed on $secName. Hyperion protected the pages." -ForegroundColor Red
            }
        }
    }

    if (-not $byfronFound) {
        Write-Host "[X] Could not locate .byfron or tempest sections in memory." -ForegroundColor Red
    }

} catch {
    Write-Host "[X] Error: $_" -ForegroundColor Red
} finally {
    [MemDumper]::CloseHandle($hProcess)
    Write-Host "[*] Handle closed." -ForegroundColor Cyan
}
