<#
.SYNOPSIS
    Suspended Process Injector for Roblox (Bypasses Hyperion memory checks)
#>

$ExePath = "C:\Users\$env:USERNAME\AppData\Local\Roblox\Versions\version-2c6fd5e09aaf4cfa\RobloxPlayerBeta.exe"
$DllPath = "C:\path\to\your\Spoofer.dll" # Put the compiled DLL here

if (-not (Test-Path $ExePath)) { Write-Host "[X] Roblox exe not found." -ForegroundColor Red; exit }
if (-not (Test-Path $DllPath)) { Write-Host "[X] Spoofer.dll not found." -ForegroundColor Red; exit }

$DllPath = (Resolve-Path $DllPath).Path
$DllBytes = [System.Text.Encoding]::ASCII.GetBytes($DllPath)

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Injector {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    // CreateProcess with CREATE_SUSPENDED flag (0x00000004)
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
}
"@

Write-Host "[*] Starting RobloxPlayerBeta.exe in SUSPENDED state..." -ForegroundColor Cyan

$si = New-Object Injector+STARTUPINFO
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = New-Object Injector+PROCESS_INFORMATION

# CREATE_SUSPENDED = 0x00000004
$success = [Injector]::CreateProcess($ExePath, $null, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x00000004, [IntPtr]::Zero, (Split-Path $ExePath), [ref]$si, [ref]$pi)

if (-not $success) {
    Write-Host "[X] Failed to create process. Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red
    exit
}

Write-Host "[+] Process created suspended. PID: $($pi.dwProcessId)" -ForegroundColor Green

# Allocate memory for the DLL path
$allocSize = $DllBytes.Length + 1
$remoteMem = [Injector]::VirtualAllocEx($pi.hProcess, [IntPtr]::Zero, $allocSize, 0x1000, 0x04) # MEM_COMMIT, PAGE_READWRITE
if ($remoteMem -eq [IntPtr]::Zero) {
    Write-Host "[X] Failed to allocate memory in target process." -ForegroundColor Red
    exit
}

Write-Host "[*] Writing DLL path to target memory..." -ForegroundColor Cyan
$bytesWritten = [IntPtr]::Zero
[Injector]::WriteProcessMemory($pi.hProcess, $remoteMem, $DllBytes, $DllBytes.Length, [ref]$bytesWritten) | Out-Null

# Get address of LoadLibraryA
$kernel32 = [Injector]::GetModuleHandle("kernel32.dll")
$loadLibraryAddr = [Injector]::GetProcAddress($kernel32, "LoadLibraryA")

Write-Host "[*] Injecting Spoofer.dll via CreateRemoteThread..." -ForegroundColor Cyan
$remoteThread = [Injector]::CreateRemoteThread($pi.hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $remoteMem, 0, [IntPtr]::Zero)

if ($remoteThread -eq [IntPtr]::Zero) {
    Write-Host "[X] Thread creation failed." -ForegroundColor Red
    exit
}

Start-Sleep -Milliseconds 500 # Wait for LoadLibrary to execute

Write-Host "[*] Resuming main Roblox thread..." -ForegroundColor Cyan
[Injector]::ResumeThread($pi.hThread) | Out-Null

Write-Host "[+] Done! Roblox is running with the GPU Spoofer injected." -ForegroundColor Green

# Cleanup
[Injector]::CloseHandle($remoteThread) | Out-Null
[Injector]::CloseHandle($pi.hThread) | Out-Null
[Injector]::CloseHandle($pi.hProcess) | Out-Null
