Write-Host "Cleaning VMware traces..." -ForegroundColor Cyan
$paths = @(
    "HKLM:\SOFTWARE\VMware, Inc.",
    "HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmci",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmhgfs",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VMMEMCTL",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VMTools",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VMRawdsk",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VMUSBMouse",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmmouse",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmxnet",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmx_svga",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmvss"
)
foreach ($path in $paths) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Removed: $path" -ForegroundColor Green
    }
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "SystemManufacturer" -Value "ASUS" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation" -Name "SystemProductName" -Value "ROG STRIX B550-F GAMING" -ErrorAction SilentlyContinue
$services = @("VMTools", "VMUSBMouse", "vmci", "vmhgfs", "VMMEMCTL")
foreach ($svc in $services) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "Disabled service: $svc" -ForegroundColor Yellow
    }
}
Write-Host "`nDone. Restart the VM and try Roblox again." -ForegroundColor Cyan
