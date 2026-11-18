Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceName -match 'Display|SVGA' } | Select-Object DeviceName, Manufacturer, DriverProviderName, DriverVersion
