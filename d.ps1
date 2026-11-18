Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPDeviceID -match 'VEN_15AD' } | Select-Object Name, PNPDeviceID
