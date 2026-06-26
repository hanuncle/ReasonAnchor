param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "anti_vm_sandbox_evasion_marker.txt"

if ($Cleanup) {
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null

$Command = @"
`$Adapter = Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue | Select-Object -First 1 -Property Name,MACAddress
`$Disk = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Select-Object -First 1 -Property Model,SerialNumber
`$Bios = Get-ItemProperty -Path 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS' -ErrorAction SilentlyContinue
`$Now = Get-Date
'sfp_anti_vm_sandbox_evasion_fixture vmware virtualbox sandbox debugger PhysicalDrive GetAdaptersAddresses GetTimeZoneInformation GetLastInputInfo idle_time' | Set-Content -LiteralPath '$Marker' -Encoding ascii
"@

Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$Command`"" -Wait -WindowStyle Hidden
