param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "system_discovery_marker.txt"

if ($Cleanup) {
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null

$Command = @"
`$Computer = `$env:COMPUTERNAME
`$Os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -First 1 -Property Caption,Version,OSArchitecture
`$Cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1 -Property Name,NumberOfCores
'sfp_system_discovery_fixture GetComputerName GetSystemInfo GlobalMemoryStatus systeminfo host_os_architecture' | Set-Content -LiteralPath '$Marker' -Encoding ascii
"@

Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$Command`"" -Wait -WindowStyle Hidden
