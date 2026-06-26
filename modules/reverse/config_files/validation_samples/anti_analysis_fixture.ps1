param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "anti_analysis_marker.txt"

if ($Cleanup) {
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null

$Command = @"
`$Names = 'procmon','wireshark','x64dbg','ollydbg','ida64','vmware','virtualbox','sandbox','debugger'
`$Results = foreach (`$Name in `$Names) { Get-Process -Name `$Name -ErrorAction SilentlyContinue | Select-Object -First 1 -Property ProcessName,Id }
`$Bios = Get-ItemProperty -Path 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS' -ErrorAction SilentlyContinue
'sfp_anti_analysis_fixture vmware virtualbox sandbox debugger procmon wireshark' | Set-Content -LiteralPath '$Marker' -Encoding ascii
"@

Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$Command`"" -Wait -WindowStyle Hidden
