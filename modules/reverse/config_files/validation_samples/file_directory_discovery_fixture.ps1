param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "file_directory_discovery_marker.txt"

if ($Cleanup) {
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null
Get-ChildItem -LiteralPath $Root -Force -ErrorAction SilentlyContinue | Out-Null
Set-Content -LiteralPath $Marker -Value "sfp_file_directory_discovery_fixture dir Get-ChildItem FindFirstFile FindNextFile directory_enumerated C:\Telemetry\fixtures" -Encoding ASCII
