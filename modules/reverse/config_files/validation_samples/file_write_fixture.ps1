param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "file_write_marker.txt"

if ($Cleanup) {
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null
Set-Content -LiteralPath $Marker -Value "sfp_file_write_fixture" -Encoding ASCII
