param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "command_execution_marker.txt"

if ($Cleanup) {
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null
Start-Process -FilePath "$env:ComSpec" -ArgumentList "/c echo sfp_command_execution_fixture > `"$Marker`"" -Wait -WindowStyle Hidden
