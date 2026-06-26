param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "credential_access_marker.txt"

if ($Cleanup) {
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null

# Benign query wording only; this fixture does not read, dump, or export credentials.
$Command = "Get-Process lsass -ErrorAction SilentlyContinue | Select-Object -First 1 -Property Id,ProcessName | Out-File -FilePath '$Marker' -Encoding ascii"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$Command`"" -Wait -WindowStyle Hidden
