param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "service_creation_marker.txt"
$ServiceName = "SFPValidationService"

if ($Cleanup) {
    sc.exe stop $ServiceName | Out-Null 2>$null
    sc.exe delete $ServiceName | Out-Null 2>$null
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null

sc.exe delete $ServiceName | Out-Null 2>$null
Start-Sleep -Milliseconds 300

$Command = "$env:ComSpec /c echo sfp_service_creation_fixture > `"$Marker`""
sc.exe create $ServiceName binPath= $Command start= demand DisplayName= "SFP Validation Service" | Out-Null
sc.exe start $ServiceName | Out-Null 2>$null
Start-Sleep -Seconds 1
sc.exe stop $ServiceName | Out-Null 2>$null
sc.exe delete $ServiceName | Out-Null 2>$null
