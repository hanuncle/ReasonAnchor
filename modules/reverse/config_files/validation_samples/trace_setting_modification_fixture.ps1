param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "trace_setting_modification_marker.txt"
$TraceKey = "HKCU:\Software\Microsoft\Tracing\SFPValidationTrace"

if ($Cleanup) {
    Remove-Item -LiteralPath $TraceKey -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null
New-Item -Path $TraceKey -Force | Out-Null
New-ItemProperty -Path $TraceKey -Name "EnableFileTracing" -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $TraceKey -Name "ConsoleTracingMask" -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $TraceKey -Name "AutoFileTracing" -Value 0 -PropertyType DWord -Force | Out-Null
Set-Content -LiteralPath $Marker -Value "sfp_trace_setting_modification_fixture Microsoft\Tracing EnableFileTracing ConsoleTracingMask AutoFileTracing" -Encoding ASCII
