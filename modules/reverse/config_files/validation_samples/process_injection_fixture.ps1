param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "process_injection_marker.txt"

if ($Cleanup) {
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null

$Source = @"
using System;
using System.Runtime.InteropServices;
public static class SFPProcessAccessFixture {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(UInt32 access, Boolean inherit, UInt32 processId);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern Boolean CloseHandle(IntPtr handle);
}
"@

Add-Type -TypeDefinition $Source -ErrorAction SilentlyContinue

$Child = Start-Process -FilePath "$env:ComSpec" -ArgumentList "/c ping 127.0.0.1 -n 4 > nul" -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 300

# PROCESS_QUERY_LIMITED_INFORMATION only; this validates cross-process access telemetry.
$Handle = [SFPProcessAccessFixture]::OpenProcess(0x1000, $false, [UInt32]$Child.Id)
if ($Handle -ne [IntPtr]::Zero) {
    [SFPProcessAccessFixture]::CloseHandle($Handle) | Out-Null
    "sfp_process_injection_fixture process_access target_pid=$($Child.Id)" | Set-Content -LiteralPath $Marker -Encoding ASCII
}

Stop-Process -Id $Child.Id -Force -ErrorAction SilentlyContinue
