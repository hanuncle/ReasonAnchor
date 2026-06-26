param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "privilege_discovery_marker.txt"

if ($Cleanup) {
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null

$Command = @"
`$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
`$Groups = `$Identity.Groups | Select-Object -First 5
whoami /priv | Out-Null
'sfp_privilege_discovery_fixture whoami /priv LookupPrivilegeValue SeDebugPrivilege AdjustTokenPrivileges token_privileges' | Set-Content -LiteralPath '$Marker' -Encoding ascii
"@

Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"$Command`"" -Wait -WindowStyle Hidden
