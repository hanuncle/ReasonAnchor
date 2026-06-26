param(
    [switch]$Cleanup
)

$RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$ValueName = "SFPValidationRunKey"
$ValueData = "$env:ComSpec /c echo sfp_registry_run_key_fixture"

if ($Cleanup) {
    Remove-ItemProperty -LiteralPath $RunKey -Name $ValueName -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -Path $RunKey -Force | Out-Null
Set-ItemProperty -LiteralPath $RunKey -Name $ValueName -Value $ValueData
