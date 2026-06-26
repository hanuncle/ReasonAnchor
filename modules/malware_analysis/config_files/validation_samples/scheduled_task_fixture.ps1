param(
    [switch]$Cleanup
)

$TaskName = "SFPValidationTask"
$Marker = "C:\Telemetry\fixtures\scheduled_task_marker.txt"

if ($Cleanup) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Marker) | Out-Null
$Action = New-ScheduledTaskAction -Execute "$env:ComSpec" -Argument "/c echo SFPValidationTask > `"$Marker`""
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Description "SFP benign validation fixture" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
