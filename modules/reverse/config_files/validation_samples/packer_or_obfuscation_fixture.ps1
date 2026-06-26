param(
    [switch]$Cleanup
)

$Root = "C:\Telemetry\fixtures"
$Marker = Join-Path $Root "packer_or_obfuscation_marker.txt"
$Blob = Join-Path $Root "packer_or_obfuscation_blob.bin"

if ($Cleanup) {
    Remove-Item -LiteralPath $Marker -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Blob -Force -ErrorAction SilentlyContinue
    exit 0
}

New-Item -ItemType Directory -Force -Path $Root | Out-Null

# Static-focused fixture: encoded/high-entropy-looking data for packer/obfuscation heuristics.
$Encoded = @(
    "9f4c2b7e1a5d8c03b6e912af44d0c8e7f13a92cb55e0061d7b89a4ce3310f6aa",
    "b64:U0ZQX09CRlVTQ0FUSU9OX0ZJWFRVUkVfQkxPQl9FTkNPREVEX0RhdGE=",
    "xor_key=0x5a; packed_section=.sfp0; virtualized_stub_marker=true"
) -join "`n"

[System.IO.File]::WriteAllBytes($Blob, [System.Text.Encoding]::ASCII.GetBytes($Encoded))
"sfp_packer_or_obfuscation_fixture encoded_blob=$Blob" | Set-Content -LiteralPath $Marker -Encoding ASCII
