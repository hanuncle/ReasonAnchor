param(
    [string]$Root = "D:\secure_tools\attack"
)

$ErrorActionPreference = "Stop"

$repos = @(
    @{
        Name = "attack-stix-data"
        Url = "https://github.com/mitre-attack/attack-stix-data.git"
    },
    @{
        Name = "mbc-markdown"
        Url = "https://github.com/MBCProject/mbc-markdown.git"
    },
    @{
        Name = "sigma"
        Url = "https://github.com/SigmaHQ/sigma.git"
    },
    @{
        Name = "capa-rules"
        Url = "https://github.com/mandiant/capa-rules.git"
    }
)

New-Item -ItemType Directory -Force -Path $Root | Out-Null

foreach ($repo in $repos) {
    $target = Join-Path $Root $repo.Name
    $gitDir = Join-Path $target ".git"
    if (Test-Path -LiteralPath $gitDir) {
        Write-Host "Updating $($repo.Name) in $target"
        git -C $target pull --ff-only
        continue
    }
    if (Test-Path -LiteralPath $target) {
        Write-Warning "Skipping $target because it exists and is not a git checkout."
        continue
    }
    Write-Host "Cloning $($repo.Name) into $target"
    git clone --depth 1 $repo.Url $target
}

Write-Host "Knowledge sources are ready under $Root"
