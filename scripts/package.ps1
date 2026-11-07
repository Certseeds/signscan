#!/usr/bin/env pwsh
# 把 artifacts/publish 下的 exe 打包成 artifacts/release/signscan-v<version>-win-x64.zip。
[CmdletBinding()]
param(
    [string]$RuntimeIdentifier = 'win-x64'
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$version = (Get-Content -LiteralPath (Join-Path $repoRoot 'package.json') -Raw | ConvertFrom-Json).version
if ([string]::IsNullOrWhiteSpace($version)) {
    throw 'package.json 中没有 version。'
}

$publishDir = Join-Path $repoRoot 'artifacts/publish'
$releaseDir = Join-Path $repoRoot 'artifacts/release'
$packageName = "signscan-v$version-$RuntimeIdentifier"
$stage = Join-Path $releaseDir $packageName
$zip = Join-Path $releaseDir "$packageName.zip"

$exe = Join-Path $publishDir 'signscan.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    throw "找不到发布产物:$exe (先运行 scripts/publish.ps1)"
}

if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}

if (Test-Path -LiteralPath $zip) {
    Remove-Item -LiteralPath $zip -Force
}

New-Item -ItemType Directory -Force -Path $stage | Out-Null

Copy-Item -LiteralPath $exe -Destination $stage
Copy-Item -LiteralPath (Join-Path $repoRoot 'readme.md') -Destination $stage
Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE_AGPL_V3_0.md') -Destination $stage

Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal

$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "package: $zip"
Write-Host "sha256 : $hash"
