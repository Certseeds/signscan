#!/usr/bin/env pwsh
# 把 artifacts/publish 下的产物 stage 到 artifacts/release/signscan-v<version>-win-x64,供 CI 上传。
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

$exe = Join-Path $publishDir 'signscan.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    throw "找不到发布产物:$exe (先运行 scripts/publish.ps1)"
}

if (Test-Path -LiteralPath $stage) {
    Remove-Item -LiteralPath $stage -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $stage | Out-Null

Copy-Item -LiteralPath $exe -Destination $stage
Copy-Item -LiteralPath (Join-Path $repoRoot 'readme.md') -Destination $stage
Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE_AGPL_V3_0.md') -Destination $stage

Write-Host "staged: $stage"
