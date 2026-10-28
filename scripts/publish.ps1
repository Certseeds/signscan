#!/usr/bin/env pwsh
# 发布 signscan 的 NativeAOT 单文件 exe。
# 与 bulkban 相同,NativeAOT 需要 vswhere.exe 在 PATH 中。
[CmdletBinding()]
param(
    [string]$RuntimeIdentifier = 'win-x64',
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'

$vsInstaller = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
if (Test-Path (Join-Path $vsInstaller 'vswhere.exe')) {
    $env:PATH = "$vsInstaller;$env:PATH"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
dotnet publish (Join-Path $repoRoot 'src/signscan/signscan.csproj') `
    -c $Configuration `
    -r $RuntimeIdentifier `
    -o (Join-Path $repoRoot 'artifacts/publish')

exit $LASTEXITCODE
