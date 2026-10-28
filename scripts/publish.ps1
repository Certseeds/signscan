#!/usr/bin/env pwsh
# 发布 signscan 的 NativeAOT 单文件 exe。
# NativeAOT 依赖 vswhere.exe 定位 MSVC;发布物不包含 PDB。
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
$projectDir = Join-Path $repoRoot 'src/signscan'
$publishDir = Join-Path $repoRoot 'artifacts/publish'

# 清掉旧产物,避免上一次的 PDB / exe 混入。
Remove-Item -LiteralPath (Join-Path $projectDir 'bin') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $projectDir 'obj') -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $publishDir -Recurse -Force -ErrorAction SilentlyContinue

dotnet publish (Join-Path $projectDir 'signscan.csproj') `
    -c $Configuration `
    -r $RuntimeIdentifier `
    -o $publishDir `
    -p:NativeDebugSymbols=false `
    -p:DebugType=None `
    -p:DebugSymbols=false

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

# PDB 会包含源码绝对路径;exe 的调试目录也会嵌入 PDB 路径。
$pdbs = @(Get-ChildItem -LiteralPath $publishDir -Recurse -Force -Filter *.pdb -ErrorAction SilentlyContinue)
if ($pdbs.Count -gt 0) {
    [Console]::Error.WriteLine(("发布目录中出现了 PDB,已中止:{0}" -f ($pdbs.FullName -join ', ')))
    Remove-Item -LiteralPath $publishDir -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

# 双保险:exe 里不应出现当前用户的 profile 绝对路径。
$exePath = Join-Path $publishDir 'signscan.exe'
if ((Test-Path -LiteralPath $exePath) -and -not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    $profileHit = & findstr.exe /M "/C:$env:USERPROFILE" $exePath 2>$null
    if ($profileHit) {
        [Console]::Error.WriteLine(("发布物中包含本机路径 '{0}',已中止。" -f $env:USERPROFILE))
        Remove-Item -LiteralPath $publishDir -Recurse -Force -ErrorAction SilentlyContinue
        exit 1
    }
}

exit 0
