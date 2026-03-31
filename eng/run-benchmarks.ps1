[CmdletBinding()]
param(
    [switch]$UseExistingEnv,
    [switch]$DownloadPortable,
    [string]$EnvFilePath = "",
    [string]$Pkcs11ToolPath = "",
    [string]$SoftHsmVersion = "2.5.0",
    [switch]$UpdateDocs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

if ([string]::IsNullOrWhiteSpace($EnvFilePath)) {
    $EnvFilePath = Join-Path ([System.IO.Path]::GetTempPath()) 'pkcs11-benchmark-fixture.ps1'
}
else {
    $EnvFilePath = [System.IO.Path]::GetFullPath($EnvFilePath)
}

if (-not $UseExistingEnv.IsPresent) {
    & (Join-Path $scriptDir 'setup-softhsm-fixture.ps1') -EnvFilePath $EnvFilePath -DownloadPortable:$DownloadPortable.IsPresent -Pkcs11ToolPath $Pkcs11ToolPath -SoftHsmVersion $SoftHsmVersion
}

. $EnvFilePath

$resultsRoot = Join-Path $repoRoot 'artifacts/benchmarks/latest'
New-Item -ItemType Directory -Force -Path $resultsRoot | Out-Null

$env:PKCS11_BENCHMARK_REPO_ROOT = $repoRoot
$env:PKCS11_BENCHMARK_RESULTS_ROOT = $resultsRoot
$env:PKCS11_BENCHMARK_SDK_VERSION = (& dotnet --version)
$runtimeMatches = (& dotnet --list-runtimes) | Select-String 'Microsoft\.AspNetCore\.App '
$env:PKCS11_BENCHMARK_RUNTIME_VERSION = ($runtimeMatches | Select-Object -Last 1).ToString().Split(' ')[1]

if ($UpdateDocs.IsPresent) {
    $env:PKCS11_BENCHMARK_CANONICAL_RESULTS_PATH = Join-Path $repoRoot 'docs/benchmarks/latest-windows-softhsm.md'
}

& dotnet run --project (Join-Path $repoRoot 'benchmarks/Pkcs11Wrapper.Benchmarks/Pkcs11Wrapper.Benchmarks.csproj') -c Release -- --filter '*'
Write-Host "Benchmark summary: $resultsRoot/summary.md"
