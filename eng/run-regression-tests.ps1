[CmdletBinding()]
param(
    [switch]$UseExistingEnv,
    [switch]$DownloadPortable,
    [string]$EnvFilePath = "",
    [string]$Pkcs11ToolPath = "",
    [string]$SoftHsmVersion = "2.5.0",
    [switch]$NoRestore,
    [switch]$NoBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

if ([string]::IsNullOrWhiteSpace($EnvFilePath)) {
    $EnvFilePath = Join-Path ([System.IO.Path]::GetTempPath()) 'pkcs11-fixture.ps1'
}
else {
    $EnvFilePath = [System.IO.Path]::GetFullPath($EnvFilePath)
}

if (-not $UseExistingEnv.IsPresent) {
    & (Join-Path $scriptDir 'setup-softhsm-fixture.ps1') -EnvFilePath $EnvFilePath -DownloadPortable:$DownloadPortable.IsPresent -Pkcs11ToolPath $Pkcs11ToolPath -SoftHsmVersion $SoftHsmVersion
}

. $EnvFilePath
$env:CI = if ([string]::IsNullOrWhiteSpace($env:CI)) { 'true' } else { $env:CI }
$env:PKCS11_STRICT_REQUIRED = '1'

if (-not $NoRestore.IsPresent) {
    dotnet restore (Join-Path $repoRoot 'Pkcs11Wrapper.sln')
}

if (-not $NoBuild.IsPresent) {
    dotnet build (Join-Path $repoRoot 'Pkcs11Wrapper.sln') -c Release --no-restore
}

dotnet test (Join-Path $repoRoot 'Pkcs11Wrapper.sln') -c Release --no-build --nologo
