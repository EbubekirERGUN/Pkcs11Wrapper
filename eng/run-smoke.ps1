[CmdletBinding()]
param(
    [switch]$UseExistingEnv,
    [switch]$DownloadPortable,
    [string]$EnvFilePath = "",
    [string]$Pkcs11ToolPath = "",
    [string]$SoftHsmVersion = "2.5.0",
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

$runArgs = @('run', '--project', (Join-Path $repoRoot 'samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj'), '-c', 'Release')
if ($NoBuild.IsPresent) {
    $runArgs += '--no-build'
}

dotnet @runArgs
