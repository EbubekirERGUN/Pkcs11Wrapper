[CmdletBinding()]
param(
    [switch]$UseExistingEnv,
    [switch]$DownloadPortable,
    [string]$EnvFilePath = "",
    [string]$Pkcs11ToolPath = "",
    [string]$SoftHsmVersion = "2.5.0",
    [switch]$NoBuild,
    [switch]$Strict
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$validatorScript = Join-Path $scriptDir 'validate-smoke-output.py'

function Resolve-PythonCommand {
    foreach ($candidate in @('python', 'python3', 'py')) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return $command.Source
        }
    }

    throw 'Python is required to validate smoke output.'
}

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

$publishDir = Join-Path $repoRoot 'artifacts/smoke-runtime/windows'
$smokeLog = Join-Path $publishDir 'smoke.log'
$runStrict = $Strict.IsPresent -or $env:PKCS11_STRICT_REQUIRED -eq '1' -or $env:CI -eq 'true'

New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

$runArgs = @('run', '--project', (Join-Path $repoRoot 'samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj'), '-c', 'Release')
if ($NoBuild.IsPresent) {
    $runArgs += '--no-build'
}

& dotnet @runArgs *>&1 | Tee-Object -FilePath $smokeLog
if ($LASTEXITCODE -ne 0) {
    throw "Smoke run failed with exit code $LASTEXITCODE."
}

if ($runStrict) {
    $python = Resolve-PythonCommand
    & $python $validatorScript $smokeLog
    if ($LASTEXITCODE -ne 0) {
        throw "Smoke validation failed with exit code $LASTEXITCODE."
    }
}

Write-Host "Smoke summary: $smokeLog"
