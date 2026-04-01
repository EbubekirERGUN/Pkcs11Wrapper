[CmdletBinding()]
param(
    [switch]$UseExistingEnv,
    [switch]$DownloadPortable,
    [string]$EnvFilePath = "",
    [string]$Pkcs11ToolPath = "",
    [string]$SoftHsmVersion = "2.5.0",
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
$env:PKCS11_STRICT_REQUIRED = '1'

$publishDir = Join-Path $repoRoot 'artifacts/smoke-aot/win-x64'
$smokeLog = Join-Path $publishDir 'smoke.log'
New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

Write-Host 'Publishing win-x64 NativeAOT smoke binary'
& dotnet publish (Join-Path $repoRoot 'samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj') -c Release -r win-x64 /p:PublishAot=true --self-contained true -o $publishDir
if ($LASTEXITCODE -ne 0) {
    throw "NativeAOT publish failed with exit code $LASTEXITCODE."
}

$smokeBinary = Join-Path $publishDir 'Pkcs11Wrapper.Smoke.exe'
if (-not (Test-Path -LiteralPath $smokeBinary -PathType Leaf)) {
    throw "Expected published smoke entrypoint is missing: $smokeBinary"
}

Write-Host 'Running win-x64 NativeAOT smoke binary'
& $smokeBinary *>&1 | Tee-Object -FilePath $smokeLog
if ($LASTEXITCODE -ne 0) {
    throw "NativeAOT smoke run failed with exit code $LASTEXITCODE."
}

if ($Strict.IsPresent -or $env:CI -eq 'true' -or $env:PKCS11_STRICT_REQUIRED -eq '1') {
    $python = Resolve-PythonCommand
    & $python $validatorScript $smokeLog
    if ($LASTEXITCODE -ne 0) {
        throw "NativeAOT smoke validation failed with exit code $LASTEXITCODE."
    }
}

Write-Host "NativeAOT smoke summary: $smokeLog"
