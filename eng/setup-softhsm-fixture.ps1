[CmdletBinding()]
param(
    [string]$EnvFilePath = "",
    [string]$FixtureRoot = "",
    [string]$SoftHsmRoot = "",
    [string]$SoftHsmVersion = "2.5.0",
    [switch]$DownloadPortable,
    [string]$Pkcs11ToolPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

function Require-File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Missing required $Description at '$Path'."
    }
}

function Get-CommandPathOrNull {
    param([Parameter(Mandatory = $true)][string]$CommandName)

    try {
        return (Get-Command $CommandName -ErrorAction Stop).Source
    }
    catch {
        return $null
    }
}

function Find-FileRecursively {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$LeafName
    )

    if (-not (Test-Path -LiteralPath $Root)) {
        return $null
    }

    return Get-ChildItem -Path $Root -Filter $LeafName -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
}

function Invoke-DownloadFile {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile
    )

    try {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile
        return
    }
    catch {
        $curlPath = Get-CommandPathOrNull -CommandName 'curl.exe'
        if ($null -eq $curlPath) {
            throw
        }

        Write-Warning "Invoke-WebRequest failed, retrying with curl.exe"
        & $curlPath --location --fail --silent --show-error --output $OutFile $Uri
        if ($LASTEXITCODE -ne 0) {
            throw "curl.exe failed to download $Uri"
        }
    }
}

function Resolve-SoftHsmPortableRoot {
    param([Parameter(Mandatory = $true)][string]$DestinationRoot)

    $candidates = @((Join-Path $DestinationRoot 'SoftHSM2'))
    $discoveredUtilPath = Find-FileRecursively -Root $DestinationRoot -LeafName 'softhsm2-util.exe'
    if (-not [string]::IsNullOrWhiteSpace($discoveredUtilPath)) {
        $candidates += (Split-Path -Parent (Split-Path -Parent $discoveredUtilPath))
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and
            (Test-Path -LiteralPath (Join-Path $candidate 'bin/softhsm2-util.exe')) -and
            (Test-Path -LiteralPath (Join-Path $candidate 'lib/softhsm2-x64.dll'))) {
            return $candidate
        }
    }

    throw "Portable SoftHSM extraction under '$DestinationRoot' did not contain the expected bin/lib layout."
}

function Download-SoftHsmPortable {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$DestinationRoot
    )

    $releaseTag = "v$Version"
    $zipName = "SoftHSM2-$Version-portable.zip"
    $downloadUrl = "https://github.com/disig/SoftHSM2-for-Windows/releases/download/$releaseTag/$zipName"
    $downloadDir = Join-Path $DestinationRoot 'downloads'
    $zipPath = Join-Path $downloadDir $zipName

    New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null
    if (-not (Test-Path -LiteralPath $zipPath)) {
        Write-Host "Downloading SoftHSM portable package from $downloadUrl"
        Invoke-DownloadFile -Uri $downloadUrl -OutFile $zipPath
    }

    $extractRoot = Join-Path $DestinationRoot 'SoftHSM2'
    if (-not (Test-Path -LiteralPath (Join-Path $extractRoot 'bin/softhsm2-util.exe'))) {
        if (Test-Path -LiteralPath $extractRoot) {
            Remove-Item -LiteralPath $extractRoot -Recurse -Force
        }

        Expand-Archive -LiteralPath $zipPath -DestinationPath $DestinationRoot -Force
    }

    return (Resolve-SoftHsmPortableRoot -DestinationRoot $DestinationRoot)
}

function Resolve-SoftHsmRoot {
    param(
        [Parameter(Mandatory = $true)][string]$RequestedRoot,
        [Parameter(Mandatory = $true)][string]$RequestedVersion,
        [Parameter(Mandatory = $true)][bool]$ShouldDownload,
        [Parameter(Mandatory = $true)][string]$WorkspaceRoot
    )

    $candidates = @()
    foreach ($candidate in @(
        $RequestedRoot,
        $env:PKCS11_SOFTHSM_ROOT,
        (Join-Path $WorkspaceRoot 'artifacts/softhsm-windows/SoftHSM2'),
        'C:\Program Files\SoftHSM2',
        'C:\SoftHSM2')) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $candidates += $candidate
        }
    }

    foreach ($candidate in $candidates) {
        if ((Test-Path -LiteralPath (Join-Path $candidate 'bin/softhsm2-util.exe')) -and
            (Test-Path -LiteralPath (Join-Path $candidate 'lib/softhsm2-x64.dll'))) {
            return $candidate
        }
    }

    if ($ShouldDownload) {
        $downloadRoot = Join-Path $WorkspaceRoot 'artifacts/softhsm-windows'
        New-Item -ItemType Directory -Force -Path $downloadRoot | Out-Null
        return (Download-SoftHsmPortable -Version $RequestedVersion -DestinationRoot $downloadRoot)
    }

    throw 'Unable to resolve SoftHSM-for-Windows installation root. Pass -DownloadPortable or set PKCS11_SOFTHSM_ROOT.'
}

function Resolve-Pkcs11ToolPath {
    param([Parameter(Mandatory = $true)][string]$RequestedPath)

    $candidates = @()
    foreach ($candidate in @(
        $RequestedPath,
        $env:PKCS11_TOOL_PATH,
        (Get-CommandPathOrNull -CommandName 'pkcs11-tool.exe'),
        'C:\ProgramData\chocolatey\bin\pkcs11-tool.exe',
        'C:\Program Files\OpenSC Project\OpenSC\pkcs11-tool.exe',
        'C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe')) {
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            $candidates += $candidate
        }
    }

    foreach ($root in @('C:\ProgramData\chocolatey\lib', 'C:\Program Files\OpenSC Project')) {
        $discovered = Find-FileRecursively -Root $root -LeafName 'pkcs11-tool.exe'
        if (-not [string]::IsNullOrWhiteSpace($discovered)) {
            $candidates += $discovered
        }
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    throw 'Unable to resolve pkcs11-tool.exe. Install OpenSC or set PKCS11_TOOL_PATH.'
}

if ([string]::IsNullOrWhiteSpace($FixtureRoot)) {
    $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("pkcs11wrapper-softhsm-" + [Guid]::NewGuid().ToString('N'))
}
else {
    $fixtureRoot = [System.IO.Path]::GetFullPath($FixtureRoot)
}

if ([string]::IsNullOrWhiteSpace($EnvFilePath)) {
    $envFilePath = Join-Path $fixtureRoot 'pkcs11-fixture.ps1'
}
else {
    $envFilePath = [System.IO.Path]::GetFullPath($EnvFilePath)
}

New-Item -ItemType Directory -Force -Path $fixtureRoot | Out-Null
$envFileDirectory = Split-Path -Parent $envFilePath
if (-not [string]::IsNullOrWhiteSpace($envFileDirectory)) {
    New-Item -ItemType Directory -Force -Path $envFileDirectory | Out-Null
}

$softHsmRoot = Resolve-SoftHsmRoot -RequestedRoot $SoftHsmRoot -RequestedVersion $SoftHsmVersion -ShouldDownload:$DownloadPortable.IsPresent -WorkspaceRoot $repoRoot
$softhsmUtilPath = Join-Path $softHsmRoot 'bin/softhsm2-util.exe'
$softhsmBinPath = Join-Path $softHsmRoot 'bin'
$softhsmLibPath = Join-Path $softHsmRoot 'lib'
$modulePath = Join-Path $softHsmRoot 'lib/softhsm2-x64.dll'
$pkcs11ToolPath = Resolve-Pkcs11ToolPath -RequestedPath $Pkcs11ToolPath

Require-File -Path $softhsmUtilPath -Description 'SoftHSM utility'
Require-File -Path $modulePath -Description 'SoftHSM PKCS#11 module'
Require-File -Path $pkcs11ToolPath -Description 'OpenSC pkcs11-tool'

$tokenLabel = if ([string]::IsNullOrWhiteSpace($env:PKCS11_TOKEN_LABEL_OVERRIDE)) { 'Pkcs11Wrapper CI Token' } else { $env:PKCS11_TOKEN_LABEL_OVERRIDE }
$userPin = if ([string]::IsNullOrWhiteSpace($env:PKCS11_USER_PIN_OVERRIDE)) { '123456' } else { $env:PKCS11_USER_PIN_OVERRIDE }
$soPin = if ([string]::IsNullOrWhiteSpace($env:PKCS11_SO_PIN_OVERRIDE)) { '12345678' } else { $env:PKCS11_SO_PIN_OVERRIDE }
$aesLabel = if ([string]::IsNullOrWhiteSpace($env:PKCS11_AES_LABEL_OVERRIDE)) { 'ci-aes' } else { $env:PKCS11_AES_LABEL_OVERRIDE }
$aesIdHex = if ([string]::IsNullOrWhiteSpace($env:PKCS11_AES_ID_HEX_OVERRIDE)) { 'A1' } else { $env:PKCS11_AES_ID_HEX_OVERRIDE }
$rsaLabel = if ([string]::IsNullOrWhiteSpace($env:PKCS11_RSA_LABEL_OVERRIDE)) { 'ci-rsa' } else { $env:PKCS11_RSA_LABEL_OVERRIDE }
$rsaIdHex = if ([string]::IsNullOrWhiteSpace($env:PKCS11_RSA_ID_HEX_OVERRIDE)) { 'B2' } else { $env:PKCS11_RSA_ID_HEX_OVERRIDE }

$tokenDir = Join-Path $fixtureRoot 'tokens'
$softHsmConf = Join-Path $fixtureRoot 'softhsm2.conf'
New-Item -ItemType Directory -Force -Path $tokenDir | Out-Null
@(
    "directories.tokendir = $tokenDir"
    'objectstore.backend = file'
    'slots.removable = false'
) | Set-Content -LiteralPath $softHsmConf -Encoding ascii

$env:SOFTHSM2_CONF = $softHsmConf
$env:PATH = $softhsmBinPath + ';' + $softhsmLibPath + ';' + $env:PATH

Write-Host "Creating Windows SoftHSM fixture in $fixtureRoot"
Write-Host "Using SoftHSM root $softHsmRoot"
Write-Host "Using PKCS#11 module $modulePath"
Write-Host "Using pkcs11-tool $pkcs11ToolPath"
Write-Host "SoftHSM utility version:"
& $softhsmUtilPath --version | Out-Host
Write-Host "OpenSC pkcs11-tool version:"
& $pkcs11ToolPath --version | Out-Host

& $softhsmUtilPath --init-token --free --label $tokenLabel --so-pin $soPin --pin $userPin | Out-Host
& $pkcs11ToolPath --module $modulePath --token-label $tokenLabel --login --pin $userPin --keygen --key-type AES:32 --label $aesLabel --id $aesIdHex --usage-decrypt --usage-wrap | Out-Host
& $pkcs11ToolPath --module $modulePath --token-label $tokenLabel --login --pin $userPin --keypairgen --key-type rsa:2048 --label $rsaLabel --id $rsaIdHex --usage-sign | Out-Host

$envLines = @(
    "`$env:PKCS11_FIXTURE_ROOT = '$fixtureRoot'"
    "`$env:PKCS11_FIXTURE_ENV_FILE = '$envFilePath'"
    "`$env:PKCS11_SOFTHSM_ROOT = '$softHsmRoot'"
    "`$env:SOFTHSM2_CONF = '$softHsmConf'"
    "`$env:PATH = '$softhsmBinPath;$softhsmLibPath;' + `$env:PATH"
    "`$env:PKCS11_MODULE_PATH = '$modulePath'"
    "`$env:PKCS11_TOOL_PATH = '$pkcs11ToolPath'"
    "`$env:PKCS11_TOKEN_LABEL = '$tokenLabel'"
    "`$env:PKCS11_USER_PIN = '$userPin'"
    "`$env:PKCS11_SO_PIN = '$soPin'"
    "`$env:PKCS11_FIND_LABEL = '$aesLabel'"
    "`$env:PKCS11_FIND_ID_HEX = '$aesIdHex'"
    "`$env:PKCS11_FIND_CLASS = 'secret'"
    "`$env:PKCS11_FIND_KEY_TYPE = 'aes'"
    "`$env:PKCS11_REQUIRE_ENCRYPT = 'true'"
    "`$env:PKCS11_REQUIRE_DECRYPT = 'true'"
    "`$env:PKCS11_MECHANISM = '0x1085'"
    "`$env:PKCS11_MECHANISM_PARAM_HEX = '00112233445566778899AABBCCDDEEFF'"
    "`$env:PKCS11_MULTIPART = 'true'"
    "`$env:PKCS11_OPERATION_STATE = 'true'"
    "`$env:PKCS11_MULTIPART_IV_HEX = '00112233445566778899AABBCCDDEEFF'"
    "`$env:PKCS11_MULTIPART_PLAINTEXT_HEX = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'"
    "`$env:PKCS11_MULTIPART_BUFFER_BLOCK_HEX = '202122232425262728292A2B2C2D2E2F'"
    "`$env:PKCS11_MULTIPART_PAD_PLAINTEXT_HEX = '30313233343536373839414243444546'"
    "`$env:PKCS11_SMOKE_PLAINTEXT = 'pkcs11-wrapper-smoke'"
    "`$env:PKCS11_DIGEST_MECHANISM = '0x250'"
    "`$env:PKCS11_DIGEST_MECHANISM_PARAM_HEX = ''"
    "`$env:PKCS11_DIGEST_DATA = 'pkcs11-wrapper-digest-smoke'"
    "`$env:PKCS11_RANDOM_LENGTH = '32'"
    "`$env:PKCS11_SIGN_MECHANISM = '0x40'"
    "`$env:PKCS11_SIGN_FIND_LABEL = '$rsaLabel'"
    "`$env:PKCS11_SIGN_FIND_ID_HEX = '$rsaIdHex'"
    "`$env:PKCS11_SIGN_FIND_CLASS = 'private'"
    "`$env:PKCS11_SIGN_FIND_KEY_TYPE = 'rsa'"
    "`$env:PKCS11_SIGN_REQUIRE_SIGN = 'true'"
    "`$env:PKCS11_VERIFY_FIND_LABEL = '$rsaLabel'"
    "`$env:PKCS11_VERIFY_FIND_ID_HEX = '$rsaIdHex'"
    "`$env:PKCS11_VERIFY_FIND_CLASS = 'public'"
    "`$env:PKCS11_VERIFY_FIND_KEY_TYPE = 'rsa'"
    "`$env:PKCS11_VERIFY_REQUIRE_VERIFY = 'true'"
    "`$env:PKCS11_SIGN_DATA = 'pkcs11-wrapper-sign-smoke'"
    "`$env:PKCS11_OBJECT_LIFECYCLE = 'true'"
    "`$env:PKCS11_OBJECT_APPLICATION = 'phase8-ci'"
    "`$env:PKCS11_OBJECT_VALUE_HEX = '50382D4349'"
    "`$env:PKCS11_PROVISIONING_REGRESSION = '1'"
    "`$env:PKCS11_GENERATE_KEYS = 'true'"
    "`$env:PKCS11_GENERATE_AES_LABEL = 'phase12-smoke-aes'"
    "`$env:PKCS11_GENERATE_AES_ID_HEX = 'C1'"
    "`$env:PKCS11_GENERATE_AES_IV_HEX = '00112233445566778899AABBCCDDEEFF'"
    "`$env:PKCS11_GENERATE_AES_PLAINTEXT = 'pkcs11-wrapper-generate-aes-smoke'"
    "`$env:PKCS11_GENERATE_RSA_LABEL = 'phase12-smoke-rsa'"
    "`$env:PKCS11_GENERATE_RSA_ID_HEX = 'D2'"
    "`$env:PKCS11_GENERATE_RSA_SIGN_DATA = 'pkcs11-wrapper-generate-rsa-smoke'"
    "`$env:PKCS11_WRAP_UNWRAP = 'true'"
    "`$env:PKCS11_WRAP_KEY_LABEL = '$aesLabel'"
    "`$env:PKCS11_WRAP_KEY_ID_HEX = '$aesIdHex'"
    "`$env:PKCS11_WRAP_UNWRAP_IV_HEX = '00112233445566778899AABBCCDDEEFF'"
    "`$env:PKCS11_WRAP_UNWRAP_PLAINTEXT = 'pkcs11-wrapper-wrap-unwrap-smoke'"
    "`$env:PKCS11_DERIVE_EC = 'true'"
    "`$env:PKCS11_DERIVE_EC_IV_HEX = '00112233445566778899AABBCCDDEEFF'"
    "`$env:PKCS11_DERIVE_EC_PLAINTEXT = 'pkcs11-wrapper-derive-ecdh-smoke'"
)
$envLines | Set-Content -LiteralPath $envFilePath -Encoding utf8

& $pkcs11ToolPath --module $modulePath --token-label $tokenLabel --login --pin $userPin --list-objects | Out-Host

Write-Host "Fixture environment file: $envFilePath"
Write-Host "Load with: . '$envFilePath'"
