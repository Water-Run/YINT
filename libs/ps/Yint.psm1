Set-StrictMode -Version Latest

# PowerShell 7+ 模块. 所有 body 与 plaintext 参数均为小写 hex.

$script:YintCore = if ($env:YINT_CORE) { $env:YINT_CORE } else { Join-Path $PSScriptRoot '../../core/bin/yint' }
$script:YintTimeWindow = if ($env:YINT_TIME_WINDOW) { [int]$env:YINT_TIME_WINDOW } else { 300 }
$script:YintNonceFile = if ($env:YINT_NONCE_FILE) { $env:YINT_NONCE_FILE } else { Join-Path ([IO.Path]::GetTempPath()) 'yint-nonces.txt' }

class YintException : System.Exception {
    [int] $Status

    YintException([string] $Message, [int] $Status) : base($Message) {
        $this.Status = $Status
    }
}

function Get-YintUnixTime {
    [OutputType([int64])]
    param()
    return [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
}

function Test-YintLowerHex {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string] $Value,
        [Parameter(Mandatory)][int] $Length
    )
    return $Value.Length -eq $Length -and $Value -cmatch '^[0-9a-f]+$'
}

function Invoke-YintCore {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string[]] $Arguments,
        [string] $InputText
    )
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $script:YintCore
    foreach ($arg in $Arguments) {
        [void]$psi.ArgumentList.Add($arg)
    }
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $proc = [Diagnostics.Process]::Start($psi)
    if ($null -eq $proc) {
        throw [YintException]::new('cannot run core', 500)
    }
    if ($null -ne $InputText) {
        $proc.StandardInput.Write($InputText)
    }
    $proc.StandardInput.Close()
    $out = $proc.StandardOutput.ReadToEnd()
    $err = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0) {
        $tag = if ($err.Trim().Length -gt 0) { $err.Trim() } else { $out.Trim() }
        throw [YintException]::new("core failed: $tag", 500)
    }
    return $out.Trim()
}

function Get-YintKeys {
    param([Parameter(Mandatory)][string] $MasterHex)
    $parts = (Invoke-YintCore -Arguments @('derive', $MasterHex)) -split '\s+'
    if ($parts.Count -ne 2 -or -not (Test-YintLowerHex $parts[0] 64) -or -not (Test-YintLowerHex $parts[1] 64)) {
        throw [YintException]::new('bad derive output', 500)
    }
    [pscustomobject]@{ KEncHex = $parts[0]; KMacHex = $parts[1] }
}

function New-YintRequest {
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string] $MasterHex,
        [Parameter(Mandatory)][string] $Method,
        [Parameter(Mandatory)][string] $Uri,
        [Parameter(Mandatory)][string] $PlaintextHex
    )
    $keys = Get-YintKeys $MasterHex
    $methodUpper = $Method.ToUpperInvariant()
    $timestamp = [string](Get-YintUnixTime)
    $nonce = Invoke-YintCore -Arguments @('random', '16')
    $iv = Invoke-YintCore -Arguments @('random', '16')
    $bodyHex = Invoke-YintCore -Arguments @('build-body', $keys.KEncHex, $iv, '-') -InputText $PlaintextHex
    $sign = Invoke-YintCore -Arguments @('sign-req', $keys.KMacHex, $methodUpper, $Uri, $timestamp, $nonce, '-') -InputText $bodyHex
    [pscustomobject]@{
        Timestamp = $timestamp
        Nonce = $nonce
        Sign = $sign
        BodyHex = $bodyHex
    }
}

function New-YintResponse {
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string] $MasterHex,
        [Parameter(Mandatory)][int] $Status,
        [Parameter(Mandatory)][string] $RequestNonce,
        [Parameter(Mandatory)][string] $PlaintextHex
    )
    $keys = Get-YintKeys $MasterHex
    $timestamp = [string](Get-YintUnixTime)
    $nonce = Invoke-YintCore -Arguments @('random', '16')
    $iv = Invoke-YintCore -Arguments @('random', '16')
    $bodyHex = Invoke-YintCore -Arguments @('build-body', $keys.KEncHex, $iv, '-') -InputText $PlaintextHex
    $sign = Invoke-YintCore -Arguments @('sign-resp', $keys.KMacHex, [string]$Status, $timestamp, $nonce, $RequestNonce, '-') -InputText $bodyHex
    [pscustomobject]@{
        Timestamp = $timestamp
        Nonce = $nonce
        Sign = $sign
        BodyHex = $bodyHex
    }
}

function Clear-YintNonceFile {
    param(
        [Parameter(Mandatory)][int64] $Now,
        [string] $NonceFile = $script:YintNonceFile
    )
    $dir = Split-Path -Parent $NonceFile
    if ($dir) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    $kept = @()
    if (Test-Path -LiteralPath $NonceFile) {
        foreach ($line in Get-Content -LiteralPath $NonceFile) {
            $parts = $line -split '\s+'
            if ($parts.Count -eq 2 -and $parts[1] -match '^[0-9]+$' -and [int64]$parts[1] -ge $Now) {
                $kept += $line
            }
        }
    }
    Set-Content -LiteralPath $NonceFile -Value $kept -Encoding ASCII
}

function Open-YintRequest {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string] $MasterHex,
        [Parameter(Mandatory)][string] $Method,
        [Parameter(Mandatory)][string] $Uri,
        [Parameter(Mandatory)][string] $Timestamp,
        [Parameter(Mandatory)][string] $Nonce,
        [Parameter(Mandatory)][string] $Sign,
        [Parameter(Mandatory)][string] $BodyHex,
        [int] $TimeWindow = $script:YintTimeWindow,
        [string] $NonceFile = $script:YintNonceFile
    )
    if ($Timestamp -notmatch '^[0-9]+$' -or -not (Test-YintLowerHex $Nonce 32) -or -not (Test-YintLowerHex $Sign 64)) {
        throw [YintException]::new('bad yint headers', 400)
    }
    $now = Get-YintUnixTime
    $ts = [int64]$Timestamp
    if ([Math]::Abs($now - $ts) -gt $TimeWindow) {
        throw [YintException]::new('unauthorized', 401)
    }
    Clear-YintNonceFile -Now $now -NonceFile $NonceFile
    if ((Test-Path -LiteralPath $NonceFile) -and (Select-String -LiteralPath $NonceFile -Pattern "^$Nonce " -Quiet)) {
        throw [YintException]::new('unauthorized', 401)
    }
    $keys = Get-YintKeys $MasterHex
    try {
        $out = Invoke-YintCore -Arguments @('verify-req', $keys.KMacHex, $Method.ToUpperInvariant(), $Uri, $Timestamp, $Nonce, $Sign, '-') -InputText $BodyHex
    } catch [YintException] {
        if ($_.Exception.Message.Contains('ERR_SIGN')) {
            throw [YintException]::new('unauthorized', 401)
        }
        throw
    }
    if ($out -ne 'OK') {
        throw [YintException]::new('unauthorized', 401)
    }
    Add-Content -LiteralPath $NonceFile -Value "$Nonce $($ts + $TimeWindow)" -Encoding ASCII
    Invoke-YintCore -Arguments @('decrypt-body', $keys.KEncHex, '-') -InputText $BodyHex
}

function Open-YintResponse {
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string] $MasterHex,
        [Parameter(Mandatory)][int] $Status,
        [Parameter(Mandatory)][string] $RequestNonce,
        [Parameter(Mandatory)][string] $Timestamp,
        [Parameter(Mandatory)][string] $Nonce,
        [Parameter(Mandatory)][string] $Sign,
        [Parameter(Mandatory)][string] $BodyHex,
        [int] $TimeWindow = $script:YintTimeWindow
    )
    if ($Timestamp -notmatch '^[0-9]+$' -or -not (Test-YintLowerHex $RequestNonce 32) -or -not (Test-YintLowerHex $Nonce 32) -or -not (Test-YintLowerHex $Sign 64)) {
        throw [YintException]::new('bad yint headers', 400)
    }
    if ([Math]::Abs((Get-YintUnixTime) - [int64]$Timestamp) -gt $TimeWindow) {
        throw [YintException]::new('unauthorized', 401)
    }
    $keys = Get-YintKeys $MasterHex
    try {
        $out = Invoke-YintCore -Arguments @('verify-resp', $keys.KMacHex, [string]$Status, $Timestamp, $Nonce, $RequestNonce, $Sign, '-') -InputText $BodyHex
    } catch [YintException] {
        if ($_.Exception.Message.Contains('ERR_SIGN')) {
            throw [YintException]::new('unauthorized', 401)
        }
        throw
    }
    if ($out -ne 'OK') {
        throw [YintException]::new('unauthorized', 401)
    }
    Invoke-YintCore -Arguments @('decrypt-body', $keys.KEncHex, '-') -InputText $BodyHex
}

Export-ModuleMember -Function Get-YintKeys,New-YintRequest,Open-YintRequest,New-YintResponse,Open-YintResponse
