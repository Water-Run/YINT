# Windows PowerShell 5.1 兼容模块. 所有 body 与 plaintext 参数均为小写 hex.

Set-StrictMode -Version 2.0

$script:YintCore = if ($env:YINT_CORE) { $env:YINT_CORE } else { Join-Path $PSScriptRoot '..\..\core\bin\yint.exe' }
if (-not (Test-Path -LiteralPath $script:YintCore)) {
    $script:YintCore = Join-Path $PSScriptRoot '..\..\core\bin\yint'
}
$script:YintTimeWindow = if ($env:YINT_TIME_WINDOW) { [int]$env:YINT_TIME_WINDOW } else { 300 }
$script:YintNonceFile = if ($env:YINT_NONCE_FILE) { $env:YINT_NONCE_FILE } else { Join-Path ([IO.Path]::GetTempPath()) 'yint-nonces.txt' }

function New-YintException {
    param([string]$Message, [int]$Status)
    $ex = New-Object System.Exception $Message
    $ex.Data['Status'] = $Status
    return $ex
}

function Get-YintUnixTime {
    $epoch = Get-Date -Date '1970-01-01T00:00:00Z'
    return [int64]([DateTime]::UtcNow - $epoch).TotalSeconds
}

function Test-YintLowerHex {
    param([string]$Value, [int]$Length)
    return $Value.Length -eq $Length -and $Value -cmatch '^[0-9a-f]+$'
}

function Invoke-YintCore {
    param([string[]]$Arguments, [string]$InputText)
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $script:YintCore
    $quoted = @()
    foreach ($arg in $Arguments) {
        $quoted += '"' + ($arg -replace '"', '\"') + '"'
    }
    $psi.Arguments = $quoted -join ' '
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $proc = [Diagnostics.Process]::Start($psi)
    if ($null -eq $proc) {
        throw (New-YintException 'cannot run core' 500)
    }
    if ($null -ne $InputText) {
        $proc.StandardInput.Write($InputText)
    }
    $proc.StandardInput.Close()
    $out = $proc.StandardOutput.ReadToEnd()
    $err = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0) {
        $tag = $err.Trim()
        if ($tag.Length -eq 0) {
            $tag = $out.Trim()
        }
        throw (New-YintException "core failed: $tag" 500)
    }
    return $out.Trim()
}

function Get-YintKeys {
    param([string]$MasterHex)
    $parts = (Invoke-YintCore -Arguments @('derive', $MasterHex)) -split '\s+'
    if ($parts.Count -ne 2 -or -not (Test-YintLowerHex $parts[0] 64) -or -not (Test-YintLowerHex $parts[1] 64)) {
        throw (New-YintException 'bad derive output' 500)
    }
    New-Object psobject -Property @{ KEncHex = $parts[0]; KMacHex = $parts[1] }
}

function New-YintRequest {
    param([string]$MasterHex, [string]$Method, [string]$Uri, [string]$PlaintextHex)
    $keys = Get-YintKeys $MasterHex
    $methodUpper = $Method.ToUpperInvariant()
    $timestamp = [string](Get-YintUnixTime)
    $nonce = Invoke-YintCore -Arguments @('random', '16')
    $iv = Invoke-YintCore -Arguments @('random', '16')
    $bodyHex = Invoke-YintCore -Arguments @('build-body', $keys.KEncHex, $iv, '-') -InputText $PlaintextHex
    $sign = Invoke-YintCore -Arguments @('sign-req', $keys.KMacHex, $methodUpper, $Uri, $timestamp, $nonce, '-') -InputText $bodyHex
    New-Object psobject -Property @{ Timestamp = $timestamp; Nonce = $nonce; Sign = $sign; BodyHex = $bodyHex }
}

function New-YintResponse {
    param([string]$MasterHex, [int]$Status, [string]$RequestNonce, [string]$PlaintextHex)
    $keys = Get-YintKeys $MasterHex
    $timestamp = [string](Get-YintUnixTime)
    $nonce = Invoke-YintCore -Arguments @('random', '16')
    $iv = Invoke-YintCore -Arguments @('random', '16')
    $bodyHex = Invoke-YintCore -Arguments @('build-body', $keys.KEncHex, $iv, '-') -InputText $PlaintextHex
    $sign = Invoke-YintCore -Arguments @('sign-resp', $keys.KMacHex, [string]$Status, $timestamp, $nonce, $RequestNonce, '-') -InputText $bodyHex
    New-Object psobject -Property @{ Timestamp = $timestamp; Nonce = $nonce; Sign = $sign; BodyHex = $bodyHex }
}

function Clear-YintNonceFile {
    param([int64]$Now, [string]$NonceFile = $script:YintNonceFile)
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
    param(
        [string]$MasterHex,
        [string]$Method,
        [string]$Uri,
        [string]$Timestamp,
        [string]$Nonce,
        [string]$Sign,
        [string]$BodyHex,
        [int]$TimeWindow = $script:YintTimeWindow,
        [string]$NonceFile = $script:YintNonceFile
    )
    if ($Timestamp -notmatch '^[0-9]+$' -or -not (Test-YintLowerHex $Nonce 32) -or -not (Test-YintLowerHex $Sign 64)) {
        throw (New-YintException 'bad yint headers' 400)
    }
    $now = Get-YintUnixTime
    $ts = [int64]$Timestamp
    if ([Math]::Abs($now - $ts) -gt $TimeWindow) {
        throw (New-YintException 'unauthorized' 401)
    }
    Clear-YintNonceFile -Now $now -NonceFile $NonceFile
    if ((Test-Path -LiteralPath $NonceFile) -and (Select-String -LiteralPath $NonceFile -Pattern "^$Nonce " -Quiet)) {
        throw (New-YintException 'unauthorized' 401)
    }
    $keys = Get-YintKeys $MasterHex
    try {
        $out = Invoke-YintCore -Arguments @('verify-req', $keys.KMacHex, $Method.ToUpperInvariant(), $Uri, $Timestamp, $Nonce, $Sign, '-') -InputText $BodyHex
    } catch {
        if ($_.Exception.Message.Contains('ERR_SIGN')) {
            throw (New-YintException 'unauthorized' 401)
        }
        throw
    }
    if ($out -ne 'OK') {
        throw (New-YintException 'unauthorized' 401)
    }
    Add-Content -LiteralPath $NonceFile -Value "$Nonce $($ts + $TimeWindow)" -Encoding ASCII
    Invoke-YintCore -Arguments @('decrypt-body', $keys.KEncHex, '-') -InputText $BodyHex
}

function Open-YintResponse {
    param(
        [string]$MasterHex,
        [int]$Status,
        [string]$RequestNonce,
        [string]$Timestamp,
        [string]$Nonce,
        [string]$Sign,
        [string]$BodyHex,
        [int]$TimeWindow = $script:YintTimeWindow
    )
    if ($Timestamp -notmatch '^[0-9]+$' -or -not (Test-YintLowerHex $RequestNonce 32) -or -not (Test-YintLowerHex $Nonce 32) -or -not (Test-YintLowerHex $Sign 64)) {
        throw (New-YintException 'bad yint headers' 400)
    }
    if ([Math]::Abs((Get-YintUnixTime) - [int64]$Timestamp) -gt $TimeWindow) {
        throw (New-YintException 'unauthorized' 401)
    }
    $keys = Get-YintKeys $MasterHex
    try {
        $out = Invoke-YintCore -Arguments @('verify-resp', $keys.KMacHex, [string]$Status, $Timestamp, $Nonce, $RequestNonce, $Sign, '-') -InputText $BodyHex
    } catch {
        if ($_.Exception.Message.Contains('ERR_SIGN')) {
            throw (New-YintException 'unauthorized' 401)
        }
        throw
    }
    if ($out -ne 'OK') {
        throw (New-YintException 'unauthorized' 401)
    }
    Invoke-YintCore -Arguments @('decrypt-body', $keys.KEncHex, '-') -InputText $BodyHex
}

Export-ModuleMember -Function Get-YintKeys,New-YintRequest,Open-YintRequest,New-YintResponse,Open-YintResponse
