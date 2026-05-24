# yint PowerShell 7 版

`libs/ps/Yint.psm1` 面向 PowerShell 7+。模块使用 typed parameter、
`DateTimeOffset.ToUnixTimeSeconds()` 与 `ProcessStartInfo.ArgumentList`。

所有明文和密文 body 均使用小写 `hex`：

```powershell
Import-Module ./Yint.psm1

$master = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
$req = New-YintRequest -MasterHex $master -Method POST -Uri '/api/echo' -PlaintextHex '68656c6c6f'
$plainHex = Open-YintRequest -MasterHex $master -Method POST -Uri '/api/echo' `
  -Timestamp $req.Timestamp -Nonce $req.Nonce -Sign $req.Sign -BodyHex $req.BodyHex
```

可配置环境变量：

- `YINT_CORE`：`core/bin/yint` 路径
- `YINT_TIME_WINDOW`：时间窗，默认 `300`
- `YINT_NONCE_FILE`：服务端 nonce 表文件
