# yint Windows PowerShell 5.1 版

`libs/ps5/Yint.psm1` 面向 Windows PowerShell 5.1，避免使用 PowerShell 7
专有语法。接口与 PowerShell 7 版一致。

所有明文和密文 body 均使用小写 `hex`：

```powershell
Import-Module .\Yint.psm1

$master = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'
$req = New-YintRequest -MasterHex $master -Method POST -Uri '/api/echo' -PlaintextHex '68656c6c6f'
```

可配置环境变量：

- `YINT_CORE`：`core\bin\yint.exe` 路径
- `YINT_TIME_WINDOW`：时间窗，默认 `300`
- `YINT_NONCE_FILE`：服务端 nonce 表文件
