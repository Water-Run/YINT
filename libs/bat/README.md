# yint Windows BAT 版

`libs/bat/yint.bat` 是经典 Windows Batch 命令入口。由于 `cmd.exe` 不适合
安全处理原始二进制，接口统一使用小写 `hex`：

- 明文输入为 `PLAINTEXT_HEX`
- 密文输出为 `body_hex`
- 发 HTTP 时由调用方把 `body_hex` 转成原始字节

示例：

```bat
set MASTER=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
call yint.bat build-request %MASTER% POST /api/echo 68656c6c6f
```

可配置环境变量：

- `YINT_CORE`：`core\bin\yint.exe` 路径
- `YINT_TIME_WINDOW`：时间窗，默认 `300`
- `YINT_NONCE_FILE`：服务端 nonce 表文件

BAT 版为了取得 Unix 秒时间戳，会调用系统自带的 `powershell -NoProfile`
执行一条时间计算命令；协议运算仍全部由 `core/bin/yint` 完成。
