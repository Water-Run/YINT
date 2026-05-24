# yint Bash 版

`libs/bash/yint.sh` 是 Bash 4+ 函数库和命令入口。它不直接处理原始二进制
HTTP body，而是统一使用小写 `hex`：

- 明文输入为 `plaintext_hex`
- 密文输出为 `body_hex`
- 调用方发送 HTTP 时，需要把 `body_hex` 转成原始字节

示例：

```sh
source ./yint.sh

master=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
req="$(yint_build_request "$master" POST '/api/echo' 68656c6c6f)"
```

可配置环境变量：

- `YINT_CORE`：`core/bin/yint` 路径
- `YINT_TIME_WINDOW`：时间窗，默认 `300`
- `YINT_NONCE_FILE`：服务端 nonce 表文件，默认 `${TMPDIR:-/tmp}/yint-nonces.txt`
