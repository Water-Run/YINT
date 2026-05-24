# yint Fish 版

`libs/fish/yint.fish` 是 Fish 3+ 函数库，`libs/fish/yint-cli.fish` 是命令入口。
接口与 Bash/Zsh 版一致，所有明文和密文 body 均使用小写 `hex`。

```fish
source ./yint.fish
set master 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
yint_build_request $master POST /api/echo 68656c6c6f
```

也可以直接调用命令入口：

```fish
fish ./yint-cli.fish build-request $master POST /api/echo 68656c6c6f
```

可配置环境变量：

- `YINT_CORE`：`core/bin/yint` 路径
- `YINT_TIME_WINDOW`：时间窗，默认 `300`
- `YINT_NONCE_FILE`：服务端 nonce 表文件
