# yint Zsh 版

`libs/zsh/yint.zsh` 是 macOS 常用的 Zsh 5+ 函数库和命令入口。

接口与 Bash 版一致，所有明文和密文 body 都使用小写 `hex`，避免 Shell
处理原始二进制时出现截断或编码问题。

```zsh
source ./yint.zsh
master=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
yint_build_request "$master" POST '/api/echo' 68656c6c6f
```

可配置环境变量：

- `YINT_CORE`：`core/bin/yint` 路径
- `YINT_TIME_WINDOW`：时间窗，默认 `300`
- `YINT_NONCE_FILE`：服务端 nonce 表文件
