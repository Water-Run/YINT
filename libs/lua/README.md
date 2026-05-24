# yint Lua 版

`libs/lua` 是 Lua 5.1+ 库。它调用仓库中的 `core/bin/yint` 完成字节级
密码学运算，并在 Lua 层实现 HTTP 头校验、时间窗、nonce 表和请求/响应封装。

```lua
local yint = require("yint")

local master = yint.hex_to_bin("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
local Y = yint.Yint.new(master)

local req = Y:build_request("POST", "/api/echo", "hello")
local plain = Y:open_request("POST", "/api/echo", req.headers, req.body)
```

运行测试前需要先构建 core：

```sh
make -C ../../core/bin
lua Test.lua ../../core/bin/yint
```

接口说明：

- `Yint.new(master_key, opts)`：创建实例。`master_key` 是 Lua 二进制字符串。
- `build_request(method, uri, plaintext)`：返回 `{ headers, body, nonce }`。
- `open_request(method, uri, headers, body)`：校验并解密请求，返回明文字符串。
- `build_response(status, req_nonce, plaintext)`：返回 `{ headers, body }`。
- `open_response(status, req_nonce, headers, body)`：校验并解密响应。
- `opts.core_path` 可指定 `core/bin/yint` 路径。
- `opts.time_window` 可指定时间窗，默认 `300` 秒。
