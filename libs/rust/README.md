# yint Rust 版

`libs/rust` 是现代 Rust 包，使用 edition 2024，运行时不引入第三方依赖。
它调用仓库中的可移植 `core/bin/yint` 可执行文件完成字节级密码学运算，并
用 Rust 实现 HTTP 协议层逻辑。

```rust
use yint::Yint;

let y = Yint::new(&master_key, None, 300)?;
let req = y.build_request("POST", "/api/echo", b"hello")?;
let plain = y.open_request("POST", "/api/echo", &req.headers, &req.body)?;
# Ok::<(), yint::YintError>(())
```

运行测试前需要先构建 core：

```sh
make -C ../../core/bin
cargo test
```
