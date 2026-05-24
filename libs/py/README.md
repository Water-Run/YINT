# yint Python 版

`libs/py` 是现代 Python 包，要求 Python 3.12 或更新版本。它调用仓库中的
可移植 `core/bin/yint` 可执行文件完成字节级密码学运算，并用带类型注解的
Python 代码实现 HTTP 协议层逻辑。

```python
from yint import Yint

y = Yint(bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"))
req = y.build_request("POST", "/api/echo", b"hello")
plain = y.open_request("POST", "/api/echo", req.headers, req.body)
```

运行测试前需要先构建 core：

```sh
make -C ../../core/bin
python -m unittest discover -s tests
```
