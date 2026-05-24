# yint PHP 版

`libs/php` 是现代 PHP 包，要求 PHP 8.3 或更新版本。代码使用严格类型、
命名空间、readonly DTO 和带状态码的异常；字节级密码学运算委托给
`core/bin/yint`。

```php
use Yint\Yint;

$y = new Yint(hex2bin('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff'));
$req = $y->buildRequest('POST', '/api/echo', 'hello');
$plain = $y->openRequest('POST', '/api/echo', $req->headers, $req->body);
```

运行测试前需要先构建 core：

```sh
make -C ../../core/bin
php tests/YintTest.php
```
