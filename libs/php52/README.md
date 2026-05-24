# `libs/php52`

这是 `yint` 的 PHP 5.2 兼容库。PHP 层只做 HTTP 接入、时间窗和 nonce 表；密码学与协议字节级操作由 `../../core/bin/yint` CLI 完成。

## 要求

- PHP 5.2 或更新版本。
- `proc_open`、`escapeshellarg`、`pack`、`bin2hex` 可用。
- 已构建 `core/bin/yint`。默认路径为 `../../core/bin/yint`，也可以在构造函数中显式传入。

## 使用

```php
require_once 'libs/php52/Yint.php';

$master_key = 'replace-with-at-least-32-random-bytes';
$yint = new Yint($master_key);              // 默认 core 路径, time_window=300
// $yint = new Yint($master_key, '/path/to/yint', 300);
```

## 改造示例

客户端改造前，常见代码直接把明文 JSON 发给老接口：

```php
$url = 'http://legacy.example.com/api/echo?x=1';
$plain = '{"hello":"yint"}';

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $plain);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    'Content-Type: application/json'
));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$resp_plain = curl_exec($ch);
$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
```

客户端改造后，业务 JSON 不变，只把 HTTP body 换成 `yint` 密文，并附加三个协议头；收到响应后再校验和解密：

```php
require_once 'libs/php52/Yint.php';

$yint = new Yint($master_key, '/path/to/core/bin/yint', 300);
$uri = '/api/echo?x=1';
$plain = '{"hello":"yint"}';
$req = $yint->build_request('POST', $uri, $plain);

$header_lines = array('Content-Type: application/octet-stream');
foreach ($req['headers'] as $name => $value) {
    $header_lines[] = $name . ': ' . $value;
}

$ch = curl_init('http://legacy.example.com' . $uri);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $req['body']);
curl_setopt($ch, CURLOPT_HTTPHEADER, $header_lines);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_HEADER, 1);
$raw = curl_exec($ch);
$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
curl_close($ch);

$raw_headers = substr($raw, 0, $header_size);
$resp_body = substr($raw, $header_size);
$resp_headers = array();
foreach (explode("\n", $raw_headers) as $line) {
    $p = strpos($line, ':');
    if ($p !== false) {
        $resp_headers[strtolower(trim(substr($line, 0, $p)))] = trim(substr($line, $p + 1));
    }
}

$resp_plain = $yint->open_response($status, $req['nonce'], $resp_headers, $resp_body);
```

服务端改造前，接口通常直接读取明文 body，处理后直接输出明文响应：

```php
$body = file_get_contents('php://input');
$data = json_decode($body, true);

$out = array(
    'ok' => true,
    'echo' => $data
);

header('Content-Type: application/json');
echo json_encode($out);
```

服务端改造后，入口先打开 `yint` 请求，业务代码仍处理明文；输出前再封装成 `yint` 响应。协议层错误不封装，直接返回空 body：

```php
require_once 'libs/php52/Yint.php';

$yint = new Yint($master_key, '/path/to/core/bin/yint', 300);
$headers = $yint->collect_headers_from_server($_SERVER);
$uri = $yint->request_uri_from_server($_SERVER);
$body = file_get_contents('php://input');

try {
    $plain = $yint->open_request($_SERVER['REQUEST_METHOD'], $uri, $headers, $body);
} catch (YintException $e) {
    header('HTTP/1.1 ' . intval($e->status));
    exit;
}

$data = json_decode($plain, true);
$out = array(
    'ok' => true,
    'echo' => $data
);
$resp_plain = json_encode($out);

$resp = $yint->build_response(200, $headers['x-yint-nonce'], $resp_plain);
header('Content-Type: application/octet-stream');
$yint->send_headers($resp['headers']);
echo $resp['body'];
```

构造请求:

```php
$req = $yint->build_request('POST', '/api/echo?x=1', '{"hello":"yint"}');

// $req['headers'] 是三个 X-Yint-* 头
// $req['body'] 是二进制密文 body
// $req['nonce'] 用于之后校验响应
```

服务端打开请求:

```php
$headers = $yint->collect_headers_from_server($_SERVER);
$uri = $yint->request_uri_from_server($_SERVER);
$body = file_get_contents('php://input');

try {
    $plain = $yint->open_request($_SERVER['REQUEST_METHOD'], $uri, $headers, $body);
} catch (YintException $e) {
    header('HTTP/1.1 ' . $e->status);
    exit;
}
```

构造响应:

```php
$resp = $yint->build_response(200, $headers['x-yint-nonce'], '{"ok":true}');
$yint->send_headers($resp['headers']);
echo $resp['body'];
```

客户端打开响应:

```php
$plain = $yint->open_response(200, $req['nonce'], $resp_headers, $resp_body);
```

## API

- `new Yint($master_key, $core_path = null, $time_window = null)`
- `build_request($method, $uri, $plaintext)`
- `open_request($method, $uri, $headers, $body)`
- `build_response($status, $req_nonce, $plaintext)`
- `open_response($status, $req_nonce, $headers, $body)`
- `decrypt_body($body)`
- `collect_headers_from_server($server)`
- `request_uri_from_server($server)`
- `send_headers($headers)`

`open_request` 会检查:

- 三个必需 `X-Yint-*` 头是否存在且格式正确。
- 是否存在未知 `X-Yint-*` 头。
- 时间戳是否在 `time_window` 内。
- nonce 是否在当前 PHP 对象的内存表中重复。
- 请求签名是否正确。

注意：nonce 表是当前 PHP 进程/对象内存，不跨进程、不跨机器共享。PHP-CGI/FPM 的多进程部署无法获得全局 replay 表；这与项目协议文档中“库自行决定，不支持跨进程/跨机器共享”的定位一致。

## 测试

```sh
php libs/php52/Test.php
php libs/php52/Test.php /absolute/path/to/core/bin/yint
```

测试覆盖密钥派生、请求往返、响应往返、nonce 重放、响应绑定请求 nonce、未知 `X-Yint-*` 头拒绝。
