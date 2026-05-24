# `yint` Protocol Specification

本文档定义`yint`协议的字节级行为. 任何符合本文档的实现必须可以与其它符合本文档的实现互通.  
本文档与`README.md`同级, 出现冲突时以本文档为准.  

## 约定  

- 所有"字节"以八位组(`octet`)计.  
- `||`表示字节串拼接.  
- `LF`表示单个换行符 (`0x0A`), 协议中**不使用** `CRLF`.  
- `hex(x)`表示`x`的小写十六进制编码, 无前缀, 无分隔符.  
- `utf8(s)`表示字符串`s`的`UTF-8`编码字节串.  
- `HMAC(k, m)`一律指`HMAC-SHA256(k, m)`, 输出 32 字节.  
- `AES-CBC(k, iv, p)`指`AES-256-CBC`, 密钥`k`为 32 字节, `iv`为 16 字节, 明文`p`使用`PKCS#7`填充至 16 字节倍数.  
- 所有随机量必须来自密码学安全随机源(`/dev/urandom`、`random_bytes()`、`secrets`等).  

## 密钥派生  

预共享的`master_key`是任意长度的字节串(建议 ≥ 32 字节). 双端从`master_key`派生两个独立的子密钥:  

```
K_enc = HMAC(master_key, utf8("yint/enc"))      // 32 字节, 用于 AES-256-CBC
K_mac = HMAC(master_key, utf8("yint/mac"))      // 32 字节, 用于 HMAC-SHA256
```

派生标签字符串严格固定为`yint/enc`和`yint/mac`, 仅作为派生域分隔, **不是**协议版本号, 也**不可**协商.  

## 请求  

### 请求头  

任何`yint`请求**必须**且**仅**附加以下三个 HTTP 头, 全部强制:  

| 头名               | 取值                                                 |
|--------------------|------------------------------------------------------|
| `X-Yint-Timestamp` | 当前 Unix 时间戳, 十进制秒, ASCII, 例如 `1732464000` |
| `X-Yint-Nonce`     | 16 字节随机数的小写`hex`, 共 32 字符                 |
| `X-Yint-Sign`      | 请求签名的小写`hex`, 共 64 字符                      |

头名大小写不敏感, 但取值大小写敏感(`hex`必须小写). 实现**不得**附加其它`X-Yint-*`头, 服务端遇到未知`X-Yint-*`头**应当**直接拒绝.  

### 请求体  

明文请求体`P`(可为空字节串)按下列步骤处理:  

```
IV   = 16 字节随机
C    = AES-CBC(K_enc, IV, P)
BODY = IV || C
```

`BODY`即作为 HTTP 请求体直接发送, **以原始字节传输**, 不再做`base64`或其它编码. `Content-Type`建议为`application/octet-stream`, 但服务端**不应**依赖此头. 当`P`为空时, `BODY`长度为 16(IV) + 16(一整块`PKCS#7`填充) = 32 字节, **没有**"省略请求体"这一形式.  

### 请求签名  

构造`StringToSign`(以下记为`S_req`), 各字段以单个`LF`分隔, 末尾**无**`LF`:  

```
S_req = utf8(METHOD)    || LF ||
        utf8(URI)       || LF ||
        utf8(TIMESTAMP) || LF ||
        utf8(NONCE)     || LF ||
        BODY
```

各字段定义:  

- `METHOD`: HTTP 方法, 全大写 ASCII, 例如`GET`/`POST`.  
- `URI`: 请求行中`?`之前的路径与`?`之后(若存在)直至`#`之前的查询串, **逐字节原样**取用. 既**不**做百分号解码, **不**对`query`参数排序, **不**做任何路径归一化(`/a//b`不等价于`/a/b`). 当无`?`时仅为路径, 不补尾随`?`.  
- `TIMESTAMP`: 与`X-Yint-Timestamp`头逐字节相同.  
- `NONCE`: 与`X-Yint-Nonce`头逐字节相同.  
- `BODY`: 上一节定义的`IV || C`原始字节, **直接拼接**, 不再经过`SHA256`或任何中间编码.  

由于`METHOD` / `URI` / `TIMESTAMP` / `NONCE`均为不含`LF`的可见 ASCII, `BODY`位于末尾不会与前序字段产生歧义.  

签名为:  

```
SIGN = hex(HMAC(K_mac, S_req))
```

`SIGN`即填入`X-Yint-Sign`头.  

## 响应  

### 响应头  

`yint`响应**必须**附加且仅附加以下三个头, 全部强制:  

| 头名               | 取值                                                        |
|--------------------|-------------------------------------------------------------|
| `X-Yint-Timestamp` | 服务端响应时刻的 Unix 秒                                    |
| `X-Yint-Nonce`     | 16 字节随机数的小写`hex`, 服务端独立生成, 与请求`nonce`无关 |
| `X-Yint-Sign`      | 响应签名的小写`hex`                                         |

### 响应体  

与请求体同构: `BODY' = IV' || C'`, 其中`C' = AES-CBC(K_enc, IV', P')`, `P'`为业务层明文响应.  

`IV'`必须为新的随机量, **不得**复用请求`IV`.  

### 响应签名  

```
S_resp = utf8(STATUS)         || LF ||
         utf8(RESP_TIMESTAMP) || LF ||
         utf8(RESP_NONCE)     || LF ||
         utf8(REQ_NONCE)      || LF ||
         BODY'
```

- `STATUS`: HTTP 状态码的十进制 ASCII, 例如`200`.  
- `RESP_TIMESTAMP` / `RESP_NONCE`: 响应自身的`X-Yint-Timestamp` / `X-Yint-Nonce`.  
- `REQ_NONCE`: 触发本次响应的请求的`X-Yint-Nonce`, 逐字节原样.  
- `BODY'`: 响应密文`IV' || C'`原始字节.  

```
SIGN' = hex(HMAC(K_mac, S_resp))
```

将`REQ_NONCE`绑定进响应签名, 是为了阻止攻击者把过去某次合法响应"嫁接"到一次新请求上. 客户端在校验响应时**必须**用本次发出的`nonce`计算预期签名.  

## 服务端校验流程  

服务端在把请求交给业务逻辑前, 按以下顺序执行. 任何一步失败立刻终止, 返回对应错误(见"错误处理").  

1. 三个`X-Yint-*`头是否齐全, 格式是否合法(`timestamp`为十进制整数, `nonce`为 32 位`hex`, `sign`为 64 位`hex`).  
2. `|now - timestamp| ≤ time_window`. `now`取服务端本地 Unix 秒.  
3. `nonce`不存在于`nonce`表中. 服务端`nonce`表是一个`{nonce → expire_at}`的内存映射, 同时承担"懒清理": 每次写入前可顺带剔除`expire_at < now`的项.  
4. 读取完整`BODY`字节, 按上述定义构造`S_req`, 计算预期签名. 与`X-Yint-Sign`做**常量时间比较**.  
5. 校验通过后, 将`nonce`写入`nonce`表, **`expire_at = timestamp + time_window`**(即该请求时间戳所对应的时间窗口右端点). **必须先校验、后写入**, 防止攻击者通过无效请求污染`nonce`表.  
6. 解密`BODY`得到`P`, 交给业务逻辑.  

`time_window`默认 300 秒, 是服务端唯一可调参数. 由于`nonce`的`expire_at`直接绑定到请求自身的时间戳, 任何在`time_window`内可能被重放的请求, 其`nonce`必然仍在表中; 任何已从表中清理掉的`nonce`, 其原始时间戳必然已经超出窗口, 会先在第 2 步被拒绝. 不存在边界窗口期, 也无需引入第二个 TTL 参数.  

## 客户端校验流程  

客户端收到响应后, 在把明文交给上层前, 按以下顺序执行:  

1. 三个`X-Yint-*`响应头是否齐全且格式合法.  
2. `|now - resp_timestamp| ≤ time_window`. 客户端**应当**校验此项, 以阻止响应延迟重放.  
3. 按"响应签名"一节构造`S_resp`(其中`REQ_NONCE`使用客户端**本次请求**所发的`nonce`), 计算预期签名, 与`X-Yint-Sign`常量时间比较.  
4. 解密`BODY'`得到`P'`.  

客户端**不**维护`nonce`表: 响应`nonce`仅参与签名输入, 服务端独立生成, 不需要查重.  

## 错误处理  

协议层错误**不**经过`yint`封装. 服务端在第 1–4 步任一失败时, 返回:  

- HTTP 状态码 `400` (格式错误) 或 `401` (时间戳过期 / `nonce`重放 / 签名不匹配).  
- 空响应体.  
- **不**附加任何`X-Yint-*`头.  

服务端**不得**在响应中区分"时间戳过期"、"`nonce`重放"、"签名不匹配"三种情况, 一律使用`401` + 空体, 以避免向攻击者泄露内部状态. 业务层错误(`4xx` / `5xx`)则**必须**经过完整`yint`封装, 与正常响应同构.  

客户端校验失败时, **必须**丢弃响应明文, **不得**将其交给上层.  

## 测试向量  

为保证跨语言互通, 本仓库`tests/vectors.json`提供如下结构的测试向量, 任何实现都**必须**通过:  

```json
{
  "master_key_hex": "...",
  "K_enc_hex":      "...",
  "K_mac_hex":      "...",
  "cases": [
    {
      "name":          "empty-body GET",
      "method":        "GET",
      "uri":           "/api/ping",
      "timestamp":     "1732464000",
      "nonce_hex":     "...",
      "iv_hex":        "...",
      "plaintext_hex": "",
      "body_hex":      "...",
      "string_to_sign_hex": "...",
      "sign_hex":      "..."
    }
  ]
}
```

每条 case 同时给出请求侧与响应侧的完整字段. 实现**不得**只通过其中一部分.  

## 不在本协议范围内  

下列内容**不**属于`yint`协议, 由各语言库自行决定, 不影响互通性:  

- `master_key`的存储与加载方式.  
- `nonce`表的具体数据结构与清理策略(只要其外部行为符合"`time_window`内查重"即可).  
- HTTP 框架的接入方式(`WSGI` / `mod_php` / 裸`socket`等).  
- 业务层明文`P`的格式(`JSON` / `MessagePack` / 自定义二进制等).
