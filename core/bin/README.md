# `yint-core` / `yint` CLI

`core/bin/`是`yint`协议的**通用 C 核心**与配套**测试驱动 CLI**.  
单源 C99, 单一可执行文件, 兼容从 Windows XP 到 Windows 11、Linux 7 到现代发行版、macOS 26 (Apple Silicon + Intel).  
本目录的实现是协议字节级行为的**参考与基准**, 与协议规范保持一字不差; 任何符合`Protocol.md`的实现都应当能与本 CLI 互通.  

## 角色定位  

`core/bin`同时承担两个角色:  

1. **参考实现 / 性能基准**.  
   提供协议要求的全部底层运算: `SHA-256`、`HMAC-SHA256`、`AES-256-CBC` + `PKCS#7`、`CSPRNG`、小写`hex`、常量时间比较, 以及上层的密钥派生、`body`构造、请求/响应签名与校验.  

2. **跨语言测试驱动**.  
   `yint-test.lua` 经由 `io.popen` 调用本目录的 CLI 验证协议字节级正确性. 同样的 CLI 也可被`libs/py312`(`subprocess`) 与 `libs/php52`(`proc_open`) 复用, 用作"对照实现"以确认互通.  

本目录**不**接管 `HTTP` 监听, **不**维护 `nonce` 表, **不**读配置(协议 §"不在本协议范围内"). 这些由各语言库自理.  

## 文件布局  

```
core/bin/
├── README.md           本文件
├── Makefile            多平台目标
├── yint-core.h         公共 C API (二进制稳定)
├── yint-core.c         单 TU 实现: 软实现后端 + 协议层
├── yint-aesni.c        x86/x64 AES-NI 后端(运行时分派)
├── yint-cli.c          子命令派发 main()
└── yint-test.lua       回归测试(纯 Lua, 无 C 模块)
```

## 兼容性矩阵

| 平台                            | 工具链                                                        | 备注                                                |
|---------------------------------|---------------------------------------------------------------|-----------------------------------------------------|
| Windows XP / Server 2003        | `i686-w64-mingw32-gcc`, `-D_WIN32_WINNT=0x0501 -static`       | CSPRNG 走`RtlGenRandom` (`advapi32!SystemFunction036`), XP→11 全通 |
| Windows 7 / 8 / 10 / 11 (32/64) | MinGW-w64 任一; MSVC 亦可                                     | 同一 32 位可执行文件可在 XP 起跑                    |
| Linux 7 (CentOS/RHEL 7)         | `gcc 4.8.5`, `glibc 2.17`, `-O2 -std=c99 -static-libgcc`      | 优先`getrandom(2)` (内核 ≥ 3.17), 回退`/dev/urandom`|
| Linux 现代发行版                | 同上                                                          | 默认动态链接                                        |
| macOS 26 (Apple Silicon + Intel)| `clang -arch arm64 -arch x86_64 -mmacosx-version-min=11.0`    | 使用`arc4random_buf`                                |

## 构建  

```sh
make             # 本机 native (默认)
make linux       # Linux 显式
make macos       # macOS, 双架构 universal binary
make win32-xp    # 32 位 Windows, XP 起兼容, 静态链接
make win64       # 64 位 Windows, 静态链接
make test        # = make && lua yint-test.lua
make clean
```

完整地, 强制使用软实现(用于审计或在不信任 CPU 时):  

```sh
make CC=cc CFLAGS="-O2 -std=c99 -DYINT_NO_AESNI -fvisibility=hidden"
```

## 运行时后端分派  

x86/x86_64 上, 启动时一次性 `cpuid (leaf 1)` 检测 ECX 第 25 位(`AES`)和第 19 位(`SSE4.1`):  

- 两者皆置位 → 安装 AES-NI 后端 (`yint info` 报告 `backend=aesni`).  
- 否则 → 保留软实现 (`backend=soft`).  

`yint-aesni.c` 内的 intrinsics **永远在分派后才被调用**, 因此即便编译时启用 `-maes -msse4.1`, 旧 CPU 上也不会触发 illegal instruction.  

非 x86 架构(如 ARM64)由 Makefile 自动跳过 `yint-aesni.o`, 可执行文件仍可用, 走纯 C 软实现.  

## CLI 用法

```
yint info
yint random       <nbytes>
yint sha256       <msg_hex>
yint hmac         <key_hex> <msg_hex>
yint derive       <master_hex>
yint aes-enc      <key32_hex> <iv16_hex> <plain_hex>
yint aes-dec      <key32_hex> <iv16_hex> <cipher_hex>
yint build-body   <kenc_hex> <iv16_hex> <plain_hex>
yint decrypt-body <kenc_hex> <body_hex>
yint sign-req     <kmac_hex> <method> <uri> <ts> <nonce_hex> <body_hex>
yint sign-resp    <kmac_hex> <status> <resp_ts> <resp_nonce_hex> <req_nonce_hex> <body_hex>
yint verify-req   <kmac_hex> <method> <uri> <ts> <nonce_hex> <sign_hex> <body_hex>
yint verify-resp  <kmac_hex> <status> <resp_ts> <resp_nonce_hex> <req_nonce_hex> <sign_hex> <body_hex>
```

约定:

- 所有字节输入 / 输出都使用**小写 hex**, 与协议 §约定一致.
- 任何 `*_hex` 实参可写为 `-`, 此时 CLI 从 stdin 读取该参数(便于大 body 测试或 shell 命令行长度受限的环境).
- 成功写 stdout, 末尾**单个** LF, 退出码 0.
- 错误写 stderr 一个稳定 token, 退出码 1. token 集合(便于跨语言断言):
  - `ERR_USAGE` 子命令参数数量错
  - `ERR_FORMAT` hex 长度 / 字符不合法, 或长度约束不满足(`key`非 32 字节、`iv` 非 16 字节、`body` 非 16 倍数等)
  - `ERR_PADDING` `PKCS#7` 填充不合法
  - `ERR_SIGN` `verify-*` 签名不匹配
  - `ERR_RANDOM` CSPRNG 失败
  - `ERR_INTERNAL` 其它

每个子命令对协议 §的对应:  

| 子命令         | 协议章节                                |
|----------------|-----------------------------------------|
| `derive`       | §密钥派生                               |
| `build-body`   | §请求体 / §响应体 (`IV \|\| C`)         |
| `decrypt-body` | §服务端校验流程 步骤 6, §客户端校验 步骤 4 |
| `sign-req`     | §请求签名                               |
| `sign-resp`    | §响应签名                               |
| `verify-req`   | §服务端校验 步骤 4(常量时间比较)        |
| `verify-resp`  | §客户端校验 步骤 3                      |

CLI **不**实现`time_window`时间窗校验, 也**不**维护`nonce`表; 这些是各语言库的服务端逻辑职责, 不影响协议字节级输出.  

## 嵌入到其它项目  

任何 C/C++ 项目都可以直接链接 `yint-core.o` (在 x86 上一并加 `yint-aesni.o`):  

```c
#include "yint-core.h"

uint8_t k_enc[32], k_mac[32];
yint_derive_keys(master, master_len, k_enc, k_mac);

uint8_t iv[16];
yint_random(iv, 16);

uint8_t body[1024];
size_t body_len = sizeof(body);
yint_build_body(k_enc, iv, plain, plain_len, body, &body_len);

char sig_hex[64];
yint_sign_request(k_mac,
                  "POST", (size_t)-1,
                  "/api/echo", (size_t)-1,
                  "1732464200", (size_t)-1,
                  nonce_hex, 32,
                  body, body_len,
                  sig_hex);
```

详见 `yint-core.h`. 头文件保证 ABI 稳定, 函数前缀 `yint_*` 在 1.x 系列内不会破坏性变更.  

## 测试  

```sh
make test
```

`yint-test.lua` 用纯 Lua 调用 CLI, 依次跑 10 组共 60+ 用例:  

- **A**. SHA-256 / HMAC-SHA256 标准向量(`NIST` & `RFC 4231`).  
- **B**. AES-256-CBC NIST `F.2.5` + `PKCS#7` 边界(`plen` ∈ {0,15,16,17,31,32}).  
- **C**. 密钥派生(交叉校验`derive`与直接`HMAC(master, "yint/enc")`/`HMAC(master, "yint/mac")`).  
- **D**. `build-body == IV || AES-CBC(K_enc, IV, plain)` 字节布局.  
- **E**. 4 条请求签名回归向量, hex 写死, 任何破坏协议字节输出的改动会立即被发现; 包括含 query 的 GET、含 UTF-8 body 的 POST、`URI=/a//b` 不归一化.  
- **F**. 响应签名 + `REQ_NONCE` 绑定否定测试.  
- **G**. 端到端往返: 客户端 `build → sign-req`, 服务端 `verify-req → decrypt → build → sign-resp`, 客户端 `verify-resp → decrypt`.  
- **H**. 否定 / 错误路径(篡改 body、篡改 sign、坏 hex、坏长度、坏 padding).  
- **I**. CSPRNG 简单去重(200 次 16 字节采样应 100% 唯一).  
- **J**. CLI 元信息 (`info` 报告版本与后端).  

测试器的 Lua 层兼容 `5.1` / `5.2` / `5.3` / `5.4` / `5.5` / `LuaJIT`. 跨平台 argv 引用同时考虑 POSIX shell 与 `cmd.exe` 的差异.  

## 性能  

在现代 x86 上, AES-NI 后端的 `AES-256-CBC` 吞吐与 `OpenSSL` 同量级(单线程数 GB/s); 软实现处理协议典型 KB 级 `body` 的延迟在微秒级, 已远低于一次 HTTP 往返的网络延迟. `SHA-256` 与 `HMAC-SHA256` 全程纯 C, 协议层每次签名涉及一次 HMAC, 耗时通常 < 5μs.  

## 安全声明  

- 软实现的 `AES` 使用纯字节版本 `S-box`, **不是常量时间**. 在与项目根 `README.md` §安全性一致的威胁模型下(信任执行环境、不防御本地侧信道), 这是有意的取舍, 用以满足`PHP 5.2`与老旧目标平台的兼容性.  
  - 在 x86 上, AES-NI 路径的 `AESENC/AESDEC` 在硬件层是常量时间, 选择该后端可缓解一部分计时风险.  
- `CSPRNG` 来源:  
  - **Windows**: `RtlGenRandom`(`advapi32!SystemFunction036`) — XP 至 11 一致.  
  - **Linux**: `getrandom(2)` (`SYS_getrandom`) 优先, 不可用时回退到阻塞读 `/dev/urandom`.  
  - **macOS**: `arc4random_buf`.  
- HMAC 验证使用常量时间字节比较 (`yint_consttime_eq`).  
- `yint_random` 失败时返回 `YINT_ERR_RANDOM`, **不**回退到非密码学源.  

更全面的威胁模型陈述见仓库根 `README.md` §安全性.  

## 许可  

随仓库 `LGPL`. 详见 `../../LICENSE`.  
