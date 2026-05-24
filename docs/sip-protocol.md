# SIP 协议解析详解

## 概述

SIP (Session Initiation Protocol) 是一个应用层控制协议，用于创建、修改和终止多媒体会话。本文档详细说明 SIP-Ban 如何解析和处理 SIP 协议消息。

## SIP 协议基础

### 消息类型

SIP 协议有两种消息类型：

1. **请求消息 (Request)**：客户端发送给服务器
2. **响应消息 (Response)**：服务器返回给客户端

### 消息格式

```
起始行 (Start-Line)
头部字段 (Header Fields)
空行 (CRLF)
消息体 (Message Body, 可选)
```

## 请求消息

### 请求行格式

```
Method SP Request-URI SP SIP-Version CRLF
```

示例：
```
INVITE sip:bob@example.com SIP/2.0
REGISTER sip:example.com SIP/2.0
```

### 支持的方法

SIP-Ban 支持以下 SIP 方法：

| 方法 | 说明 | 用途 |
|------|------|------|
| INVITE | 邀请 | 发起会话，建立通话 |
| ACK | 确认 | 确认收到最终响应 |
| BYE | 再见 | 终止会话 |
| CANCEL | 取消 | 取消正在进行的请求 |
| REGISTER | 注册 | 注册用户位置信息 |
| OPTIONS | 选项 | 查询服务器能力 |

### 方法定义

在 `internal/sip/method.go` 中：

```go
type Method int

const (
    MethodInvite   Method = 1
    MethodAck      Method = 2
    MethodBye      Method = 3
    MethodCancel   Method = 4
    MethodRegister Method = 5
    MethodOptions  Method = 6
)
```

## 响应消息

### 状态行格式

```
SIP-Version SP Status-Code SP Reason-Phrase CRLF
```

示例：
```
SIP/2.0 200 OK
SIP/2.0 401 Unauthorized
SIP/2.0 486 Busy Here
```

### 响应状态码分类

#### 1xx - 临时响应 (Provisional)

| 状态码 | 说明 |
|--------|------|
| 100 | Trying - 正在处理 |
| 180 | Ringing - 振铃中 |
| 181 | Call Is Being Forwarded - 呼叫转移中 |
| 182 | Queued - 排队中 |
| 183 | Session Progress - 会话进行中 |

#### 2xx - 成功响应 (Success)

| 状态码 | 说明 |
|--------|------|
| 200 | OK - 请求成功 |
| 202 | Accepted - 已接受（用于引用） |

#### 3xx - 重定向响应 (Redirection)

| 状态码 | 说明 |
|--------|------|
| 300 | Multiple Choices - 多个选择 |
| 301 | Moved Permanently - 永久移动 |
| 302 | Moved Temporarily - 临时移动 |
| 305 | Use Proxy - 使用代理 |
| 380 | Alternative Service - 替代服务 |

#### 4xx - 客户端错误 (Client Error)

| 状态码 | 说明 | 常见原因 |
|--------|------|----------|
| 400 | Bad Request - 错误请求 | 语法错误 |
| 401 | Unauthorized - 未授权 | 需要认证 |
| 403 | Forbidden - 禁止 | 拒绝服务 |
| 404 | Not Found - 未找到 | 用户不存在 |
| 407 | Proxy Authentication Required - 需要代理认证 | 代理需要认证 |
| 408 | Request Timeout - 请求超时 | 超时 |
| 410 | Gone - 已失效 | 用户不再可用 |
| 413 | Request Entity Too Large - 请求实体过大 | 消息体过大 |
| 414 | Request-URI Too Long - URI 过长 | URI 超长 |
| 415 | Unsupported Media Type - 不支持的媒体类型 | 媒体类型错误 |
| 416 | Unsupported URI Scheme - 不支持的 URI 方案 | URI 方案错误 |
| 420 | Bad Extension - 错误扩展 | 不支持的扩展 |
| 421 | Extension Required - 需要扩展 | 缺少必需扩展 |
| 423 | Interval Too Brief - 间隔过短 | 注册间隔太短 |
| 480 | Temporarily Unavailable - 暂时不可用 | 用户暂时不可达 |
| 481 | Call/Transaction Does Not Exist - 呼叫/事务不存在 | 无效的呼叫 |
| 482 | Loop Detected - 检测到循环 | 路由循环 |
| 483 | Too Many Hops - 跳数过多 | 超过最大转发次数 |
| 484 | Address Incomplete - 地址不完整 | URI 不完整 |
| 485 | Ambiguous - 模糊 | 地址模糊 |
| 486 | Busy Here - 忙 | 用户忙 |
| 487 | Request Terminated - 请求终止 | 请求被取消 |
| 488 | Not Acceptable Here - 不可接受 | 媒体参数不可接受 |
| 491 | Request Pending - 请求挂起 | 有请求正在处理 |
| 493 | Undecipherable - 无法解密 | 加密消息无法解密 |

#### 5xx - 服务器错误 (Server Error)

| 状态码 | 说明 |
|--------|------|
| 500 | Server Internal Error - 服务器内部错误 |
| 501 | Not Implemented - 未实现 |
| 502 | Bad Gateway - 网关错误 |
| 503 | Service Unavailable - 服务不可用 |
| 504 | Server Time-out - 服务器超时 |
| 505 | Version Not Supported - 版本不支持 |
| 513 | Message Too Large - 消息过大 |

#### 6xx - 全局失败 (Global Failure)

| 状态码 | 说明 |
|--------|------|
| 600 | Busy Everywhere - 全忙 |
| 603 | Decline - 拒绝 |
| 604 | Does Not Exist Anywhere - 任何地方都不存在 |
| 606 | Not Acceptable - 不可接受 |

## 头部字段

### 必需头部

以下头部字段在所有 SIP 消息中都是必需的：

| 头部 | 说明 | 示例 |
|------|------|------|
| Call-ID | 唯一标识一个呼叫 | `Call-ID: f81d4fae-7dec-11d0-a765-00a0c91e6bf6@example.com` |
| CSeq | 命令序列号 | `CSeq: 1 INVITE` |
| From | 发起方 | `From: Alice <sip:alice@example.com>;tag=1928301774` |
| To | 接收方 | `To: Bob <sip:bob@example.com>` |
| Via | 路由路径 | `Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds` |
| Max-Forwards | 最大转发次数 | `Max-Forwards: 70` |

### 常用头部

| 头部 | 说明 | 示例 |
|------|------|------|
| Contact | 联系地址 | `Contact: <sip:alice@pc33.example.com>` |
| Content-Type | 消息体类型 | `Content-Type: application/sdp` |
| Content-Length | 消息体长度 | `Content-Length: 142` |
| User-Agent | 用户代理 | `User-Agent: Softphone 1.0` |
| Allow | 支持的方法 | `Allow: INVITE, ACK, CANCEL, BYE` |
| Expires | 过期时间 | `Expires: 3600` |

## SIP-Ban 的解析实现

### 解析流程

```
1. 读取原始字节数据
2. 解析第一行（请求行或状态行）
   ├─ 判断是请求还是响应
   ├─ 提取方法/状态码
   └─ 提取 URI/状态描述
3. 逐行解析头部字段
   ├─ 按 ":" 分割
   ├─ 头部名称转小写（不区分大小写）
   └─ 存入 map
4. 验证 Call-ID 头部（必须存在）
5. 返回解析结果
```

### 核心数据结构

```go
type Package struct {
    Method         Method            // SIP 方法（仅请求消息）
    Headers        map[string]string // 头部字段集合
    RequestURI     string            // 请求 URI（仅请求消息）
    IsResponse     bool              // 是否为响应消息
    ResponseCode   int               // 响应状态码（仅响应消息）
    ResponseStatus string            // 响应状态描述（仅响应消息）
}
```

### 解析示例

#### 请求消息

输入：
```
REGISTER sip:example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-123
From: <sip:user@example.com>;tag=abc
To: <sip:user@example.com>
Call-ID: 1234567890@192.168.1.100
CSeq: 1 REGISTER
Contact: <sip:user@192.168.1.100:5060>
Expires: 3600
Content-Length: 0
```

解析结果：
```go
Package{
    Method: MethodRegister,
    IsResponse: false,
    Headers: map[string]string{
        "via": "SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-123",
        "from": "<sip:user@example.com>;tag=abc",
        "to": "<sip:user@example.com>",
        "call-id": "1234567890@192.168.1.100",
        "cseq": "1 REGISTER",
        "contact": "<sip:user@192.168.1.100:5060>",
        "expires": "3600",
        "content-length": "0",
    },
}
```

#### 响应消息

输入：
```
SIP/2.0 401 Unauthorized
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-123
From: <sip:user@example.com>;tag=abc
To: <sip:user@example.com>;tag=xyz
Call-ID: 1234567890@192.168.1.100
CSeq: 1 REGISTER
WWW-Authenticate: Digest realm="example.com", nonce="abc123"
Content-Length: 0
```

解析结果：
```go
Package{
    IsResponse: true,
    ResponseCode: 401,
    ResponseStatus: "Unauthorized",
    Headers: map[string]string{
        "via": "SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK-123",
        "from": "<sip:user@example.com>;tag=abc",
        "to": "<sip:user@example.com>;tag=xyz",
        "call-id": "1234567890@192.168.1.100",
        "cseq": "1 REGISTER",
        "www-authenticate": "Digest realm=\"example.com\", nonce=\"abc123\"",
        "content-length": "0",
    },
}
```

## 攻击模式识别

### 1. 暴力破解 (Brute Force)

**特征**：
- 大量 REGISTER 请求
- 收到 401/407 响应后继续尝试
- 短时间内多次重试

**检测规则**：
```go
// 120 秒内收到超过 40 次 401 响应
banRuleCodes[401] = &analyzer.BanRule{
    FindTime: 120,
    MaxRetry: 40,
}
```

### 2. 扫描攻击 (Scanning)

**特征**：
- 大量 OPTIONS 请求
- 探测服务器能力
- 尝试不同的用户名

**检测规则**：
```go
// 60 秒内收到超过 10 次 404 响应
banRuleCodes[404] = &analyzer.BanRule{
    FindTime: 60,
    MaxRetry: 10,
}
```

### 3. 拒绝服务 (DoS)

**特征**：
- 大量 INVITE 请求
- 不等待响应就发送新请求
- 消耗服务器资源

**检测规则**：
```go
// 60 秒内收到超过 10 次 INVITE 相关响应
banRuleCodes[486] = &analyzer.BanRule{
    FindTime: 60,
    MaxRetry: 10,
}
```

### 4. 地理位置异常

**特征**：
- 来自非预期地区的请求
- 通常是僵尸网络

**检测规则**：
```go
// 非中国 IP 直接封禁
if !geoChecker.IsChina(ip) {
    firewall.Ban(ip)
}
```

## 典型攻击场景

### 场景 1：SIP 注册暴力破解

```
攻击者 → 服务器: REGISTER (用户名: admin, 密码: 123456)
服务器 → 攻击者: 401 Unauthorized

攻击者 → 服务器: REGISTER (用户名: admin, 密码: password)
服务器 → 攻击者: 401 Unauthorized

攻击者 → 服务器: REGISTER (用户名: admin, 密码: admin)
服务器 → 攻击者: 401 Unauthorized

... (重复多次)
```

**SIP-Ban 响应**：
- 监控出站流量（服务器发出的 401 响应）
- 统计 120 秒内收到 401 响应的次数
- 超过 40 次后封禁攻击者 IP

### 场景 2：SIP 扫描攻击

```
攻击者 → 服务器: OPTIONS sip:user1@example.com
服务器 → 攻击者: 404 Not Found

攻击者 → 服务器: OPTIONS sip:user2@example.com
服务器 → 攻击者: 404 Not Found

攻击者 → 服务器: OPTIONS sip:user3@example.com
服务器 → 攻击者: 404 Not Found

... (扫描大量用户名)
```

**SIP-Ban 响应**：
- 监控 404 响应
- 60 秒内超过 10 次后封禁

### 场景 3：INVITE 洪水攻击

```
攻击者 → 服务器: INVITE sip:victim@example.com
服务器 → 攻击者: 100 Trying
服务器 → 攻击者: 486 Busy Here

攻击者 → 服务器: INVITE sip:victim@example.com
服务器 → 攻击者: 100 Trying
服务器 → 攻击者: 486 Busy Here

... (快速重复)
```

**SIP-Ban 响应**：
- 监控 486 响应
- 60 秒内超过 10 次后封禁

## 协议扩展

### 添加新方法支持

1. 在 `internal/sip/method.go` 中定义：

```go
const (
    // 现有方法...
    MethodSubscribe Method = 7
    MethodNotify    Method = 8
)

var methodNames = map[Method]string{
    // 现有映射...
    MethodSubscribe: "SUBSCRIBE",
    MethodNotify:    "NOTIFY",
}

var methodValues = map[string]Method{
    // 现有映射...
    "SUBSCRIBE": MethodSubscribe,
    "NOTIFY":    MethodNotify,
}
```

2. 添加对应的封禁规则（如需要）：

```go
banRules["SUBSCRIBE"] = &analyzer.BanRule{
    FindTime: 60,
    MaxRetry: 20,
}
```

### 添加新状态码检测

在 `cmd/sip-ban/run.go` 中：

```go
banRuleCodes[<状态码>] = &analyzer.BanRule{
    FindTime: <时间窗口>,
    MaxRetry: <最大次数>,
}
```

## 性能优化

### 1. 快速路径

只解析必要的头部字段：

```go
// 只需要 Call-ID 验证消息有效性
if p.GetCallID() == "" {
    return errors.New("不是标准的 sip 消息")
}
```

### 2. 避免正则表达式

使用简单的字符串操作：

```go
// 使用 strings.SplitN 而不是正则
splits := strings.SplitN(string(line), " ", 3)
```

### 3. 头部名称小写化

统一转为小写，避免大小写比较：

```go
name := strings.ToLower(strings.TrimSpace(string(header[:index])))
```

## 调试技巧

### 1. 打印原始消息

```go
fmt.Printf("Raw SIP message:\n%s\n", string(data))
```

### 2. 使用 tcpdump 捕获

```bash
sudo tcpdump -i eth0 -n -A 'udp port 5060'
```

### 3. 使用 SIPp 生成测试流量

```bash
# 安装 SIPp
sudo apt install sipp

# 发送 REGISTER 请求
sipp -sn uac -s user@example.com 192.168.1.1:5060
```

## 参考资料

### RFC 文档

- [RFC 3261 - SIP: Session Initiation Protocol](https://tools.ietf.org/html/rfc3261)
- [RFC 3262 - Reliability of Provisional Responses in SIP](https://tools.ietf.org/html/rfc3262)
- [RFC 3263 - SIP: Locating SIP Servers](https://tools.ietf.org/html/rfc3263)
- [RFC 3264 - An Offer/Answer Model with SDP](https://tools.ietf.org/html/rfc3264)
- [RFC 3265 - SIP-Specific Event Notification](https://tools.ietf.org/html/rfc3265)

### 在线工具

- [SIP Parser Online](https://www.sipparser.com/)
- [SIP Message Validator](https://www.sipvalidator.com/)

### 测试工具

- [SIPp - SIP Test Tool](http://sipp.sourceforge.net/)
- [SIPVicious - VoIP Security Testing](https://github.com/EnableSecurity/sipvicious)
- [Wireshark - Network Protocol Analyzer](https://www.wireshark.org/)
