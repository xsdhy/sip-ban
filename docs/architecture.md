# SIP-Ban 架构设计文档

## 概述

SIP-Ban 是一个基于 Go 语言开发的 SIP 协议流量监控和自动封禁工具，用于保护 VoIP 服务器免受恶意攻击。本文档详细描述了系统的架构设计、模块职责和工作流程。

## 设计原则

### 1. 模块化设计
- 每个模块职责单一，边界清晰
- 模块间通过接口交互，降低耦合度
- 便于单元测试和功能扩展

### 2. 无全局状态
- 所有状态封装在结构体中
- 避免使用全局变量
- 提高代码的可测试性和可维护性

### 3. 依赖注入
- 通过构造函数注入依赖
- 便于 mock 和单元测试
- 提高代码的灵活性

### 4. 平台兼容性
- 使用 build tags 实现平台特定功能
- 核心功能跨平台支持
- daemon 模式仅限 Linux

## 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                         cmd/sip-ban                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   dispatch   │  │   commands   │  │     main     │      │
│  │  (子命令分发) │  │ (start/stop) │  │   (入口点)    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      internal packages                       │
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │    config    │  │    daemon    │  │   capture    │      │
│  │  (配置管理)   │  │ (后台进程管理) │  │  (流量捕获)   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                              │               │
│  ┌──────────────┐  ┌──────────────┐        ▼               │
│  │   analyzer   │  │     sip      │  ┌──────────────┐      │
│  │  (流量分析)   │◄─┤ (协议解析)    │  │ pcap_handle  │      │
│  └──────────────┘  └──────────────┘  │  (抓包封装)   │      │
│         │                             └──────────────┘      │
│         ▼                                                    │
│  ┌──────────────┐  ┌──────────────┐                        │
│  │    geoip     │  │   firewall   │                        │
│  │ (地理位置查询) │  │ (防火墙管理)  │                        │
│  └──────────────┘  └──────────────┘                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      pkg/iptables                            │
│                   (iptables 操作封装)                         │
└─────────────────────────────────────────────────────────────┘
```

## 核心模块

### 1. cmd/sip-ban - 命令行入口

#### main.go
程序主入口，负责：
- 检测是否为 daemon 子进程（通过环境变量 `SIPBAN_DAEMONIZED`）
- 子进程模式：执行 `runDaemonChild()` 完成激活和业务逻辑
- 父进程模式：通过 `dispatch()` 分发到不同子命令

#### dispatch.go
子命令分发器，解析命令行参数并路由到：
- 空命令：前台运行模式
- `start`：启动服务（支持 `-d` 后台模式）
- `status`：查询运行状态
- `stop`：停止服务
- `restart`：重启服务

#### commands.go
实现各个子命令的具体逻辑：
- `runStart`：启动服务，支持前台和后台模式
- `runStatus`：读取 PID 文件并验证进程状态，显示 uptime
- `runStop`：发送 SIGTERM 信号停止进程，超时后发送 SIGKILL
- `runRestart`：先停止再启动

### 2. internal/config - 配置管理

负责解析命令行参数并生成配置对象。

**核心设计**：
- `RegisterFlags`：将配置项注册到 FlagSet
- `LoadFromFlagSet`：从指定 FlagSet 解析参数
- 支持多个子命令各自构造独立的 FlagSet，避免全局状态污染

**配置项**：
```go
type Config struct {
    DeviceName       string  // 网卡名称
    Protocol         string  // 协议类型（tcp/udp）
    FilterPort       int     // 监听端口
    RegisterFindTime int     // REGISTER 时间窗口
    RegisterMaxRetry int     // REGISTER 最大重试次数
    InviteFindTime   int     // INVITE 时间窗口
    InviteMaxRetry   int     // INVITE 最大重试次数
    IPDBPath         string  // IP 数据库路径
}
```

### 3. internal/daemon - 后台进程管理

实现 Linux 平台的 daemon 功能，无需依赖 systemd。

**核心功能**：
- **PID 文件管理**：记录 PID 和启动时间（jiffies）
- **进程身份校验**：通过 `/proc/<pid>/stat` 验证进程是否为原进程
- **双进程握手**：父进程 fork 子进程后通过管道等待子进程就绪
- **信号处理**：子进程注册 SIGTERM/SIGINT 信号处理器，优雅退出
- **文件锁**：使用 flock 防止重复启动

**关键文件**：
- `daemon.go`：平台无关的接口定义
- `daemon_linux.go`：Linux 平台实现（PID 验证、信号处理）
- `spawn_linux.go`：进程 fork 和握手逻辑
- `pidfile_linux.go`：PID 文件的读写和锁管理

**PID 文件格式**：
```
<pid> <start_time_jiffies>
```

**身份校验流程**：
1. 读取 PID 文件获取 `expected_start_time`
2. 读取 `/proc/<pid>/stat` 第 22 字段获取 `actual_start_time`
3. 比较两者是否一致，防止 PID 被复用

### 4. internal/capture - 流量捕获

负责网络流量的捕获和分发。

**核心设计**：
- 使用 `gopacket/pcap` 进行底层抓包
- 支持多网卡同时监控
- 每个网卡独立的 goroutine 和 worker pool
- 通过 `context.Context` 控制生命周期

**Worker Pool 模式**：
```
┌─────────────┐
│ captureDevice│
│  (主循环)     │
└──────┬──────┘
       │ ReadPacketData()
       ▼
┌─────────────┐
│ packetQueue │ (buffered channel)
└──────┬──────┘
       │
       ├──► Worker 1 ──► Analyzer
       ├──► Worker 2 ──► Analyzer
       ├──► Worker 3 ──► Analyzer
       └──► Worker N ──► Analyzer
```

**优势**：
- 限制并发 goroutine 数量，避免高流量场景下 OOM
- 队列缓冲机制，平滑流量峰值
- 队列满时丢弃数据包，保护系统稳定性

**配置参数**：
- `workerPoolSize`：每个网卡的 worker 数量（默认 100）
- `packetQueueSize`：数据包队列缓冲大小（默认 1000）

### 5. internal/sip - SIP 协议解析

解析 SIP 协议消息，提取关键信息。

**支持的消息类型**：
- 请求消息：`INVITE`、`REGISTER`、`ACK`、`BYE`、`CANCEL`、`OPTIONS`
- 响应消息：状态码 + 状态描述

**解析流程**：
1. 解析第一行（请求行或状态行）
2. 逐行解析头部字段（不区分大小写）
3. 验证 `Call-ID` 头部（必须存在）

**数据结构**：
```go
type Package struct {
    Method         Method            // SIP 方法
    Headers        map[string]string // 头部字段
    RequestURI     string            // 请求 URI
    IsResponse     bool              // 是否为响应
    ResponseCode   int               // 响应状态码
    ResponseStatus string            // 响应状态描述
}
```

### 6. internal/analyzer - 流量分析

分析 SIP 流量并根据规则决定是否封禁。

**分析维度**：
1. **地理位置检查**：非中国 IP 直接封禁
2. **频率检查**：基于响应码的时间窗口内重试次数

**封禁规则**：
```go
type BanRule struct {
    FindTime int  // 时间窗口（秒）
    MaxRetry int  // 最大重试次数
}
```

**缓存机制**：
- 使用 `go-cache` 记录 IP 在时间窗口内的请求次数
- 缓存键格式：`<IP>.<响应码>`
- 超过阈值时触发封禁

**去重机制**：
- 使用 `sync.Map` 记录已封禁的 IP
- 避免重复封禁同一 IP

### 7. internal/geoip - 地理位置查询

基于 IP 数据库查询 IP 地理位置。

**实现**：
- 使用 `ipdb-go` 库加载 IP 数据库
- 支持局域网和本机地址识别
- 查询失败时默认放行（fail-open）

**判断逻辑**：
```go
switch info.CountryName {
case "局域网", "本机地址":
    return true, "局域网"
case "中国":
    return true, "中国"
default:
    return false, info.CountryName
}
```

### 8. internal/firewall - 防火墙管理

管理 iptables 规则，封禁恶意 IP。

**封禁规则**：
```bash
iptables -A INPUT -s <IP> -j DROP
```

**安全检查**：
- 验证 IP 地址格式（仅支持 IPv4）
- 拒绝特殊地址：`0.0.0.0`、`255.255.255.255`、回环地址、多播地址
- 检查规则是否已存在，避免重复添加

### 9. pkg/iptables - iptables 封装

封装 iptables 命令行操作。

**核心方法**：
- `Append`：添加规则
- `Exists`：检查规则是否存在
- `Delete`：删除规则

## 工作流程

### 前台运行模式

```
1. 解析命令行参数 (config.LoadFromFlagSet)
2. 初始化 GeoIP 检查器 (geoip.New)
3. 初始化防火墙管理器 (firewall.New)
4. 构造封禁规则 (BanRule)
5. 创建捕获管理器 (capture.New)
6. 启动捕获 (manager.Start)
   ├─ 列举网卡
   ├─ 为每个网卡启动 captureDevice goroutine
   │  ├─ 打开 pcap 句柄
   │  ├─ 设置 BPF 过滤器
   │  ├─ 启动 worker pool
   │  └─ 循环读取数据包
   └─ 返回 WaitGroup
7. 等待信号 (SIGINT/SIGTERM)
8. 取消 context，优雅退出
9. 等待所有 goroutine 退出 (wg.Wait)
```

### 后台运行模式（Linux）

```
父进程:
1. 解析 -d、-pid、-log 参数
2. 调用 daemon.Spawn
   ├─ 检查 PID 文件是否存在（防止重复启动）
   ├─ 创建握手管道
   ├─ fork 子进程（设置环境变量 SIPBAN_DAEMONIZED=1）
   ├─ 等待子进程握手（读取管道）
   └─ 退出

子进程:
1. 检测到 SIPBAN_DAEMONIZED=1
2. 调用 daemon.Activate
   ├─ 写入 PID 文件（PID + start_time）
   ├─ 对 PID 文件加锁（flock）
   ├─ 注册信号处理器（SIGTERM/SIGINT）
   ├─ 通过握手管道向父进程报告成功
   └─ 返回 context 和 cleanup 函数
3. 执行业务逻辑（同前台模式）
4. 收到信号或 context 取消时退出
5. 调用 cleanup（解锁、删除 PID 文件）
```

### 数据包分析流程

```
1. captureDevice 读取原始数据包
2. 解析为 gopacket.Packet
3. 发送到 packetQueue
4. worker 从队列取出数据包
5. 调用 analyzer.AnalyzePacket
   ├─ 提取 IP 层信息
   ├─ 判断流量方向（IN/OUT）
   ├─ 提取端口信息
   ├─ 解析 SIP 消息 (sip.Package)
   ├─ 仅处理出站流量（本机发出的响应）
   ├─ 检查地理位置 (geoChecker.IsChina)
   │  └─ 非中国 IP → 封禁
   └─ 检查封禁规则 (checkBanRules)
      ├─ 查找响应码对应的规则
      ├─ 更新缓存计数
      └─ 超过阈值 → 封禁
```

## 并发模型

### Goroutine 层次结构

```
main goroutine
├─ captureDevice goroutine (网卡 1)
│  ├─ packetWorker goroutine 1
│  ├─ packetWorker goroutine 2
│  └─ packetWorker goroutine N
├─ captureDevice goroutine (网卡 2)
│  ├─ packetWorker goroutine 1
│  └─ ...
└─ signal handler goroutine
```

### 同步机制

- **context.Context**：控制所有 goroutine 的生命周期
- **sync.WaitGroup**：等待所有 goroutine 退出
- **sync.Map**：记录已封禁的 IP（并发安全）
- **go-cache**：记录 IP 请求次数（内置锁）

## 平台兼容性

### Linux
- 完整支持所有功能
- daemon 模式可用
- 使用 `/proc` 文件系统进行进程管理

### macOS / Windows
- 支持前台运行模式
- 不支持 daemon 模式（`start -d` 会报错）
- 核心功能（流量捕获、分析、封禁）正常工作

### Build Tags

```go
//go:build linux
// daemon_linux.go, spawn_linux.go, pidfile_linux.go

//go:build !linux
// daemon_other.go, spawn_other.go, pidfile_other.go
```

## 错误处理

### 退出码约定

- `0`：成功
- `1`：用户错误（参数错误、已在运行、平台不支持）
- `2`：系统错误（启动失败、停止失败、握手失败）
- `3`：进程未运行（status/stop 时）

### 容错策略

- **GeoIP 查询失败**：默认放行（fail-open）
- **数据包解析失败**：跳过该包，继续处理
- **队列满**：丢弃数据包，保护系统稳定性
- **iptables 操作失败**：记录错误，继续运行

## 性能优化

### 1. Worker Pool
- 限制并发 goroutine 数量
- 避免高流量场景下 OOM

### 2. 缓冲队列
- 平滑流量峰值
- 解耦捕获和分析逻辑

### 3. BPF 过滤器
- 在内核层面过滤数据包
- 减少用户空间处理负担

### 4. 去重机制
- 避免重复封禁同一 IP
- 减少 iptables 操作次数

### 5. 缓存过期
- 自动清理过期的计数记录
- 避免内存泄漏

## 扩展性

### 添加新的封禁规则

```go
// 在 cmd/sip-ban/run.go 中添加
banRuleCodes[<响应码>] = &analyzer.BanRule{
    FindTime: <时间窗口>,
    MaxRetry: <最大重试次数>,
}
```

### 支持新的协议

1. 在 `internal/sip` 中添加协议解析逻辑
2. 在 `internal/analyzer` 中添加分析规则
3. 在 `internal/capture` 中调整 BPF 过滤器

### 支持新的防火墙后端

1. 实现 `analyzer.FirewallManager` 接口
2. 在 `cmd/sip-ban/run.go` 中注入新的实现

## 测试策略

### 单元测试
- 每个模块独立测试
- 使用 mock 隔离依赖
- 覆盖核心业务逻辑

### 集成测试
- 测试模块间交互
- 使用真实的 pcap 数据
- 验证端到端流程

### 平台测试
- 使用 build tags 分离平台特定代码
- 在 Linux 上测试 daemon 功能
- 在 macOS/Windows 上测试前台模式

## 安全考虑

### 1. 权限要求
- 需要 root 权限（pcap 和 iptables）
- 建议使用 capabilities 限制权限范围

### 2. IP 验证
- 拒绝封禁特殊地址（回环、广播、多播）
- 防止误封本机或关键服务

### 3. 进程身份校验
- 通过 start_time 防止 PID 复用攻击
- 使用文件锁防止重复启动

### 4. 信号处理
- 优雅退出，清理资源
- 超时后强制终止（SIGKILL）

## 未来改进方向

1. **日志系统**：结构化日志、日志切割
2. **监控指标**：Prometheus metrics、性能统计
3. **配置文件**：支持 YAML/TOML 配置文件
4. **白名单**：支持 IP 白名单，避免误封
5. **动态规则**：支持运行时更新封禁规则
6. **分布式部署**：支持多节点协同防护
7. **Web 界面**：提供可视化管理界面
