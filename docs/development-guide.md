# 开发指南

## 开发环境搭建

### 系统要求

- Go 1.21 或更高版本
- Linux / macOS / Windows
- libpcap 开发库

### 安装依赖

#### Linux (Ubuntu/Debian)

```bash
# 安装 Go
sudo apt update
sudo apt install golang-go

# 安装 libpcap 开发库
sudo apt install libpcap-dev

# 安装 iptables（通常已预装）
sudo apt install iptables
```

#### macOS

```bash
# 安装 Go
brew install go

# 安装 libpcap（通常已预装）
# 如果需要，可以通过 Xcode Command Line Tools 安装
xcode-select --install
```

#### Windows

```bash
# 安装 Go
# 从 https://golang.org/dl/ 下载安装包

# 安装 WinPcap 或 Npcap
# 从 https://npcap.org/ 下载安装
```

### 克隆项目

```bash
git clone <repository-url>
cd sip-ban
```

### 安装 Go 依赖

```bash
go mod download
```

## 项目结构

```
sip-ban/
├── cmd/
│   └── sip-ban/              # 主程序入口
│       ├── main.go           # 程序入口
│       ├── dispatch.go       # 子命令分发
│       ├── commands.go       # 子命令实现
│       ├── run.go            # 业务逻辑入口
│       ├── uptime_linux.go   # Linux uptime 计算
│       └── uptime_other.go   # 其他平台 uptime
├── internal/                 # 内部包（不对外暴露）
│   ├── analyzer/            # 流量分析
│   │   ├── analyzer.go
│   │   └── analyzer_test.go
│   ├── capture/             # 网络包捕获
│   │   ├── manager.go
│   │   ├── manager_test.go
│   │   └── pcap_handle.go
│   ├── config/              # 配置管理
│   │   ├── config.go
│   │   └── config_test.go
│   ├── daemon/              # 后台进程管理
│   │   ├── daemon.go        # 平台无关接口
│   │   ├── daemon_linux.go  # Linux 实现
│   │   ├── daemon_other.go  # 其他平台实现
│   │   ├── spawn_linux.go   # Linux fork 逻辑
│   │   ├── spawn_other.go   # 其他平台占位
│   │   ├── pidfile_linux.go # Linux PID 文件管理
│   │   └── pidfile_other.go # 其他平台占位
│   ├── firewall/            # 防火墙管理
│   │   ├── iptables.go
│   │   └── iptables_test.go
│   ├── geoip/               # IP 地理位置查询
│   │   ├── checker.go
│   │   └── checker_test.go
│   └── sip/                 # SIP 协议解析
│       ├── method.go
│       ├── parser.go
│       └── parser_test.go
├── pkg/                     # 可复用的公共包
│   └── iptables/           # iptables 操作封装
│       └── iptables.go
├── data/                    # 数据文件
│   └── ipv4.ipdb           # IP 地理位置数据库
├── docs/                    # 文档
│   ├── architecture.md     # 架构设计文档
│   ├── daemon-mode.md      # Daemon 模式详解
│   └── development-guide.md # 开发指南（本文档）
├── go.mod                   # Go 模块定义
├── go.sum                   # 依赖校验和
├── Makefile                 # 构建脚本
└── README.md                # 项目说明
```

## 编译和运行

### 编译

```bash
# 编译到当前目录
go build -o sip-ban ./cmd/sip-ban

# 或使用 Makefile
make build
```

### 运行

```bash
# 前台运行（需要 root 权限）
sudo ./sip-ban -i eth0

# 后台运行（仅 Linux）
sudo ./sip-ban start -d -i eth0

# 查看帮助
./sip-ban -h
```

### 交叉编译

```bash
# 编译 Linux 版本
GOOS=linux GOARCH=amd64 go build -o sip-ban-linux ./cmd/sip-ban

# 编译 macOS 版本
GOOS=darwin GOARCH=amd64 go build -o sip-ban-darwin ./cmd/sip-ban

# 编译 Windows 版本
GOOS=windows GOARCH=amd64 go build -o sip-ban.exe ./cmd/sip-ban
```

## 测试

### 运行所有测试

```bash
go test ./...
```

### 运行特定包的测试

```bash
go test ./internal/sip
go test ./internal/config
go test ./internal/analyzer
```

### 运行测试并显示详细输出

```bash
go test -v ./...
```

### 生成覆盖率报告

```bash
# 生成覆盖率文件
go test ./... -coverprofile=coverage.out

# 查看覆盖率统计
go tool cover -func=coverage.out

# 生成 HTML 覆盖率报告
go tool cover -html=coverage.out -o coverage.html
```

### 运行基准测试

```bash
go test -bench=. ./...
```

### 运行竞态检测

```bash
go test -race ./...
```

## 代码规范

### 格式化

使用 `gofmt` 或 `goimports` 格式化代码：

```bash
# 格式化所有文件
gofmt -w .

# 或使用 goimports（自动管理 import）
goimports -w .
```

### 静态检查

使用 `go vet` 进行静态检查：

```bash
go vet ./...
```

### Linter

推荐使用 `golangci-lint`：

```bash
# 安装
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# 运行
golangci-lint run
```

### 命名规范

- **包名**：小写，单数，简短（如 `sip`、`config`）
- **文件名**：小写，下划线分隔（如 `analyzer_test.go`）
- **类型名**：大驼峰（如 `Analyzer`、`BanRule`）
- **函数名**：大驼峰（导出）或小驼峰（未导出）
- **常量名**：大驼峰或全大写下划线分隔
- **变量名**：小驼峰

### 注释规范

- 每个导出的类型、函数、常量都应有注释
- 注释以类型/函数名开头
- 包注释写在 `package` 语句之前

示例：

```go
// Package sip 提供 SIP 协议相关的解析和处理功能
package sip

// Method 表示 SIP 请求方法
type Method int

// New 创建一个新的流量分析器
// 参数:
//   protocol - 协议类型（tcp 或 udp）
//   deviceIP - 本机设备 IP 地址
// 返回:
//   *Analyzer - 分析器实例
func New(protocol, deviceIP string) *Analyzer {
    // ...
}
```

## 添加新功能

### 1. 添加新的 SIP 方法

在 `internal/sip/method.go` 中添加：

```go
const (
    // 现有方法...
    MethodNewMethod Method = 7
)

var methodNames = map[Method]string{
    // 现有映射...
    MethodNewMethod: "NEWMETHOD",
}

var methodValues = map[string]Method{
    // 现有映射...
    "NEWMETHOD": MethodNewMethod,
}
```

### 2. 添加新的封禁规则

在 `cmd/sip-ban/run.go` 中添加：

```go
banRuleCodes := map[int]*analyzer.BanRule{
    // 现有规则...
    999: {
        FindTime: 60,
        MaxRetry: 5,
    },
}
```

### 3. 添加新的配置项

在 `internal/config/config.go` 中：

```go
type Config struct {
    // 现有字段...
    NewOption string
}

func (c *Config) RegisterFlags(fs *flag.FlagSet) {
    // 现有注册...
    fs.StringVar(&c.NewOption, "new-option", "default", "新选项说明")
}
```

### 4. 添加新的防火墙后端

实现 `analyzer.FirewallManager` 接口：

```go
type NewFirewall struct {
    // ...
}

func (f *NewFirewall) Ban(ip string) error {
    // 实现封禁逻辑
    return nil
}
```

在 `cmd/sip-ban/run.go` 中注入：

```go
fw := &NewFirewall{}
manager := capture.New(protocol, port, device, geoChecker, fw, rules, ruleCodes)
```

## 调试技巧

### 1. 使用 Delve 调试器

```bash
# 安装 Delve
go install github.com/go-delve/delve/cmd/dlv@latest

# 调试程序
sudo dlv exec ./sip-ban -- -i eth0

# 在 Delve 中设置断点
(dlv) break main.main
(dlv) continue
```

### 2. 添加调试日志

```go
import "log"

log.Printf("DEBUG: variable value = %v", variable)
```

### 3. 使用 pprof 性能分析

在代码中添加：

```go
import (
    "net/http"
    _ "net/http/pprof"
)

func main() {
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
    // ...
}
```

访问 `http://localhost:6060/debug/pprof/` 查看性能数据。

### 4. 查看网络包

使用 tcpdump 验证 BPF 过滤器：

```bash
sudo tcpdump -i eth0 -n 'udp and port 5060'
```

## 常见问题

### 1. 编译错误：找不到 pcap.h

**原因**：未安装 libpcap 开发库

**解决**：
```bash
# Linux
sudo apt install libpcap-dev

# macOS
xcode-select --install
```

### 2. 运行错误：permission denied

**原因**：需要 root 权限进行网络抓包

**解决**：
```bash
sudo ./sip-ban -i eth0
```

或设置 capabilities：
```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./sip-ban
./sip-ban -i eth0
```

### 3. 测试失败：no suitable device found

**原因**：测试环境没有网卡或权限不足

**解决**：跳过需要真实网卡的测试，或使用 mock

### 4. daemon 模式不可用

**原因**：在非 Linux 平台上使用

**解决**：daemon 模式仅支持 Linux，其他平台使用前台模式

## 贡献指南

### 提交代码前检查清单

- [ ] 代码已格式化（`gofmt -w .`）
- [ ] 通过静态检查（`go vet ./...`）
- [ ] 通过所有测试（`go test ./...`）
- [ ] 添加了必要的测试
- [ ] 更新了相关文档
- [ ] 提交信息清晰明确

### Git 提交信息规范

```
<type>(<scope>): <subject>

<body>

<footer>
```

**type**：
- `feat`：新功能
- `fix`：修复 bug
- `docs`：文档更新
- `style`：代码格式调整
- `refactor`：重构
- `test`：测试相关
- `chore`：构建/工具相关

**示例**：
```
feat(analyzer): 添加基于 User-Agent 的封禁规则

- 新增 UserAgentBanRule 类型
- 支持正则表达式匹配
- 添加单元测试

Closes #123
```

### Pull Request 流程

1. Fork 项目
2. 创建特性分支（`git checkout -b feature/new-feature`）
3. 提交更改（`git commit -am 'feat: add new feature'`）
4. 推送到分支（`git push origin feature/new-feature`）
5. 创建 Pull Request

### 代码审查要点

- 代码逻辑是否正确
- 是否有潜在的性能问题
- 是否有安全隐患
- 错误处理是否完善
- 测试覆盖是否充分
- 文档是否完整

## 性能优化建议

### 1. 减少内存分配

```go
// 不好：每次都分配新的 slice
func process() {
    data := make([]byte, 1024)
    // ...
}

// 好：复用 buffer
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 1024)
    },
}

func process() {
    data := bufferPool.Get().([]byte)
    defer bufferPool.Put(data)
    // ...
}
```

### 2. 使用 BPF 过滤器

在内核层面过滤数据包，减少用户空间处理：

```go
bpf := "udp and port 5060 and not src host 127.0.0.1"
handle.SetBPFFilter(bpf)
```

### 3. 批量处理

```go
// 不好：逐个处理
for _, packet := range packets {
    process(packet)
}

// 好：批量处理
processBatch(packets)
```

### 4. 避免不必要的锁

```go
// 不好：频繁加锁
mu.Lock()
value := cache[key]
mu.Unlock()

// 好：使用 sync.Map 或读写锁
value, ok := cache.Load(key)
```

## 安全开发实践

### 1. 输入验证

```go
func Ban(ip string) error {
    // 验证 IP 格式
    if net.ParseIP(ip) == nil {
        return fmt.Errorf("invalid IP: %s", ip)
    }
    
    // 拒绝特殊地址
    if ip == "127.0.0.1" {
        return fmt.Errorf("cannot ban localhost")
    }
    
    // ...
}
```

### 2. 避免命令注入

```go
// 不好：直接拼接命令
cmd := exec.Command("sh", "-c", "iptables -A INPUT -s "+ip+" -j DROP")

// 好：使用参数化命令
cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
```

### 3. 错误处理

```go
// 不好：忽略错误
data, _ := os.ReadFile(path)

// 好：处理错误
data, err := os.ReadFile(path)
if err != nil {
    return fmt.Errorf("read file failed: %w", err)
}
```

### 4. 资源清理

```go
// 使用 defer 确保资源释放
file, err := os.Open(path)
if err != nil {
    return err
}
defer file.Close()

// 使用 context 控制超时
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
```

## 平台特定开发

### 使用 Build Tags

```go
//go:build linux

package daemon

// Linux 特定实现
```

```go
//go:build !linux

package daemon

// 其他平台实现
```

### 条件编译

```bash
# 仅编译 Linux 版本
go build -tags linux ./cmd/sip-ban

# 排除 Linux 特定代码
go build -tags '!linux' ./cmd/sip-ban
```

## 发布流程

### 1. 更新版本号

在 `cmd/sip-ban/main.go` 中：

```go
const version = "v1.2.3"
```

### 2. 更新 CHANGELOG

记录本次发布的变更：

```markdown
## [1.2.3] - 2026-05-24

### Added
- 新增 XXX 功能

### Fixed
- 修复 XXX 问题

### Changed
- 优化 XXX 性能
```

### 3. 创建 Git Tag

```bash
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3
```

### 4. 构建发布包

```bash
# 使用 Makefile
make release

# 或手动构建
GOOS=linux GOARCH=amd64 go build -o sip-ban-linux-amd64 ./cmd/sip-ban
GOOS=darwin GOARCH=amd64 go build -o sip-ban-darwin-amd64 ./cmd/sip-ban
```

### 5. 发布到 GitHub Releases

上传构建好的二进制文件和 CHANGELOG。

## 参考资源

### Go 语言

- [Go 官方文档](https://golang.org/doc/)
- [Effective Go](https://golang.org/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)

### 网络编程

- [gopacket 文档](https://pkg.go.dev/github.com/google/gopacket)
- [libpcap 文档](https://www.tcpdump.org/manpages/pcap.3pcap.html)

### SIP 协议

- [RFC 3261 - SIP: Session Initiation Protocol](https://tools.ietf.org/html/rfc3261)
- [SIP 协议详解](https://www.ietf.org/rfc/rfc3261.txt)

### Linux 系统编程

- [The Linux Programming Interface](https://man7.org/tlpi/)
- [Advanced Programming in the UNIX Environment](https://www.apuebook.com/)

## 联系方式

如有问题或建议，请通过以下方式联系：

- 提交 Issue
- 发起 Pull Request
- 邮件联系维护者
