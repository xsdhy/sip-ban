# SIP Ban - SIP流量监控与防护工具

基于Go语言开发的SIP协议流量监控和自动封禁工具，用于防护VoIP服务器免受恶意攻击。

## 项目结构

```
sip-ban/
├── cmd/
│   └── sip-ban/          # 主程序入口
│       └── main.go
├── internal/             # 内部包（不对外暴露）
│   ├── config/          # 配置管理
│   ├── capture/         # 网络包捕获
│   ├── analyzer/        # 流量分析
│   ├── sip/            # SIP协议解析
│   ├── geoip/          # IP地理位置检查
│   └── firewall/       # 防火墙管理
├── pkg/                 # 可复用的公共包
│   └── iptables/       # iptables操作封装
├── data/               # 数据文件
│   └── ipv4.ipdb      # IP地理位置数据库
└── go.mod
```

## 功能特性

- 实时监控SIP协议流量（UDP/TCP）
- 基于地理位置的IP过滤（仅允许中国IP）
- 基于规则的频率限制检测
- 自动添加iptables封禁规则
- 支持多网卡同时监控

## 使用方法

### 编译

```bash
go build -o sip-ban ./cmd/sip-ban
```

### 运行

```bash
# 监控所有网卡的5060端口UDP流量
sudo ./sip-ban

# 指定网卡
sudo ./sip-ban -i eth0

# 自定义参数
sudo ./sip-ban -i eth0 -p udp -P 5060 -rt 120 -rn 40 -it 60 -in 10
```

### 参数说明

- `-i`: 指定监控的网卡名称（默认监控所有）
- `-p`: 协议类型（默认: udp）
- `-P`: 监控端口（默认: 5060）
- `-rt`: REGISTER方法的时间窗口（秒，默认: 120）
- `-rn`: REGISTER方法的最大重试次数（默认: 40）
- `-it`: INVITE方法的时间窗口（秒，默认: 60）
- `-in`: INVITE方法的最大重试次数（默认: 10）
- `-ipdb`: IP数据库路径（默认: ./data/ipv4.ipdb）

## 架构设计

### 设计原则

项目采用模块化设计，遵循Go语言最佳实践：

- **消除全局变量**: 所有状态封装在结构体中
- **依赖注入**: 通过构造函数注入依赖，便于测试
- **单一职责**: 每个模块职责明确，易于维护和扩展
- **清晰的接口边界**: 模块间通过接口交互，降低耦合

### 模块职责

- **config**: 配置加载和命令行参数解析
- **capture**: 网络包捕获和设备管理
- **analyzer**: 流量分析和规则匹配
- **sip**: SIP协议解析
- **geoip**: IP地理位置查询
- **firewall**: iptables规则管理

### 工作流程

1. 启动时加载配置和初始化各模块
2. 扫描网卡并开始捕获指定端口的流量
3. 解析SIP协议包，提取关键信息
4. 检查IP地理位置，非中国IP直接封禁
5. 基于响应码和方法类型进行频率检测
6. 超过阈值时自动添加iptables封禁规则

## 注意事项

- 需要root权限运行（用于pcap和iptables操作）
- 确保已安装libpcap开发库
- IP数据库文件需要放在data目录下

## 依赖

- github.com/google/gopacket - 网络包捕获
- github.com/ipipdotnet/ipdb-go - IP地理位置查询
- github.com/patrickmn/go-cache - 内存缓存
- github.com/fatih/color - 彩色输出

## 测试

### 运行测试

```bash
# 运行所有测试
go test ./...

# 运行测试并生成覆盖率报告
go test ./... -coverprofile=coverage.out

# 查看覆盖率详情
go tool cover -func=coverage.out

# 生成HTML覆盖率报告
go tool cover -html=coverage.out -o coverage.html
```

### 测试覆盖率

- **总测试用例数**: 43个
- **internal包覆盖率**: 56.6%
- **核心模块覆盖率**:
  - config: 100%
  - sip: 93.8%
  - firewall: 38.5%
  - geoip: 38.5%
  - analyzer: 34.8%

部分模块覆盖率较低是因为依赖系统环境（iptables、IP数据库、网络包捕获），需要集成测试环境才能进一步提升。核心业务逻辑（配置管理、SIP协议解析）已达到高覆盖率。
