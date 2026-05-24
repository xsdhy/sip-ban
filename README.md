# SIP-Ban

基于 Go 语言开发的 SIP 协议流量监控和自动封禁工具，用于防护 VoIP 服务器免受恶意攻击。

## 📚 文档

完整文档请查看：**[docs/INDEX.md](docs/INDEX.md)**

文档包含：

- **快速开始** - 安装、部署和基本使用
- **架构设计** - 系统设计原则和模块详解
- **SIP 协议解析** - 协议基础和攻击模式识别
- **Daemon 模式** - 后台运行的实现原理
- **部署指南** - 生产环境部署和运维实践
- **开发指南** - 开发环境搭建和贡献指南
- **常见问题 (FAQ)** - 快速找到问题答案

## 🚀 快速开始

### 编译

```bash
go build -o sip-ban ./cmd/sip-ban
```

### 运行

```bash
# 前台运行
sudo ./sip-ban -i eth0

# 后台运行（仅 Linux）
sudo ./sip-ban start -d -i eth0

# 查询状态
sudo ./sip-ban status

# 停止
sudo ./sip-ban stop
```

更多使用方法请查看 [部署指南](docs/deployment-guide.md)。

## ✨ 功能特性

- 实时监控 SIP 协议流量（UDP/TCP）
- 基于地理位置的 IP 过滤
- 基于规则的频率限制检测
- 自动添加 iptables 封禁规则
- 支持多网卡同时监控
- 内置 Daemon 模式（Linux）

## 📖 更多信息

- **架构设计**：[docs/architecture.md](docs/architecture.md)
- **SIP 协议**：[docs/sip-protocol.md](docs/sip-protocol.md)
- **Daemon 模式**：[docs/daemon-mode.md](docs/daemon-mode.md)
- **部署指南**：[docs/deployment-guide.md](docs/deployment-guide.md)
- **开发指南**：[docs/development-guide.md](docs/development-guide.md)
- **常见问题**：[docs/faq.md](docs/faq.md)

## 🤝 贡献

欢迎贡献代码和文档，详见 [开发指南](docs/development-guide.md#贡献指南)。

## 📄 许可证

MIT License
