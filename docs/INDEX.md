# SIP-Ban 文档中心

欢迎来到 SIP-Ban 文档中心。这里提供了完整的文档，帮助您了解、部署和使用 SIP-Ban。

## 📚 文档导航

### 快速开始

- **[项目 README](../README.md)** - 项目概述、快速开始和基本使用
- **[常见问题 (FAQ)](faq.md)** - 常见问题解答，快速找到答案

### 核心文档

- **[架构设计文档](architecture.md)** - 系统架构、设计原则和模块详解
- **[SIP 协议解析详解](sip-protocol.md)** - SIP 协议基础和解析实现
- **[Daemon 模式详解](daemon-mode.md)** - 后台运行模式的实现原理和使用方法

### 运维文档

- **[部署指南](deployment-guide.md)** - 生产环境部署、配置和运维实践
- **[监控和告警](deployment-guide.md#监控和告警)** - 监控指标和告警配置
- **[故障排查](deployment-guide.md#故障排查)** - 常见问题的排查和解决

### 开发文档

- **[开发指南](development-guide.md)** - 开发环境搭建、代码规范和贡献指南
- **[测试指南](development-guide.md#测试)** - 单元测试、集成测试和性能测试
- **[API 文档](development-guide.md#添加新功能)** - 扩展和定制开发

## 🎯 按角色查看

### 我是运维工程师

1. 先阅读 [项目 README](../README.md) 了解基本概念
2. 参考 [部署指南](deployment-guide.md) 进行部署
3. 配置 [监控和告警](deployment-guide.md#监控和告警)
4. 遇到问题查看 [常见问题 (FAQ)](faq.md) 或 [故障排查](deployment-guide.md#故障排查)

### 我是开发者

1. 阅读 [架构设计文档](architecture.md) 了解系统设计
2. 参考 [开发指南](development-guide.md) 搭建开发环境
3. 查看 [SIP 协议解析详解](sip-protocol.md) 了解协议处理
4. 贡献代码前阅读 [贡献指南](development-guide.md#贡献指南)

### 我是安全研究员

1. 阅读 [SIP 协议解析详解](sip-protocol.md) 了解攻击模式识别
2. 查看 [架构设计文档](architecture.md) 了解防护机制
3. 参考 [开发指南](development-guide.md) 添加新的检测规则

### 我是新用户

1. 从 [项目 README](../README.md) 开始
2. 查看 [常见问题 (FAQ)](faq.md) 了解基本概念
3. 参考 [部署指南](deployment-guide.md) 快速部署
4. 遇到问题先查 [FAQ](faq.md)，再查 [故障排查](deployment-guide.md#故障排查)

## 📖 文档详情

### [架构设计文档](architecture.md)

**内容概览**：
- 设计原则（模块化、无全局状态、依赖注入）
- 系统架构图和模块职责
- 核心模块详解（config、daemon、capture、sip、analyzer、geoip、firewall）
- 工作流程（前台模式、后台模式、数据包分析）
- 并发模型和同步机制
- 平台兼容性和错误处理
- 性能优化和扩展性

**适合人群**：开发者、架构师、技术决策者

### [SIP 协议解析详解](sip-protocol.md)

**内容概览**：
- SIP 协议基础（消息类型、格式）
- 支持的 SIP 方法（INVITE、REGISTER、ACK、BYE、CANCEL、OPTIONS）
- 响应状态码分类（1xx-6xx）
- 头部字段说明
- SIP-Ban 的解析实现
- 攻击模式识别（暴力破解、扫描攻击、DoS）
- 典型攻击场景和防护策略
- 协议扩展和性能优化

**适合人群**：开发者、安全研究员、运维工程师

### [Daemon 模式详解](daemon-mode.md)

**内容概览**：
- Daemon 模式概述和平台支持
- 使用方法（启动、停止、重启、状态查询）
- 实现原理（双进程模型、PID 文件、进程身份校验、文件锁、握手协议、信号处理）
- 路径解析规则（PID 文件、日志文件）
- 退出码约定
- 与 systemd 集成
- 日志管理和故障排查
- 安全考虑和限制

**适合人群**：运维工程师、开发者

### [部署指南](deployment-guide.md)

**内容概览**：
- 系统要求（硬件、软件、网络）
- 安装方式（二进制、源码编译、Docker）
- 配置（基本配置、封禁规则、IP 数据库）
- systemd 集成（单实例、多实例）
- 日志管理（日志位置、格式、切割、监控）
- 防火墙管理（查看规则、解封 IP、持久化、白名单）
- 性能优化（Worker Pool、BPF 过滤器、系统参数、CPU 亲和性）
- 监控和告警（监控指标、健康检查、Prometheus 集成）
- 高可用部署（主备模式、负载均衡）
- 安全加固（Capabilities、文件权限、AppArmor/SELinux）
- 故障排查（常见问题和解决方法）
- 升级指南和最佳实践

**适合人群**：运维工程师、系统管理员

### [开发指南](development-guide.md)

**内容概览**：
- 开发环境搭建（系统要求、依赖安装）
- 项目结构详解
- 编译和运行（本地编译、交叉编译）
- 测试（单元测试、覆盖率、基准测试、竞态检测）
- 代码规范（格式化、静态检查、Linter、命名规范、注释规范）
- 添加新功能（SIP 方法、封禁规则、配置项、防火墙后端）
- 调试技巧（Delve、日志、pprof、tcpdump）
- 常见问题和解决方法
- 贡献指南（提交规范、PR 流程、代码审查）
- 性能优化建议
- 安全开发实践
- 平台特定开发（Build Tags、条件编译）
- 发布流程

**适合人群**：开发者、贡献者

### [常见问题 (FAQ)](faq.md)

**内容概览**：
- 一般问题（什么是 SIP-Ban、支持的平台、权限要求）
- 安装和部署（安装方法、开机自启、多网卡监控）
- 配置和使用（调整规则、白名单、查看封禁 IP、解封 IP）
- Daemon 模式（使用方法、PID 文件、运行时间）
- 日志和监控（日志位置、实时查看、日志切割、统计）
- 性能和优化（性能指标、优化方法、内存和 CPU 问题）
- 故障排查（启动失败、无法捕获流量、封禁不生效、编译错误）
- 安全问题（敏感信息、日志保护、防止误封）
- 开发和贡献（添加新功能、运行测试、调试）
- 其他问题（IPv6、其他协议、Web 界面、分布式部署）

**适合人群**：所有用户

## 🔍 快速查找

### 按主题查找

| 主题 | 相关文档 |
|------|----------|
| 安装部署 | [部署指南](deployment-guide.md)、[FAQ Q6-Q9](faq.md#q6-如何安装-sip-ban) |
| 配置调优 | [部署指南 - 配置](deployment-guide.md#配置)、[FAQ Q10-Q15](faq.md#q10-如何调整封禁规则) |
| Daemon 模式 | [Daemon 模式详解](daemon-mode.md)、[FAQ Q16-Q21](faq.md#q16-什么是-daemon-模式) |
| 日志管理 | [部署指南 - 日志管理](deployment-guide.md#日志管理)、[FAQ Q22-Q26](faq.md#q22-日志文件在哪里) |
| 性能优化 | [部署指南 - 性能优化](deployment-guide.md#性能优化)、[FAQ Q27-Q30](faq.md#q27-sip-ban-的性能如何) |
| 故障排查 | [部署指南 - 故障排查](deployment-guide.md#故障排查)、[FAQ Q31-Q35](faq.md#q31-无法启动提示-permission-denied) |
| 开发贡献 | [开发指南](development-guide.md)、[FAQ Q40-Q44](faq.md#q40-如何添加新的-sip-方法) |
| SIP 协议 | [SIP 协议解析详解](sip-protocol.md)、[FAQ Q5](faq.md#q5-sip-ban-支持哪些-sip-方法) |
| 架构设计 | [架构设计文档](architecture.md) |

### 按问题类型查找

| 问题类型 | 查看文档 |
|---------|----------|
| 无法启动 | [FAQ Q31](faq.md#q31-无法启动提示-permission-denied)、[部署指南 - 故障排查](deployment-guide.md#问题-1无法启动) |
| 无法捕获流量 | [FAQ Q32](faq.md#q32-无法捕获流量日志中没有任何记录)、[部署指南 - 故障排查](deployment-guide.md#问题-2无法捕获流量) |
| 封禁不生效 | [FAQ Q33](faq.md#q33-封禁不生效ip-仍能访问)、[部署指南 - 故障排查](deployment-guide.md#问题-3封禁不生效) |
| 编译错误 | [FAQ Q34](faq.md#q34-编译错误找不到-pcaph)、[开发指南 - 常见问题](development-guide.md#常见问题) |
| 内存泄漏 | [FAQ Q29](faq.md#q29-内存使用持续增长怎么办)、[部署指南 - 故障排查](deployment-guide.md#问题-4内存泄漏) |
| CPU 过高 | [FAQ Q30](faq.md#q30-cpu-使用率过高怎么办)、[部署指南 - 故障排查](deployment-guide.md#问题-5cpu-使用率过高) |

## 🛠️ 实用工具

### 命令速查

```bash
# 启动（前台）
sudo sip-ban -i eth0

# 启动（后台）
sudo sip-ban start -d -i eth0

# 查询状态
sudo sip-ban status

# 停止
sudo sip-ban stop

# 重启
sudo sip-ban restart -i eth0

# 查看日志
sudo tail -f /var/log/sip-ban.log

# 查看封禁 IP
sudo iptables -L INPUT -n -v | grep DROP

# 解封 IP
sudo iptables -D INPUT -s <IP> -j DROP

# 查看 systemd 日志
sudo journalctl -u sip-ban -f
```

### 配置模板

**systemd 服务文件**：`/etc/systemd/system/sip-ban.service`

```ini
[Unit]
Description=SIP-Ban - SIP Traffic Monitor and Firewall
After=network-online.target

[Service]
Type=forking
PIDFile=/var/run/sip-ban.pid
ExecStart=/usr/local/bin/sip-ban start -d -i eth0
ExecStop=/usr/local/bin/sip-ban stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

**logrotate 配置**：`/etc/logrotate.d/sip-ban`

```
/var/log/sip-ban.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl restart sip-ban > /dev/null 2>&1 || true
    endscript
}
```

## 📝 文档贡献

如果您发现文档有错误或需要改进，欢迎贡献：

1. Fork 项目
2. 修改文档（Markdown 格式）
3. 提交 Pull Request

文档风格指南：

- 使用清晰的标题层次
- 提供代码示例
- 包含实际的命令输出
- 添加图表和流程图（如适用）
- 保持语言简洁明了

## 🔗 相关链接

- **GitHub 仓库**：https://github.com/your-org/sip-ban
- **问题反馈**：https://github.com/your-org/sip-ban/issues
- **Pull Requests**：https://github.com/your-org/sip-ban/pulls
- **发布版本**：https://github.com/your-org/sip-ban/releases

## 📄 许可证

本文档遵循与 SIP-Ban 项目相同的许可证。

---

**最后更新**：2026-05-24

**文档版本**：1.0.0

如有疑问，请查看 [常见问题 (FAQ)](faq.md) 或提交 [Issue](https://github.com/your-org/sip-ban/issues)。
