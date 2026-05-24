# 常见问题 (FAQ)

## 一般问题

### Q1: SIP-Ban 是什么？

SIP-Ban 是一个基于 Go 语言开发的 SIP 协议流量监控和自动封禁工具，用于保护 VoIP 服务器免受恶意攻击。它通过实时监控 SIP 流量，识别暴力破解、扫描攻击等恶意行为，并自动添加 iptables 规则封禁攻击者 IP。

### Q2: SIP-Ban 支持哪些平台？

- **Linux**：完整支持（包括 daemon 模式）
- **macOS**：支持前台运行模式，不支持 daemon 模式
- **Windows**：支持前台运行模式，不支持 daemon 模式

### Q3: SIP-Ban 需要什么权限？

SIP-Ban 需要以下权限：

- **网络抓包**：`CAP_NET_RAW` capability 或 root 权限
- **防火墙管理**：`CAP_NET_ADMIN` capability 或 root 权限

推荐使用 capabilities 代替 root：

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/sip-ban
```

### Q4: SIP-Ban 会影响正常用户吗？

SIP-Ban 采用保守的封禁策略，只在以下情况下封禁 IP：

1. **地理位置异常**：非中国 IP（可配置）
2. **频率异常**：短时间内大量失败请求（可配置阈值）

正常用户不会触发封禁规则。如果误封，可以手动解封：

```bash
sudo iptables -D INPUT -s <IP> -j DROP
```

### Q5: SIP-Ban 支持哪些 SIP 方法？

当前支持：

- INVITE（邀请）
- REGISTER（注册）
- ACK（确认）
- BYE（再见）
- CANCEL（取消）
- OPTIONS（选项）

可以通过修改 `internal/sip/method.go` 添加新方法。

## 安装和部署

### Q6: 如何安装 SIP-Ban？

**方式 1：二进制安装（推荐）**

```bash
wget https://github.com/your-org/sip-ban/releases/download/v1.0.0/sip-ban-linux-amd64
chmod +x sip-ban-linux-amd64
sudo mv sip-ban-linux-amd64 /usr/local/bin/sip-ban
```

**方式 2：源码编译**

```bash
git clone https://github.com/your-org/sip-ban.git
cd sip-ban
go build -o sip-ban ./cmd/sip-ban
sudo mv sip-ban /usr/local/bin/
```

详见 [部署指南](deployment-guide.md)。

### Q7: 如何配置开机自启？

使用 systemd：

```bash
# 创建服务文件
sudo nano /etc/systemd/system/sip-ban.service

# 启用服务
sudo systemctl enable sip-ban
sudo systemctl start sip-ban
```

详见 [部署指南 - systemd 集成](deployment-guide.md#systemd-集成)。

### Q8: 如何同时监控 TCP 和 UDP？

需要启动两个实例：

```bash
# UDP 实例
sudo sip-ban start -d -i eth0 -p udp -pid /var/run/sip-ban-udp.pid -log /var/log/sip-ban-udp.log

# TCP 实例
sudo sip-ban start -d -i eth0 -p tcp -pid /var/run/sip-ban-tcp.pid -log /var/log/sip-ban-tcp.log
```

或使用 systemd 模板服务，详见 [部署指南 - 多实例部署](deployment-guide.md#多实例部署)。

### Q9: 如何监控多个网卡？

**方式 1：不指定网卡（监控所有）**

```bash
sudo sip-ban start -d
```

**方式 2：启动多个实例**

```bash
sudo sip-ban start -d -i eth0 -pid /var/run/sip-ban-eth0.pid -log /var/log/sip-ban-eth0.log
sudo sip-ban start -d -i eth1 -pid /var/run/sip-ban-eth1.pid -log /var/log/sip-ban-eth1.log
```

## 配置和使用

### Q10: 如何调整封禁规则？

修改 `cmd/sip-ban/run.go` 中的规则：

```go
// 401 响应（认证失败）
banRuleCodes[401] = &analyzer.BanRule{
    FindTime: 120,  // 时间窗口（秒）
    MaxRetry: 40,   // 最大重试次数
}
```

重新编译后部署：

```bash
go build -o sip-ban ./cmd/sip-ban
sudo systemctl restart sip-ban
```

### Q11: 如何禁用地理位置检查？

修改 `cmd/sip-ban/run.go`，将 `geoChecker` 设置为 `nil`：

```go
var geoChecker *geoip.Checker = nil
```

或者修改 `internal/geoip/checker.go`，让所有 IP 都返回 `true`。

### Q12: 如何添加白名单？

当前版本不支持白名单功能，可以通过 iptables 实现：

```bash
# 在 INPUT 链开头添加白名单规则
sudo iptables -I INPUT 1 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -I INPUT 2 -s 10.0.0.0/8 -j ACCEPT

# 保存规则
sudo netfilter-persistent save
```

### Q13: 如何查看当前封禁的 IP？

```bash
# 查看所有 DROP 规则
sudo iptables -L INPUT -n -v | grep DROP

# 统计封禁 IP 数量
sudo iptables -L INPUT -n | grep DROP | wc -l

# 从日志中查看
sudo grep "BAN IP SUCCESS" /var/log/sip-ban.log
```

### Q14: 如何手动解封 IP？

```bash
# 删除指定 IP 的封禁规则
sudo iptables -D INPUT -s 203.0.113.50 -j DROP

# 或使用规则编号
sudo iptables -L INPUT -n --line-numbers
sudo iptables -D INPUT <行号>
```

### Q15: 如何清空所有封禁规则？

```bash
# 清空 INPUT 链（谨慎操作）
sudo iptables -F INPUT

# 或只删除 DROP 规则
sudo iptables -L INPUT -n --line-numbers | grep DROP | awk '{print $1}' | tac | xargs -I {} sudo iptables -D INPUT {}
```

## Daemon 模式

### Q16: 什么是 daemon 模式？

daemon 模式允许 SIP-Ban 在后台运行，无需依赖 systemd 或 supervisor。它通过 fork 子进程实现，父进程退出后子进程继续运行。

### Q17: daemon 模式支持哪些平台？

仅支持 Linux。macOS 和 Windows 上使用 daemon 模式会报错：

```
daemon mode is Linux-only
```

### Q18: 如何使用 daemon 模式？

```bash
# 启动
sudo sip-ban start -d -i eth0

# 查询状态
sudo sip-ban status

# 停止
sudo sip-ban stop

# 重启
sudo sip-ban restart -i eth0
```

详见 [Daemon 模式详解](daemon-mode.md)。

### Q19: 如何指定 PID 文件和日志文件路径？

```bash
sudo sip-ban start -d -i eth0 -pid /var/run/myban.pid -log /var/log/myban.log
```

查询和停止时也需要指定相同的 PID 文件路径：

```bash
sudo sip-ban status -pid /var/run/myban.pid
sudo sip-ban stop -pid /var/run/myban.pid
```

### Q20: 为什么提示 "already running"？

可能的原因：

1. **进程确实在运行**：使用 `ps aux | grep sip-ban` 确认
2. **PID 文件 stale**：进程已退出但 PID 文件未删除

解决方法：

```bash
# 检查进程
ps aux | grep sip-ban

# 如果进程不存在，删除 PID 文件
sudo rm /var/run/sip-ban.pid

# 重新启动
sudo sip-ban start -d -i eth0
```

### Q21: 如何查看 daemon 进程的运行时间？

```bash
sudo sip-ban status
```

输出示例：

```
running, pid=12345, uptime=1h23m45s, started_at=2026-05-24T10:30:00+08:00
```

## 日志和监控

### Q22: 日志文件在哪里？

- **daemon 模式**：`/var/log/sip-ban.log`（可通过 `-log` 参数指定）
- **前台模式**：输出到终端
- **systemd 模式**：`journalctl -u sip-ban`

### Q23: 如何实时查看日志？

```bash
# daemon 模式
sudo tail -f /var/log/sip-ban.log

# systemd 模式
sudo journalctl -u sip-ban -f
```

### Q24: 日志文件太大怎么办？

使用 logrotate 进行日志切割：

创建 `/etc/logrotate.d/sip-ban`：

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

详见 [部署指南 - 日志管理](deployment-guide.md#日志管理)。

### Q25: 如何统计封禁 IP 数量？

```bash
# 从日志统计
sudo grep "BAN IP SUCCESS" /var/log/sip-ban.log | wc -l

# 从 iptables 统计
sudo iptables -L INPUT -n | grep DROP | wc -l
```

### Q26: 如何监控 SIP-Ban 的运行状态？

创建健康检查脚本：

```bash
#!/bin/bash
if ! pgrep -f sip-ban > /dev/null; then
    echo "ERROR: sip-ban is not running"
    exit 1
fi
echo "OK: sip-ban is healthy"
exit 0
```

添加到 cron：

```bash
*/5 * * * * /usr/local/bin/sip-ban-healthcheck.sh || systemctl restart sip-ban
```

详见 [部署指南 - 监控和告警](deployment-guide.md#监控和告警)。

## 性能和优化

### Q27: SIP-Ban 的性能如何？

性能取决于硬件配置和流量规模：

| 流量规模 | CPU | 内存 | 推荐配置 |
|---------|-----|------|----------|
| < 100 并发 | 1 核 | 512 MB | 默认配置 |
| 100-1000 并发 | 2 核 | 2 GB | 调整 worker pool |
| > 1000 并发 | 4 核 | 4 GB | 多实例部署 |

### Q28: 如何优化性能？

1. **调整 worker pool 大小**：修改 `internal/capture/manager.go`
2. **使用 BPF 过滤器**：在内核层面过滤数据包
3. **调整系统参数**：增加网络缓冲区和文件描述符限制
4. **使用 CPU 亲和性**：绑定到特定 CPU 核心

详见 [部署指南 - 性能优化](deployment-guide.md#性能优化)。

### Q29: 内存使用持续增长怎么办？

可能的原因：

1. **缓存未过期**：go-cache 会自动清理过期条目
2. **封禁 IP 过多**：iptables 规则占用内存
3. **内存泄漏**：使用 pprof 分析

临时解决方法：

```bash
sudo systemctl restart sip-ban
```

### Q30: CPU 使用率过高怎么办？

可能的原因：

1. **流量过大**：使用 `iftop` 查看流量
2. **worker pool 过小**：调整 worker pool 大小
3. **BPF 过滤器不够严格**：优化过滤规则

## 故障排查

### Q31: 无法启动，提示 "permission denied"

**原因**：权限不足

**解决**：

```bash
# 使用 root 权限
sudo sip-ban start -d -i eth0

# 或设置 capabilities
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/sip-ban
```

### Q32: 无法捕获流量，日志中没有任何记录

**排查步骤**：

1. 检查网卡是否有流量：
   ```bash
   sudo tcpdump -i eth0 -n 'udp port 5060'
   ```

2. 检查网卡名称是否正确：
   ```bash
   ip addr show
   ```

3. 检查权限：
   ```bash
   sudo getcap /usr/local/bin/sip-ban
   ```

### Q33: 封禁不生效，IP 仍能访问

**排查步骤**：

1. 检查 iptables 规则：
   ```bash
   sudo iptables -L INPUT -n -v | grep <IP>
   ```

2. 检查规则顺序：
   ```bash
   sudo iptables -L INPUT -n --line-numbers
   # 确保 DROP 规则在 ACCEPT 规则之前
   ```

3. 检查防火墙是否启用：
   ```bash
   sudo iptables -L -n
   ```

### Q34: 编译错误：找不到 pcap.h

**原因**：未安装 libpcap 开发库

**解决**：

```bash
# Ubuntu/Debian
sudo apt install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel

# macOS
xcode-select --install
```

### Q35: 运行时错误：no suitable device found

**原因**：没有可用的网卡或权限不足

**解决**：

1. 检查网卡：
   ```bash
   ip addr show
   ```

2. 指定网卡：
   ```bash
   sudo sip-ban -i eth0
   ```

3. 检查权限：
   ```bash
   sudo sip-ban -i eth0
   ```

## 安全问题

### Q36: SIP-Ban 会记录敏感信息吗？

SIP-Ban 只记录以下信息：

- IP 地址
- 端口号
- SIP 方法
- 响应状态码
- Call-ID

不会记录：

- SIP 消息体（如 SDP）
- 认证凭据
- 用户密码

### Q37: 如何保护日志文件？

```bash
# 设置权限
sudo chmod 640 /var/log/sip-ban.log
sudo chown root:adm /var/log/sip-ban.log

# 定期清理
sudo logrotate -f /etc/logrotate.d/sip-ban
```

### Q38: 如何防止误封？

1. **调整封禁阈值**：增加 `MaxRetry` 值
2. **增加时间窗口**：增加 `FindTime` 值
3. **使用白名单**：通过 iptables 添加 ACCEPT 规则
4. **定期检查封禁列表**：及时解封误封 IP

### Q39: SIP-Ban 本身会被攻击吗？

SIP-Ban 采用以下安全措施：

1. **输入验证**：验证 IP 地址格式，拒绝特殊地址
2. **命令参数化**：避免命令注入
3. **资源限制**：worker pool 限制并发数量
4. **队列保护**：队列满时丢弃数据包，避免 OOM

建议：

- 使用 capabilities 代替 root
- 使用 AppArmor 或 SELinux 限制权限
- 定期更新到最新版本

## 开发和贡献

### Q40: 如何添加新的 SIP 方法？

1. 在 `internal/sip/method.go` 中定义：

```go
const (
    // 现有方法...
    MethodSubscribe Method = 7
)

var methodNames = map[Method]string{
    // 现有映射...
    MethodSubscribe: "SUBSCRIBE",
}

var methodValues = map[string]Method{
    // 现有映射...
    "SUBSCRIBE": MethodSubscribe,
}
```

2. 添加测试：

```go
func TestParseMethod_Subscribe(t *testing.T) {
    method, err := ParseMethod("SUBSCRIBE")
    assert.NoError(t, err)
    assert.Equal(t, MethodSubscribe, method)
}
```

3. 重新编译部署

### Q41: 如何添加新的封禁规则？

在 `cmd/sip-ban/run.go` 中：

```go
banRuleCodes[<状态码>] = &analyzer.BanRule{
    FindTime: <时间窗口>,
    MaxRetry: <最大次数>,
}
```

### Q42: 如何贡献代码？

1. Fork 项目
2. 创建特性分支
3. 提交更改
4. 创建 Pull Request

详见 [开发指南 - 贡献指南](development-guide.md#贡献指南)。

### Q43: 如何运行测试？

```bash
# 运行所有测试
go test ./...

# 运行特定包的测试
go test ./internal/sip

# 生成覆盖率报告
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Q44: 如何调试 SIP-Ban？

1. **使用 Delve 调试器**：
   ```bash
   sudo dlv exec ./sip-ban -- -i eth0
   ```

2. **添加调试日志**：
   ```go
   log.Printf("DEBUG: variable value = %v", variable)
   ```

3. **使用 pprof 性能分析**：
   ```go
   import _ "net/http/pprof"
   go func() {
       log.Println(http.ListenAndServe("localhost:6060", nil))
   }()
   ```

详见 [开发指南 - 调试技巧](development-guide.md#调试技巧)。

## 其他问题

### Q45: SIP-Ban 支持 IPv6 吗？

当前版本仅支持 IPv4。IPv6 支持计划在未来版本中添加。

### Q46: SIP-Ban 支持其他协议吗？

当前版本仅支持 SIP 协议。如果需要支持其他协议（如 RTP、RTCP），需要修改代码。

### Q47: SIP-Ban 可以用于其他场景吗？

SIP-Ban 的架构设计是模块化的，可以扩展到其他场景：

- HTTP 暴力破解防护
- SSH 暴力破解防护
- DNS 查询监控

需要修改 `internal/sip` 和 `internal/analyzer` 模块。

### Q48: SIP-Ban 有 Web 界面吗？

当前版本没有 Web 界面。可以通过以下方式查看状态：

- 命令行：`sip-ban status`
- 日志：`tail -f /var/log/sip-ban.log`
- iptables：`iptables -L INPUT -n -v`

Web 界面计划在未来版本中添加。

### Q49: SIP-Ban 支持分布式部署吗？

当前版本不支持分布式部署。每个实例独立运行，封禁规则不共享。

如果需要分布式部署，可以考虑：

- 使用中心化的封禁列表（Redis、etcd）
- 使用消息队列同步封禁事件
- 使用 API 接口管理封禁规则

### Q50: 如何联系维护者？

- **提交 Issue**：https://github.com/your-org/sip-ban/issues
- **发起 Pull Request**：https://github.com/your-org/sip-ban/pulls
- **邮件联系**：maintainer@example.com

## 相关资源

- [README](../README.md) - 项目说明
- [架构设计文档](architecture.md) - 系统架构
- [Daemon 模式详解](daemon-mode.md) - Daemon 模式
- [开发指南](development-guide.md) - 开发文档
- [部署指南](deployment-guide.md) - 部署文档
- [SIP 协议解析详解](sip-protocol.md) - SIP 协议
