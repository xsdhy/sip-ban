# 部署指南

## 概述

本文档提供 SIP-Ban 在生产环境中的部署指南，包括系统要求、安装步骤、配置建议和运维实践。

## 系统要求

### 硬件要求

| 流量规模 | CPU | 内存 | 磁盘 |
|---------|-----|------|------|
| 小型（< 100 并发） | 1 核 | 512 MB | 10 GB |
| 中型（100-1000 并发） | 2 核 | 2 GB | 20 GB |
| 大型（> 1000 并发） | 4 核 | 4 GB | 50 GB |

### 软件要求

- **操作系统**：Linux（推荐 Ubuntu 20.04+ 或 CentOS 7+）
- **内核版本**：3.10+
- **依赖库**：libpcap
- **权限**：root 或 CAP_NET_RAW + CAP_NET_ADMIN

### 网络要求

- 能够访问被保护的 SIP 服务器网卡
- 能够执行 iptables 命令
- 建议部署在 SIP 服务器同一主机或同一网段

## 安装方式

### 方式 1：二进制安装（推荐）

```bash
# 下载最新版本
wget https://github.com/your-org/sip-ban/releases/download/v1.0.0/sip-ban-linux-amd64

# 添加执行权限
chmod +x sip-ban-linux-amd64

# 移动到系统路径
sudo mv sip-ban-linux-amd64 /usr/local/bin/sip-ban

# 验证安装
sip-ban -h
```

### 方式 2：源码编译

```bash
# 安装 Go 1.21+
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# 安装依赖
sudo apt update
sudo apt install -y libpcap-dev git

# 克隆项目
git clone https://github.com/your-org/sip-ban.git
cd sip-ban

# 编译
go build -o sip-ban ./cmd/sip-ban

# 安装
sudo mv sip-ban /usr/local/bin/
```

### 方式 3：Docker 部署

```bash
# 拉取镜像
docker pull your-org/sip-ban:latest

# 运行容器（需要 host 网络模式和特权模式）
docker run -d \
  --name sip-ban \
  --network host \
  --privileged \
  -v /var/log/sip-ban:/var/log \
  your-org/sip-ban:latest \
  start -d -i eth0
```

**注意**：Docker 部署需要 `--privileged` 和 `--network host`，因为需要访问网络接口和修改 iptables。

## 配置

### 基本配置

```bash
# 监控指定网卡的 UDP 5060 端口
sudo sip-ban start -d -i eth0

# 自定义端口
sudo sip-ban start -d -i eth0 -P 5061

# 同时监控 TCP 和 UDP（需要启动两个实例）
sudo sip-ban start -d -i eth0 -p udp -pid /var/run/sip-ban-udp.pid -log /var/log/sip-ban-udp.log
sudo sip-ban start -d -i eth0 -p tcp -pid /var/run/sip-ban-tcp.pid -log /var/log/sip-ban-tcp.log
```

### 调整封禁规则

修改 `cmd/sip-ban/run.go` 中的规则：

```go
// REGISTER 暴力破解检测
// 120 秒内超过 40 次 401 响应
banRuleCodes[401] = &analyzer.BanRule{
    FindTime: 120,  // 时间窗口（秒）
    MaxRetry: 40,   // 最大重试次数
}

// INVITE 洪水攻击检测
// 60 秒内超过 10 次 486 响应
banRuleCodes[486] = &analyzer.BanRule{
    FindTime: 60,
    MaxRetry: 10,
}
```

重新编译后部署：

```bash
go build -o sip-ban ./cmd/sip-ban
sudo systemctl restart sip-ban
```

### IP 数据库配置

```bash
# 下载最新的 IP 数据库
wget https://your-ipdb-source/ipv4.ipdb -O /opt/sip-ban/data/ipv4.ipdb

# 指定数据库路径
sudo sip-ban start -d -i eth0 -ipdb /opt/sip-ban/data/ipv4.ipdb
```

## systemd 集成

### 创建 systemd 服务

创建 `/etc/systemd/system/sip-ban.service`：

```ini
[Unit]
Description=SIP-Ban - SIP Traffic Monitor and Firewall
Documentation=https://github.com/your-org/sip-ban
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/sip-ban.pid
ExecStart=/usr/local/bin/sip-ban start -d -i eth0 -P 5060
ExecStop=/usr/local/bin/sip-ban stop
ExecReload=/usr/local/bin/sip-ban restart -i eth0 -P 5060
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

# 安全加固
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/run /var/log

# 资源限制
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
```

### 启用服务

```bash
# 重载 systemd 配置
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start sip-ban

# 查看状态
sudo systemctl status sip-ban

# 开机自启
sudo systemctl enable sip-ban

# 查看日志
sudo journalctl -u sip-ban -f
```

### 多实例部署

如果需要同时监控 TCP 和 UDP：

`/etc/systemd/system/sip-ban@.service`：

```ini
[Unit]
Description=SIP-Ban - %i
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/sip-ban-%i.pid
EnvironmentFile=/etc/sip-ban/%i.conf
ExecStart=/usr/local/bin/sip-ban start -d -pid /var/run/sip-ban-%i.pid -log /var/log/sip-ban-%i.log $OPTIONS
ExecStop=/usr/local/bin/sip-ban stop -pid /var/run/sip-ban-%i.pid
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

配置文件：

`/etc/sip-ban/udp.conf`：
```bash
OPTIONS="-i eth0 -p udp -P 5060"
```

`/etc/sip-ban/tcp.conf`：
```bash
OPTIONS="-i eth0 -p tcp -P 5060"
```

启用：

```bash
sudo systemctl enable sip-ban@udp
sudo systemctl enable sip-ban@tcp
sudo systemctl start sip-ban@udp
sudo systemctl start sip-ban@tcp
```

## 日志管理

### 日志位置

- **默认日志**：`/var/log/sip-ban.log`
- **systemd 日志**：`journalctl -u sip-ban`

### 日志格式

```
2026-05-24 10:30:15 eth0 UDP-OUT 192.168.1.100:5060->203.0.113.50:5060 abc123@192.168.1.100 REGISTER Unauthorized.401 Rule:120-40 Key:203.0.113.50.401 Times:41
BAN___ 2026-05-24 10:30:15 eth0 UDP-OUT 192.168.1.100:5060->203.0.113.50:5060 abc123@192.168.1.100 REGISTER Unauthorized.401 Rule:120-40 Key:203.0.113.50.401 Times:41
BAN IP SUCCESS 203.0.113.50
```

### 日志切割

使用 logrotate 管理日志：

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
    sharedscripts
    postrotate
        # 当前版本不支持重新打开日志，需要重启
        systemctl restart sip-ban > /dev/null 2>&1 || true
    endscript
}
```

测试配置：

```bash
sudo logrotate -d /etc/logrotate.d/sip-ban
```

手动执行：

```bash
sudo logrotate -f /etc/logrotate.d/sip-ban
```

### 日志监控

使用 `tail` 实时查看：

```bash
sudo tail -f /var/log/sip-ban.log
```

使用 `grep` 过滤封禁事件：

```bash
sudo grep "BAN IP SUCCESS" /var/log/sip-ban.log
```

统计封禁 IP 数量：

```bash
sudo grep "BAN IP SUCCESS" /var/log/sip-ban.log | wc -l
```

## 防火墙管理

### 查看封禁规则

```bash
# 查看所有 INPUT 链规则
sudo iptables -L INPUT -n -v

# 查看 DROP 规则
sudo iptables -L INPUT -n -v | grep DROP

# 统计封禁 IP 数量
sudo iptables -L INPUT -n | grep DROP | wc -l
```

### 手动解封 IP

```bash
# 删除指定 IP 的封禁规则
sudo iptables -D INPUT -s 203.0.113.50 -j DROP

# 或使用规则编号
sudo iptables -L INPUT -n --line-numbers
sudo iptables -D INPUT <行号>
```

### 清空所有封禁规则

```bash
# 清空 INPUT 链（谨慎操作）
sudo iptables -F INPUT

# 或只删除 SIP-Ban 添加的规则
sudo iptables -L INPUT -n --line-numbers | grep DROP | awk '{print $1}' | tac | xargs -I {} sudo iptables -D INPUT {}
```

### 持久化 iptables 规则

#### Ubuntu/Debian

```bash
# 安装 iptables-persistent
sudo apt install iptables-persistent

# 保存当前规则
sudo netfilter-persistent save

# 重启后自动加载
sudo systemctl enable netfilter-persistent
```

#### CentOS/RHEL

```bash
# 保存规则
sudo service iptables save

# 或
sudo iptables-save > /etc/sysconfig/iptables
```

### 白名单配置

如果需要白名单功能，可以在 iptables 中添加 ACCEPT 规则：

```bash
# 在 INPUT 链开头添加白名单规则
sudo iptables -I INPUT 1 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -I INPUT 2 -s 10.0.0.0/8 -j ACCEPT

# 保存规则
sudo netfilter-persistent save
```

## 性能优化

### 1. 调整 Worker Pool 大小

修改 `internal/capture/manager.go`：

```go
const defaultWorkerPoolSize = 200  // 默认 100，根据 CPU 核心数调整
const defaultPacketQueueSize = 2000  // 默认 1000，根据内存大小调整
```

### 2. 使用 BPF 过滤器

BPF 过滤器在内核层面过滤数据包，减少用户空间处理：

```go
// 只捕获 SIP 端口的流量
bpf := "udp and port 5060"

// 排除本地流量
bpf := "udp and port 5060 and not src host 127.0.0.1"

// 只捕获特定网段
bpf := "udp and port 5060 and src net 0.0.0.0/0"
```

### 3. 调整系统参数

编辑 `/etc/sysctl.conf`：

```bash
# 增加网络缓冲区
net.core.rmem_max = 134217728
net.core.rmem_default = 67108864
net.core.wmem_max = 134217728
net.core.wmem_default = 67108864

# 增加连接跟踪表大小
net.netfilter.nf_conntrack_max = 1048576

# 增加文件描述符限制
fs.file-max = 1048576
```

应用配置：

```bash
sudo sysctl -p
```

### 4. 使用 CPU 亲和性

将进程绑定到特定 CPU 核心：

```bash
# 绑定到 CPU 0-3
sudo taskset -c 0-3 /usr/local/bin/sip-ban start -d -i eth0
```

## 监控和告警

### 1. 监控指标

关键指标：

- **封禁 IP 数量**：`grep "BAN IP SUCCESS" /var/log/sip-ban.log | wc -l`
- **处理数据包数量**：通过日志统计
- **内存使用**：`ps aux | grep sip-ban`
- **CPU 使用**：`top -p $(pgrep sip-ban)`
- **iptables 规则数量**：`iptables -L INPUT -n | grep DROP | wc -l`

### 2. 健康检查脚本

创建 `/usr/local/bin/sip-ban-healthcheck.sh`：

```bash
#!/bin/bash

# 检查进程是否运行
if ! pgrep -f sip-ban > /dev/null; then
    echo "ERROR: sip-ban is not running"
    exit 1
fi

# 检查日志是否有新内容（最近 5 分钟）
if [ $(find /var/log/sip-ban.log -mmin -5 | wc -l) -eq 0 ]; then
    echo "WARNING: No log updates in the last 5 minutes"
    exit 2
fi

# 检查内存使用
MEM_USAGE=$(ps aux | grep sip-ban | grep -v grep | awk '{print $4}')
if (( $(echo "$MEM_USAGE > 50" | bc -l) )); then
    echo "WARNING: High memory usage: ${MEM_USAGE}%"
    exit 2
fi

echo "OK: sip-ban is healthy"
exit 0
```

添加到 cron：

```bash
# 每 5 分钟检查一次
*/5 * * * * /usr/local/bin/sip-ban-healthcheck.sh || /usr/bin/systemctl restart sip-ban
```

### 3. Prometheus 集成（未来功能）

当前版本不支持 Prometheus metrics，可以通过日志解析实现：

```bash
# 使用 mtail 或 promtail 解析日志
# 导出 metrics 到 Prometheus
```

### 4. 告警配置

使用 Prometheus Alertmanager 或简单的邮件告警：

创建 `/usr/local/bin/sip-ban-alert.sh`：

```bash
#!/bin/bash

# 检查最近 1 小时封禁的 IP 数量
BAN_COUNT=$(grep "BAN IP SUCCESS" /var/log/sip-ban.log | grep "$(date +%Y-%m-%d\ %H)" | wc -l)

if [ $BAN_COUNT -gt 100 ]; then
    echo "High ban rate: $BAN_COUNT IPs banned in the last hour" | \
    mail -s "SIP-Ban Alert" admin@example.com
fi
```

添加到 cron：

```bash
# 每小时检查一次
0 * * * * /usr/local/bin/sip-ban-alert.sh
```

## 高可用部署

### 主备模式

在两台服务器上部署 SIP-Ban，使用 Keepalived 实现主备切换：

`/etc/keepalived/keepalived.conf`：

```
vrrp_script check_sip_ban {
    script "/usr/local/bin/sip-ban-healthcheck.sh"
    interval 5
    weight -20
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1
    
    authentication {
        auth_type PASS
        auth_pass secret
    }
    
    virtual_ipaddress {
        192.168.1.100/24
    }
    
    track_script {
        check_sip_ban
    }
}
```

### 负载均衡模式

使用多台服务器分别监控不同的网卡或端口：

```
服务器 1: 监控 eth0 UDP 5060
服务器 2: 监控 eth1 UDP 5060
服务器 3: 监控 eth0 TCP 5060
```

## 安全加固

### 1. 使用 Capabilities 代替 root

```bash
# 设置 capabilities
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/sip-ban

# 创建专用用户
sudo useradd -r -s /bin/false sipban

# 以普通用户运行
sudo -u sipban /usr/local/bin/sip-ban start -d -i eth0
```

### 2. 限制文件权限

```bash
# PID 文件
sudo chmod 644 /var/run/sip-ban.pid

# 日志文件
sudo chmod 640 /var/log/sip-ban.log
sudo chown root:adm /var/log/sip-ban.log

# 配置文件
sudo chmod 600 /etc/sip-ban/*.conf
```

### 3. 使用 AppArmor 或 SELinux

创建 AppArmor 配置文件（Ubuntu）：

`/etc/apparmor.d/usr.local.bin.sip-ban`：

```
#include <tunables/global>

/usr/local/bin/sip-ban {
  #include <abstractions/base>
  
  capability net_raw,
  capability net_admin,
  
  /usr/local/bin/sip-ban r,
  /var/run/sip-ban.pid rw,
  /var/log/sip-ban.log w,
  /proc/*/stat r,
  /sys/class/net/ r,
  
  # IP 数据库
  /opt/sip-ban/data/ipv4.ipdb r,
}
```

加载配置：

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.sip-ban
```

## 故障排查

### 问题 1：无法启动

**症状**：`start` 命令失败

**排查步骤**：

1. 检查权限：
   ```bash
   sudo /usr/local/bin/sip-ban start -d -i eth0
   ```

2. 检查网卡是否存在：
   ```bash
   ip addr show eth0
   ```

3. 检查 PID 文件：
   ```bash
   ls -l /var/run/sip-ban.pid
   sudo rm /var/run/sip-ban.pid  # 如果是 stale
   ```

4. 查看日志：
   ```bash
   sudo tail -f /var/log/sip-ban.log
   ```

### 问题 2：无法捕获流量

**症状**：日志中没有任何流量记录

**排查步骤**：

1. 检查网卡是否有流量：
   ```bash
   sudo tcpdump -i eth0 -n 'udp port 5060'
   ```

2. 检查 BPF 过滤器：
   ```bash
   # 在代码中临时移除 BPF 过滤器测试
   ```

3. 检查权限：
   ```bash
   sudo getcap /usr/local/bin/sip-ban
   ```

### 问题 3：封禁不生效

**症状**：IP 被封禁但仍能访问

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

### 问题 4：内存泄漏

**症状**：内存使用持续增长

**排查步骤**：

1. 使用 pprof 分析：
   ```bash
   go tool pprof http://localhost:6060/debug/pprof/heap
   ```

2. 检查缓存大小：
   ```bash
   # 查看日志中的缓存操作
   grep "SET CACHE" /var/log/sip-ban.log | wc -l
   ```

3. 重启服务：
   ```bash
   sudo systemctl restart sip-ban
   ```

### 问题 5：CPU 使用率过高

**症状**：CPU 使用率持续 > 80%

**排查步骤**：

1. 检查流量大小：
   ```bash
   sudo iftop -i eth0
   ```

2. 调整 worker pool 大小

3. 使用更严格的 BPF 过滤器

4. 考虑硬件升级

## 升级指南

### 升级步骤

1. 备份当前版本：
   ```bash
   sudo cp /usr/local/bin/sip-ban /usr/local/bin/sip-ban.bak
   ```

2. 停止服务：
   ```bash
   sudo systemctl stop sip-ban
   ```

3. 替换二进制文件：
   ```bash
   sudo cp sip-ban-new /usr/local/bin/sip-ban
   sudo chmod +x /usr/local/bin/sip-ban
   ```

4. 启动服务：
   ```bash
   sudo systemctl start sip-ban
   ```

5. 验证：
   ```bash
   sudo systemctl status sip-ban
   sudo tail -f /var/log/sip-ban.log
   ```

### 回滚

如果升级失败：

```bash
sudo systemctl stop sip-ban
sudo cp /usr/local/bin/sip-ban.bak /usr/local/bin/sip-ban
sudo systemctl start sip-ban
```

## 最佳实践

1. **定期备份 iptables 规则**
2. **监控日志大小，及时切割**
3. **定期更新 IP 数据库**
4. **配置告警，及时发现异常**
5. **定期检查封禁 IP 列表，清理误封**
6. **使用白名单保护关键 IP**
7. **在测试环境验证配置变更**
8. **记录所有配置变更**

## 参考配置

### 小型部署（< 100 并发）

```bash
sudo sip-ban start -d -i eth0 -P 5060 \
  -rt 120 -rn 40 \
  -it 60 -in 10
```

### 中型部署（100-1000 并发）

```bash
# 调整 worker pool 大小（需要重新编译）
# defaultWorkerPoolSize = 200
# defaultPacketQueueSize = 2000

sudo sip-ban start -d -i eth0 -P 5060 \
  -rt 60 -rn 30 \
  -it 30 -in 5
```

### 大型部署（> 1000 并发）

```bash
# 多实例部署
sudo sip-ban start -d -i eth0 -p udp -P 5060 \
  -pid /var/run/sip-ban-udp.pid \
  -log /var/log/sip-ban-udp.log

sudo sip-ban start -d -i eth0 -p tcp -P 5060 \
  -pid /var/run/sip-ban-tcp.pid \
  -log /var/log/sip-ban-tcp.log

# 配合硬件负载均衡
```
