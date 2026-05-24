# Daemon 模式详解

## 概述

SIP-Ban 内置了简单的 daemon 能力，无需依赖 systemd 或 supervisor 即可后台常驻运行。本文档详细说明 daemon 模式的实现原理、使用方法和注意事项。

## 平台支持

- **Linux**：完整支持
- **macOS / Windows**：不支持（会报错 "daemon mode is Linux-only"）

## 使用方法

### 基本命令

```bash
# 后台启动（默认 PID 文件 /var/run/sip-ban.pid，日志 /var/log/sip-ban.log）
sudo ./sip-ban start -d -i eth0

# 查询状态
sudo ./sip-ban status

# 停止
sudo ./sip-ban stop

# 重启
sudo ./sip-ban restart -i eth0
```

### 自定义路径

```bash
# 指定 PID 文件和日志文件路径
sudo ./sip-ban start -d -pid /var/run/myban.pid -log /var/log/myban.log -i eth0

# 查询状态时需要指定相同的 PID 文件路径
sudo ./sip-ban status -pid /var/run/myban.pid

# 停止时也需要指定
sudo ./sip-ban stop -pid /var/run/myban.pid
```

### 非 root 用户运行

非 root 用户也可以使用 daemon 模式，程序会自动降级到 `$XDG_RUNTIME_DIR` 或 `/tmp`：

```bash
# 启动时会显示 "using fallback pidfile <path>"
./sip-ban start -d -i eth0

# 查询和停止时需要指定相同的路径
./sip-ban status -pid /tmp/sip-ban-<uid>.pid
./sip-ban stop -pid /tmp/sip-ban-<uid>.pid
```

**注意**：非 root 用户无法进行网络抓包和 iptables 操作，需要配置相应的 capabilities。

## 实现原理

### 双进程模型

```
┌─────────────────────────────────────────────────────────────┐
│                         父进程                                │
│  1. 解析参数                                                  │
│  2. 检查 PID 文件（防止重复启动）                              │
│  3. 创建握手管道                                              │
│  4. fork 子进程                                               │
│  5. 等待子进程握手（读取管道）                                 │
│  6. 退出（返回 shell）                                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ fork + exec
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         子进程                                │
│  1. 检测环境变量 SIPBAN_DAEMONIZED=1                          │
│  2. 写入 PID 文件（PID + start_time）                         │
│  3. 对 PID 文件加锁（flock）                                  │
│  4. 注册信号处理器（SIGTERM/SIGINT）                          │
│  5. 通过握手管道向父进程报告成功                               │
│  6. 执行业务逻辑                                              │
│  7. 收到信号或 context 取消时退出                             │
│  8. 清理资源（解锁、删除 PID 文件）                            │
└─────────────────────────────────────────────────────────────┘
```

### PID 文件格式

```
<pid> <start_time_jiffies>
```

示例：
```
12345 1234567890
```

- `pid`：进程 ID
- `start_time_jiffies`：进程启动时刻（从 `/proc/<pid>/stat` 第 22 字段读取）

### 进程身份校验

为了防止 PID 被复用（旧进程退出后，新进程恰好分配到相同的 PID），daemon 模式使用 **PID + start_time** 双重校验：

```go
// 1. 读取 PID 文件
expected_pid, expected_start_time := readPIDFile()

// 2. 读取 /proc/<pid>/stat 第 22 字段
actual_start_time := readProcStartTime(expected_pid)

// 3. 比较
if actual_start_time == expected_start_time {
    // 确认是同一个进程
} else {
    // PID 已被复用，原进程已退出
}
```

### 文件锁机制

使用 `flock` 对 PID 文件加锁，防止重复启动：

```go
// 子进程启动时
fd := open(pidPath, O_RDWR|O_CREATE)
flock(fd, LOCK_EX|LOCK_NB)  // 非阻塞排他锁
if err != nil {
    // 锁已被占用，说明已有实例在运行
    return ErrAlreadyRunning
}
```

### 握手协议

父子进程通过管道进行握手，确保子进程成功启动：

```
父进程                          子进程
  │                              │
  ├─ 创建管道 (fd 3)              │
  ├─ fork + exec ───────────────►│
  │                              ├─ 写入 PID 文件
  │                              ├─ 加锁
  │                              ├─ 注册信号
  │                              ├─ 写入管道 "ok\n"
  ├─ 读取管道 ◄──────────────────┤
  ├─ 收到 "ok" → 退出             │
  │                              ├─ 关闭管道
  │                              └─ 执行业务逻辑
```

如果子进程启动失败，会通过管道发送错误信息：

```
err: <错误描述>
```

父进程读取到错误信息后，会打印错误并以非零退出码退出。

### 信号处理

子进程注册 SIGTERM 和 SIGINT 信号处理器：

```go
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

go func() {
    <-sigCh
    cancel()  // 取消 context
}()
```

当收到信号时，通过 `context.Context` 通知所有 goroutine 优雅退出。

### 停止流程

```
1. 读取 PID 文件
2. 验证进程身份（PID + start_time）
3. 发送 SIGTERM 信号
4. 每 100ms 轮询一次，检查进程是否退出
5. 如果超时（默认 10 秒）仍未退出：
   ├─ 打印警告
   ├─ 发送 SIGKILL 信号
   └─ 再等待 2 秒
6. 进程退出后，删除 PID 文件
```

## 路径解析规则

### PID 文件路径

优先级（从高到低）：

1. 命令行参数 `-pid <path>`
2. 环境变量 `SIPBAN_PID_FILE`
3. root 用户：`/var/run/sip-ban.pid`
4. 非 root 用户：
   - `$XDG_RUNTIME_DIR/sip-ban.pid`（如果目录存在）
   - `/tmp/sip-ban-<uid>.pid`（fallback）

### 日志文件路径

优先级（从高到低）：

1. 命令行参数 `-log <path>`
2. 环境变量 `SIPBAN_LOG_FILE`
3. root 用户：`/var/log/sip-ban.log`
4. 非 root 用户：
   - `$XDG_RUNTIME_DIR/sip-ban.log`（如果目录存在）
   - `/tmp/sip-ban-<uid>.log`（fallback）

### Fallback 提示

当使用 fallback 路径时，程序会在 stdout 显式打印：

```
using fallback pidfile /tmp/sip-ban-1000.pid
```

这样可以避免运维人员在 `status` 或 `stop` 时找不到 PID 文件。

## 退出码约定

- `0`：成功
- `1`：用户错误
  - 参数错误
  - 已有实例在运行（`start` 时）
  - 平台不支持（macOS/Windows）
- `2`：系统错误
  - 启动失败
  - 停止失败
  - 握手失败
- `3`：进程未运行（`status` 或 `stop` 时）

## 状态查询

`status` 命令会显示以下信息：

```bash
$ sudo ./sip-ban status
running, pid=12345, uptime=1h23m45s, started_at=2026-05-24T10:30:00+08:00
```

- `pid`：进程 ID
- `uptime`：运行时长
- `started_at`：启动时间（RFC3339 格式）

如果进程未运行：

```bash
$ sudo ./sip-ban status
not running
```

如果 PID 文件存在但进程已退出（stale pidfile）：

```bash
$ sudo ./sip-ban status
not running (stale pidfile: /var/run/sip-ban.pid)
```

## 与 systemd 集成

虽然 daemon 模式可以独立运行，但如果需要开机自启，建议配合 systemd：

### 创建 systemd unit 文件

`/etc/systemd/system/sip-ban.service`：

```ini
[Unit]
Description=SIP-Ban - SIP Traffic Monitor and Firewall
After=network.target

[Service]
Type=forking
PIDFile=/var/run/sip-ban.pid
ExecStart=/usr/local/bin/sip-ban start -d -i eth0
ExecStop=/usr/local/bin/sip-ban stop
Restart=on-failure
RestartSec=5s

# 安全加固
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 启用和管理

```bash
# 重载 systemd 配置
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start sip-ban

# 查看状态
sudo systemctl status sip-ban

# 开机自启
sudo systemctl enable sip-ban

# 停止服务
sudo systemctl stop sip-ban

# 重启服务
sudo systemctl restart sip-ban

# 查看日志
sudo journalctl -u sip-ban -f
```

## 日志管理

### 日志输出

daemon 模式下，所有输出（stdout 和 stderr）会重定向到日志文件。

### 日志切割

程序本身不内建日志切割功能，长期运行建议配合 `logrotate`：

`/etc/logrotate.d/sip-ban`：

```
/var/log/sip-ban.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        /usr/bin/killall -SIGUSR1 sip-ban 2>/dev/null || true
    endscript
}
```

**注意**：当前版本不支持 SIGUSR1 重新打开日志文件，`postrotate` 脚本需要根据实际情况调整。

## 故障排查

### 启动失败

1. **检查权限**：
   ```bash
   # 需要 root 权限或 CAP_NET_RAW + CAP_NET_ADMIN
   sudo ./sip-ban start -d -i eth0
   ```

2. **检查 PID 文件**：
   ```bash
   # 查看 PID 文件是否存在
   ls -l /var/run/sip-ban.pid
   
   # 查看内容
   cat /var/run/sip-ban.pid
   
   # 手动删除（如果确认进程已退出）
   sudo rm /var/run/sip-ban.pid
   ```

3. **查看日志**：
   ```bash
   sudo tail -f /var/log/sip-ban.log
   ```

### 无法停止

1. **检查进程是否存在**：
   ```bash
   ps aux | grep sip-ban
   ```

2. **手动发送信号**：
   ```bash
   sudo kill -TERM <pid>
   
   # 如果无响应，强制终止
   sudo kill -KILL <pid>
   ```

3. **清理 PID 文件**：
   ```bash
   sudo rm /var/run/sip-ban.pid
   ```

### 重复启动

如果提示 "already running" 但实际进程不存在：

```bash
# 1. 检查 PID 文件
cat /var/run/sip-ban.pid

# 2. 检查进程是否存在
ps -p <pid>

# 3. 如果进程不存在，删除 PID 文件
sudo rm /var/run/sip-ban.pid

# 4. 重新启动
sudo ./sip-ban start -d -i eth0
```

## 安全考虑

### 1. 权限最小化

使用 Linux capabilities 代替 root 权限：

```bash
# 设置 capabilities
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/sip-ban

# 以普通用户运行
./sip-ban start -d -i eth0
```

### 2. PID 文件权限

确保 PID 文件只能被授权用户访问：

```bash
# root 用户
chmod 644 /var/run/sip-ban.pid

# 非 root 用户
chmod 600 /tmp/sip-ban-<uid>.pid
```

### 3. 日志文件权限

防止敏感信息泄露：

```bash
chmod 640 /var/log/sip-ban.log
chown root:adm /var/log/sip-ban.log
```

### 4. 防止 PID 复用攻击

daemon 模式通过 **PID + start_time** 双重校验，防止恶意进程伪装：

- 攻击者无法伪造 `/proc/<pid>/stat` 中的 start_time
- 即使 PID 被复用，start_time 也会不同

## 限制和注意事项

### 1. 平台限制

- 仅支持 Linux
- 依赖 `/proc` 文件系统

### 2. 不支持的功能

- 自动拉起（需要配合 systemd 或 cron）
- 日志切割（需要配合 logrotate）
- 热重载配置（需要重启）

### 3. 性能考虑

- daemon 模式本身开销极小（仅多一次 fork）
- 主要性能瓶颈在网络抓包和分析

### 4. 调试建议

开发和调试时建议使用前台模式：

```bash
# 前台运行，输出到终端
sudo ./sip-ban -i eth0

# 或者使用 start 不带 -d
sudo ./sip-ban start -i eth0
```

## 与其他 daemon 方案对比

| 特性 | 内置 daemon | systemd | supervisor |
|------|------------|---------|------------|
| 依赖 | 无 | systemd | Python |
| 平台支持 | Linux | Linux | 跨平台 |
| 开机自启 | 需手动配置 | 内置 | 需手动配置 |
| 日志管理 | 简单 | 强大 | 中等 |
| 进程监控 | 无 | 内置 | 内置 |
| 资源限制 | 无 | 内置 | 有限 |
| 学习成本 | 低 | 中 | 中 |

**建议**：
- 开发和测试：使用内置 daemon
- 生产环境：配合 systemd 使用
- 跨平台部署：考虑 supervisor

## 未来改进

1. **支持 SIGHUP 重载配置**
2. **支持 SIGUSR1 重新打开日志文件**
3. **内置日志切割**
4. **支持 macOS launchd**
5. **支持 Windows 服务**
6. **健康检查接口**
7. **性能监控指标**
