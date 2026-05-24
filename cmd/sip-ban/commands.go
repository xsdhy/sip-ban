// Package main 的子命令具体实现：start / status / stop / restart。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"sip-ban/internal/config"
	"sip-ban/internal/daemon"
)

// stopTimeout 是 stop 子命令等待进程响应 SIGTERM 的硬上限。
const stopTimeout = 10 * time.Second

// runStart 实现 `sip-ban start [-d] ...` 子命令。
//
// 行为：
//   - 不带 -d：等价于前台运行（同 §5.1）；
//   - 带 -d：解析 PID / 日志路径 → 调用 daemon.Spawn 拉起子进程 → 父进程退出。
//
// 注意：如果当前进程是 daemon 子进程（SIPBAN_DAEMONIZED=1），
// 走的是 main.go 中的特殊分支（runDaemonChild），不会进到这里。
func runStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	var (
		daemonize bool
		pidFlag   string
		logFlag   string
	)
	fs.BoolVar(&daemonize, "d", false, "后台运行（仅 Linux）")
	fs.StringVar(&pidFlag, "pid", "", "PID 文件路径")
	fs.StringVar(&logFlag, "log", "", "日志文件路径")

	cfg, err := config.LoadFromFlagSet(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(daemon.ExitUserError)
	}

	if !daemonize {
		// 前台模式：与旧 CLI 行为完全一致。
		if err := runForeground(context.Background(), cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(daemon.ExitSystemError)
		}
		return
	}

	// 后台模式：先解析路径
	pidPath, logPath, fallback, err := daemon.ResolvePaths(pidFlag, logFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "解析路径失败:", err)
		os.Exit(daemon.ExitSystemError)
	}
	if fallback {
		// 落到 XDG 或 /tmp 时显式打印，避免运维迷惑。
		fmt.Printf("using fallback pidfile %s\n", pidPath)
	}

	// 透传 extraArgs：start 子命令的所有原始参数减去 -d
	extra := stripFlag(args, "-d")
	if err := daemon.Spawn(pidPath, logPath, extra); err != nil {
		if errors.Is(err, daemon.ErrUnsupportedPlatform) {
			fmt.Fprintln(os.Stderr, "daemon mode is Linux-only")
			os.Exit(daemon.ExitUserError)
		}
		if errors.Is(err, daemon.ErrAlreadyRunning) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(daemon.ExitUserError)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(daemon.ExitSystemError)
	}
}

// runStatus 实现 `sip-ban status [-pid path]`。
//
// 输出：
//   - 进程在跑：running, pid=<n>, uptime=<x>, started_at=<rfc3339>，退出码 0；
//   - PID 文件不存在：not running，退出码 3；
//   - PID 文件 stale：not running (stale pidfile: <path>)，退出码 3。
func runStatus(args []string) {
	pidPath := parsePIDPathOnly(args, "status")

	info, alive, err := daemon.ReadAndVerify(pidPath)
	if err != nil {
		if errors.Is(err, daemon.ErrUnsupportedPlatform) {
			fmt.Fprintln(os.Stderr, "daemon mode is Linux-only")
			os.Exit(daemon.ExitUserError)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(daemon.ExitSystemError)
	}
	if !alive {
		// 区分 PID 文件不存在 vs stale
		if _, err := os.Stat(pidPath); err != nil {
			fmt.Println("not running")
		} else {
			fmt.Printf("not running (stale pidfile: %s)\n", pidPath)
		}
		os.Exit(daemon.ExitNotRunning)
	}

	startedAt, uptime, err := procStartedAtAndUptime(info)
	if err != nil {
		// uptime 算不出来也不致命，给基本信息
		fmt.Printf("running, pid=%d\n", info.PID)
		return
	}
	fmt.Printf("running, pid=%d, uptime=%s, started_at=%s\n",
		info.PID, uptime.Truncate(time.Second), startedAt.Format(time.RFC3339))
}

// runStop 实现 `sip-ban stop [-pid path]`。
func runStop(args []string) {
	pidPath := parsePIDPathOnly(args, "stop")
	if err := daemon.SendStop(pidPath, stopTimeout); err != nil {
		if errors.Is(err, daemon.ErrUnsupportedPlatform) {
			fmt.Fprintln(os.Stderr, "daemon mode is Linux-only")
			os.Exit(daemon.ExitUserError)
		}
		if errors.Is(err, daemon.ErrStaleOrNotRunning) {
			fmt.Println("not running")
			os.Exit(daemon.ExitNotRunning)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(daemon.ExitSystemError)
	}
	fmt.Println("stopped")
}

// runRestart 实现 `sip-ban restart [-pid path]`。
//
// 等价于：stop（容忍 not-running）→ start -d，使用相同的 -pid 路径。
func runRestart(args []string) {
	pidPath := parsePIDPathOnly(args, "restart")

	// 1. 先尝试停止；进程不存在是允许的
	if err := daemon.SendStop(pidPath, stopTimeout); err != nil {
		if errors.Is(err, daemon.ErrUnsupportedPlatform) {
			fmt.Fprintln(os.Stderr, "daemon mode is Linux-only")
			os.Exit(daemon.ExitUserError)
		}
		if !errors.Is(err, daemon.ErrStaleOrNotRunning) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(daemon.ExitSystemError)
		}
	}

	// 2. 再启动；这里复用 runStart 的 -d 路径但只传 -pid。
	startArgs := []string{"-d"}
	if pidPath != "" {
		startArgs = append(startArgs, "-pid", pidPath)
	}
	runStart(startArgs)
}

// parsePIDPathOnly 解析 status / stop / restart 共享的「仅 -pid」参数。
// 若用户未指定，则按 ResolvePaths 的优先级查找现有 PID 文件路径。
func parsePIDPathOnly(args []string, cmdName string) string {
	fs := flag.NewFlagSet(cmdName, flag.ExitOnError)
	var pidFlag string
	fs.StringVar(&pidFlag, "pid", "", "PID 文件路径")
	if err := fs.Parse(args); err != nil {
		os.Exit(daemon.ExitUserError)
	}
	// ResolvePaths 的第二个参数（log）这里没用，给空字符串。
	pidPath, _, _, err := daemon.ResolvePaths(pidFlag, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(daemon.ExitSystemError)
	}
	return pidPath
}

// stripFlag 从 args 中移除一个无值的 flag（例如 "-d"）。
// 仅匹配恰好等于 name 的元素；不处理 -d=true / --d 等变体（start 子命令里没用到）。
func stripFlag(args []string, name string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == name {
			continue
		}
		out = append(out, a)
	}
	return out
}

// procStartedAtAndUptime 根据 PIDInfo 计算进程的启动时间与 uptime。
//
// 通过 /proc/uptime 与 /proc/stat 的 btime 配合 PIDInfo.StartTimeJiffies 得到。
// 失败时返回错误，调用方应回退到只打 PID。
func procStartedAtAndUptime(info daemon.PIDInfo) (time.Time, time.Duration, error) {
	return computeStartedAt(info)
}
