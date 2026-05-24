// Package main SIP-Ban主程序入口。
//
// 入口职责（需求 §5）：
//  1. 如果当前进程是 daemon 子进程（SIPBAN_DAEMONIZED=1），先执行
//     daemon.Activate（抢锁 / 注册信号 / 向父进程汇报 ok）然后跑业务逻辑。
//  2. 否则按 dispatch 规则分派到前台 / start / status / stop / restart。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"sip-ban/internal/config"
	"sip-ban/internal/daemon"
)

// main 主入口。
func main() {
	// daemon 子进程：先 Activate 再跑业务，与父子命令分发解耦。
	if daemon.IsChildProcess() {
		runDaemonChild()
		return
	}

	cmd := dispatch(os.Args)
	switch cmd.name {
	case "":
		runForegroundCLI(cmd.args)
	case "start":
		runStart(cmd.args)
	case "status":
		runStatus(cmd.args)
	case "stop":
		runStop(cmd.args)
	case "restart":
		runRestart(cmd.args)
	case "?":
		fallthrough
	default:
		printUsageAndExit(daemon.ExitUserError)
	}
}

// runForegroundCLI 旧 CLI 风格的前台入口。
//
// 接受全部旧参数（-i / -P / -p / -rt 等），不接受 daemon 相关 flag。
// 与 §5 派发规则 1 / 2 对应。
func runForegroundCLI(args []string) {
	fs := flag.NewFlagSet("sip-ban", flag.ExitOnError)
	cfg, err := config.LoadFromFlagSet(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(daemon.ExitUserError)
	}
	if err := runForeground(context.Background(), cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(daemon.ExitSystemError)
	}
}

// runForeground 启动一次完整的前台捕获流程，并在收到 SIGINT/SIGTERM 时优雅退出。
//
// 该函数也被 `start`（不带 -d）复用；daemon 子进程走的是 runDaemonChild。
func runForeground(parent context.Context, cfg *config.Config) error {
	ctx, cancel := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return Run(ctx, cfg)
}

// runDaemonChild 是 daemon 子进程的入口流程。
//
// 行为：
//   1. 读取父进程传入的 PID 文件路径；
//   2. 重新用 start 子命令的 FlagSet 解析 os.Args[2:]（os.Args[1] 必然为 "start"）；
//   3. 调用 daemon.Activate 完成抢锁 / 信号注册 / 握手；
//   4. 调用 Run 进入正常业务流程；
//   5. 退出前 cleanup。
//
// 失败时通过 os.Exit(非 0) 终止——daemon.Activate 已经把 err 经握手管道汇报给父。
func runDaemonChild() {
	pidPath, _ := daemon.ChildPaths()

	// 解析子进程参数：os.Args = [exe, "start", ...]
	// 这里需要剔除 -d、-pid、-log 这三个 daemon 专属 flag，
	// 让 config.LoadFromFlagSet 能拿到原本的捕获参数。
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		dummyD   bool
		dummyPid string
		dummyLog string
	)
	fs.BoolVar(&dummyD, "d", false, "")
	fs.StringVar(&dummyPid, "pid", "", "")
	fs.StringVar(&dummyLog, "log", "", "")

	subArgs := []string{}
	if len(os.Args) > 1 && os.Args[1] == "start" {
		subArgs = os.Args[2:]
	} else if len(os.Args) > 1 {
		subArgs = os.Args[1:]
	}

	cfg, err := config.LoadFromFlagSet(fs, subArgs)
	if err != nil {
		// 父进程通过日志能看到 stderr；同时通过握手管道汇报。
		hs := os.NewFile(3, "handshake")
		if hs != nil {
			fmt.Fprintf(hs, "err: 解析参数失败: %v\n", err)
			_ = hs.Close()
		}
		os.Exit(daemon.ExitSystemError)
	}

	ctx, cleanup, err := daemon.Activate(pidPath)
	if err != nil {
		// Activate 已经写过 err 到握手管道
		fmt.Fprintln(os.Stderr, "daemon activate 失败:", err)
		os.Exit(daemon.ExitSystemError)
	}
	defer cleanup()

	if err := Run(ctx, cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(daemon.ExitSystemError)
	}
}
