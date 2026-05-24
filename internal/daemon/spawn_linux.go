//go:build linux

package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// 环境变量名：用于父子进程间标记「我已经在 daemon 模式」。
const (
	envDaemonized = "SIPBAN_DAEMONIZED"
	envPIDPath    = "SIPBAN_PIDFILE"
	envLogPath    = "SIPBAN_LOGFILE"
)

// handshakeFD 是父子约定的握手管道在子进程内的固定 fd 号。
// 0/1/2 给标准流，3 是第一个 ExtraFiles 槽位。
const handshakeFD = 3

// handshakeTimeout 是父进程等待子进程汇报启动结果的硬上限。
// 超时即视为启动失败，让用户去查日志，避免父进程无限挂起。
// 暴露为 var 仅是为了让单元测试可以临时调短。
var handshakeTimeout = 10 * time.Second

// IsChildProcess 判断当前进程是否为通过 Spawn 启动的 daemon 子进程。
// 子进程视角的入口（main 函数最早期）应据此走 Activate 流程。
func IsChildProcess() bool {
	return os.Getenv(envDaemonized) == "1"
}

// ChildPaths 返回 daemon 子进程应使用的 PID / 日志路径。
// 仅在 IsChildProcess() 为 true 时调用才有意义。
func ChildPaths() (pidPath, logPath string) {
	return os.Getenv(envPIDPath), os.Getenv(envLogPath)
}

// Spawn 从父进程视角启动 daemon 子进程。
//
// 流程（需求 §4.1）：
//  1. 建立 os.Pipe() 作为握手管道；
//  2. exec.Cmd 启动自身二进制，通过 ExtraFiles 把管道写端传给子进程（固定 fd=3）；
//  3. stdin → /dev/null，stdout/stderr → log 文件；
//  4. Setsid=true 让子进程脱离控制终端；
//  5. 父进程关闭自己的写端，阻塞读取一行结果：
//     - "ok\n"   → 打印 started, pid=<n>，返回 nil；
//     - "err: ..." 或 EOF + 非 0 退出码 → 返回错误；
//     - 10 秒超时 → 返回 timeout 错误。
//
// 参数：
//   - pidPath / logPath：传递给子进程的路径；
//   - extraArgs：透传给子进程的子命令参数（不含 -d 自身）；
//     调用方应传入「start -i eth0 -P 5060 -pid ... -log ...」中去掉 -d 的那部分。
//
// 返回：error == nil 表示子进程已成功启动并完成抢锁等初始化；
// 非 nil 时调用方应输出错误并以 ExitSystemError 退出。
func Spawn(pidPath, logPath string, extraArgs []string) error {
	// 1. 创建握手管道：r 留给父读，w 通过 ExtraFiles 传给子进程。
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("创建握手管道失败: %w", err)
	}

	// 2. 打开日志文件（追加写）。子进程的 stdout/stderr 都重定向到这里。
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		_ = r.Close()
		_ = w.Close()
		return fmt.Errorf("打开日志文件失败 %s: %w", logPath, err)
	}

	// 3. /dev/null 作为 stdin
	devNull, err := os.OpenFile("/dev/null", os.O_RDONLY, 0)
	if err != nil {
		_ = r.Close()
		_ = w.Close()
		_ = logFile.Close()
		return fmt.Errorf("打开 /dev/null 失败: %w", err)
	}

	// 4. 自身二进制路径
	exe, err := os.Executable()
	if err != nil {
		_ = r.Close()
		_ = w.Close()
		_ = logFile.Close()
		_ = devNull.Close()
		return fmt.Errorf("无法定位自身二进制: %w", err)
	}

	// 5. 拼接子进程参数：保留子命令 start 与全部 extraArgs，但**不**包含 -d。
	args := append([]string{"start"}, extraArgs...)

	cmd := exec.Command(exe, args...)
	cmd.Stdin = devNull
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.ExtraFiles = []*os.File{w} // → 子进程 fd=3
	cmd.Env = append(os.Environ(),
		envDaemonized+"=1",
		envPIDPath+"="+pidPath,
		envLogPath+"="+logPath,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // 子进程脱离当前控制终端
	}

	if err := cmd.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		_ = logFile.Close()
		_ = devNull.Close()
		return fmt.Errorf("启动子进程失败: %w", err)
	}
	// 父进程不再需要这些 fd
	_ = w.Close()
	_ = logFile.Close()
	_ = devNull.Close()

	// 6. 等待握手结果，带 10 秒硬超时
	result, err := readHandshake(r, handshakeTimeout)
	_ = r.Close()
	if err != nil {
		// 超时或读错误时主动收掉子进程，避免遗留僵尸
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return fmt.Errorf("握手失败: %w (查看日志 %s)", err, logPath)
	}
	if result == "ok" {
		fmt.Printf("started, pid=%d\n", cmd.Process.Pid)
		// 子进程已 ok：释放等待，让它独立运行
		_ = cmd.Process.Release()
		return nil
	}

	// 子进程汇报了错误
	_, _ = cmd.Process.Wait()
	return fmt.Errorf("子进程启动失败: %s (日志 %s)", result, logPath)
}

// readHandshake 从握手管道读取一行结果，带超时。
//
// 行为：
//   - 返回 "ok" 表示子进程成功；
//   - 返回 "err: <reason>" 字面的 reason；
//   - 超时或 EOF 时返回 error。
func readHandshake(r *os.File, timeout time.Duration) (string, error) {
	done := make(chan struct {
		line string
		err  error
	}, 1)

	go func() {
		br := bufio.NewReader(r)
		line, err := br.ReadString('\n')
		done <- struct {
			line string
			err  error
		}{strings.TrimRight(line, "\r\n"), err}
	}()

	select {
	case res := <-done:
		if res.err != nil && res.err != io.EOF {
			return "", res.err
		}
		if res.line == "" {
			return "", errors.New("子进程在汇报前退出（EOF）")
		}
		if strings.HasPrefix(res.line, "err:") {
			return strings.TrimSpace(strings.TrimPrefix(res.line, "err:")), nil
		}
		return strings.TrimSpace(res.line), nil
	case <-time.After(timeout):
		return "", fmt.Errorf("等待子进程汇报超时（>%s）", timeout)
	}
}

// Activate 在 daemon 子进程内完成初始化并向父进程汇报。
//
// 流程（需求 §4.1）：
//   1. 抢 flock + 写 PID 文件；
//   2. 注册 SIGTERM/SIGINT 处理器，返回的 ctx 在收到信号时被取消；
//   3. 通过 fd=3 向父进程发送 "ok\n" 并关闭管道；
//   4. 任何一步失败：通过 fd=3 写入 "err: <reason>\n" 后 exit 非 0。
//
// 返回：
//   - ctx：在收到 SIGTERM/SIGINT 时被取消，主流程应据此关闭 capture；
//   - cleanup：调用方在退出前应 defer 调用，用于释放锁并删除 PID 文件；
//   - err：初始化失败（已自动汇报给父进程）。调用方应直接 os.Exit。
func Activate(pidPath string) (context.Context, func(), error) {
	// 子进程内：fd=3 是握手写端
	hs := os.NewFile(uintptr(handshakeFD), "handshake")
	// 在所有错误路径上都需要向父汇报；用一个闭包简化。
	reportErr := func(msg string) {
		if hs != nil {
			fmt.Fprintf(hs, "err: %s\n", msg)
			_ = hs.Close()
		}
	}

	// 1. 抢锁 + 写 PID
	st, err := CurrentStartTime()
	if err != nil {
		reportErr(fmt.Sprintf("读自身 start_time 失败: %v", err))
		return nil, nil, err
	}
	info := PIDInfo{PID: os.Getpid(), StartTimeJiffies: st}
	pf, err := AcquirePIDFile(pidPath, info)
	if err != nil {
		reportErr(fmt.Sprintf("抢占 PID 文件失败: %v", err))
		return nil, nil, err
	}

	// 2. 注册信号 → ctx
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// 3. 汇报 ok 并关闭握手管道
	if hs != nil {
		if _, err := fmt.Fprint(hs, "ok\n"); err != nil {
			// 父进程已经断开（很罕见）：继续运行而不是退出，
			// 否则会让用户失去 daemon。
			fmt.Fprintf(os.Stderr, "warning: 向父进程汇报失败: %v\n", err)
		}
		_ = hs.Close()
	}

	cleanup := func() {
		signal.Stop(sigCh)
		cancel()
		_ = pf.Release()
	}
	return ctx, cleanup, nil
}
