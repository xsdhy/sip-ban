// Package daemon 提供后台运行支持：路径解析、PID 文件锁、身份校验、进程停止。
//
// 平台分支：
//   - daemon_linux.go：完整实现 flock、/proc/<pid>/stat 解析等 Linux-only 能力；
//   - daemon_other.go：在非 Linux 平台返回 ErrUnsupportedPlatform，保证 macOS / Windows
//     仍可 `go build`，但在运行时拒绝 daemon 子命令。
//
// 详见 docs/daemon-mode.md。
package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrUnsupportedPlatform 表示当前平台不支持 daemon 能力。
// 非 Linux 平台调用 Spawn / Activate / ReadAndVerify / SendStop 时返回此错误。
var ErrUnsupportedPlatform = errors.New("daemon mode is Linux-only")

// 退出码统一定义，方便调用方对外抛出一致的语义。
const (
	ExitOK                = 0 // 操作成功
	ExitUserError         = 1 // 用户错误 / 已在运行
	ExitSystemError       = 2 // 系统错误（含停止失败、握手失败等）
	ExitNotRunning        = 3 // 进程未运行
)

// PIDInfo 描述一份 PID 文件的内容。
//
// 字段：
//   - PID：进程号。
//   - StartTimeJiffies：进程启动时刻的内核 jiffies 计数；
//     与 /proc/<pid>/stat 第 22 个字段一致；
//     用于消除 PID 复用误判。
type PIDInfo struct {
	PID              int
	StartTimeJiffies uint64
}

// String 用于 PID 文件内容；格式：`<pid> <start_time>\n`。
func (p PIDInfo) String() string {
	return fmt.Sprintf("%d %d", p.PID, p.StartTimeJiffies)
}

// 默认路径常量（按需求 §6.1）。
const (
	defaultRunRootPID   = "/var/run/sip-ban.pid"
	defaultRunRootLog   = "/var/log/sip-ban.log"
	defaultTmpPID       = "/tmp/sip-ban.pid"
	defaultTmpLog       = "/tmp/sip-ban.log"
	defaultFileBaseName = "sip-ban"
)

// ResolvePaths 按需求文档 §6.1 的优先级解析 PID / 日志文件路径。
//
// 优先级（先 PID，再日志，单独决定）：
//   1. 用户通过 -pid / -log 显式指定；
//   2. 当前进程有权写入 /var/run / /var/log（典型 root 情况）；
//   3. $XDG_RUNTIME_DIR 已设置且可写；
//   4. /tmp 兜底。
//
// **绝不会** fallback 到当前工作目录，避免「换个目录跑 status 找不到」的运维灾难。
//
// 返回：
//   - pidPath / logPath：最终选用的绝对路径。
//   - fallback：当 PID 文件落在第 3 或第 4 档时为 true，提示调用方
//     在 stdout 输出降级警告，方便用户立刻知道这次的实际位置。
//   - err：所有候选路径均不可写时返回。
func ResolvePaths(pidFlag, logFlag string) (pidPath, logPath string, fallback bool, err error) {
	// 1. 用户显式指定 - 直接采用，不做可写性预检（让 open 时报错更直接）。
	if pidFlag != "" {
		pidPath = pidFlag
	}
	if logFlag != "" {
		logPath = logFlag
	}
	if pidPath != "" && logPath != "" {
		return pidPath, logPath, false, nil
	}

	// 2 / 3 / 4 仅在用户未显式指定时分别为 PID 和 LOG 兜底。
	if pidPath == "" {
		var pidFallback bool
		pidPath, pidFallback, err = resolveFile("pid")
		if err != nil {
			return "", "", false, err
		}
		fallback = fallback || pidFallback
	}
	if logPath == "" {
		var logFallback bool
		logPath, logFallback, err = resolveFile("log")
		if err != nil {
			return "", "", false, err
		}
		// 仅 PID 决定是否打印 fallback 提示；log 单独 fallback 不强提示
		// （在文档里 fallback 主要服务于「找不到 PID」的运维场景）。
		_ = logFallback
	}
	return pidPath, logPath, fallback, nil
}

// resolveFile 实际执行单个文件（pid / log）的优先级查找。
//
// kind 取 "pid" 或 "log"，用于决定文件名与第 2 档的目标目录。
func resolveFile(kind string) (path string, fallback bool, err error) {
	var (
		rootPath string
		baseName string
		rootDir  string
	)
	switch kind {
	case "pid":
		rootPath = defaultRunRootPID
		baseName = defaultFileBaseName + ".pid"
		rootDir = "/var/run"
	case "log":
		rootPath = defaultRunRootLog
		baseName = defaultFileBaseName + ".log"
		rootDir = "/var/log"
	default:
		return "", false, fmt.Errorf("不支持的文件类型: %s", kind)
	}

	// 第 2 档：/var/run 或 /var/log
	if dirWritable(rootDir) {
		return rootPath, false, nil
	}

	// 第 3 档：$XDG_RUNTIME_DIR
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" && dirWritable(xdg) {
		return filepath.Join(xdg, baseName), true, nil
	}

	// 第 4 档：/tmp 兜底
	if kind == "pid" {
		return defaultTmpPID, true, nil
	}
	return defaultTmpLog, true, nil
}

// dirWritable 判断指定目录是否存在且可写。
//
// 实现思路：尝试在目录里创建并立刻删除一个 . 开头的临时文件。
// 用 access(2) / W_OK 在某些 setuid 场景下不够准确，文件级创建更可靠。
func dirWritable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	// 在该目录创建一个临时文件；CreateTemp 在权限不足时会失败。
	f, err := os.CreateTemp(dir, ".sip-ban-write-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// SendStop 通过 PID 文件停止后台进程。
//
// 算法：
//  1. 读取 PID 文件并做身份校验（避免 PID 复用误判）；
//  2. 身份匹配 → 发送 SIGTERM；
//  3. 轮询最多 timeout（建议 10 秒）等待进程消失；
//  4. 仍存活则发 SIGKILL，再等待最多 2 秒；
//  5. 由调用方负责 unlink PID 文件（也可由 SendStop 完成，行为见实现）。
//
// 跨平台 stub 见 daemon_other.go。
func SendStop(pidPath string, timeout time.Duration) error {
	return sendStop(pidPath, timeout)
}

// ReadAndVerify 读取 PID 文件并对其中记录的进程做身份校验。
//
// 返回：
//   - info：PID 文件内容（失败时为零值）。
//   - alive：true 表示进程仍在运行且身份匹配。
//   - err：读取或解析失败时返回；进程不存在不算错误（alive=false）。
func ReadAndVerify(pidPath string) (PIDInfo, bool, error) {
	return readAndVerify(pidPath)
}
