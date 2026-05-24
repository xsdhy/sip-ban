//go:build linux

package daemon

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// readAndVerify 实现 Linux 上的 PID 文件读取与身份校验。
//
// 校验流程（需求 §5.1）：
//   1. 解析 PID 文件得到 expected_start_time；
//   2. 读 /proc/<pid>/stat 第 22 字段得到 actual_start_time；
//   3. 若 /proc/<pid> 不存在 → 进程已死；
//   4. 两个 start_time 一致 → 视为「就是我们当时启动的那个进程」。
func readAndVerify(pidPath string) (PIDInfo, bool, error) {
	data, err := os.ReadFile(pidPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return PIDInfo{}, false, nil
		}
		return PIDInfo{}, false, fmt.Errorf("读取 PID 文件失败: %w", err)
	}
	info, err := parsePIDFileContent(string(data))
	if err != nil {
		return PIDInfo{}, false, fmt.Errorf("解析 PID 文件失败: %w", err)
	}

	actual, err := readProcStartTime(info.PID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// 进程已经退出
			return info, false, nil
		}
		return info, false, err
	}
	if actual != info.StartTimeJiffies {
		// PID 已被复用给别的进程
		return info, false, nil
	}
	return info, true, nil
}

// parsePIDFileContent 把 "<pid> <start_time>\n" 解析为 PIDInfo。
//
// 容错：去除前后空白，允许中间有任意空白分隔。
func parsePIDFileContent(s string) (PIDInfo, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return PIDInfo{}, errors.New("PID 文件为空")
	}
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return PIDInfo{}, fmt.Errorf("格式应为 \"<pid> <start_time>\"，得到 %q", s)
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil || pid <= 0 {
		return PIDInfo{}, fmt.Errorf("无效的 PID: %q", parts[0])
	}
	st, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return PIDInfo{}, fmt.Errorf("无效的 start_time: %q", parts[1])
	}
	return PIDInfo{PID: pid, StartTimeJiffies: st}, nil
}

// readProcStartTime 读取 /proc/<pid>/stat 第 22 字段（进程启动时刻 jiffies）。
//
// 关键陷阱：/proc/<pid>/stat 第 2 字段是 comm，被括号包裹，且 **comm 内部可能含空格**（如 "(my prog)" 或 "(a) b)" 这种极端情况）。
// 因此不能直接按空格切分，必须先找到最后一个右括号，再从其后开始切。
func readProcStartTime(pid int) (uint64, error) {
	path := fmt.Sprintf("/proc/%d/stat", pid)
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	content, err := reader.ReadString('\n')
	if err != nil && content == "" {
		return 0, fmt.Errorf("读取 /proc/%d/stat 失败: %w", pid, err)
	}
	content = strings.TrimRight(content, "\n")

	// 从右往左找最后一个 ')'，避开 comm 里可能含 ')' 的情况。
	rparen := strings.LastIndex(content, ")")
	if rparen < 0 || rparen+2 > len(content) {
		return 0, fmt.Errorf("/proc/%d/stat 格式异常", pid)
	}
	rest := content[rparen+2:] // 跳过 ") "
	fields := strings.Fields(rest)
	// 全部字段中：field 1 = pid, field 2 = comm, 之后从 state 开始算。
	// 在我们的 rest 里：rest[0] = state (字段 3), rest[19] = starttime (字段 22)。
	const startTimeIdxInRest = 22 - 3
	if len(fields) <= startTimeIdxInRest {
		return 0, fmt.Errorf("/proc/%d/stat 字段不足", pid)
	}
	st, err := strconv.ParseUint(fields[startTimeIdxInRest], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("解析 start_time 失败: %w", err)
	}
	return st, nil
}

// CurrentStartTime 返回当前进程的启动时刻 jiffies，供 Activate 写 PID 文件时使用。
func CurrentStartTime() (uint64, error) {
	return readProcStartTime(os.Getpid())
}

// sendStop 实现 Linux 上的停止流程。
//
// 行为：
//   - 身份校验未通过：不发信号，按 stale pidfile 处理。
//   - 发送 SIGTERM，每 100ms 轮询 kill(pid, 0)；
//   - 超过 timeout 仍存活 → SIGKILL；
//   - SIGKILL 后再等待 2 秒确认；
//   - 进程消失后 unlink PID 文件。
func sendStop(pidPath string, timeout time.Duration) error {
	info, alive, err := readAndVerify(pidPath)
	if err != nil {
		return err
	}
	if !alive {
		// 进程不存在或 PID 已被复用，stale；调用方自行决定是否清理。
		return ErrStaleOrNotRunning
	}

	proc, err := os.FindProcess(info.PID)
	if err != nil {
		return fmt.Errorf("查找进程失败: %w", err)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			// 抢先退出了
			_ = os.Remove(pidPath)
			return nil
		}
		return fmt.Errorf("发送 SIGTERM 失败: %w", err)
	}

	if waitProcessGone(info, timeout) {
		_ = os.Remove(pidPath)
		return nil
	}

	// 超时仍在 → SIGKILL
	fmt.Fprintf(os.Stderr, "warning: pid=%d 在 %s 内未响应 SIGTERM，发送 SIGKILL\n", info.PID, timeout)
	if err := proc.Signal(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("发送 SIGKILL 失败: %w", err)
	}
	if waitProcessGone(info, 2*time.Second) {
		_ = os.Remove(pidPath)
		return nil
	}
	return fmt.Errorf("进程 pid=%d 无法终止", info.PID)
}

// ErrStaleOrNotRunning 表示停止操作发现进程其实并不在运行（PID 文件 stale 或缺失）。
// 调用方可以据此输出 not running 的提示并以退出码 3 退出。
var ErrStaleOrNotRunning = errors.New("daemon not running (stale or missing pidfile)")

// waitProcessGone 轮询等待 PID 不再可用或 start_time 变化（PID 被复用），
// 表示原进程已退出。返回 true 表示成功观察到进程消失。
func waitProcessGone(info PIDInfo, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := readProcStartTime(info.PID)
		if err != nil {
			// 进程不存在 → 退出
			if errors.Is(err, os.ErrNotExist) {
				return true
			}
			// 其它错误（如权限），保守地认为进程还在
		} else if st != info.StartTimeJiffies {
			// PID 被新进程复用 → 原进程已消失
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
