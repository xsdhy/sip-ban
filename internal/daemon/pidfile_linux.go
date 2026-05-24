//go:build linux

package daemon

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// PIDFile 表示一份已经被本进程持有的 PID 文件锁。
// 调用方在 graceful 退出时应 Close 来释放锁并 unlink 文件。
type PIDFile struct {
	path string
	f    *os.File
}

// Path 返回 PID 文件路径。
func (p *PIDFile) Path() string { return p.path }

// AcquirePIDFile 按需求文档 §6.2 的算法抢占 PID 文件锁并写入 PIDInfo。
//
// 算法：
//  1. open(path, O_RDWR|O_CREAT, 0644) —— 不截断，保留旧内容；
//  2. flock(LOCK_EX|LOCK_NB) —— 非阻塞独占锁；失败说明另一个 daemon 持锁。
//  3. 读现有内容做身份校验：
//     - 校验通过（旧 daemon 仍存活）→ 报 ErrAlreadyRunning；
//     - 校验未通过（stale）→ 继续覆盖；
//  4. ftruncate + seek(0) + write 新的 PIDInfo；
//  5. 持续持有 fd，直到 Close。
//
// 返回：
//   - *PIDFile：本进程持有的锁与文件句柄；
//   - error：失败原因。其中 ErrAlreadyRunning 是常见情况，调用方应单独识别。
func AcquirePIDFile(path string, info PIDInfo) (*PIDFile, error) {
	// 1. 不截断打开
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, fmt.Errorf("打开 PID 文件失败 %s: %w", path, err)
	}

	// 2. 非阻塞独占锁
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			// 另一进程持锁——尝试给出更具体的提示：读它的 PID
			if data, rerr := os.ReadFile(path); rerr == nil {
				if existing, perr := parsePIDFileContent(string(data)); perr == nil {
					return nil, fmt.Errorf("%w (pid=%d)", ErrAlreadyRunning, existing.PID)
				}
			}
			return nil, ErrAlreadyRunning
		}
		return nil, fmt.Errorf("flock 失败: %w", err)
	}

	// 3. 读现有内容做身份校验
	buf := make([]byte, 256)
	if _, err := f.ReadAt(buf, 0); err != nil && err.Error() != "EOF" {
		// 读失败不致命；继续覆盖
	}
	existing, parseErr := parsePIDFileContent(string(buf))
	if parseErr == nil && existing.PID > 0 {
		if st, err := readProcStartTime(existing.PID); err == nil && st == existing.StartTimeJiffies {
			// 旧 daemon 仍存活——理论上 flock 应该已经阻塞这一步，但保留作为防御
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
			return nil, fmt.Errorf("%w (pid=%d)", ErrAlreadyRunning, existing.PID)
		}
	}

	// 4. 截断 + seek + 写
	if err := f.Truncate(0); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		return nil, fmt.Errorf("truncate 失败: %w", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		return nil, fmt.Errorf("seek 失败: %w", err)
	}
	if _, err := f.WriteString(info.String() + "\n"); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		return nil, fmt.Errorf("写 PID 文件失败: %w", err)
	}
	// 主动 fsync，让 stop 在并发场景下立刻看到新内容。
	_ = f.Sync()

	return &PIDFile{path: path, f: f}, nil
}

// Release 释放 PID 文件锁并 unlink 文件。
// graceful 退出路径调用；SIGKILL 路径下 fd 被内核回收，文件残留为 stale。
func (p *PIDFile) Release() error {
	if p.f == nil {
		return nil
	}
	_ = syscall.Flock(int(p.f.Fd()), syscall.LOCK_UN)
	_ = p.f.Close()
	p.f = nil
	return os.Remove(p.path)
}

// ErrAlreadyRunning 表示同一 PID 文件已被另一个 sip-ban 实例持有。
var ErrAlreadyRunning = errors.New("already running")
