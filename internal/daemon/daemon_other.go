//go:build !linux

package daemon

import (
	"errors"
	"time"
)

// readAndVerify 在非 Linux 平台返回 ErrUnsupportedPlatform。
// 注意：ResolvePaths 不依赖任何平台特性，可以在所有平台正常工作；
// 仅 PID 文件锁与 /proc 解析是 Linux-only。
func readAndVerify(pidPath string) (PIDInfo, bool, error) {
	return PIDInfo{}, false, ErrUnsupportedPlatform
}

// sendStop 在非 Linux 平台返回 ErrUnsupportedPlatform。
func sendStop(pidPath string, timeout time.Duration) error {
	return ErrUnsupportedPlatform
}

// CurrentStartTime 在非 Linux 平台返回 ErrUnsupportedPlatform。
// 仅保留以便包内 Activate 实现统一引用，不会在生产路径调用到。
func CurrentStartTime() (uint64, error) {
	return 0, ErrUnsupportedPlatform
}

// ErrStaleOrNotRunning 在非 Linux 平台同样存在，与 Linux 实现等价（指示进程不在运行）。
// 保证调用方代码不需要平台分支。
var ErrStaleOrNotRunning = errors.New("daemon not running (stale or missing pidfile)")
