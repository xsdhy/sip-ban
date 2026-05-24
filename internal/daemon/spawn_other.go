//go:build !linux

package daemon

import "context"

// IsChildProcess 非 Linux 平台没有 daemon 能力，永远返回 false。
func IsChildProcess() bool { return false }

// ChildPaths 在非 Linux 平台返回空字符串。
func ChildPaths() (pidPath, logPath string) { return "", "" }

// Spawn 在非 Linux 平台返回 ErrUnsupportedPlatform。
func Spawn(pidPath, logPath string, extraArgs []string) error {
	return ErrUnsupportedPlatform
}

// Activate 在非 Linux 平台返回 ErrUnsupportedPlatform。
func Activate(pidPath string) (context.Context, func(), error) {
	return nil, nil, ErrUnsupportedPlatform
}
