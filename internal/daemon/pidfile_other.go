//go:build !linux

package daemon

import (
	"errors"
)

// PIDFile 在非 Linux 平台只是空结构体，所有方法返回 ErrUnsupportedPlatform，
// 但其类型存在让上层代码可以无平台分支地引用。
type PIDFile struct{}

// Path 返回空字符串。
func (p *PIDFile) Path() string { return "" }

// AcquirePIDFile 在非 Linux 平台直接返回 ErrUnsupportedPlatform。
func AcquirePIDFile(path string, info PIDInfo) (*PIDFile, error) {
	return nil, ErrUnsupportedPlatform
}

// Release 在非 Linux 平台是 no-op。
func (p *PIDFile) Release() error { return nil }

// ErrAlreadyRunning 在所有平台共享同一个值，保证 errors.Is 比较有效。
var ErrAlreadyRunning = errors.New("already running")
