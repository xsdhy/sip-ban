//go:build !linux

package main

import (
	"errors"
	"time"

	"sip-ban/internal/daemon"
)

// computeStartedAt 在非 Linux 平台上无法计算（也用不到），直接返回错误。
// 调用方在 runStatus 里仅会在 Linux 平台上使用。
func computeStartedAt(info daemon.PIDInfo) (time.Time, time.Duration, error) {
	_ = info
	return time.Time{}, 0, errors.New("unsupported platform")
}
