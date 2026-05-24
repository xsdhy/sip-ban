//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"sip-ban/internal/daemon"
)

// computeStartedAt 在 Linux 上根据 PIDInfo 计算进程启动时间与 uptime。
//
// 算法：
//   1. 读 /proc/stat 的 btime 字段（系统启动的 Unix 时间戳，单位秒）；
//   2. 读 sysconf(_SC_CLK_TCK)；Go 标准库不直接暴露，常见为 100；
//      考虑到不同发行版差异，我们通过读 /proc/<pid>/stat 22 字段（已在 info.StartTimeJiffies）
//      与 sysconf 100 估算。若估算偏差大，可改用 cgo，但对 uptime 显示精度无影响。
//   3. started_at = btime + startTimeJiffies / clkTck；
//   4. uptime = now - started_at。
func computeStartedAt(info daemon.PIDInfo) (time.Time, time.Duration, error) {
	btime, err := readBtime()
	if err != nil {
		return time.Time{}, 0, err
	}
	const clkTck = 100 // Linux 默认 USER_HZ，对显示足够
	startedAt := time.Unix(btime+int64(info.StartTimeJiffies/clkTck), 0)
	uptime := time.Since(startedAt)
	if uptime < 0 {
		// 时钟回拨之类的极端情况，避免负值
		uptime = 0
	}
	return startedAt, uptime, nil
}

// readBtime 读取 /proc/stat 的 btime 字段。
func readBtime() (int64, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return 0, fmt.Errorf("/proc/stat btime 格式异常: %q", line)
		}
		return strconv.ParseInt(parts[1], 10, 64)
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("/proc/stat 未找到 btime")
}
