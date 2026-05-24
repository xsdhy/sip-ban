//go:build linux

package daemon

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestParsePIDFileContent 覆盖各种 PID 文件格式。
func TestParsePIDFileContent(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantPID int
		wantST  uint64
		wantErr bool
	}{
		{"正常格式", "1234 5678", 1234, 5678, false},
		{"带换行", "1234 5678\n", 1234, 5678, false},
		{"前后空格", "  1234  5678  ", 1234, 5678, false},
		{"空字符串", "", 0, 0, true},
		{"缺少 start_time", "1234", 0, 0, true},
		{"非法 PID", "abc 5678", 0, 0, true},
		{"非法 start_time", "1234 xyz", 0, 0, true},
		{"PID 为 0", "0 5678", 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := parsePIDFileContent(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("期望错误，得到 %+v", info)
				}
				return
			}
			if err != nil {
				t.Errorf("不期望错误: %v", err)
			}
			if info.PID != tt.wantPID || info.StartTimeJiffies != tt.wantST {
				t.Errorf("info = %+v, want pid=%d st=%d", info, tt.wantPID, tt.wantST)
			}
		})
	}
}

// TestReadProcStartTime 验证 /proc/<pid>/stat 第 22 字段能被正确解析。
// 用当前进程做基准。
func TestReadProcStartTime(t *testing.T) {
	st, err := readProcStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("读自身 start_time 失败: %v", err)
	}
	if st == 0 {
		t.Errorf("start_time 不应为 0")
	}
}

// TestReadProcStartTimeMissing 验证一个不存在的 PID 返回 os.ErrNotExist。
func TestReadProcStartTimeMissing(t *testing.T) {
	// 99999 一般不会存在；即使偶尔被占用，文件也可能不可读。
	// 为稳妥起见，取一个一定不会存在的 PID（max int 附近）。
	_, err := readProcStartTime(1 << 30)
	if err == nil {
		t.Skip("意外存在该 PID，跳过")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("期望 ErrNotExist，得到 %v", err)
	}
}

// TestReadAndVerifyMissingFile PID 文件不存在 → alive=false，无错误。
func TestReadAndVerifyMissingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "no.pid")
	info, alive, err := readAndVerify(path)
	if err != nil {
		t.Fatalf("不期望错误: %v", err)
	}
	if alive {
		t.Errorf("alive 应为 false")
	}
	if info.PID != 0 {
		t.Errorf("info 应为零值")
	}
}

// TestReadAndVerifyAliveSelf 写一个指向当前进程的 PID 文件，应被识别为 alive。
func TestReadAndVerifyAliveSelf(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "self.pid")
	st, err := readProcStartTime(os.Getpid())
	if err != nil {
		t.Fatalf("readProcStartTime: %v", err)
	}
	if err := os.WriteFile(path, []byte((PIDInfo{PID: os.Getpid(), StartTimeJiffies: st}).String()), 0644); err != nil {
		t.Fatalf("写 PID 文件: %v", err)
	}

	info, alive, err := readAndVerify(path)
	if err != nil {
		t.Fatalf("不期望错误: %v", err)
	}
	if !alive {
		t.Errorf("当前进程应被识别为 alive")
	}
	if info.PID != os.Getpid() {
		t.Errorf("PID 不匹配")
	}
}

// TestReadAndVerifyStaleStartTime 当 start_time 不匹配时应识别为 stale。
func TestReadAndVerifyStaleStartTime(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "stale.pid")
	// 故意写一个错误的 start_time
	if err := os.WriteFile(path, []byte((PIDInfo{PID: os.Getpid(), StartTimeJiffies: 0}).String()), 0644); err != nil {
		t.Fatalf("写 PID 文件: %v", err)
	}

	_, alive, err := readAndVerify(path)
	if err != nil {
		t.Fatalf("不期望错误: %v", err)
	}
	if alive {
		t.Errorf("start_time 不匹配时应被识别为 stale")
	}
}

// TestAcquirePIDFileBasic 验证 AcquirePIDFile 在干净环境下能成功，并写入正确内容。
func TestAcquirePIDFileBasic(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "x.pid")
	st, _ := readProcStartTime(os.Getpid())
	info := PIDInfo{PID: os.Getpid(), StartTimeJiffies: st}

	pf, err := AcquirePIDFile(path, info)
	if err != nil {
		t.Fatalf("AcquirePIDFile 失败: %v", err)
	}
	defer pf.Release()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 PID 文件: %v", err)
	}
	if !strings.Contains(string(data), info.String()) {
		t.Errorf("PID 文件内容 %q 应包含 %q", data, info.String())
	}
}

// TestAcquirePIDFileConcurrent 验证并发抢锁只允许一个成功。
func TestAcquirePIDFileConcurrent(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "concurrent.pid")
	st, _ := readProcStartTime(os.Getpid())

	const N = 8
	var (
		success atomic.Int32
		wg      sync.WaitGroup
		held    *PIDFile
		heldMu  sync.Mutex
	)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			pf, err := AcquirePIDFile(path, PIDInfo{PID: os.Getpid(), StartTimeJiffies: st})
			if err == nil {
				success.Add(1)
				heldMu.Lock()
				if held == nil {
					held = pf
				} else {
					// 不应该发生：多个 goroutine 同时拿到锁
					_ = pf.Release()
				}
				heldMu.Unlock()
				return
			}
			if !errors.Is(err, ErrAlreadyRunning) {
				t.Errorf("非 ErrAlreadyRunning 错误: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := success.Load(); got != 1 {
		t.Errorf("应当只有 1 个 goroutine 抢锁成功，实际 %d", got)
	}
	if held != nil {
		_ = held.Release()
	}
}

// TestAcquirePIDFileStaleOverwrite 验证遇到 stale PID 文件时能覆盖。
func TestAcquirePIDFileStaleOverwrite(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "stale.pid")
	// 预先写一个 stale 的 PID 文件（指向自身但 start_time=0）
	if err := os.WriteFile(path, []byte((PIDInfo{PID: os.Getpid(), StartTimeJiffies: 0}).String()+"\n"), 0644); err != nil {
		t.Fatalf("写 stale PID 文件: %v", err)
	}

	st, _ := readProcStartTime(os.Getpid())
	pf, err := AcquirePIDFile(path, PIDInfo{PID: os.Getpid(), StartTimeJiffies: st})
	if err != nil {
		t.Fatalf("应能覆盖 stale PID 文件，得到错误: %v", err)
	}
	defer pf.Release()

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "0\n") {
		t.Errorf("PID 文件未被覆盖，内容仍为 %q", data)
	}
}

// TestReleaseRemovesFile 验证 Release 释放锁并删除文件。
func TestReleaseRemovesFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "release.pid")
	st, _ := readProcStartTime(os.Getpid())
	pf, err := AcquirePIDFile(path, PIDInfo{PID: os.Getpid(), StartTimeJiffies: st})
	if err != nil {
		t.Fatalf("AcquirePIDFile: %v", err)
	}
	if err := pf.Release(); err != nil {
		t.Fatalf("Release 失败: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Release 后 PID 文件仍存在: %v", err)
	}
}

// TestSendStopMissingFile 当 PID 文件不存在时返回 ErrStaleOrNotRunning。
func TestSendStopMissingFile(t *testing.T) {
	err := SendStop(filepath.Join(t.TempDir(), "no.pid"), time.Second)
	if !errors.Is(err, ErrStaleOrNotRunning) {
		t.Errorf("期望 ErrStaleOrNotRunning，得到 %v", err)
	}
}

// TestSendStopRealSleep 启动一个 sleep 子进程作为真实目标，验证 SendStop 能够通过 SIGTERM 杀掉它并清理 PID 文件。
func TestSendStopRealSleep(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("无 sleep 命令")
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("启动 sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	st, err := readProcStartTime(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("readProcStartTime: %v", err)
	}
	path := filepath.Join(t.TempDir(), "sleep.pid")
	info := PIDInfo{PID: cmd.Process.Pid, StartTimeJiffies: st}
	if err := os.WriteFile(path, []byte(info.String()+"\n"), 0644); err != nil {
		t.Fatalf("写 PID 文件: %v", err)
	}

	if err := SendStop(path, 5*time.Second); err != nil {
		t.Fatalf("SendStop 失败: %v", err)
	}
	// 子进程应已退出
	state, err := cmd.Process.Wait()
	if err != nil {
		t.Fatalf("Wait sleep: %v", err)
	}
	if state.ExitCode() == 0 {
		t.Errorf("sleep 不应是正常退出（应被信号杀掉）")
	}
	// PID 文件应被删除
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("SendStop 后 PID 文件应被删除")
	}
}
