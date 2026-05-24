package daemon

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestResolvePathsRespectsExplicitFlags 验证用户显式传入 -pid / -log 时直接采用。
func TestResolvePathsRespectsExplicitFlags(t *testing.T) {
	pid, log, fallback, err := ResolvePaths("/custom/sip.pid", "/custom/sip.log")
	if err != nil {
		t.Fatalf("ResolvePaths 不应失败: %v", err)
	}
	if pid != "/custom/sip.pid" {
		t.Errorf("pid = %q, want /custom/sip.pid", pid)
	}
	if log != "/custom/sip.log" {
		t.Errorf("log = %q, want /custom/sip.log", log)
	}
	if fallback {
		t.Errorf("用户显式指定时不应报 fallback")
	}
}

// TestResolvePathsFallsBackToXDG 当 /var/run 不可写、XDG_RUNTIME_DIR 可写时，
// 应该落在 XDG 目录并标记 fallback=true。
func TestResolvePathsFallsBackToXDG(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 用户跑这个用例会落到 /var/run，跳过")
	}
	xdg := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", xdg)

	pid, log, fallback, err := ResolvePaths("", "")
	if err != nil {
		t.Fatalf("ResolvePaths 不应失败: %v", err)
	}
	if !fallback {
		t.Errorf("应当报 fallback=true")
	}
	if !strings.HasPrefix(pid, xdg+string(filepath.Separator)) {
		t.Errorf("pid = %q, 应当在 XDG_RUNTIME_DIR (%s) 下", pid, xdg)
	}
	if !strings.HasPrefix(log, xdg+string(filepath.Separator)) {
		t.Errorf("log = %q, 应当在 XDG_RUNTIME_DIR (%s) 下", log, xdg)
	}
}

// TestResolvePathsFallsBackToTmp 当 /var/run 与 XDG 均不可用时，落在 /tmp。
func TestResolvePathsFallsBackToTmp(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 用户跑这个用例会落到 /var/run，跳过")
	}
	t.Setenv("XDG_RUNTIME_DIR", "/this/path/does/not/exist")

	pid, log, fallback, err := ResolvePaths("", "")
	if err != nil {
		t.Fatalf("ResolvePaths 不应失败: %v", err)
	}
	if !fallback {
		t.Errorf("应当报 fallback=true")
	}
	if pid != defaultTmpPID {
		t.Errorf("pid = %q, want %s", pid, defaultTmpPID)
	}
	if log != defaultTmpLog {
		t.Errorf("log = %q, want %s", log, defaultTmpLog)
	}
}

// TestResolvePathsMixedExplicit 一个显式一个默认：显式那个不应触发 fallback，
// 而默认那个应正常按优先级解析。
func TestResolvePathsMixedExplicit(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 用户跳过")
	}
	t.Setenv("XDG_RUNTIME_DIR", "")

	pid, log, _, err := ResolvePaths("/my.pid", "")
	if err != nil {
		t.Fatalf("ResolvePaths 不应失败: %v", err)
	}
	if pid != "/my.pid" {
		t.Errorf("显式 pid 被覆盖了：%q", pid)
	}
	if log == "" {
		t.Error("log 路径不应为空")
	}
}

// TestDirWritable 验证 dirWritable 在临时目录上成功、在不可写目录上失败。
func TestDirWritable(t *testing.T) {
	tmp := t.TempDir()
	if !dirWritable(tmp) {
		t.Errorf("dirWritable(%q) = false, 期望 true", tmp)
	}
	if dirWritable("/this/path/does/not/exist/123") {
		t.Errorf("dirWritable 对不存在路径应返回 false")
	}
}

// TestPIDInfoString 检查 PID 文件内容格式。
func TestPIDInfoString(t *testing.T) {
	info := PIDInfo{PID: 1234, StartTimeJiffies: 99999}
	if got, want := info.String(), "1234 99999"; got != want {
		t.Errorf("PIDInfo.String() = %q, want %q", got, want)
	}
}

// TestUnsupportedPlatform 在非 Linux 平台上，readAndVerify / sendStop 应返回 ErrUnsupportedPlatform。
func TestUnsupportedPlatform(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux 平台跳过 unsupported 用例")
	}
	if _, _, err := ReadAndVerify("/nonexistent"); err != ErrUnsupportedPlatform {
		t.Errorf("非 Linux 平台 ReadAndVerify 应返回 ErrUnsupportedPlatform，得到 %v", err)
	}
	if err := SendStop("/nonexistent", 0); err != ErrUnsupportedPlatform {
		t.Errorf("非 Linux 平台 SendStop 应返回 ErrUnsupportedPlatform，得到 %v", err)
	}
	if err := Spawn("/x", "/y", nil); err != ErrUnsupportedPlatform {
		t.Errorf("非 Linux 平台 Spawn 应返回 ErrUnsupportedPlatform，得到 %v", err)
	}
	if _, _, err := Activate("/x"); err != ErrUnsupportedPlatform {
		t.Errorf("非 Linux 平台 Activate 应返回 ErrUnsupportedPlatform，得到 %v", err)
	}
	if IsChildProcess() {
		t.Errorf("非 Linux 平台 IsChildProcess 应返回 false")
	}
}
