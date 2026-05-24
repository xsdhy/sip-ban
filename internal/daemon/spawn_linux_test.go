//go:build linux

package daemon

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain 拦截一个测试模式：当 SIPBAN_TEST_CHILD_MODE 被设置时，
// 进程把自己当成 daemon 子进程跑：调用 Activate、按 mode 决定如何退出。
// 这样可以用 `go test` 自身二进制做真实的父子进程握手测试。
func TestMain(m *testing.M) {
	if mode := os.Getenv("SIPBAN_TEST_CHILD_MODE"); mode != "" {
		runChildMode(mode)
		return
	}
	os.Exit(m.Run())
}

// runChildMode 在 daemon 子进程视角执行一组预设动作。
//
//   - "ok"          → 正常 Activate 后阻塞，等 SIGTERM；
//   - "ok-then-exit"→ Activate 成功后立刻干净退出；
//   - "fail-bad-pid"→ 故意让 PID 路径不可写以触发 err 汇报。
//
// 退出码：
//   - mode "ok" 收到信号后退出 0；
//   - 失败模式 exit 1（Spawn 会读到 err 行并返回错误）。
func runChildMode(mode string) {
	pid, _ := ChildPaths()
	switch mode {
	case "fail-bad-pid":
		// 强行指向一个不可写的目录
		pid = "/this/path/does/not/exist/sip-ban.pid"
	}
	ctx, cleanup, err := Activate(pid)
	if err != nil {
		// Activate 内部已经向父进程汇报 err
		os.Exit(1)
	}
	defer cleanup()

	if mode == "ok-then-exit" {
		// 子进程主动退出（不等信号）；用于验证父进程能正确收到 ok
		os.Exit(0)
	}
	// 默认阻塞等待 ctx 取消（SIGTERM 触发）
	<-ctx.Done()
	os.Exit(0)
}

// childEnvCmd 构造一个把自身作为 daemon 子进程跑的 exec.Cmd。
// 通过环境变量 SIPBAN_TEST_CHILD_MODE 选择子进程行为。
// 注意：实际进入子进程逻辑需要 Spawn 设置的 SIPBAN_DAEMONIZED=1、ExtraFiles 等。
// 此函数仅用于在测试里直接拼装一个 Spawn 风格的子进程二进制路径。
func selfExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return exe
}

// TestSpawnSuccess 端到端验证：父进程能调用 Spawn 拉起子进程、收到 ok、写好 PID 文件。
//
// 这里通过自定义环境变量把 `go test` 二进制本身当作 daemon 子进程，
// 在子进程 main 入口由 TestMain 拦截走 Activate 流程。
func TestSpawnSuccess(t *testing.T) {
	tmp := t.TempDir()
	pidPath := filepath.Join(tmp, "spawn.pid")
	logPath := filepath.Join(tmp, "spawn.log")

	// 用环境变量告诉子进程「以 ok 模式跑」。Spawn 会保留当前进程的 env。
	t.Setenv("SIPBAN_TEST_CHILD_MODE", "ok")
	// 让子进程不接受任何命令行参数（go test 接受 -test.* 但我们传空）
	// 通过给 extraArgs 加一个无害的 -test.run 让 go test 不真的跑所有测试。
	extraArgs := []string{"-test.run", "^$"} // 不匹配任何测试
	// 把 -test.run 作为 start 子命令的「附加参数」传给子进程；
	// 但 Spawn 内部会把第一个固定为 "start"——这与 go test 的 flag 冲突。
	// 实际上 go test 二进制并不识别 "start" 这个子命令，会把它当成位置参数；
	// 这没关系，因为 TestMain 在解析 flag 前就根据 env 跑 child mode 并退出，
	// 不会再走 m.Run。
	if err := Spawn(pidPath, logPath, extraArgs); err != nil {
		t.Fatalf("Spawn 应成功: %v", err)
	}

	// 子进程现在在阻塞等 ctx 取消。验证 PID 文件存在且身份匹配。
	info, alive, err := readAndVerify(pidPath)
	if err != nil {
		t.Fatalf("readAndVerify: %v", err)
	}
	if !alive {
		t.Errorf("PID 文件指向的进程应当 alive")
	}

	// 收尾：通过 SendStop 把子进程干掉
	if err := SendStop(pidPath, 3*time.Second); err != nil {
		t.Errorf("SendStop 失败: %v", err)
	}
	// SendStop 后 PID 文件应已被删除
	if _, err := os.Stat(pidPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("SendStop 后 PID 文件应被删除")
	}
	_ = info
}

// TestSpawnReportsChildFailure 验证子进程在抢锁前失败时，
// 父进程能从握手管道读到 err: 并返回非 nil error。
func TestSpawnReportsChildFailure(t *testing.T) {
	tmp := t.TempDir()
	// 故意指定一个父进程认为没问题、但子进程会自己改写为坏路径的 pidPath
	pidPath := filepath.Join(tmp, "ignored.pid")
	logPath := filepath.Join(tmp, "spawn.log")
	t.Setenv("SIPBAN_TEST_CHILD_MODE", "fail-bad-pid")

	extraArgs := []string{"-test.run", "^$"}
	err := Spawn(pidPath, logPath, extraArgs)
	if err == nil {
		t.Fatalf("Spawn 应失败")
	}
	if !strings.Contains(err.Error(), "子进程启动失败") &&
		!strings.Contains(err.Error(), "握手失败") {
		t.Errorf("错误信息不符合预期: %v", err)
	}
}

// TestSpawnTimesOut 验证父进程在子进程不写握手时会立即返回（EOF / timeout）。
// 我们用 `go test` 二进制本身做子进程，且不设置 SIPBAN_TEST_CHILD_MODE，
// 这样 TestMain 走 m.Run；配合 -test.run 不匹配任何用例 → 子进程很快退出，
// 触发握手管道 EOF 而非 ok。
func TestSpawnTimesOut(t *testing.T) {
	// 调短握手超时，避免测试卡 10 秒
	orig := handshakeTimeout
	defer func() { handshakeTimeout = orig }()
	handshakeTimeout = 2 * time.Second

	tmp := t.TempDir()
	pidPath := filepath.Join(tmp, "to.pid")
	logPath := filepath.Join(tmp, "to.log")

	t.Setenv("SIPBAN_TEST_CHILD_MODE", "") // 不进入 child mode
	err := Spawn(pidPath, logPath, []string{"-test.run", "^$", "-test.timeout", "60s"})
	if err == nil {
		t.Fatalf("应当返回错误（EOF 或超时）")
	}
}

// handshakeTimeoutOverride 占位，避免历史引用编译错误；当前无使用。
var handshakeTimeoutOverride time.Duration

// TestSpawnUnknownExeStillCleansUp 验证 Spawn 在 exec.Cmd.Start 失败时
// 清理握手 fd / 日志 fd 等资源。无法直接观察 fd 泄漏，但至少应返回错误。
func TestSpawnUnknownExeStillCleansUp(t *testing.T) {
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("缺 true 命令")
	}
	tmp := t.TempDir()
	pidPath := filepath.Join(tmp, "n.pid")
	logPath := filepath.Join(tmp, "n.log")

	// 把日志文件父目录设置为不存在的路径 → 触发 OpenFile 失败
	bad := filepath.Join(tmp, "no", "such", "dir", "x.log")
	err := Spawn(pidPath, bad, nil)
	if err == nil {
		t.Fatalf("应返回错误")
	}
	_ = logPath
}
