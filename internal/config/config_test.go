package config

import (
	"flag"
	"os"
	"testing"
)

// TestConfigDefaults 测试配置的默认值
func TestConfigDefaults(t *testing.T) {
	// 重置flag以避免测试间干扰
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// 模拟无参数启动
	os.Args = []string{"cmd"}

	cfg := Load()

	// 验证默认值
	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"DeviceName默认为空", cfg.DeviceName, ""},
		{"Protocol默认为udp", cfg.Protocol, "udp"},
		{"FilterPort默认为5060", cfg.FilterPort, 5060},
		{"RegisterFindTime默认为120", cfg.RegisterFindTime, 120},
		{"RegisterMaxRetry默认为40", cfg.RegisterMaxRetry, 40},
		{"InviteFindTime默认为60", cfg.InviteFindTime, 60},
		{"InviteMaxRetry默认为10", cfg.InviteMaxRetry, 10},
		{"IPDBPath默认路径", cfg.IPDBPath, "./data/ipv4.ipdb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s: got %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

// TestConfigCustomValues 测试自定义配置值
func TestConfigCustomValues(t *testing.T) {
	// 重置flag
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// 模拟带参数启动
	os.Args = []string{
		"cmd",
		"-i", "eth0",
		"-p", "tcp",
		"-P", "5080",
		"-rt", "180",
		"-rn", "50",
		"-it", "90",
		"-in", "15",
		"-ipdb", "/custom/path/ipdb",
	}

	cfg := Load()

	// 验证自定义值
	tests := []struct {
		name string
		got  interface{}
		want interface{}
	}{
		{"DeviceName", cfg.DeviceName, "eth0"},
		{"Protocol", cfg.Protocol, "tcp"},
		{"FilterPort", cfg.FilterPort, 5080},
		{"RegisterFindTime", cfg.RegisterFindTime, 180},
		{"RegisterMaxRetry", cfg.RegisterMaxRetry, 50},
		{"InviteFindTime", cfg.InviteFindTime, 90},
		{"InviteMaxRetry", cfg.InviteMaxRetry, 15},
		{"IPDBPath", cfg.IPDBPath, "/custom/path/ipdb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s: got %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

// TestConfigPartialValues 测试部分自定义配置
func TestConfigPartialValues(t *testing.T) {
	// 重置flag
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	// 只设置部分参数
	os.Args = []string{
		"cmd",
		"-i", "lo",
		"-P", "5070",
	}

	cfg := Load()

	// 验证部分自定义，其他保持默认
	if cfg.DeviceName != "lo" {
		t.Errorf("DeviceName = %v, want lo", cfg.DeviceName)
	}

	if cfg.FilterPort != 5070 {
		t.Errorf("FilterPort = %v, want 5070", cfg.FilterPort)
	}

	// 其他应该是默认值
	if cfg.Protocol != "udp" {
		t.Errorf("Protocol = %v, want udp (default)", cfg.Protocol)
	}

	if cfg.RegisterFindTime != 120 {
		t.Errorf("RegisterFindTime = %v, want 120 (default)", cfg.RegisterFindTime)
	}
}

// TestConfigStructure 测试Config结构体字段
func TestConfigStructure(t *testing.T) {
	cfg := &Config{
		DeviceName:       "test",
		Protocol:         "udp",
		FilterPort:       5060,
		RegisterFindTime: 120,
		RegisterMaxRetry: 40,
		InviteFindTime:   60,
		InviteMaxRetry:   10,
		IPDBPath:         "./data/ipv4.ipdb",
	}

	// 验证结构体可以正确赋值和读取
	if cfg.DeviceName != "test" {
		t.Error("DeviceName字段赋值失败")
	}

	if cfg.Protocol != "udp" {
		t.Error("Protocol字段赋值失败")
	}

	if cfg.FilterPort != 5060 {
		t.Error("FilterPort字段赋值失败")
	}
}

// TestLoadFromFlagSet 验证 LoadFromFlagSet 在独立 FlagSet 上的行为：
//   - 不污染 flag.CommandLine；
//   - 可以叠加额外的自定义 flag（模拟 start 子命令叠加 -pid / -log）。
func TestLoadFromFlagSet(t *testing.T) {
	// 独立的 FlagSet，与 flag.CommandLine 完全隔离
	fs := flag.NewFlagSet("start", flag.ContinueOnError)

	// 调用方先注册自己的 flag
	var pidPath string
	fs.StringVar(&pidPath, "pid", "", "PID 文件路径")

	args := []string{
		"-i", "eth1",
		"-P", "5061",
		"-pid", "/tmp/sip-ban.pid",
	}

	cfg, err := LoadFromFlagSet(fs, args)
	if err != nil {
		t.Fatalf("LoadFromFlagSet 不应失败: %v", err)
	}

	if cfg.DeviceName != "eth1" {
		t.Errorf("DeviceName = %q, want %q", cfg.DeviceName, "eth1")
	}
	if cfg.FilterPort != 5061 {
		t.Errorf("FilterPort = %d, want 5061", cfg.FilterPort)
	}
	if pidPath != "/tmp/sip-ban.pid" {
		t.Errorf("pidPath = %q, want /tmp/sip-ban.pid", pidPath)
	}
}

// TestLoadFromFlagSetUnknownFlag 验证传入未知 flag 时返回错误，而不是 panic / 退出。
func TestLoadFromFlagSetUnknownFlag(t *testing.T) {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	// 关闭 usage 噪音输出，让测试干净
	fs.SetOutput(devNull{})

	_, err := LoadFromFlagSet(fs, []string{"-unknown-flag", "value"})
	if err == nil {
		t.Fatal("LoadFromFlagSet 在遇到未知 flag 时应返回错误")
	}
}

// devNull 实现 io.Writer，用于丢弃 flag 包的 usage 输出。
type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }
