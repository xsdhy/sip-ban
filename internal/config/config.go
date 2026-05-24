// Package config 提供配置管理功能，负责解析命令行参数并生成配置对象。
//
// 设计要点：
//   - LoadFromFlagSet 是真正干活的入口，可以由调用方传入独立的 *flag.FlagSet
//     与参数列表。这样 daemon 的 start / status / stop 等子命令可以各自构造
//     自己的 FlagSet，避免与 flag.CommandLine 全局状态相互污染。
//   - Load 保留为向后兼容的薄包装，仍然走 flag.CommandLine + os.Args[1:]。
package config

import (
	"flag"
	"os"
)

// Config 配置结构体，包含所有运行时配置参数
type Config struct {
	// DeviceName 指定要监控的网卡名称，为空则监控所有网卡
	DeviceName string
	// Protocol 网络协议类型，支持 tcp 或 udp
	Protocol string
	// FilterPort 要监控的端口号
	FilterPort int

	// RegisterFindTime REGISTER方法的时间窗口（秒）
	RegisterFindTime int
	// RegisterMaxRetry REGISTER方法在时间窗口内的最大重试次数
	RegisterMaxRetry int
	// InviteFindTime INVITE方法的时间窗口（秒）
	InviteFindTime int
	// InviteMaxRetry INVITE方法在时间窗口内的最大重试次数
	InviteMaxRetry int

	// IPDBPath IP地理位置数据库文件路径
	IPDBPath string
}

// RegisterFlags 把所有公共配置项注册到给定的 FlagSet 上。
// 调用方负责执行 fs.Parse(args)。
// 这样 daemon 相关的子命令可以在同一个 FlagSet 上叠加自己的 -pid / -log 参数，
// 同时与前台模式的参数解析共享同一套定义、避免漂移。
func (c *Config) RegisterFlags(fs *flag.FlagSet) {
	fs.StringVar(&c.DeviceName, "i", "", "网卡")
	fs.StringVar(&c.Protocol, "p", "udp", "协议")
	fs.IntVar(&c.FilterPort, "P", 5060, "端口号")
	fs.IntVar(&c.RegisterFindTime, "rt", 120, "Register-FindTime")
	fs.IntVar(&c.RegisterMaxRetry, "rn", 40, "Register-MaxRetry")
	fs.IntVar(&c.InviteFindTime, "it", 60, "Invite-FindTime")
	fs.IntVar(&c.InviteMaxRetry, "in", 10, "Invite-MaxRetry")
	fs.StringVar(&c.IPDBPath, "ipdb", "./data/ipv4.ipdb", "IP数据库路径")
}

// LoadFromFlagSet 在指定 FlagSet 上解析参数并生成 Config。
// 参数：
//   - fs：已初始化好的 FlagSet。调用方可以在调用本函数前为它注册额外的 flag。
//   - args：待解析的参数列表（通常是 os.Args[<n>:]，去掉了子命令本身）。
//
// 返回：
//   - *Config：解析后的配置。
//   - error：解析失败时返回（例如未知 flag）。
func LoadFromFlagSet(fs *flag.FlagSet, args []string) (*Config, error) {
	cfg := &Config{}
	cfg.RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Load 从命令行参数加载配置。
// 此函数保留作为向后兼容入口，内部委托给 LoadFromFlagSet。
// 当解析失败时（受 flag.ExitOnError 控制）程序会直接退出。
//
// 返回：
//   - *Config：初始化好的配置对象。
func Load() *Config {
	cfg, err := LoadFromFlagSet(flag.CommandLine, os.Args[1:])
	if err != nil {
		// flag.CommandLine 默认 ExitOnError，理论上到不了这里；
		// 但即使到了，也只能让程序退出以保持原语义。
		os.Exit(2)
	}
	return cfg
}
