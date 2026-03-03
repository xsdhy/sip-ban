// Package config 提供配置管理功能，负责解析命令行参数并生成配置对象
package config

import "flag"

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

// Load 从命令行参数加载配置
// 返回初始化好的配置对象
func Load() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.DeviceName, "i", "", "网卡")
	flag.StringVar(&cfg.Protocol, "p", "udp", "协议")
	flag.IntVar(&cfg.FilterPort, "P", 5060, "端口号")
	flag.IntVar(&cfg.RegisterFindTime, "rt", 120, "Register-FindTime")
	flag.IntVar(&cfg.RegisterMaxRetry, "rn", 40, "Register-MaxRetry")
	flag.IntVar(&cfg.InviteFindTime, "it", 60, "Invite-FindTime")
	flag.IntVar(&cfg.InviteMaxRetry, "in", 10, "Invite-MaxRetry")
	flag.StringVar(&cfg.IPDBPath, "ipdb", "./data/ipv4.ipdb", "IP数据库路径")
	flag.Parse()

	return cfg
}
