// Package firewall 提供防火墙管理功能
package firewall

import (
	"fmt"
	"net"
	"sip-ban/pkg/iptables"
)

// Manager 防火墙管理器
type Manager struct {
	ipt *iptables.IPTables // iptables操作实例
}

// New 创建一个新的防火墙管理器
// 返回:
//   *Manager - 管理器实例
//   error - 初始化失败时返回错误
func New() (*Manager, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	return &Manager{ipt: ipt}, nil
}

// Ban 封禁指定IP地址
// 在iptables的INPUT链中添加DROP规则，阻止来自该IP的所有流量
// 参数:
//   ip - 要封禁的IP地址
// 返回:
//   error - 操作失败时返回错误
func (m *Manager) Ban(ip string) error {
	if m.ipt == nil {
		return fmt.Errorf("iptables not initialized")
	}

	// 验证IP地址格式
	if err := validateIP(ip); err != nil {
		return err
	}

	// 构造iptables规则: -s <ip> -j DROP
	rule := []string{"-s", ip, "-j", "DROP"}

	// 检查规则是否已存在
	exists, err := m.ipt.Exists("filter", "INPUT", rule...)
	if err != nil {
		return err
	}
	if exists {
		// 规则已存在，无需重复添加
		return nil
	}

	// 添加新规则
	return m.ipt.Append("filter", "INPUT", rule...)
}

// validateIP 验证IP地址的合法性
// 参数:
//   ip - 要验证的IP地址字符串
// 返回:
//   error - IP地址非法时返回错误
func validateIP(ip string) error {
	// 使用net.ParseIP验证IP格式
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}

	// 只接受IPv4地址，拒绝IPv6
	if parsedIP.To4() == nil {
		return fmt.Errorf("only IPv4 addresses are supported: %s", ip)
	}

	// 拒绝特殊IP地址
	// 0.0.0.0 - 未指定地址
	if parsedIP.Equal(net.IPv4zero) {
		return fmt.Errorf("cannot ban unspecified address: %s", ip)
	}

	// 255.255.255.255 - 广播地址
	if parsedIP.Equal(net.IPv4bcast) {
		return fmt.Errorf("cannot ban broadcast address: %s", ip)
	}

	// 127.0.0.0/8 - 回环地址
	if parsedIP.IsLoopback() {
		return fmt.Errorf("cannot ban loopback address: %s", ip)
	}

	// 拒绝多播地址
	if parsedIP.IsMulticast() {
		return fmt.Errorf("cannot ban multicast address: %s", ip)
	}

	return nil
}
