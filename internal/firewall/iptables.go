// Package firewall 提供防火墙管理功能
package firewall

import (
	"fmt"
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
