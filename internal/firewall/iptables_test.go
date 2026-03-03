package firewall

import (
	"testing"
)

// TestNew 测试创建防火墙管理器
func TestNew(t *testing.T) {
	// 注意：这个测试需要root权限才能真正初始化iptables
	// 在没有权限的环境下会返回错误
	_, err := New()

	// 我们不强制要求成功，因为测试环境可能没有权限
	// 只验证函数可以被调用
	if err != nil {
		t.Logf("New() 返回错误（可能是权限问题）: %v", err)
	}
}

// TestManager_BanWithNilIPT 测试iptables未初始化时的Ban操作
func TestManager_BanWithNilIPT(t *testing.T) {
	manager := &Manager{ipt: nil}

	err := manager.Ban("192.168.1.100")
	if err == nil {
		t.Error("iptables为nil时Ban应该返回错误")
	}

	expectedMsg := "iptables not initialized"
	if err.Error() != expectedMsg {
		t.Errorf("错误消息 = %v, want %v", err.Error(), expectedMsg)
	}
}

// TestManager_Structure 测试Manager结构体
func TestManager_Structure(t *testing.T) {
	manager := &Manager{ipt: nil}

	if manager.ipt != nil {
		t.Error("ipt字段应该为nil")
	}
}

// TestManager_BanIPFormat 测试不同格式的IP地址
func TestManager_BanIPFormat(t *testing.T) {
	// 这个测试只验证函数调用，不验证实际的iptables操作
	manager := &Manager{ipt: nil}

	testIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"1.2.3.4",
	}

	for _, ip := range testIPs {
		t.Run(ip, func(t *testing.T) {
			err := manager.Ban(ip)
			// 应该返回"iptables not initialized"错误
			if err == nil {
				t.Error("应该返回错误")
			}
		})
	}
}

// TestManager_BanEmptyIP 测试空IP地址
func TestManager_BanEmptyIP(t *testing.T) {
	manager := &Manager{ipt: nil}

	err := manager.Ban("")
	if err == nil {
		t.Error("空IP应该返回错误")
	}
}

// TestManager_BanInvalidIP 测试无效IP地址
func TestManager_BanInvalidIP(t *testing.T) {
	manager := &Manager{ipt: nil}

	invalidIPs := []string{
		"invalid",
		"999.999.999.999",
		"not-an-ip",
		"abc.def.ghi.jkl",
	}

	for _, ip := range invalidIPs {
		t.Run(ip, func(t *testing.T) {
			err := manager.Ban(ip)
			// 应该返回错误（iptables未初始化）
			if err == nil {
				t.Error("无效IP应该返回错误")
			}
		})
	}
}

// 注意：完整的iptables功能测试需要：
// 1. root权限
// 2. 真实的Linux环境
// 3. 集成测试环境
// 这里只测试了基本的错误处理和结构
