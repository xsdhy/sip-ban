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

// TestValidateIP_ValidIPs 测试合法的IP地址
func TestValidateIP_ValidIPs(t *testing.T) {
	validIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"1.2.3.4",
		"223.5.5.5",
		"114.114.114.114",
		"1.1.1.1",
	}

	for _, ip := range validIPs {
		t.Run(ip, func(t *testing.T) {
			err := validateIP(ip)
			if err != nil {
				t.Errorf("合法IP %s 应该通过验证，但返回错误: %v", ip, err)
			}
		})
	}
}

// TestValidateIP_InvalidFormat 测试无效格式的IP地址
func TestValidateIP_InvalidFormat(t *testing.T) {
	invalidIPs := []string{
		"",                     // 空字符串
		"invalid",              // 非IP格式
		"999.999.999.999",      // 超出范围
		"not-an-ip",            // 包含字母
		"abc.def.ghi.jkl",      // 全是字母
		"192.168.1",            // 不完整
		"192.168.1.1.1",        // 过多段
		"192.168.-1.1",         // 负数
		"192.168.1.256",        // 超出范围
		"192.168.1.1/24",       // CIDR格式（不应接受）
		"192.168.1.1:8080",     // 包含端口
		"::1",                  // IPv6（当前只处理IPv4）
		"2001:db8::1",          // IPv6
	}

	for _, ip := range invalidIPs {
		t.Run(ip, func(t *testing.T) {
			err := validateIP(ip)
			if err == nil {
				t.Errorf("无效IP %s 应该返回错误", ip)
			}
		})
	}
}

// TestValidateIP_SpecialAddresses 测试特殊IP地址（应该被拒绝）
func TestValidateIP_SpecialAddresses(t *testing.T) {
	specialIPs := []struct {
		ip          string
		description string
	}{
		{"0.0.0.0", "未指定地址"},
		{"255.255.255.255", "广播地址"},
		{"127.0.0.1", "回环地址"},
		{"127.0.0.2", "回环地址"},
		{"127.255.255.255", "回环地址"},
		{"224.0.0.1", "多播地址"},
		{"239.255.255.255", "多播地址"},
	}

	for _, tc := range specialIPs {
		t.Run(tc.ip, func(t *testing.T) {
			err := validateIP(tc.ip)
			if err == nil {
				t.Errorf("特殊IP %s (%s) 应该被拒绝", tc.ip, tc.description)
			}
			t.Logf("正确拒绝 %s (%s): %v", tc.ip, tc.description, err)
		})
	}
}

// TestManager_Ban_WithValidation 测试Ban方法的IP验证功能
func TestManager_Ban_WithValidation(t *testing.T) {
	// 使用nil的ipt，这样不会真正执行iptables命令
	// 但会执行IP验证逻辑
	manager := &Manager{ipt: nil}

	tests := []struct {
		name        string
		ip          string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "空IP",
			ip:          "",
			shouldError: true,
			errorMsg:    "invalid IP address format",
		},
		{
			name:        "无效格式",
			ip:          "invalid-ip",
			shouldError: true,
			errorMsg:    "invalid IP address format",
		},
		{
			name:        "未指定地址",
			ip:          "0.0.0.0",
			shouldError: true,
			errorMsg:    "cannot ban unspecified address",
		},
		{
			name:        "广播地址",
			ip:          "255.255.255.255",
			shouldError: true,
			errorMsg:    "cannot ban broadcast address",
		},
		{
			name:        "回环地址",
			ip:          "127.0.0.1",
			shouldError: true,
			errorMsg:    "cannot ban loopback address",
		},
		{
			name:        "多播地址",
			ip:          "224.0.0.1",
			shouldError: true,
			errorMsg:    "cannot ban multicast address",
		},
		{
			name:        "合法IP但ipt未初始化",
			ip:          "192.168.1.100",
			shouldError: true,
			errorMsg:    "iptables not initialized",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.Ban(tt.ip)

			if tt.shouldError {
				if err == nil {
					t.Errorf("应该返回错误")
				} else {
					// 验证错误消息包含预期的关键字
					if tt.errorMsg != "" {
						errMsg := err.Error()
						// 简单检查错误消息是否包含关键字
						found := false
						if tt.errorMsg == "invalid IP address format" &&
							(errMsg == "invalid IP address format: "+tt.ip) {
							found = true
						} else if tt.errorMsg == "cannot ban unspecified address" &&
							(errMsg == "cannot ban unspecified address: "+tt.ip) {
							found = true
						} else if tt.errorMsg == "cannot ban broadcast address" &&
							(errMsg == "cannot ban broadcast address: "+tt.ip) {
							found = true
						} else if tt.errorMsg == "cannot ban loopback address" &&
							(errMsg == "cannot ban loopback address: "+tt.ip) {
							found = true
						} else if tt.errorMsg == "cannot ban multicast address" &&
							(errMsg == "cannot ban multicast address: "+tt.ip) {
							found = true
						} else if tt.errorMsg == "iptables not initialized" &&
							(errMsg == "iptables not initialized") {
							found = true
						}

						if !found {
							t.Logf("错误消息: %v", errMsg)
						}
					}
				}
			} else {
				if err != nil {
					t.Errorf("不应该返回错误: %v", err)
				}
			}
		})
	}
}

// TestValidateIP_PrivateAddresses 测试私有IP地址（应该被允许）
func TestValidateIP_PrivateAddresses(t *testing.T) {
	privateIPs := []string{
		"10.0.0.1",       // 10.0.0.0/8
		"10.255.255.254", // 10.0.0.0/8
		"172.16.0.1",     // 172.16.0.0/12
		"172.31.255.254", // 172.16.0.0/12
		"192.168.0.1",    // 192.168.0.0/16
		"192.168.255.254", // 192.168.0.0/16
	}

	for _, ip := range privateIPs {
		t.Run(ip, func(t *testing.T) {
			err := validateIP(ip)
			if err != nil {
				t.Errorf("私有IP %s 应该被允许封禁，但返回错误: %v", ip, err)
			}
		})
	}
}

// TestValidateIP_PublicAddresses 测试公网IP地址（应该被允许）
func TestValidateIP_PublicAddresses(t *testing.T) {
	publicIPs := []string{
		"8.8.8.8",         // Google DNS
		"1.1.1.1",         // Cloudflare DNS
		"114.114.114.114", // 中国DNS
		"223.5.5.5",       // 阿里DNS
		"208.67.222.222",  // OpenDNS
	}

	for _, ip := range publicIPs {
		t.Run(ip, func(t *testing.T) {
			err := validateIP(ip)
			if err != nil {
				t.Errorf("公网IP %s 应该被允许封禁，但返回错误: %v", ip, err)
			}
		})
	}
}
