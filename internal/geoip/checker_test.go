package geoip

import (
	"testing"
)

// TestNew_InvalidPath 测试使用无效路径创建Checker
func TestNew_InvalidPath(t *testing.T) {
	_, err := New("/nonexistent/path/to/ipdb")
	if err == nil {
		t.Error("使用无效路径应该返回错误")
	}
}

// TestChecker_NilDB 测试数据库为nil时的行为
func TestChecker_NilDB(t *testing.T) {
	checker := &Checker{db: nil}

	isChina, country := checker.IsChina("8.8.8.8")

	// 当数据库为nil时，应该默认返回true（放行）
	if !isChina {
		t.Error("数据库为nil时应该返回true")
	}

	if country != "" {
		t.Errorf("数据库为nil时country应该为空，got %s", country)
	}
}

// TestChecker_InvalidIP 测试无效IP地址
func TestChecker_InvalidIP(t *testing.T) {
	// 由于没有真实的数据库文件，我们创建一个nil checker来测试
	checker := &Checker{db: nil}

	tests := []string{
		"invalid",
		"999.999.999.999",
		"",
		"not-an-ip",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			isChina, _ := checker.IsChina(ip)
			// 无效IP应该默认放行
			if !isChina {
				t.Errorf("无效IP %s 应该默认放行", ip)
			}
		})
	}
}

// TestChecker_Structure 测试Checker结构体
func TestChecker_Structure(t *testing.T) {
	checker := &Checker{db: nil}

	if checker.db != nil {
		t.Error("db字段应该为nil")
	}
}

// TestChecker_LocalIPs 测试本地IP地址处理
func TestChecker_LocalIPs(t *testing.T) {
	checker := &Checker{db: nil}

	localIPs := []string{
		"127.0.0.1",
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
	}

	for _, ip := range localIPs {
		t.Run(ip, func(t *testing.T) {
			isChina, _ := checker.IsChina(ip)
			// 本地IP应该默认放行
			if !isChina {
				t.Errorf("本地IP %s 应该默认放行", ip)
			}
		})
	}
}

// TestChecker_PublicIPs 测试公网IP地址
func TestChecker_PublicIPs(t *testing.T) {
	checker := &Checker{db: nil}

	publicIPs := []string{
		"8.8.8.8",
		"1.1.1.1",
		"114.114.114.114",
	}

	for _, ip := range publicIPs {
		t.Run(ip, func(t *testing.T) {
			isChina, _ := checker.IsChina(ip)
			// 没有数据库时应该默认放行
			if !isChina {
				t.Errorf("公网IP %s 在无数据库时应该默认放行", ip)
			}
		})
	}
}

// 注意：由于IsChina方法依赖真实的IP数据库文件，
// 完整的功能测试需要在集成测试中进行，或者使用mock
// 这里只测试了错误处理和边界情况
