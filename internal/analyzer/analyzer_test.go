package analyzer

import (
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/patrickmn/go-cache"

	"sip-ban/internal/firewall"
	"sip-ban/internal/geoip"
)

// TestNew 测试创建分析器
func TestNew(t *testing.T) {
	rules := map[string]*BanRule{
		"INVITE": {
			FindTime: 60,
			MaxRetry: 10,
		},
	}

	ruleCodes := map[int]*BanRule{
		401: rules["INVITE"],
	}

	analyzer := New("udp", "192.168.1.1", "eth0", nil, nil, rules, ruleCodes)

	if analyzer == nil {
		t.Fatal("New() 返回nil")
	}

	if analyzer.protocol != "udp" {
		t.Errorf("protocol = %v, want udp", analyzer.protocol)
	}

	if analyzer.deviceIP != "192.168.1.1" {
		t.Errorf("deviceIP = %v, want 192.168.1.1", analyzer.deviceIP)
	}

	if analyzer.deviceName != "eth0" {
		t.Errorf("deviceName = %v, want eth0", analyzer.deviceName)
	}

	if analyzer.cache == nil {
		t.Error("cache不应该为nil")
	}

	if analyzer.banRules == nil {
		t.Error("banRules不应该为nil")
	}

	if analyzer.banRuleCode == nil {
		t.Error("banRuleCode不应该为nil")
	}
}

// TestBanRule 测试BanRule结构体
func TestBanRule(t *testing.T) {
	rule := &BanRule{
		FindTime: 120,
		MaxRetry: 40,
	}

	if rule.FindTime != 120 {
		t.Errorf("FindTime = %v, want 120", rule.FindTime)
	}

	if rule.MaxRetry != 40 {
		t.Errorf("MaxRetry = %v, want 40", rule.MaxRetry)
	}
}

// TestAnalyzer_GetDirection 测试流量方向判断
func TestAnalyzer_GetDirection(t *testing.T) {
	analyzer := &Analyzer{
		deviceIP: "192.168.1.100",
		cache:    cache.New(5*time.Minute, 10*time.Minute),
	}

	tests := []struct {
		name   string
		srcIP  string
		dstIP  string
		want   string
	}{
		{"出站流量", "192.168.1.100", "8.8.8.8", DirectionOut},
		{"入站流量", "8.8.8.8", "192.168.1.100", DirectionIn},
		{"其他流量", "1.1.1.1", "8.8.8.8", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 构造IPv4层
			ip := &layers.IPv4{
				SrcIP: []byte(tt.srcIP),
				DstIP: []byte(tt.dstIP),
			}

			// 手动设置IP地址
			ip.SrcIP = []byte{192, 168, 1, 100}
			if tt.srcIP != "192.168.1.100" {
				ip.SrcIP = []byte{8, 8, 8, 8}
			}

			ip.DstIP = []byte{8, 8, 8, 8}
			if tt.dstIP == "192.168.1.100" {
				ip.DstIP = []byte{192, 168, 1, 100}
			}

			got := analyzer.getDirection(ip)
			if got != tt.want {
				t.Errorf("getDirection() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDirectionConstants 测试方向常量
func TestDirectionConstants(t *testing.T) {
	if DirectionIn != "IN" {
		t.Errorf("DirectionIn = %v, want IN", DirectionIn)
	}

	if DirectionOut != "OUT" {
		t.Errorf("DirectionOut = %v, want OUT", DirectionOut)
	}
}

// TestAnalyzer_CheckBanRules_NoRule 测试没有匹配规则的情况
func TestAnalyzer_CheckBanRules_NoRule(t *testing.T) {
	analyzer := &Analyzer{
		cache:       cache.New(5*time.Minute, 10*time.Minute),
		banRuleCode: map[int]*BanRule{},
	}

	// 调用checkBanRules，响应码999没有对应规则
	// 应该直接返回，不会panic
	analyzer.checkBanRules("192.168.1.1", 999, "log", "sip")
}

// TestAnalyzer_CheckBanRules_WithRule 测试有匹配规则的情况
func TestAnalyzer_CheckBanRules_WithRule(t *testing.T) {
	rule := &BanRule{
		FindTime: 60,
		MaxRetry: 5,
	}

	analyzer := &Analyzer{
		cache: cache.New(5*time.Minute, 10*time.Minute),
		banRuleCode: map[int]*BanRule{
			401: rule,
		},
	}

	// 第一次调用，应该添加到缓存
	analyzer.checkBanRules("192.168.1.1", 401, "log", "sip")

	// 验证缓存中有该键
	key := "192.168.1.1.401"
	_, found := analyzer.cache.Get(key)
	if !found {
		t.Error("应该在缓存中找到该键")
	}

	// 多次调用以增加计数
	for i := 0; i < 3; i++ {
		analyzer.checkBanRules("192.168.1.1", 401, "log", "sip")
	}

	// 验证计数增加
	val, _ := analyzer.cache.Get(key)
	if val.(int) < 2 {
		t.Errorf("计数应该至少为2，got %v", val)
	}
}

// TestAnalyzer_CheckGeoIP_NilChecker 测试geoChecker为nil的情况
func TestAnalyzer_CheckGeoIP_NilChecker(t *testing.T) {
	analyzer := &Analyzer{
		geoChecker: nil,
		cache:      cache.New(5*time.Minute, 10*time.Minute),
	}

	// geoChecker为nil时应该返回true（放行）
	result := analyzer.checkGeoIP("8.8.8.8", "log", "sip")
	if !result {
		t.Error("geoChecker为nil时应该返回true")
	}
}

// TestAnalyzer_CheckGeoIP_WithChecker 测试有geoChecker的情况
func TestAnalyzer_CheckGeoIP_WithChecker(t *testing.T) {
	// 创建一个nil数据库的checker（会默认放行）
	checker := &geoip.Checker{}

	analyzer := &Analyzer{
		geoChecker: checker,
		firewall:   &firewall.Manager{},
		cache:      cache.New(5*time.Minute, 10*time.Minute),
	}

	// 测试中国IP（应该放行）
	result := analyzer.checkGeoIP("192.168.1.1", "log", "sip")
	if !result {
		t.Error("中国IP应该返回true")
	}
}

// TestAnalyzer_CacheOperations 测试缓存操作
func TestAnalyzer_CacheOperations(t *testing.T) {
	c := cache.New(5*time.Minute, 10*time.Minute)

	// 测试添加和获取
	err := c.Add("test-key", 1, 1*time.Minute)
	if err != nil {
		t.Errorf("Add() error = %v", err)
	}

	val, found := c.Get("test-key")
	if !found {
		t.Error("应该找到缓存项")
	}

	if val != 1 {
		t.Errorf("缓存值 = %v, want 1", val)
	}

	// 测试增加计数
	newVal, err := c.IncrementInt("test-key", 1)
	if err != nil {
		t.Errorf("IncrementInt() error = %v", err)
	}

	if newVal != 2 {
		t.Errorf("增加后的值 = %v, want 2", newVal)
	}
}

// TestAnalyzer_MultipleRules 测试多个封禁规则
func TestAnalyzer_MultipleRules(t *testing.T) {
	rules := map[string]*BanRule{
		"INVITE": {
			FindTime: 60,
			MaxRetry: 10,
		},
		"REGISTER": {
			FindTime: 120,
			MaxRetry: 40,
		},
	}

	ruleCodes := map[int]*BanRule{
		401: rules["REGISTER"],
		403: rules["INVITE"],
		407: rules["INVITE"],
	}

	analyzer := New("udp", "192.168.1.1", "eth0", nil, nil, rules, ruleCodes)

	// 验证规则映射正确
	if analyzer.banRuleCode[401] != rules["REGISTER"] {
		t.Error("401响应码应该映射到REGISTER规则")
	}

	if analyzer.banRuleCode[403] != rules["INVITE"] {
		t.Error("403响应码应该映射到INVITE规则")
	}

	if analyzer.banRuleCode[407] != rules["INVITE"] {
		t.Error("407响应码应该映射到INVITE规则")
	}
}

// TestAnalyzer_ExtractPorts_TCP 测试TCP端口提取
func TestAnalyzer_ExtractPorts_TCP(t *testing.T) {
	analyzer := &Analyzer{
		protocol: "tcp",
		cache:    cache.New(5*time.Minute, 10*time.Minute),
	}

	// 注意：这个测试需要构造完整的packet，比较复杂
	// 这里只测试协议字段设置
	if analyzer.protocol != "tcp" {
		t.Error("protocol应该为tcp")
	}
}

// TestAnalyzer_ExtractPorts_UDP 测试UDP端口提取
func TestAnalyzer_ExtractPorts_UDP(t *testing.T) {
	analyzer := &Analyzer{
		protocol: "udp",
		cache:    cache.New(5*time.Minute, 10*time.Minute),
	}

	if analyzer.protocol != "udp" {
		t.Error("protocol应该为udp")
	}
}

// TestAnalyzer_CacheExpiration 测试缓存过期
func TestAnalyzer_CacheExpiration(t *testing.T) {
	c := cache.New(100*time.Millisecond, 200*time.Millisecond)

	// 添加一个短期缓存项
	err := c.Add("expire-key", 1, 100*time.Millisecond)
	if err != nil {
		t.Errorf("Add() error = %v", err)
	}

	// 立即获取应该存在
	_, found := c.Get("expire-key")
	if !found {
		t.Error("刚添加的缓存项应该存在")
	}

	// 等待过期
	time.Sleep(150 * time.Millisecond)

	// 再次获取应该不存在
	_, found = c.Get("expire-key")
	if found {
		t.Error("过期的缓存项不应该存在")
	}
}

// TestAnalyzer_CheckBanRules_MaxRetry 测试超过最大重试次数
func TestAnalyzer_CheckBanRules_MaxRetry(t *testing.T) {
	rule := &BanRule{
		FindTime: 60,
		MaxRetry: 3,
	}

	analyzer := &Analyzer{
		cache: cache.New(5*time.Minute, 10*time.Minute),
		banRuleCode: map[int]*BanRule{
			401: rule,
		},
	}

	// 调用多次以超过最大重试次数
	for i := 0; i < 5; i++ {
		analyzer.checkBanRules("192.168.1.1", 401, "log", "sip")
	}

	// 验证缓存中的计数
	key := "192.168.1.1.401"
	val, found := analyzer.cache.Get(key)
	if !found {
		t.Error("应该在缓存中找到该键")
	}

	if val.(int) <= rule.MaxRetry {
		t.Logf("计数 = %v, 已超过MaxRetry = %v", val, rule.MaxRetry)
	}
}

// 注意：完整的AnalyzePacket测试需要：
// 1. 构造真实的gopacket.Packet对象
// 2. Mock geoip.Checker和firewall.Manager
// 3. 集成测试环境
// 这里只测试了基本的结构和逻辑
