// Package analyzer 提供SIP流量分析和封禁决策功能
package analyzer

import (
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/patrickmn/go-cache"

	"sip-ban/internal/firewall"
	"sip-ban/internal/geoip"
	"sip-ban/internal/sip"
)

// 流量方向常量
const (
	DirectionIn  = "IN"  // 入站流量
	DirectionOut = "OUT" // 出站流量
)

// BanRule 封禁规则配置
type BanRule struct {
	FindTime int // 时间窗口（秒）
	MaxRetry int // 时间窗口内允许的最大重试次数
}

// Analyzer SIP流量分析器
type Analyzer struct {
	cache        *cache.Cache          // 缓存，用于记录IP的请求次数
	geoChecker   *geoip.Checker        // IP地理位置检查器
	firewall     *firewall.Manager     // 防火墙管理器
	banRules     map[string]*BanRule   // 基于SIP方法的封禁规则
	banRuleCode  map[int]*BanRule      // 基于响应码的封禁规则
	protocol     string                // 协议类型（tcp/udp）
	deviceIP     string                // 本机设备IP
	deviceName   string                // 网卡名称
}

// New 创建一个新的流量分析器
// 参数:
//   protocol - 协议类型（tcp或udp）
//   deviceIP - 本机设备IP地址
//   deviceName - 网卡名称
//   geoChecker - IP地理位置检查器
//   fw - 防火墙管理器
//   rules - 基于SIP方法的封禁规则映射
//   ruleCodes - 基于响应码的封禁规则映射
// 返回:
//   *Analyzer - 分析器实例
func New(protocol, deviceIP, deviceName string, geoChecker *geoip.Checker, fw *firewall.Manager, rules map[string]*BanRule, ruleCodes map[int]*BanRule) *Analyzer {
	return &Analyzer{
		cache:       cache.New(5*time.Minute, 10*time.Minute),
		geoChecker:  geoChecker,
		firewall:    fw,
		banRules:    rules,
		banRuleCode: ruleCodes,
		protocol:    protocol,
		deviceIP:    deviceIP,
		deviceName:  deviceName,
	}
}

// AnalyzePacket 分析单个网络数据包
// 检查IP地理位置和SIP响应码，根据规则决定是否封禁
// 参数:
//   packet - 要分析的网络数据包
func (a *Analyzer) AnalyzePacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return
	}

	// 判断流量方向
	direction := a.getDirection(ip)
	srcPort, dstPort := a.extractPorts(packet)
	if srcPort == 0 {
		return
	}

	// 构造基础日志信息
	logBase := fmt.Sprintf("%s %s\t%s-%s %s:%d->%s:%d",
		time.Now().Format("2006-01-02 15:04:05"),
		a.deviceName,
		ip.Protocol,
		direction,
		ip.SrcIP, srcPort,
		ip.DstIP, dstPort)

	// 提取应用层数据（SIP消息）
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}

	// 解析SIP消息
	sipPkg := &sip.Package{}
	if err := sipPkg.DecodeFromBytes(appLayer.LayerContents()); err != nil {
		return
	}

	// 构造SIP日志信息
	logSip := fmt.Sprintf("%s\t%s\t%s.%d",
		sipPkg.GetCallID(),
		sipPkg.Method,
		sipPkg.ResponseStatus,
		sipPkg.ResponseCode)

	// 只处理出站流量（本机发出的响应）
	if direction == DirectionIn {
		return
	}

	// 检查目标IP的地理位置
	if !a.checkGeoIP(ip.DstIP.String(), logBase, logSip) {
		return
	}

	// 检查是否触发封禁规则
	a.checkBanRules(ip.DstIP.String(), sipPkg.ResponseCode, logBase, logSip)
}

// getDirection 判断数据包的流量方向
// 参数:
//   ip - IPv4层数据
// 返回:
//   string - 流量方向（IN/OUT）
func (a *Analyzer) getDirection(ip *layers.IPv4) string {
	if a.deviceIP == ip.SrcIP.String() {
		return DirectionOut
	} else if a.deviceIP == ip.DstIP.String() {
		return DirectionIn
	}
	return ""
}

// extractPorts 从数据包中提取源端口和目标端口
// 参数:
//   packet - 网络数据包
// 返回:
//   uint16 - 源端口号
//   uint16 - 目标端口号
func (a *Analyzer) extractPorts(packet gopacket.Packet) (uint16, uint16) {
	switch a.protocol {
	case "tcp":
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			return 0, 0
		}
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return 0, 0
		}
		return uint16(tcp.SrcPort), uint16(tcp.DstPort)
	case "udp":
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return 0, 0
		}
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return 0, 0
		}
		return uint16(udp.SrcPort), uint16(udp.DstPort)
	}
	return 0, 0
}

// checkGeoIP 检查IP地理位置，非中国IP直接封禁
// 参数:
//   ip - 要检查的IP地址
//   logBase - 基础日志信息
//   logSip - SIP日志信息
// 返回:
//   bool - true表示通过检查，false表示已封禁
func (a *Analyzer) checkGeoIP(ip, logBase, logSip string) bool {
	if a.geoChecker == nil {
		return true
	}

	isChina, countryName := a.geoChecker.IsChina(ip)
	if !isChina {
		// 非中国IP，记录并封禁
		color.Red(fmt.Sprintf("BAN___ %s\t%s\t%s\n", logBase, logSip, countryName))
		if err := a.firewall.Ban(ip); err != nil {
			fmt.Printf("BAN IP ERROR %s: %s\n", ip, err)
		} else {
			fmt.Printf("BAN IP SUCCESS %s\n", ip)
		}
		return false
	}
	return true
}

// checkBanRules 检查是否触发基于响应码的封禁规则
// 通过缓存记录IP在时间窗口内的请求次数，超过阈值则封禁
// 参数:
//   ip - 要检查的IP地址
//   responseCode - SIP响应状态码
//   logBase - 基础日志信息
//   logSip - SIP日志信息
func (a *Analyzer) checkBanRules(ip string, responseCode int, logBase, logSip string) {
	rule := a.banRuleCode[responseCode]
	if rule == nil {
		// 该响应码没有对应的封禁规则
		return
	}

	// 使用"IP.响应码"作为缓存键
	key := fmt.Sprintf("%s.%d", ip, responseCode)
	incrementInt := 0

	if _, exists := a.cache.Get(key); exists {
		// 缓存已存在，增加计数
		incrementInt, _ = a.cache.IncrementInt(key, 1)
	} else {
		// 首次记录，设置过期时间为规则的时间窗口
		if err := a.cache.Add(key, 1, time.Duration(rule.FindTime)*time.Second); err != nil {
			fmt.Printf("ERROR SET CACHE %s\t%s: %s\n", logBase, key, err)
		} else {
			fmt.Printf("SET CACHE START %s\t%s %d\n", logBase, key, rule.FindTime)
		}
	}

	logRule := fmt.Sprintf("Rule:%d-%d Key:%s Times:%d",
		rule.FindTime, rule.MaxRetry, key, incrementInt)

	if incrementInt > rule.MaxRetry {
		// 超过最大重试次数，标记为需要封禁
		color.Red(fmt.Sprintf("BAN___ %s\t%s\t%s\n", logBase, logSip, logRule))
	} else {
		// 正常流量
		color.Blue(fmt.Sprintf("Normal %s\t%s\t%s\n", logBase, logSip, logRule))
	}
}
