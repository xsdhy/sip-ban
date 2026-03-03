// Package main SIP-Ban主程序入口
// 用于监控SIP流量并自动封禁恶意IP
package main

import (
	"fmt"
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"sip-ban/internal/analyzer"
	"sip-ban/internal/config"
	"sip-ban/internal/firewall"
	"sip-ban/internal/geoip"
	"sip-ban/internal/sip"
)

// main 主函数，程序入口点
func main() {
	// 加载配置
	cfg := config.Load()

	// 初始化防火墙管理器
	fw, err := firewall.New()
	if err != nil {
		fmt.Printf("警告: Iptables初始化失败: %s\n", err)
	}

	// 初始化IP地理位置检查器
	geoChecker, err := geoip.New(cfg.IPDBPath)
	if err != nil {
		fmt.Printf("警告: IP数据库加载失败: %s\n", err)
	}

	// 配置基于SIP方法的封禁规则
	banRules := map[string]*analyzer.BanRule{
		sip.MethodInvite.String(): {
			FindTime: cfg.InviteFindTime,
			MaxRetry: cfg.InviteMaxRetry,
		},
		sip.MethodRegister.String(): {
			FindTime: cfg.RegisterFindTime,
			MaxRetry: cfg.RegisterMaxRetry,
		},
	}

	// 配置基于响应码的封禁规则
	// 407: Proxy Authentication Required
	// 403: Forbidden
	// 401: Unauthorized
	banRuleCodes := map[int]*analyzer.BanRule{
		407: banRules[sip.MethodInvite.String()],
		403: banRules[sip.MethodInvite.String()],
		401: banRules[sip.MethodRegister.String()],
	}

	// 启动网络包捕获
	wg := &sync.WaitGroup{}
	startCapture(cfg, geoChecker, fw, banRules, banRuleCodes, wg)
	wg.Wait()
}

// startCapture 扫描网卡并启动流量捕获
// 参数:
//   cfg - 配置对象
//   geoChecker - IP地理位置检查器
//   fw - 防火墙管理器
//   banRules - 基于SIP方法的封禁规则
//   banRuleCodes - 基于响应码的封禁规则
//   wg - 等待组，用于协程同步
func startCapture(cfg *config.Config, geoChecker *geoip.Checker, fw *firewall.Manager, banRules map[string]*analyzer.BanRule, banRuleCodes map[int]*analyzer.BanRule, wg *sync.WaitGroup) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// 遍历所有网卡设备
	for _, device := range devices {
		if len(device.Addresses) == 0 {
			continue
		}

		// 查找IPv4地址
		for _, address := range device.Addresses {
			if address.IP.To4() != nil {
				// 如果指定了网卡名称，则只处理该网卡
				if cfg.DeviceName != "" && device.Name != cfg.DeviceName {
					break
				}
				// 为每个网卡启动一个协程进行捕获
				wg.Add(1)
				go captureDevice(cfg, device.Name, address.IP.String(), geoChecker, fw, banRules, banRuleCodes, wg)
				break
			}
		}
	}
}

// captureDevice 在指定网卡上捕获和分析流量
// 参数:
//   cfg - 配置对象
//   deviceName - 网卡名称
//   deviceIP - 网卡IP地址
//   geoChecker - IP地理位置检查器
//   fw - 防火墙管理器
//   banRules - 基于SIP方法的封禁规则
//   banRuleCodes - 基于响应码的封禁规则
//   wg - 等待组
func captureDevice(cfg *config.Config, deviceName, deviceIP string, geoChecker *geoip.Checker, fw *firewall.Manager, banRules map[string]*analyzer.BanRule, banRuleCodes map[int]*analyzer.BanRule, wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Printf("开始捕获: %s %s %s %d\n", deviceName, deviceIP, cfg.Protocol, cfg.FilterPort)

	// 打开网卡进行实时捕获
	// 参数: 设备名, 快照长度, 混杂模式, 超时时间
	handle, err := pcap.OpenLive(deviceName, 1024, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// 设置BPF过滤器，只捕获指定协议和端口的流量
	if err := handle.SetBPFFilter(fmt.Sprintf("%s and port %d", cfg.Protocol, cfg.FilterPort)); err != nil {
		log.Fatal(err)
	}

	// 创建流量分析器
	a := analyzer.New(cfg.Protocol, deviceIP, deviceName, geoChecker, fw, banRules, banRuleCodes)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// 持续处理捕获到的数据包
	for packet := range packetSource.Packets() {
		// 每个数据包在独立的协程中分析，提高并发性能
		go a.AnalyzePacket(packet)
	}
}
