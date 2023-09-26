package main

import (
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/patrickmn/go-cache"

	"sip-ban/pkg/iptables"
)

var (
	variableCache *cache.Cache
	deviceName    = ""
	protocol      = "udp"
	filterPort    = 5060
	banRule       map[string]*BanRule
	banRuleCode   map[int]*BanRule

	ipt *iptables.IPTables
)

const DIRECTION_IN = "IN"
const DIRECTION_OUT = "OUT"

type BanRule struct {
	FindTime int
	MaxRetry int
}

func main() {
	var err error
	//初始化Iptables
	ipt, err = iptables.New()
	if err != nil {
		fmt.Println("启动错误Iptables:", err.Error())
		//return
	}

	wg := &sync.WaitGroup{}

	banRule = map[string]*BanRule{}
	banRuleCode = map[int]*BanRule{}

	//如果120s内发起过30次
	banRule[layers.SIPMethodInvite.String()] = &BanRule{
		FindTime: 60,
		MaxRetry: 10,
	}
	banRule[layers.SIPMethodRegister.String()] = &BanRule{
		FindTime: 120,
		MaxRetry: 40,
	}
	banRuleCode[407] = banRule[layers.SIPMethodInvite.String()]
	banRuleCode[403] = banRule[layers.SIPMethodInvite.String()]
	banRuleCode[401] = banRule[layers.SIPMethodRegister.String()]

	flag.StringVar(&deviceName, "i", "", "网卡")
	flag.StringVar(&protocol, "p", "udp", "协议")
	flag.IntVar(&filterPort, "P", 5060, "端口号")

	flag.IntVar(&banRule[layers.SIPMethodRegister.String()].FindTime, "rt", 120, "Register-FindTime")
	flag.IntVar(&banRule[layers.SIPMethodRegister.String()].MaxRetry, "rn", 40, "Register-MaxRetry")
	flag.IntVar(&banRule[layers.SIPMethodInvite.String()].FindTime, "it", 120, "Invite-FindTime")
	flag.IntVar(&banRule[layers.SIPMethodInvite.String()].MaxRetry, "in", 30, "Invite-MaxRetry")
	flag.Parse()
	//初始化缓存
	variableCache = cache.New(5*time.Minute, 10*time.Minute)

	findAllDevice(wg)

	wg.Wait()
}
func findAllDevice(wg *sync.WaitGroup) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, device := range devices {
		if len(device.Addresses) <= 0 {
			continue
		}
		for _, address := range device.Addresses {
			//只查找有ipv4的网卡
			if address.IP.To4() != nil {
				//如果指定了要捕获的网卡则
				if deviceName != "" && device.Name != deviceName {
					break
				}
				wg.Add(1)

				go captureDevice(device.Name, address.IP.String())
				break
			}
		}
	}
}

func captureDevice(deviceName string, deviceIp string) {
	fmt.Println(fmt.Sprintf("开始捕获:%s %s %s %d", deviceName, deviceIp, protocol, filterPort))
	var handle *pcap.Handle

	var err error
	handle, err = pcap.OpenLive(deviceName, 1024, false, 1*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("%s and port %d", protocol, filterPort))
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		go analysisPacket(deviceName, deviceIp, packet)
	}
}

// analysisPacket 分析一个具体的包
func analysisPacket(deviceName string, deviceIp string, packet gopacket.Packet) {
	var direction string
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	ip, ipOk := ipLayer.(*layers.IPv4)
	if !ipOk {
		return
	}
	if deviceIp == ip.SrcIP.String() {
		direction = DIRECTION_OUT
	} else if deviceIp == ip.DstIP.String() {
		direction = DIRECTION_IN
	} else {
		direction = ""
	}

	var srcPort uint16
	var dstPort uint16

	switch protocol {
	case "tcp":
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			return
		}

		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return
		}
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
	case "udp":
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return
		}
		udp, ok := udpLayer.(*layers.UDP)
		if !ok {
			return
		}
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
	}
	logBase := fmt.Sprintf("%s %s\t%s-%s %s:%d->%s:%d",
		time.Now().Format("2006-01-02 15:04:05"),
		deviceName,
		ip.Protocol,
		direction,
		ip.SrcIP, srcPort,
		ip.DstIP, dstPort)

	//应用层
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return
	}
	sip := &SipPackage{}
	err := sip.DecodeFromBytes(appLayer.LayerContents())
	if err != nil {
		//fmt.Printf("NotSip %s \n", logBase)
		return
	}
	logSip := fmt.Sprintf("%s\t%s\t%s.%d",
		sip.GetCallID(),
		sip.Method,
		sip.ResponseStatus,
		sip.ResponseCode,
	)

	if direction == DIRECTION_IN {
		//fmt.Printf("IGNORE %s\t%s\n", logBase, logSip)
		return
	}

	key := fmt.Sprintf("%s.%d", ip.DstIP, sip.ResponseCode)

	//获取规则
	rule := banRuleCode[sip.ResponseCode]
	if rule == nil {
		//fmt.Printf("NoRule %s\t%s \n", logBase, logSip)
		return
	}

	incrementInt := 0
	_, b := variableCache.Get(key)
	if b {
		incrementInt, _ = variableCache.IncrementInt(key, 1)
	} else {
		err = variableCache.Add(key, 1, time.Duration(rule.FindTime)*time.Second)
		if err != nil {
			fmt.Printf("ERROR SET CACHE %s\t%s%s\n", logBase, key, err.Error())
		} else {
			fmt.Printf("SET CACHE START %s\t%s %d\n", logBase, key, rule.FindTime)
		}
	}

	logRule := fmt.Sprintf("Rule:%d-%d Key:%s Times:%d",
		rule.FindTime,
		rule.MaxRetry,
		key,
		incrementInt,
	)

	if incrementInt > rule.MaxRetry {
		color.Red(fmt.Sprintf("BAN___ %s\t%s\t%s \n", logBase, logSip, logRule))
		//ban(ip.SrcIP.String())
	} else {
		color.Blue(fmt.Sprintf("Normal %s\t%s\t%s \n", logBase, logSip, logRule))
	}

}

func ban(ip string) {
	if ipt == nil {
		return
	}
	//iptables -I INPUT -s 66.94.127.156 -j DROP
	rule := fmt.Sprintf("-s %s -p %s --dport %d -j DROP", ip, protocol, filterPort)
	exists, err := ipt.Exists("filter", "INPUT", rule)
	if err != nil || exists {
		fmt.Println(rule, err.Error(), exists)
		return
	}
	err = ipt.Append("filter", "INPUT", rule)
	fmt.Println(rule, err.Error())
}
