package main

import (
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/patrickmn/go-cache"

	"sip-ban/pkg/iptables"
)

var (
	variableCache *cache.Cache
	deviceName    = ""
	filterPort    = 5060
	banRule       map[string]*BanRule
)

type BanRule struct {
	FindTime int
	MaxRetry int
}

func main() {
	wg := &sync.WaitGroup{}

	banRule = map[string]*BanRule{}
	banRule[layers.SIPMethodInvite.String()] = &BanRule{
		FindTime: 120,
		MaxRetry: 30,
	}
	banRule[layers.SIPMethodRegister.String()] = &BanRule{
		FindTime: 120,
		MaxRetry: 40,
	}

	flag.StringVar(&deviceName, "i", "", "网卡")
	flag.IntVar(&filterPort, "p", 5060, "端口号")
	flag.IntVar(&banRule[layers.SIPMethodRegister.String()].FindTime, "rt", 120, "Register-FindTime")
	flag.IntVar(&banRule[layers.SIPMethodRegister.String()].MaxRetry, "rn", 40, "Register-MaxRetry")
	flag.IntVar(&banRule[layers.SIPMethodInvite.String()].FindTime, "it", 120, "Invite-FindTime")
	flag.IntVar(&banRule[layers.SIPMethodInvite.String()].MaxRetry, "in", 30, "Invite-MaxRetry")

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
	fmt.Println(fmt.Sprintf("开始捕获:%s %s", deviceName, deviceIp))
	var handle *pcap.Handle

	var err error
	handle, err = pcap.OpenLive(deviceName, 1024, false, 1*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(fmt.Sprintf("port %d", filterPort))
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		go analysisPacket(deviceName, deviceIp, packet)
	}
}

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
		direction = "in"
	} else if deviceIp == ip.DstIP.String() {
		direction = "out"
	} else {
		direction = ""
	}

	var srcPort uint16
	var dstPort uint16

	switch ip.Protocol {
	case layers.IPProtocolTCP:
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
	case layers.IPProtocolUDP:
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

	sipLayer := packet.Layer(layers.LayerTypeSIP)
	if sipLayer == nil {
		return
	}
	sip, ok := sipLayer.(*layers.SIP)
	if !ok {
		return
	}

	fmt.Printf("%s %s(%s) %s %s-%s From %s:%d To %s:%d %s %d %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		deviceName,
		deviceIp,
		direction,
		ip.Protocol,
		sip.Method,
		ip.SrcIP, srcPort,
		ip.DstIP, dstPort,
		sip.GetCallID(),
		sip.ResponseCode,
		sip.ResponseStatus,
	)

	key := fmt.Sprintf("%s-%s:%d", sip.Method, ip.SrcIP, srcPort)

	//获取规则
	rule := banRule[sip.Method.String()]
	if rule == nil {
		return
	}
	//尝试增加次数
	incrementInt, _ := variableCache.IncrementInt(key, 1)
	if incrementInt <= 0 {
		variableCache.Set(key, 1, time.Duration(rule.FindTime)*time.Millisecond)
	} else if incrementInt > rule.MaxRetry {
		//todo::封禁
		//ban(ip.SrcIP.String())
	}
}

func ban(ip string) {
	ipt, err := iptables.New()
	if err != nil {
		return
	}
	rule := fmt.Sprintf("-s %s -p all --dport %s -j REJECT", ip, filterPort)
	_ = ipt.Append("filter", "INPUT", rule)
}
