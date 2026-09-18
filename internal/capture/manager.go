package capture

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"sip-ban/internal/analyzer"
)

type Manager struct {
	protocol   string
	filterPort int
	deviceName string
	mu         sync.RWMutex
	analyzers  map[string]*analyzer.Analyzer
}

func New(protocol string, filterPort int, deviceName string) *Manager {
	return &Manager{
		protocol:   strings.ToLower(strings.TrimSpace(protocol)),
		filterPort: filterPort,
		deviceName: deviceName,
		analyzers:  make(map[string]*analyzer.Analyzer),
	}
}

func (m *Manager) Start(wg *sync.WaitGroup) error {
	if m == nil {
		return fmt.Errorf("nil capture manager")
	}
	if wg == nil {
		return fmt.Errorf("nil wait group")
	}
	if m.protocol != "tcp" && m.protocol != "udp" {
		return fmt.Errorf("unsupported protocol %q", m.protocol)
	}
	if m.filterPort < 1 || m.filterPort > 65535 {
		return fmt.Errorf("invalid port %d", m.filterPort)
	}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	started := false
	for _, device := range devices {
		if len(device.Addresses) == 0 {
			continue
		}

		for _, address := range device.Addresses {
			if address.IP.To4() != nil {
				if m.deviceName != "" && device.Name != m.deviceName {
					break
				}
				wg.Add(1)
				go m.captureDevice(device.Name, address.IP.String(), wg)
				started = true
				break
			}
		}
	}
	if !started {
		return fmt.Errorf("没有找到符合条件的网卡")
	}
	return nil
}

func (m *Manager) captureDevice(deviceName, deviceIP string, wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Printf("开始捕获: %s %s %s %d\n", deviceName, deviceIP, m.protocol, m.filterPort)

	handle, err := pcap.OpenLive(deviceName, 65535, false, time.Second)
	if err != nil {
		fmt.Printf("打开网卡 %s 失败: %s\n", deviceName, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(fmt.Sprintf("%s and port %d", m.protocol, m.filterPort)); err != nil {
		fmt.Printf("设置网卡 %s 过滤器失败: %s\n", deviceName, err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	if m.protocol == "tcp" {
		m.mu.RLock()
		a := m.analyzers[deviceName]
		m.mu.RUnlock()
		assembler := analyzer.NewTCPAssembler(a)
		for packet := range packetSource.Packets() {
			assembler.Assemble(packet)
		}
		assembler.Flush()
		return
	}
	jobs := make(chan gopacket.Packet, 256)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for packet := range jobs {
				m.processPacket(deviceName, packet)
			}
		}()
	}
	for packet := range packetSource.Packets() {
		jobs <- packet
	}
	close(jobs)
	workers.Wait()
}

func (m *Manager) processPacket(deviceName string, packet gopacket.Packet) {
	m.mu.RLock()
	a := m.analyzers[deviceName]
	m.mu.RUnlock()
	if a != nil {
		a.AnalyzePacket(packet)
	}
}

func (m *Manager) SetAnalyzer(deviceName, deviceIP string, a *analyzer.Analyzer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.analyzers == nil {
		m.analyzers = make(map[string]*analyzer.Analyzer)
	}
	m.analyzers[deviceName] = a
}
