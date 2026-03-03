package capture

import (
	"fmt"
	"log"
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
}

func New(protocol string, filterPort int, deviceName string) *Manager {
	return &Manager{
		protocol:   protocol,
		filterPort: filterPort,
		deviceName: deviceName,
	}
}

func (m *Manager) Start(wg *sync.WaitGroup) error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

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
				break
			}
		}
	}
	return nil
}

func (m *Manager) captureDevice(deviceName, deviceIP string, wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Printf("开始捕获: %s %s %s %d\n", deviceName, deviceIP, m.protocol, m.filterPort)

	handle, err := pcap.OpenLive(deviceName, 1024, false, 1*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(fmt.Sprintf("%s and port %d", m.protocol, m.filterPort)); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		go m.processPacket(packet)
	}
}

func (m *Manager) processPacket(packet gopacket.Packet) {
	// This will be injected by the main application
}

func (m *Manager) SetAnalyzer(deviceName, deviceIP string, a *analyzer.Analyzer) {
	// Store analyzer for this device
}
