// Package capture 提供网络流量捕获能力。
//
// 设计要点：
//   - Manager 在内部管理所有需要监听的网卡，并按需为每个网卡启动一个独立的捕获协程。
//   - 所有捕获协程的生命周期由调用方传入的 context.Context 控制。
//     当 ctx 被取消时，捕获协程会在最多 1 秒内（一个 pcap 读超时周期）完成退出。
//   - Manager 在内部组装 analyzer.Analyzer 所需的所有依赖，让 cmd/sip-ban
//     的入口代码不再关心 analyzer / firewall / geoip 之间的细节。
package capture

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"sip-ban/internal/analyzer"
	"sip-ban/internal/firewall"
	"sip-ban/internal/geoip"
)

// pcapReadTimeout 是 pcap.OpenLive 的读超时。
// 选 1 秒是为了让 ctx 取消信号能在 1 秒内被 select 感知到，
// 同时也不会让捕获循环空转过于频繁。
const pcapReadTimeout = 1 * time.Second

// pcapSnapLen 是 pcap 抓包的最大长度，与旧实现保持一致。
const pcapSnapLen = 1024

// defaultWorkerPoolSize 是默认的 worker pool 大小
// 每个网卡使用独立的 worker pool，避免高流量场景下创建无限 goroutine
const defaultWorkerPoolSize = 100

// defaultPacketQueueSize 是数据包队列的默认缓冲大小
// 当 worker 处理不过来时，队列会缓冲一定数量的数据包
const defaultPacketQueueSize = 1000

// Manager 负责管理多网卡的流量捕获。
type Manager struct {
	protocol     string                       // 网络协议（tcp / udp）
	filterPort   int                          // 监听端口
	deviceName   string                       // 指定网卡名，为空则监听所有 IPv4 网卡
	geoChecker   *geoip.Checker               // IP 地理位置检查器（允许为 nil）
	firewall     *firewall.Manager            // 防火墙管理器（允许为 nil）
	banRules     map[string]*analyzer.BanRule // 基于 SIP 方法的封禁规则
	banRuleCodes map[int]*analyzer.BanRule    // 基于响应码的封禁规则

	// worker pool 配置
	workerPoolSize   int // 每个网卡的 worker 数量
	packetQueueSize  int // 数据包队列缓冲大小

	// deviceLister 用于发现可用网卡。默认指向 pcap.FindAllDevs；
	// 测试时可以覆盖以避免依赖真实网卡。
	deviceLister func() ([]pcap.Interface, error)
	// handleOpener 用于打开网卡句柄。测试时可以替换为 mock，
	// 返回的对象只需实现 packetHandle 接口。
	handleOpener func(deviceName string) (packetHandle, error)
}

// packetHandle 抽象出 pcap.Handle 在本包内用到的最小能力，方便测试 mock。
type packetHandle interface {
	SetBPFFilter(expr string) error
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layerType
	Close()
}

// layerType 是 pcap.Handle.LinkType 返回值的最小封装。
// 通过 newLayerType 间接绑定到 gopacket/layers，从而避免本文件直接 import layers
// 仅是为了减少耦合点；底层就是 layers.LinkType（uint8）。
type layerType struct {
	v uint8
}

// New 构造一个 Manager 实例，所有依赖通过参数注入。
//
// 参数：
//   - protocol：协议（tcp / udp）。
//   - filterPort：监听端口。
//   - deviceName：指定网卡（为空则监听全部 IPv4 网卡）。
//   - geoChecker：IP 地理位置检查器（允许 nil）。
//   - fw：防火墙管理器（允许 nil）。
//   - banRules / banRuleCodes：封禁规则。
func New(
	protocol string,
	filterPort int,
	deviceName string,
	geoChecker *geoip.Checker,
	fw *firewall.Manager,
	banRules map[string]*analyzer.BanRule,
	banRuleCodes map[int]*analyzer.BanRule,
) *Manager {
	m := &Manager{
		protocol:        protocol,
		filterPort:      filterPort,
		deviceName:      deviceName,
		geoChecker:      geoChecker,
		firewall:        fw,
		banRules:        banRules,
		banRuleCodes:    banRuleCodes,
		workerPoolSize:  defaultWorkerPoolSize,
		packetQueueSize: defaultPacketQueueSize,
	}
	m.deviceLister = pcap.FindAllDevs
	m.handleOpener = defaultOpenLive
	return m
}

// SetWorkerPoolSize 设置每个网卡的 worker pool 大小
// 必须在 Start 之前调用
func (m *Manager) SetWorkerPoolSize(size int) {
	if size > 0 {
		m.workerPoolSize = size
	}
}

// SetPacketQueueSize 设置数据包队列的缓冲大小
// 必须在 Start 之前调用
func (m *Manager) SetPacketQueueSize(size int) {
	if size > 0 {
		m.packetQueueSize = size
	}
}

// Start 在所有匹配的网卡上启动捕获协程。
//
// 行为：
//   - ctx 取消时，所有捕获协程会在大约 pcapReadTimeout 时间内退出。
//   - 调用方应 Wait 返回的 *sync.WaitGroup，确保所有协程干净退出。
//
// 返回：
//   - *sync.WaitGroup：跟踪所有内部捕获协程。
//   - error：列举网卡失败时返回。
func (m *Manager) Start(ctx context.Context) (*sync.WaitGroup, error) {
	devices, err := m.deviceLister()
	if err != nil {
		return nil, err
	}

	wg := &sync.WaitGroup{}
	for _, device := range devices {
		if len(device.Addresses) == 0 {
			continue
		}
		for _, address := range device.Addresses {
			if address.IP.To4() == nil {
				continue
			}
			if m.deviceName != "" && device.Name != m.deviceName {
				break
			}
			wg.Add(1)
			go m.captureDevice(ctx, device.Name, address.IP.String(), wg)
			break
		}
	}
	return wg, nil
}

// captureDevice 在单个网卡上循环读包并交给 analyzer 处理。
//
// 关键设计：
//   - 不使用 pcap.BlockForever，避免 ctx 取消时无法唤醒。
//   - 主循环以 select(ctx.Done(), default) + pcap 读超时为节奏。
//   - 使用 worker pool 模式限制并发 goroutine 数量，避免高流量场景下 OOM。
func (m *Manager) captureDevice(ctx context.Context, deviceName, deviceIP string, wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Printf("开始捕获: %s %s %s %d\n", deviceName, deviceIP, m.protocol, m.filterPort)

	handle, err := m.handleOpener(deviceName)
	if err != nil {
		fmt.Printf("打开网卡失败 %s: %s\n", deviceName, err)
		return
	}
	defer handle.Close()

	bpf := fmt.Sprintf("%s and port %d", m.protocol, m.filterPort)
	if err := handle.SetBPFFilter(bpf); err != nil {
		fmt.Printf("设置 BPF 过滤器失败 %s: %s\n", deviceName, err)
		return
	}

	a := analyzer.New(m.protocol, deviceIP, deviceName, m.geoChecker, m.firewall, m.banRules, m.banRuleCodes)

	// 创建数据包队列
	packetQueue := make(chan gopacket.Packet, m.packetQueueSize)

	// 启动 worker pool
	workerWg := &sync.WaitGroup{}
	for i := 0; i < m.workerPoolSize; i++ {
		workerWg.Add(1)
		go m.packetWorker(ctx, a, packetQueue, workerWg, deviceName, i)
	}

	// 主循环：读取数据包并发送到队列
	for {
		// 每轮循环先检查 ctx，保证退出迅速。
		select {
		case <-ctx.Done():
			fmt.Printf("停止捕获: %s\n", deviceName)
			close(packetQueue) // 关闭队列，通知 worker 退出
			workerWg.Wait()    // 等待所有 worker 完成
			return
		default:
		}

		data, _, err := handle.ReadPacketData()
		if err != nil {
			// 超时是正常的，用于轮询 ctx，继续下一轮。
			if isTimeout(err) {
				continue
			}
			// 其它错误：短暂 sleep 后继续，避免出错时狂打日志。
			fmt.Printf("读包错误 %s: %s\n", deviceName, err)
			select {
			case <-ctx.Done():
				close(packetQueue)
				workerWg.Wait()
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}

		// 解析数据包
		lt := handle.LinkType()
		packet := gopacket.NewPacket(data, decoderFor(lt), gopacket.NoCopy)

		// 尝试将数据包发送到队列，如果队列满了则丢弃
		// 这样可以避免在高流量场景下阻塞捕获循环
		select {
		case packetQueue <- packet:
			// 成功发送到队列
		default:
			// 队列已满，丢弃数据包
			// 在生产环境中可以添加计数器统计丢包数
		}
	}
}

// packetWorker 是 worker pool 中的工作协程
// 从队列中取出数据包并交给 analyzer 处理
func (m *Manager) packetWorker(ctx context.Context, a *analyzer.Analyzer, packetQueue <-chan gopacket.Packet, wg *sync.WaitGroup, deviceName string, workerID int) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			// context 取消，退出
			return
		case packet, ok := <-packetQueue:
			if !ok {
				// 队列已关闭，退出
				return
			}
			// 处理数据包
			a.AnalyzePacket(packet)
		}
	}
}
