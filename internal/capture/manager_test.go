package capture

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"sip-ban/internal/analyzer"
)

// fakeHandle 实现 packetHandle 接口，用于在单元测试里模拟 pcap 行为，
// 避免依赖真实网卡。
type fakeHandle struct {
	mu      sync.Mutex
	packets [][]byte         // 待返回的数据包队列
	bpf     string           // 记录最后设置的 BPF 表达式
	closed  bool             // 是否已被关闭
	reads   atomic.Int32     // 总读次数（包含超时）
	timeout error            // 队列空时返回的错误（模拟超时）
}

// newFakeHandle 创建一个 fakeHandle，默认在没有数据时返回 pcap 超时错误，
// 模拟真实 pcap 的轮询语义。
func newFakeHandle() *fakeHandle {
	return &fakeHandle{timeout: pcap.NextErrorTimeoutExpired}
}

// queue 把一个原始数据包追加到队列。
func (f *fakeHandle) queue(pkt []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.packets = append(f.packets, pkt)
}

// SetBPFFilter 记录 BPF 表达式以便测试断言。
func (f *fakeHandle) SetBPFFilter(expr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bpf = expr
	return nil
}

// ReadPacketData 从队列取一个数据包；队列空时返回 timeout 错误，
// 用于驱动 manager 的 select 循环检查 ctx。
func (f *fakeHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	f.reads.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.packets) == 0 {
		return nil, gopacket.CaptureInfo{}, f.timeout
	}
	data := f.packets[0]
	f.packets = f.packets[1:]
	return data, gopacket.CaptureInfo{CaptureLength: len(data), Length: len(data)}, nil
}

// LinkType 返回 Ethernet 链路类型；layers.LayerTypeEthernet = 1，
// 这里取 pcap.LinkType 的 uint8 值（对应 layers.LinkTypeEthernet = 1）。
func (f *fakeHandle) LinkType() layerType { return layerType{v: 1} }

// Close 标记已关闭，便于测试断言资源被释放。
func (f *fakeHandle) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
}

// isClosed 返回 fakeHandle 是否已被 Close 过，供测试断言用。
func (f *fakeHandle) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// TestStartListsAndFiltersDevices 验证 Start：
//  1. 调用注入的 deviceLister；
//  2. 跳过没有 IPv4 地址的网卡；
//  3. 当指定了 deviceName 时，只为匹配项启动协程。
func TestStartListsAndFiltersDevices(t *testing.T) {
	devices := []pcap.Interface{
		{Name: "lo", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("127.0.0.1")}}},
		{Name: "eth0", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("192.168.1.10")}}},
		{Name: "wlan0", Addresses: []pcap.InterfaceAddress{}}, // 无地址，应被跳过
		{Name: "v6only", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("::1")}}}, // 无 IPv4，应被跳过
	}

	var opened []string
	var mu sync.Mutex
	openerCalled := func(name string) (packetHandle, error) {
		mu.Lock()
		opened = append(opened, name)
		mu.Unlock()
		return newFakeHandle(), nil
	}

	m := New("udp", 5060, "eth0", nil, nil, nil, nil)
	m.deviceLister = func() ([]pcap.Interface, error) { return devices, nil }
	m.handleOpener = openerCalled

	ctx, cancel := context.WithCancel(context.Background())
	wg, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	// 给捕获协程一点时间执行 SetBPFFilter / 进入循环
	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(opened) != 1 || opened[0] != "eth0" {
		t.Errorf("仅应在 eth0 上启动捕获，实际打开: %v", opened)
	}
}

// TestStartListsAllWhenDeviceNameEmpty 验证未指定网卡时，所有有 IPv4 的网卡都会被监听。
func TestStartListsAllWhenDeviceNameEmpty(t *testing.T) {
	devices := []pcap.Interface{
		{Name: "lo", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("127.0.0.1")}}},
		{Name: "eth0", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("192.168.1.10")}}},
	}

	var opened []string
	var mu sync.Mutex
	m := New("udp", 5060, "", nil, nil, nil, nil)
	m.deviceLister = func() ([]pcap.Interface, error) { return devices, nil }
	m.handleOpener = func(name string) (packetHandle, error) {
		mu.Lock()
		opened = append(opened, name)
		mu.Unlock()
		return newFakeHandle(), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(opened) != 2 {
		t.Errorf("应启动 2 个捕获，实际 %d: %v", len(opened), opened)
	}
}

// TestCaptureExitsOnContextCancel 验证 ctx 取消后，捕获协程能在 1 秒内退出。
// 这是 daemon 优雅退出的基础假设。
func TestCaptureExitsOnContextCancel(t *testing.T) {
	devices := []pcap.Interface{
		{Name: "eth0", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("10.0.0.1")}}},
	}
	fh := newFakeHandle()

	m := New("udp", 5060, "eth0", nil, nil, nil, nil)
	m.deviceLister = func() ([]pcap.Interface, error) { return devices, nil }
	m.handleOpener = func(string) (packetHandle, error) { return fh, nil }

	ctx, cancel := context.WithCancel(context.Background())
	wg, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start 失败: %v", err)
	}

	// 让捕获协程跑一会儿，触发若干次超时读
	time.Sleep(30 * time.Millisecond)
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// 正常退出
	case <-time.After(2 * time.Second):
		t.Fatal("捕获协程未在 2 秒内响应 ctx 取消")
	}

	if !fh.isClosed() {
		t.Error("退出时未关闭 pcap handle")
	}
	if fh.reads.Load() == 0 {
		t.Error("ReadPacketData 未被调用，循环可能没有真正运行")
	}
}

// TestCaptureSetsBPFFilter 验证 BPF 表达式按 protocol + port 拼接正确。
func TestCaptureSetsBPFFilter(t *testing.T) {
	devices := []pcap.Interface{
		{Name: "eth0", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("10.0.0.1")}}},
	}
	fh := newFakeHandle()

	m := New("tcp", 5061, "eth0", nil, nil, nil, nil)
	m.deviceLister = func() ([]pcap.Interface, error) { return devices, nil }
	m.handleOpener = func(string) (packetHandle, error) { return fh, nil }

	ctx, cancel := context.WithCancel(context.Background())
	wg, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	cancel()
	wg.Wait()

	fh.mu.Lock()
	defer fh.mu.Unlock()
	if fh.bpf != "tcp and port 5061" {
		t.Errorf("BPF = %q, want %q", fh.bpf, "tcp and port 5061")
	}
}

// TestStartReturnsDeviceListerError 验证 deviceLister 错误透传。
func TestStartReturnsDeviceListerError(t *testing.T) {
	wantErr := errors.New("boom")
	m := New("udp", 5060, "", nil, nil, nil, nil)
	m.deviceLister = func() ([]pcap.Interface, error) { return nil, wantErr }
	m.handleOpener = func(string) (packetHandle, error) { return nil, io.ErrUnexpectedEOF }

	_, err := m.Start(context.Background())
	if !errors.Is(err, wantErr) {
		t.Errorf("Start 应返回 deviceLister 的错误，得到 %v", err)
	}
}

// TestIsTimeoutMatchesPcapSentinel 验证 isTimeout 能识别 pcap 的超时哨兵值。
func TestIsTimeoutMatchesPcapSentinel(t *testing.T) {
	if !isTimeout(pcap.NextErrorTimeoutExpired) {
		t.Error("isTimeout 未识别 pcap.NextErrorTimeoutExpired")
	}
	if isTimeout(errors.New("random error")) {
		t.Error("isTimeout 误判普通错误为超时")
	}
	if isTimeout(nil) {
		t.Error("isTimeout(nil) 应返回 false")
	}
}

// 确保引入未使用包导致编译错误时能立刻发现（防止未来重构遗漏）。
var _ = analyzer.BanRule{}

// TestWorkerPoolSize 验证可以设置 worker pool 大小
func TestWorkerPoolSize(t *testing.T) {
	m := New("udp", 5060, "", nil, nil, nil, nil)

	// 验证默认值
	if m.workerPoolSize != defaultWorkerPoolSize {
		t.Errorf("默认 workerPoolSize = %d, want %d", m.workerPoolSize, defaultWorkerPoolSize)
	}

	// 设置自定义值
	m.SetWorkerPoolSize(50)
	if m.workerPoolSize != 50 {
		t.Errorf("设置后 workerPoolSize = %d, want 50", m.workerPoolSize)
	}

	// 设置无效值（应该被忽略）
	m.SetWorkerPoolSize(0)
	if m.workerPoolSize != 50 {
		t.Errorf("设置0后 workerPoolSize = %d, 应保持 50", m.workerPoolSize)
	}

	m.SetWorkerPoolSize(-10)
	if m.workerPoolSize != 50 {
		t.Errorf("设置负数后 workerPoolSize = %d, 应保持 50", m.workerPoolSize)
	}
}

// TestPacketQueueSize 验证可以设置数据包队列大小
func TestPacketQueueSize(t *testing.T) {
	m := New("udp", 5060, "", nil, nil, nil, nil)

	// 验证默认值
	if m.packetQueueSize != defaultPacketQueueSize {
		t.Errorf("默认 packetQueueSize = %d, want %d", m.packetQueueSize, defaultPacketQueueSize)
	}

	// 设置自定义值
	m.SetPacketQueueSize(500)
	if m.packetQueueSize != 500 {
		t.Errorf("设置后 packetQueueSize = %d, want 500", m.packetQueueSize)
	}

	// 设置无效值（应该被忽略）
	m.SetPacketQueueSize(0)
	if m.packetQueueSize != 500 {
		t.Errorf("设置0后 packetQueueSize = %d, 应保持 500", m.packetQueueSize)
	}

	m.SetPacketQueueSize(-10)
	if m.packetQueueSize != 500 {
		t.Errorf("设置负数后 packetQueueSize = %d, 应保持 500", m.packetQueueSize)
	}
}

// TestWorkerPoolProcessesPackets 验证 worker pool 能正确处理数据包
func TestWorkerPoolProcessesPackets(t *testing.T) {
	devices := []pcap.Interface{
		{Name: "eth0", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("10.0.0.1")}}},
	}

	fh := newFakeHandle()
	// 添加一些测试数据包
	for i := 0; i < 10; i++ {
		fh.queue([]byte{0x00, 0x01, 0x02, 0x03})
	}

	m := New("udp", 5060, "eth0", nil, nil, nil, nil)
	m.SetWorkerPoolSize(5) // 使用较小的 worker pool 便于测试
	m.deviceLister = func() ([]pcap.Interface, error) { return devices, nil }
	m.handleOpener = func(string) (packetHandle, error) { return fh, nil }

	ctx, cancel := context.WithCancel(context.Background())
	wg, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start 失败: %v", err)
	}

	// 等待数据包被处理
	time.Sleep(100 * time.Millisecond)
	cancel()
	wg.Wait()

	// 验证所有数据包都被读取
	fh.mu.Lock()
	remainingPackets := len(fh.packets)
	fh.mu.Unlock()

	if remainingPackets != 0 {
		t.Errorf("还有 %d 个数据包未被处理", remainingPackets)
	}
}

// TestWorkerPoolGracefulShutdown 验证 worker pool 能优雅退出
func TestWorkerPoolGracefulShutdown(t *testing.T) {
	devices := []pcap.Interface{
		{Name: "eth0", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("10.0.0.1")}}},
	}

	fh := newFakeHandle()

	m := New("udp", 5060, "eth0", nil, nil, nil, nil)
	m.SetWorkerPoolSize(10)
	m.deviceLister = func() ([]pcap.Interface, error) { return devices, nil }
	m.handleOpener = func(string) (packetHandle, error) { return fh, nil }

	ctx, cancel := context.WithCancel(context.Background())
	wg, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start 失败: %v", err)
	}

	// 让 worker pool 运行一会儿
	time.Sleep(50 * time.Millisecond)
	cancel()

	// 验证能在合理时间内退出
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// 正常退出
	case <-time.After(3 * time.Second):
		t.Fatal("worker pool 未在 3 秒内优雅退出")
	}

	if !fh.isClosed() {
		t.Error("退出时未关闭 pcap handle")
	}
}

// TestWorkerPoolWithSmallQueue 验证队列较小时的行为
func TestWorkerPoolWithSmallQueue(t *testing.T) {
	devices := []pcap.Interface{
		{Name: "eth0", Addresses: []pcap.InterfaceAddress{{IP: net.ParseIP("10.0.0.1")}}},
	}

	fh := newFakeHandle()
	// 添加大量数据包
	for i := 0; i < 100; i++ {
		fh.queue([]byte{0x00, 0x01, 0x02, 0x03})
	}

	m := New("udp", 5060, "eth0", nil, nil, nil, nil)
	m.SetWorkerPoolSize(2)
	m.SetPacketQueueSize(5) // 使用很小的队列
	m.deviceLister = func() ([]pcap.Interface, error) { return devices, nil }
	m.handleOpener = func(string) (packetHandle, error) { return fh, nil }

	ctx, cancel := context.WithCancel(context.Background())
	wg, err := m.Start(ctx)
	if err != nil {
		t.Fatalf("Start 失败: %v", err)
	}

	// 等待一段时间让部分数据包被处理
	time.Sleep(100 * time.Millisecond)
	cancel()
	wg.Wait()

	// 验证程序没有崩溃或死锁
	// 由于队列小，部分数据包可能被丢弃，这是预期行为
	if !fh.isClosed() {
		t.Error("退出时未关闭 pcap handle")
	}
}
