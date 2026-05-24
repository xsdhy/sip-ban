package capture

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// realHandle 把 *pcap.Handle 适配到 packetHandle 接口。
type realHandle struct {
	h *pcap.Handle
}

// SetBPFFilter 设置 BPF 过滤表达式。
func (r *realHandle) SetBPFFilter(expr string) error { return r.h.SetBPFFilter(expr) }

// ReadPacketData 读取一个原始数据包。
func (r *realHandle) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return r.h.ReadPacketData()
}

// LinkType 返回链路层类型。
func (r *realHandle) LinkType() layerType { return layerType{v: uint8(r.h.LinkType())} }

// Close 关闭句柄。
func (r *realHandle) Close() { r.h.Close() }

// defaultOpenLive 是 handleOpener 的默认实现，调用真实的 pcap.OpenLive。
func defaultOpenLive(deviceName string) (packetHandle, error) {
	h, err := pcap.OpenLive(deviceName, pcapSnapLen, false, pcapReadTimeout)
	if err != nil {
		return nil, err
	}
	return &realHandle{h: h}, nil
}

// decoderFor 把内部 layerType 还原为 gopacket 的 Decoder。
func decoderFor(lt layerType) gopacket.Decoder {
	return layers.LinkType(lt.v)
}

// isTimeout 判断错误是否为 pcap 读超时。
// pcap 在读超时返回的 error 是 pcap.NextErrorTimeoutExpired，
// 不同版本下还可能直接是字符串 "Read Error" 之类，做最宽容的匹配。
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, pcap.NextErrorTimeoutExpired) {
		return true
	}
	// 部分平台/版本不导出哨兵值，回退到字符串匹配。
	return err.Error() == pcap.NextErrorTimeoutExpired.Error()
}
