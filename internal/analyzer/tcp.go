package analyzer

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// TCPAssembler reassembles SIP over TCP before handing complete messages to an
// Analyzer.  SIP is a stream protocol, so packet-by-packet parsing loses
// messages whenever TCP segmentation or coalescing occurs.
type TCPAssembler struct {
	analyzer  *Analyzer
	assembler *tcpassembly.Assembler
}

func NewTCPAssembler(a *Analyzer) *TCPAssembler {
	factory := &tcpStreamFactory{analyzer: a}
	pool := tcpassembly.NewStreamPool(factory)
	return &TCPAssembler{analyzer: a, assembler: tcpassembly.NewAssembler(pool)}
}

func (a *TCPAssembler) Assemble(packet gopacket.Packet) {
	if a == nil || a.assembler == nil {
		return
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	ip, ipOK := ipLayer.(*layers.IPv4)
	tcp, tcpOK := tcpLayer.(*layers.TCP)
	if !ipOK || !tcpOK {
		return
	}
	a.assembler.Assemble(ip.NetworkFlow(), tcp)
}

func (a *TCPAssembler) Flush() {
	if a != nil && a.assembler != nil {
		a.assembler.FlushAll()
	}
}

type tcpStreamFactory struct{ analyzer *Analyzer }

func (f *tcpStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	src := netFlow.Src().String()
	dst := netFlow.Dst().String()
	var srcPort, dstPort uint16
	if raw := tcpFlow.Src().Raw(); len(raw) >= 2 {
		srcPort = binary.BigEndian.Uint16(raw[:2])
	}
	if raw := tcpFlow.Dst().Raw(); len(raw) >= 2 {
		dstPort = binary.BigEndian.Uint16(raw[:2])
	}
	return &tcpStream{analyzer: f.analyzer, srcIP: src, dstIP: dst, srcPort: srcPort, dstPort: dstPort}
}

type tcpStream struct {
	analyzer         *Analyzer
	srcIP, dstIP     string
	srcPort, dstPort uint16
	buffer           []byte
}

func (s *tcpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, r := range reassemblies {
		if r.Skip != 0 {
			s.buffer = nil
		}
		s.buffer = append(s.buffer, r.Bytes...)
	}
	s.consume()
}

func (s *tcpStream) ReassemblyComplete() { s.consume() }

func (s *tcpStream) consume() {
	for len(s.buffer) > 0 {
		end := bytes.Index(s.buffer, []byte("\r\n\r\n"))
		separatorLen := 4
		if end < 0 {
			end = bytes.Index(s.buffer, []byte("\n\n"))
			separatorLen = 2
		}
		if end < 0 {
			return
		}
		headerEnd := end + separatorLen
		contentLength := 0
		for _, line := range strings.Split(string(s.buffer[:end]), "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
			if len(parts) == 2 && (strings.EqualFold(strings.TrimSpace(parts[0]), "Content-Length") || strings.EqualFold(strings.TrimSpace(parts[0]), "l")) {
				contentLength, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		}
		total := headerEnd + contentLength
		if len(s.buffer) < total {
			return
		}
		if s.analyzer != nil {
			s.analyzer.AnalyzeMessage(s.srcIP, s.dstIP, s.srcPort, s.dstPort, s.buffer[:total])
		}
		s.buffer = s.buffer[total:]
	}
}
