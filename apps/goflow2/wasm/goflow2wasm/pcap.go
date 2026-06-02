package goflow2wasm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

type captureFormat int

const (
	captureFormatUnknown captureFormat = iota
	captureFormatPcap
	captureFormatPcapNG
)

const (
	packetInputTypeBytes = "bytes"
	packetInputTypeFlow  = "flow"
	syntheticFlowSrc     = "192.0.2.1:2055"
	syntheticFlowDst     = "192.0.2.2:9995"
)

func readCapture(input CaptureInput) ([]udpDatagram, RunStats, []string, error) {
	if len(input.Packets) > 0 {
		return readPacketInputs(input.Packets)
	}
	if input.Data == "" {
		return nil, RunStats{}, nil, fmt.Errorf("import a pcap or pcapng file first")
	}
	data, err := base64.StdEncoding.DecodeString(input.Data)
	if err != nil {
		return nil, RunStats{}, nil, fmt.Errorf("decode capture data: %w", err)
	}
	switch detectCaptureFormat(data) {
	case captureFormatPcap:
		return readPcap(data)
	case captureFormatPcapNG:
		return readPcapNG(data)
	}

	name := strings.ToLower(input.Name)
	if strings.HasSuffix(name, ".pcapng") {
		return readPcapNG(data)
	}
	if strings.HasSuffix(name, ".pcap") || strings.HasSuffix(name, ".cap") {
		return readPcap(data)
	}
	datagrams, stats, warnings, err := readPcap(data)
	if err == nil {
		return datagrams, stats, warnings, nil
	}
	datagrams, stats, warnings, ngErr := readPcapNG(data)
	if ngErr == nil {
		return datagrams, stats, warnings, nil
	}
	return nil, RunStats{}, nil, fmt.Errorf("open capture as pcap (%v) or pcapng (%v)", err, ngErr)
}

func InspectCaptureJSON(raw []byte) ([]byte, error) {
	var input CaptureInput
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, fmt.Errorf("decode capture request: %w", err)
	}
	result, err := InspectCapture(input)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encode capture inspection: %w", err)
	}
	return data, nil
}

func InspectCapture(input CaptureInput) (*CaptureInspectResult, error) {
	if input.Data == "" {
		return nil, fmt.Errorf("import a pcap or pcapng file first")
	}
	data, err := base64.StdEncoding.DecodeString(input.Data)
	if err != nil {
		return nil, fmt.Errorf("decode capture data: %w", err)
	}

	var packets []PacketInput
	var stats RunStats
	var warnings []string
	switch detectCaptureFormat(data) {
	case captureFormatPcap:
		packets, stats, warnings, err = inspectPcap(data, input.ImportType)
	case captureFormatPcapNG:
		packets, stats, warnings, err = inspectPcapNG(data, input.ImportType)
	default:
		name := strings.ToLower(input.Name)
		if strings.HasSuffix(name, ".pcapng") {
			packets, stats, warnings, err = inspectPcapNG(data, input.ImportType)
		} else {
			packets, stats, warnings, err = inspectPcap(data, input.ImportType)
			if err != nil {
				var ngErr error
				packets, stats, warnings, ngErr = inspectPcapNG(data, input.ImportType)
				if ngErr != nil {
					return nil, fmt.Errorf("open capture as pcap (%v) or pcapng (%v)", err, ngErr)
				}
				err = nil
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return &CaptureInspectResult{
		Name:     input.Name,
		MimeType: input.MimeType,
		Packets:  packets,
		Stats:    stats,
		Warnings: warnings,
	}, nil
}

func detectCaptureFormat(data []byte) captureFormat {
	switch {
	case len(data) < 4:
		return captureFormatUnknown
	case bytes.Equal(data[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}):
		return captureFormatPcapNG
	case bytes.Equal(data[:4], []byte{0xa1, 0xb2, 0xc3, 0xd4}),
		bytes.Equal(data[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}),
		bytes.Equal(data[:4], []byte{0xa1, 0xb2, 0x3c, 0x4d}),
		bytes.Equal(data[:4], []byte{0x4d, 0x3c, 0xb2, 0xa1}):
		return captureFormatPcap
	default:
		return captureFormatUnknown
	}
}

func readPcap(data []byte) ([]udpDatagram, RunStats, []string, error) {
	reader, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, RunStats{}, nil, err
	}
	return readPackets(reader, reader.LinkType())
}

func readPcapNG(data []byte) ([]udpDatagram, RunStats, []string, error) {
	reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		return nil, RunStats{}, nil, err
	}
	return readPackets(reader, 0)
}

func inspectPcap(data []byte, importType string) ([]PacketInput, RunStats, []string, error) {
	reader, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, RunStats{}, nil, err
	}
	return inspectPackets(reader, reader.LinkType(), importType)
}

func inspectPcapNG(data []byte, importType string) ([]PacketInput, RunStats, []string, error) {
	reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		return nil, RunStats{}, nil, err
	}
	return inspectPackets(reader, 0, importType)
}

func readPackets(reader packetReader, defaultLink layers.LinkType) ([]udpDatagram, RunStats, []string, error) {
	var out []udpDatagram
	var stats RunStats
	var warnings []string
	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				return out, stats, warnings, nil
			}
			return nil, stats, warnings, fmt.Errorf("read packet: %w", err)
		}
		stats.Frames++
		linkType := packetLinkType(ci, defaultLink)
		if linkType == 0 {
			stats.Skipped++
			continue
		}
		datagram, ok := udpDatagramFromPacket(stats.Frames, data, ci, linkType)
		if !ok {
			stats.Skipped++
			continue
		}
		stats.UDPDatagrams++
		out = append(out, datagram)
	}
}

func inspectPackets(reader packetReader, defaultLink layers.LinkType, importType string) ([]PacketInput, RunStats, []string, error) {
	var packets []PacketInput
	var stats RunStats
	var warnings []string
	payloadOnly := normalizePacketInputType(importType) == packetInputTypeFlow
	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				return packets, stats, warnings, nil
			}
			return nil, stats, warnings, fmt.Errorf("read packet: %w", err)
		}
		stats.Frames++
		linkType := packetLinkType(ci, defaultLink)
		if linkType == 0 {
			stats.Skipped++
			warnings = append(warnings, fmt.Sprintf("frame %d: missing link type", stats.Frames))
			continue
		}
		if payloadOnly {
			payload := applicationPayload(linkType, data)
			if len(payload) == 0 {
				stats.Skipped++
				continue
			}
			stats.UDPDatagrams++
			packets = append(packets, PacketInput{
				Frame:       stats.Frames,
				Type:        packetInputTypeFlow,
				Hex:         hex.EncodeToString(payload),
				ReceivedAt:  packetTimestamp(ci),
				CapturedLen: len(payload),
				OriginalLen: len(payload),
				Src:         syntheticFlowSrc,
				Dst:         syntheticFlowDst,
			})
			continue
		}
		datagram, ok := udpDatagramFromPacket(stats.Frames, data, ci, linkType)
		if ok {
			stats.UDPDatagrams++
		} else {
			stats.Skipped++
		}
		packets = append(packets, PacketInput{
			Frame:       stats.Frames,
			Type:        packetInputTypeBytes,
			Hex:         hex.EncodeToString(data),
			LinkType:    int(linkType),
			ReceivedAt:  packetTimestamp(ci),
			CapturedLen: ci.CaptureLength,
			OriginalLen: ci.Length,
			Src:         datagram.meta.Src,
			Dst:         datagram.meta.Dst,
		})
	}
}

func readPacketInputs(inputs []PacketInput) ([]udpDatagram, RunStats, []string, error) {
	var out []udpDatagram
	var stats RunStats
	var warnings []string
	for i, input := range inputs {
		clean := cleanHex(input.Hex)
		if clean == "" {
			continue
		}
		data, err := hex.DecodeString(clean)
		if err != nil {
			return nil, stats, warnings, fmt.Errorf("packet %d hex: %w", i+1, err)
		}
		stats.Frames++
		if normalizePacketInputType(input.Type) == packetInputTypeFlow {
			receivedAt := packetInputReceivedAt(input, i+1, &warnings)
			out = append(out, udpDatagram{
				meta: PacketMeta{
					Frame:      firstNonZero(input.Frame, stats.Frames),
					Src:        firstNonEmpty(input.Src, syntheticFlowSrc),
					Dst:        firstNonEmpty(input.Dst, syntheticFlowDst),
					ReceivedAt: receivedAt.Format(time.RFC3339Nano),
					PayloadLen: len(data),
				},
				payload: data,
			})
			stats.UDPDatagrams++
			continue
		}
		linkType := layers.LinkType(input.LinkType)
		if linkType == 0 {
			linkType = layers.LinkTypeEthernet
		}
		receivedAt := packetInputReceivedAt(input, i+1, &warnings)
		ci := gopacket.CaptureInfo{
			Timestamp:     receivedAt,
			CaptureLength: len(data),
			Length:        len(data),
		}
		if input.CapturedLen > 0 {
			ci.CaptureLength = input.CapturedLen
		}
		if input.OriginalLen > 0 {
			ci.Length = input.OriginalLen
		}
		datagram, ok := udpDatagramFromPacket(firstNonZero(input.Frame, stats.Frames), data, ci, linkType)
		if !ok {
			stats.Skipped++
			continue
		}
		stats.UDPDatagrams++
		out = append(out, datagram)
	}
	return out, stats, warnings, nil
}

func normalizePacketInputType(value string) string {
	if strings.EqualFold(value, packetInputTypeFlow) {
		return packetInputTypeFlow
	}
	return packetInputTypeBytes
}

func packetInputReceivedAt(input PacketInput, index int, warnings *[]string) time.Time {
	receivedAt := time.Now().UTC()
	if input.ReceivedAt == "" {
		return receivedAt
	}
	parsed, err := time.Parse(time.RFC3339Nano, input.ReceivedAt)
	if err != nil {
		*warnings = append(*warnings, fmt.Sprintf("packet %d: ignored timestamp %q", index, input.ReceivedAt))
		return receivedAt
	}
	return parsed.UTC()
}

func packetTimestamp(ci gopacket.CaptureInfo) string {
	receivedAt := ci.Timestamp.UTC()
	if receivedAt.IsZero() {
		receivedAt = time.Now().UTC()
	}
	return receivedAt.Format(time.RFC3339Nano)
}

func packetLinkType(ci gopacket.CaptureInfo, defaultLink layers.LinkType) layers.LinkType {
	if len(ci.AncillaryData) > 0 {
		if typed, ok := ci.AncillaryData[0].(layers.LinkType); ok {
			return typed
		}
	}
	return defaultLink
}

func cleanHex(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
			out.WriteRune(r)
		case r >= 'a' && r <= 'f':
			out.WriteRune(r)
		case r >= 'A' && r <= 'F':
			out.WriteRune(r + ('a' - 'A'))
		}
	}
	return out.String()
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func applicationPayload(linkType layers.LinkType, data []byte) []byte {
	if payload := transportPayload(linkType, data); len(payload) > 0 {
		return payload
	}
	packet := gopacket.NewPacket(data, linkType.LayerType(), gopacket.Default)
	if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
		return append([]byte(nil), layer.(*layers.UDP).Payload...)
	}
	if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		return append([]byte(nil), layer.(*layers.TCP).Payload...)
	}
	if layer := packet.ApplicationLayer(); layer != nil {
		return append([]byte(nil), layer.Payload()...)
	}
	return nil
}

func transportPayload(linkType layers.LinkType, data []byte) []byte {
	switch linkType {
	case layers.LinkTypeEthernet:
		return ethernetPayload(data)
	case layers.LinkTypeRaw:
		return rawIPPayload(data)
	case layers.LinkTypeIPv4:
		return ipv4TransportPayload(data, 0)
	case layers.LinkTypeIPv6:
		return ipv6TransportPayload(data, 0)
	default:
		return nil
	}
}

func ethernetPayload(data []byte) []byte {
	if len(data) < 14 {
		return nil
	}
	offset := 14
	etherType := uint16(data[12])<<8 | uint16(data[13])
	for etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100 {
		if len(data) < offset+4 {
			return nil
		}
		etherType = uint16(data[offset+2])<<8 | uint16(data[offset+3])
		offset += 4
	}
	switch etherType {
	case 0x0800:
		return ipv4TransportPayload(data, offset)
	case 0x86dd:
		return ipv6TransportPayload(data, offset)
	default:
		return nil
	}
}

func rawIPPayload(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	switch data[0] >> 4 {
	case 4:
		return ipv4TransportPayload(data, 0)
	case 6:
		return ipv6TransportPayload(data, 0)
	default:
		return nil
	}
}

func ipv4TransportPayload(data []byte, offset int) []byte {
	if len(data) < offset+20 {
		return nil
	}
	ihl := int(data[offset]&0x0f) * 4
	if ihl < 20 || len(data) < offset+ihl {
		return nil
	}
	totalLen := int(uint16(data[offset+2])<<8 | uint16(data[offset+3]))
	end := len(data)
	if totalLen >= ihl && offset+totalLen <= len(data) {
		end = offset + totalLen
	}
	return l4Payload(data, offset+ihl, end, data[offset+9])
}

func ipv6TransportPayload(data []byte, offset int) []byte {
	if len(data) < offset+40 {
		return nil
	}
	payloadLen := int(uint16(data[offset+4])<<8 | uint16(data[offset+5]))
	end := len(data)
	if offset+40+payloadLen <= len(data) {
		end = offset + 40 + payloadLen
	}
	return l4Payload(data, offset+40, end, data[offset+6])
}

func l4Payload(data []byte, offset int, end int, proto byte) []byte {
	if end > len(data) {
		end = len(data)
	}
	switch proto {
	case 17:
		if end <= offset+8 {
			return nil
		}
		udpLen := int(uint16(data[offset+4])<<8 | uint16(data[offset+5]))
		if udpLen >= 8 && offset+udpLen <= end {
			end = offset + udpLen
		}
		return append([]byte(nil), data[offset+8:end]...)
	case 6:
		if end < offset+20 {
			return nil
		}
		headerLen := int(data[offset+12]>>4) * 4
		if headerLen < 20 || end <= offset+headerLen {
			return nil
		}
		return append([]byte(nil), data[offset+headerLen:end]...)
	default:
		return nil
	}
}

func udpDatagramFromPacket(frame int, data []byte, ci gopacket.CaptureInfo, linkType layers.LinkType) (udpDatagram, bool) {
	packet := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return udpDatagram{}, false
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok || len(udp.Payload) == 0 {
		return udpDatagram{}, false
	}
	srcAddr, dstAddr, ok := packetAddresses(packet)
	if !ok {
		return udpDatagram{}, false
	}
	receivedAt := ci.Timestamp.UTC()
	if receivedAt.IsZero() {
		receivedAt = time.Now().UTC()
	}
	src := netip.AddrPortFrom(srcAddr, uint16(udp.SrcPort))
	dst := netip.AddrPortFrom(dstAddr, uint16(udp.DstPort))
	return udpDatagram{
		meta: PacketMeta{
			Frame:      frame,
			Src:        src.String(),
			Dst:        dst.String(),
			ReceivedAt: receivedAt.Format(time.RFC3339Nano),
			PayloadLen: len(udp.Payload),
		},
		payload: append([]byte(nil), udp.Payload...),
	}, true
}

func packetAddresses(packet gopacket.Packet) (netip.Addr, netip.Addr, bool) {
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip, ok := layer.(*layers.IPv4)
		if !ok {
			return netip.Addr{}, netip.Addr{}, false
		}
		src, okSrc := netip.AddrFromSlice(ip.SrcIP)
		dst, okDst := netip.AddrFromSlice(ip.DstIP)
		return src.Unmap(), dst.Unmap(), okSrc && okDst
	}
	if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		ip, ok := layer.(*layers.IPv6)
		if !ok {
			return netip.Addr{}, netip.Addr{}, false
		}
		src, okSrc := netip.AddrFromSlice(ip.SrcIP)
		dst, okDst := netip.AddrFromSlice(ip.DstIP)
		return src.Unmap(), dst.Unmap(), okSrc && okDst
	}
	return netip.Addr{}, netip.Addr{}, false
}
