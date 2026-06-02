package reflowwasm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	captureFormatPcap   = "pcap"
	captureFormatPcapng = "pcapng"
)

// ImportCaptureJSON is the JSON boundary used by the browser-facing syscall/js
// wrapper for pcap and pcapng imports.
func ImportCaptureJSON(raw []byte) ([]byte, error) {
	var req ImportCaptureRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("decode import request: %w", err)
	}
	result, err := ImportCapture(req)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encode import result: %w", err)
	}
	return data, nil
}

// ImportCapture explodes pcap and pcapng files into input entries. Full-packet
// imports become bytes entries; payload-only imports become flow entries so
// IPFIX, NetFlow, and sFlow datagrams can be decoded directly.
func ImportCapture(req ImportCaptureRequest) (*ImportCaptureResult, error) {
	var result ImportCaptureResult
	for _, file := range req.Files {
		data := file.Bytes
		if len(data) == 0 && file.Data != "" {
			decoded, err := base64.StdEncoding.DecodeString(file.Data)
			if err != nil {
				return nil, fmt.Errorf("decode file %q: %w", file.Name, err)
			}
			data = decoded
		}
		entries, packets, err := importCaptureFile(file.Name, data, req.Format, req.PayloadOnly)
		if err != nil {
			return nil, err
		}
		if req.NativeBinary {
			for i := range entries {
				entries[i].Bytes = entries[i].BytesFromPayload()
				entries[i].Payload = ""
			}
		}
		result.Entries = append(result.Entries, entries...)
		result.Stats.Packets += packets
	}
	result.Stats.Entries = len(result.Entries)
	return &result, nil
}

func importCaptureFile(name string, data []byte, format string, payloadOnly bool) ([]ImportedInputEntry, int, error) {
	format = normalizedCaptureFormat(name, data, format)
	switch format {
	case captureFormatPcapng:
		reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.NgReaderOptions{WantMixedLinkType: true})
		if err != nil {
			return nil, 0, fmt.Errorf("open %s as pcapng: %w", name, err)
		}
		return importCapturePackets(reader, layers.LinkTypeNull, payloadOnly)
	case captureFormatPcap:
		reader, err := pcapgo.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, 0, fmt.Errorf("open %s as pcap: %w", name, err)
		}
		return importCapturePackets(reader, reader.LinkType(), payloadOnly)
	default:
		return nil, 0, fmt.Errorf("unsupported capture format %q", format)
	}
}

func normalizedCaptureFormat(name string, data []byte, format string) string {
	if len(data) >= 4 {
		switch {
		case bytes.Equal(data[:4], []byte{0x0a, 0x0d, 0x0d, 0x0a}):
			return captureFormatPcapng
		case bytes.Equal(data[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}),
			bytes.Equal(data[:4], []byte{0xa1, 0xb2, 0xc3, 0xd4}),
			bytes.Equal(data[:4], []byte{0x4d, 0x3c, 0xb2, 0xa1}),
			bytes.Equal(data[:4], []byte{0xa1, 0xb2, 0x3c, 0x4d}):
			return captureFormatPcap
		}
	}
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case captureFormatPcap, captureFormatPcapng:
		return format
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pcapng":
		return captureFormatPcapng
	default:
		return captureFormatPcap
	}
}

func importCapturePackets(reader packetReader, defaultLink layers.LinkType, payloadOnly bool) ([]ImportedInputEntry, int, error) {
	entryType := "bytes"
	if payloadOnly {
		entryType = "flow"
	}
	var entries []ImportedInputEntry
	var packets int
	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				return entries, packets, nil
			}
			return nil, packets, fmt.Errorf("read packet: %w", err)
		}
		packets++
		linkType := packetLinkType(ci, defaultLink)
		payload := data
		if payloadOnly {
			payload = applicationPayload(linkType, data)
			if len(payload) == 0 {
				continue
			}
		}
		var receivedAt int64
		if !ci.Timestamp.IsZero() {
			receivedAt = ci.Timestamp.UTC().UnixMilli()
		}
		entries = append(entries, ImportedInputEntry{
			Type:       entryType,
			Payload:    base64.StdEncoding.EncodeToString(payload),
			Bytes:      append([]byte(nil), payload...),
			ReceivedAt: receivedAt,
			Length:     len(payload),
		})
	}
}

func (entry ImportedInputEntry) BytesFromPayload() []byte {
	if len(entry.Bytes) > 0 {
		return entry.Bytes
	}
	if entry.Payload == "" {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(entry.Payload)
	if err != nil {
		return nil
	}
	return data
}

func packetLinkType(ci gopacket.CaptureInfo, fallback layers.LinkType) layers.LinkType {
	if len(ci.AncillaryData) > 0 {
		if typed, ok := ci.AncillaryData[0].(layers.LinkType); ok {
			return typed
		}
	}
	return fallback
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
