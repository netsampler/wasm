package reflowwasm

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// wireViewCapture packages encoder output in a form the browser can inspect.
// Existing pcap output is passed through; flow datagrams are wrapped in a small
// synthetic Ethernet/IP/UDP capture.
func wireViewCapture(encoderType string, payloads []timedPayload, nativeBinary bool) (*WireViewCapture, error) {
	switch encoderType {
	case "pcap":
		data := joinTimedPayloads(payloads)
		if len(data) == 0 {
			return nil, nil
		}
		timeline, err := pcapPacketTimeline(data, "pcap packet")
		if err != nil {
			return nil, fmt.Errorf("read WireView pcap timestamps: %w", err)
		}
		return wireViewCaptureResult(WireViewCapture{
			Filename:   "reflow-output.pcap",
			MimeType:   "application/vnd.tcpdump.pcap",
			Bytes:      append([]byte(nil), data...),
			Timestamps: timelineTimestamps(timeline),
			Timeline:   timeline,
		}, nativeBinary), nil
	case "pcapng":
		data := joinTimedPayloads(payloads)
		if len(data) == 0 {
			return nil, nil
		}
		timeline, err := pcapngPacketTimeline(data, "pcapng packet")
		if err != nil {
			return nil, fmt.Errorf("read WireView pcapng timestamps: %w", err)
		}
		return wireViewCaptureResult(WireViewCapture{
			Filename:   "reflow-output.pcapng",
			MimeType:   "application/octet-stream",
			Bytes:      append([]byte(nil), data...),
			Timestamps: timelineTimestamps(timeline),
			Timeline:   timeline,
		}, nativeBinary), nil
	case "sflow", "ipfix", "netflowv5", "netflowv9":
		data, err := datagramsToPcap(encoderType, payloads)
		if err != nil {
			return nil, fmt.Errorf("build WireView capture: %w", err)
		}
		if len(data) == 0 {
			return nil, nil
		}
		timeline := payloadTimeline(encoderType, payloads)
		return wireViewCaptureResult(WireViewCapture{
			Filename:   "reflow-" + encoderType + ".pcap",
			MimeType:   "application/vnd.tcpdump.pcap",
			Bytes:      append([]byte(nil), data...),
			Timestamps: timelineTimestamps(timeline),
			Timeline:   timeline,
		}, nativeBinary), nil
	default:
		return nil, nil
	}
}

func wireViewCaptureResult(capture WireViewCapture, nativeBinary bool) *WireViewCapture {
	if !nativeBinary {
		capture.Base64 = base64.StdEncoding.EncodeToString(capture.Bytes)
		capture.Bytes = nil
	}
	return &capture
}

func pcapPacketTimeline(data []byte, packetType string) ([]WireViewPacketPoint, error) {
	reader, err := pcapgo.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return packetTimeline(reader, packetType)
}

func pcapngPacketTimeline(data []byte, packetType string) ([]WireViewPacketPoint, error) {
	reader, err := pcapgo.NewNgReader(bytes.NewReader(data), pcapgo.NgReaderOptions{})
	if err != nil {
		return nil, err
	}
	return packetTimeline(reader, packetType)
}

func packetTimeline(reader packetReader, packetType string) ([]WireViewPacketPoint, error) {
	var timeline []WireViewPacketPoint
	for {
		_, ci, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				return timeline, nil
			}
			return nil, err
		}
		timeline = append(timeline, WireViewPacketPoint{
			Timestamp: ci.Timestamp.UTC().UnixMilli(),
			Type:      packetType,
		})
	}
}

func payloadTimeline(encoderType string, payloads []timedPayload) []WireViewPacketPoint {
	timeline := make([]WireViewPacketPoint, 0, len(payloads))
	now := time.Now()
	for i, payload := range payloads {
		if len(payload.Data) == 0 {
			continue
		}
		timestamp := payload.ReceivedAt
		if timestamp.IsZero() {
			timestamp = now.Add(time.Duration(i) * time.Millisecond)
		}
		timeline = append(timeline, WireViewPacketPoint{
			Timestamp: timestamp.UTC().UnixMilli(),
			Type:      encodedPayloadTimelineType(encoderType, payload.Data),
		})
	}
	return timeline
}

func encodedPayloadTimelineType(encoderType string, payload []byte) string {
	switch encoderType {
	case "ipfix":
		switch templatedControlPayloadKind(encoderType, payload) {
		case "template":
			return "ipfix template"
		case "options":
			return "ipfix options"
		default:
			return "ipfix data"
		}
	case "netflowv9":
		switch templatedControlPayloadKind(encoderType, payload) {
		case "template":
			return "netflowv9 template"
		case "options":
			return "netflowv9 options"
		default:
			return "netflowv9 data"
		}
	case "netflowv5":
		return "netflowv5 data"
	case "sflow":
		return "sflow data"
	default:
		return "packet"
	}
}

func timelineTimestamps(timeline []WireViewPacketPoint) []int64 {
	timestamps := make([]int64, 0, len(timeline))
	for _, point := range timeline {
		timestamps = append(timestamps, point.Timestamp)
	}
	return timestamps
}

func joinTimedPayloads(payloads []timedPayload) []byte {
	chunks := make([][]byte, 0, len(payloads))
	for _, payload := range payloads {
		chunks = append(chunks, payload.Data)
	}
	return bytes.Join(chunks, nil)
}

// datagramsToPcap wraps flow datagrams in synthetic packets so packet tools can
// decode protocols that are normally transported over UDP.
func datagramsToPcap(encoderType string, payloads []timedPayload) ([]byte, error) {
	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return nil, err
	}
	dstPort := udpPortForEncoder(encoderType)
	now := time.Now()
	for i, payload := range payloads {
		if len(payload.Data) == 0 {
			continue
		}
		packet, err := udpDatagramPacket(payload.Data, dstPort)
		if err != nil {
			return nil, err
		}
		timestamp := payload.ReceivedAt
		if timestamp.IsZero() {
			timestamp = now.Add(time.Duration(i) * time.Millisecond)
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     timestamp.UTC(),
			CaptureLength: len(packet),
			Length:        len(packet),
		}, packet); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func udpPortForEncoder(encoderType string) layers.UDPPort {
	switch encoderType {
	case "sflow":
		return 6343
	case "ipfix":
		return 4739
	case "netflowv5", "netflowv9":
		return 2055
	default:
		return 9999
	}
}

func udpDatagramPacket(payload []byte, dstPort layers.UDPPort) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 0, 2, 10},
		DstIP:    []byte{192, 0, 2, 20},
	}
	udp := &layers.UDP{
		SrcPort: 50000,
		DstPort: dstPort,
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth,
		ip,
		udp,
		gopacket.Payload(payload),
	); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
