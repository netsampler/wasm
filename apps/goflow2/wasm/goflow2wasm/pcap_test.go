package goflow2wasm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const testUDPPacketHex = "00112233445566778899aabb0800450000200000000040110000c0000201c6336402303918d5000c000000000005"

func TestInspectCaptureConvertsPcapToHexPackets(t *testing.T) {
	packet := mustHexPacket(t)
	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Date(2026, 6, 2, 4, 0, 0, 0, time.UTC),
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet); err != nil {
		t.Fatalf("write packet: %v", err)
	}

	result, err := InspectCapture(CaptureInput{
		Name:     "sample.pcap",
		MimeType: "application/vnd.tcpdump.pcap",
		Data:     base64.StdEncoding.EncodeToString(buf.Bytes()),
	})
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if result.Stats.Frames != 1 || result.Stats.UDPDatagrams != 1 {
		t.Fatalf("unexpected stats: %+v", result.Stats)
	}
	if len(result.Packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(result.Packets))
	}
	if result.Packets[0].Hex != testUDPPacketHex {
		t.Fatalf("unexpected packet hex:\nwant %s\n got %s", testUDPPacketHex, result.Packets[0].Hex)
	}
	if result.Packets[0].Type != packetInputTypeBytes {
		t.Fatalf("unexpected packet type: %q", result.Packets[0].Type)
	}
	if result.Packets[0].LinkType != int(layers.LinkTypeEthernet) {
		t.Fatalf("unexpected link type: %d", result.Packets[0].LinkType)
	}
}

func TestInspectCaptureAsFlowConvertsPcapToPayloads(t *testing.T) {
	packet := mustHexPacket(t)
	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Date(2026, 6, 2, 4, 0, 0, 0, time.UTC),
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet); err != nil {
		t.Fatalf("write packet: %v", err)
	}

	result, err := InspectCapture(CaptureInput{
		Name:       "sample.pcap",
		MimeType:   "application/vnd.tcpdump.pcap",
		ImportType: packetInputTypeFlow,
		Data:       base64.StdEncoding.EncodeToString(buf.Bytes()),
	})
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if result.Stats.Frames != 1 || result.Stats.UDPDatagrams != 1 {
		t.Fatalf("unexpected stats: %+v", result.Stats)
	}
	if len(result.Packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(result.Packets))
	}
	if result.Packets[0].Type != packetInputTypeFlow {
		t.Fatalf("unexpected packet type: %q", result.Packets[0].Type)
	}
	if result.Packets[0].Hex != "00000005" {
		t.Fatalf("unexpected payload hex: %s", result.Packets[0].Hex)
	}
	if result.Packets[0].Src == "" || result.Packets[0].Dst == "" {
		t.Fatalf("expected source metadata, got %+v", result.Packets[0])
	}
}

func TestInspectCaptureAsFlowSupportsRawIPPackets(t *testing.T) {
	packet := mustHexPacket(t)[14:]
	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeRaw); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Date(2026, 6, 2, 4, 0, 0, 0, time.UTC),
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet); err != nil {
		t.Fatalf("write packet: %v", err)
	}

	result, err := InspectCapture(CaptureInput{
		Name:       "raw.pcap",
		MimeType:   "application/vnd.tcpdump.pcap",
		ImportType: packetInputTypeFlow,
		Data:       base64.StdEncoding.EncodeToString(buf.Bytes()),
	})
	if err != nil {
		t.Fatalf("inspect capture: %v", err)
	}
	if result.Stats.Frames != 1 || result.Stats.UDPDatagrams != 1 || result.Stats.Skipped != 0 {
		t.Fatalf("unexpected stats: %+v", result.Stats)
	}
	if len(result.Packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(result.Packets))
	}
	if result.Packets[0].Type != packetInputTypeFlow {
		t.Fatalf("unexpected packet type: %q", result.Packets[0].Type)
	}
	if result.Packets[0].Hex != "00000005" {
		t.Fatalf("unexpected payload hex: %s", result.Packets[0].Hex)
	}
	if result.Packets[0].Src != syntheticFlowSrc {
		t.Fatalf("unexpected synthetic source: %s", result.Packets[0].Src)
	}
}

func TestReadCaptureFromHexPackets(t *testing.T) {
	datagrams, stats, warnings, err := readCapture(CaptureInput{
		Packets: []PacketInput{{
			Frame:      7,
			Type:       packetInputTypeBytes,
			Hex:        testUDPPacketHex,
			LinkType:   int(layers.LinkTypeEthernet),
			ReceivedAt: "2026-06-02T04:00:00Z",
		}},
	})
	if err != nil {
		t.Fatalf("read capture: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if stats.Frames != 1 || stats.UDPDatagrams != 1 || stats.Skipped != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if len(datagrams) != 1 {
		t.Fatalf("expected 1 datagram, got %d", len(datagrams))
	}
	if datagrams[0].meta.Frame != 7 {
		t.Fatalf("unexpected frame: %d", datagrams[0].meta.Frame)
	}
	if got := hex.EncodeToString(datagrams[0].payload); got != "00000005" {
		t.Fatalf("unexpected payload: %s", got)
	}
}

func TestReadCaptureFromFlowPayloadFakesSource(t *testing.T) {
	datagrams, stats, warnings, err := readCapture(CaptureInput{
		Packets: []PacketInput{{
			Frame:      9,
			Type:       packetInputTypeFlow,
			Hex:        "00000005",
			ReceivedAt: "2026-06-02T04:00:00Z",
		}},
	})
	if err != nil {
		t.Fatalf("read capture: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if stats.Frames != 1 || stats.UDPDatagrams != 1 || stats.Skipped != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if len(datagrams) != 1 {
		t.Fatalf("expected 1 datagram, got %d", len(datagrams))
	}
	if datagrams[0].meta.Frame != 9 {
		t.Fatalf("unexpected frame: %d", datagrams[0].meta.Frame)
	}
	if datagrams[0].meta.Src != syntheticFlowSrc {
		t.Fatalf("unexpected synthetic source: %s", datagrams[0].meta.Src)
	}
	if datagrams[0].meta.Dst != syntheticFlowDst {
		t.Fatalf("unexpected synthetic destination: %s", datagrams[0].meta.Dst)
	}
	if got := hex.EncodeToString(datagrams[0].payload); got != "00000005" {
		t.Fatalf("unexpected payload: %s", got)
	}
}

func mustHexPacket(t *testing.T) []byte {
	t.Helper()
	packet, err := hex.DecodeString(testUDPPacketHex)
	if err != nil {
		t.Fatalf("decode test packet: %v", err)
	}
	return packet
}
