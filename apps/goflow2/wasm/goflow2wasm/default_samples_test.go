package goflow2wasm

import (
	"encoding/hex"
	"testing"

	flowmessage "github.com/netsampler/goflow2/v3/pb"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const (
	defaultIPFIXTemplateHex = "000a00446630f0000000000000003039000200340100000b00080004000c00040004000100070002000b0002000a0004000e000400010008000200080098000800990008"
	defaultIPFIXDataHex     = "000a004c6630f00100000001000030390100003cc000020ac633641406303901bb0000000a0000000e00000000000005dc000000000000000a0000018f2f2980000000018f2f2984d2000000"
	defaultSFlowHex         = "0000000500000001c0000264000000010000000200000bb80000000100000001000000480000002a0000000700000064000003e8000000000000000a0000000e000000010000000300000020000005dc00000006cb00710ac633641400003039000001bb0000001200000000"
)

func TestDefaultGoFlow2SamplesDecodeIPFIXAndSFlow(t *testing.T) {
	result, err := Run(RunRequest{
		Options: RunOptions{
			Scheme:  "flow",
			Produce: "sample",
			Format:  "json",
		},
		Capture: CaptureInput{
			Packets: []PacketInput{
				{Type: packetInputTypeFlow, Hex: defaultIPFIXTemplateHex, ReceivedAt: "2026-06-02T04:00:00Z"},
				{Type: packetInputTypeFlow, Hex: defaultIPFIXDataHex, ReceivedAt: "2026-06-02T04:00:00.001Z"},
				{Type: packetInputTypeFlow, Hex: defaultSFlowHex, ReceivedAt: "2026-06-02T04:00:00.002Z"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Stats.Frames != 3 || result.Stats.UDPDatagrams != 3 || result.Stats.Decoded != 3 || result.Stats.Errors != 0 {
		t.Fatalf("unexpected stats: %+v logs=%v", result.Stats, result.Logs)
	}
	if result.Stats.TotalElapsedNs <= 0 || result.Stats.NsPerPacket <= 0 {
		t.Fatalf("expected run timing stats, got %+v", result.Stats)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("expected 2 emitted flow records, got %d: %#v", len(result.Entries), result.Entries)
	}
	if result.Entries[0].Protocol != "ipfix" {
		t.Fatalf("expected first emitted record to be ipfix, got %q", result.Entries[0].Protocol)
	}
	if result.Entries[1].Protocol != "sflow" {
		t.Fatalf("expected second emitted record to be sflow, got %q", result.Entries[1].Protocol)
	}
}

func TestDefaultGoFlow2ProtoOutputProducesBinary(t *testing.T) {
	result, err := Run(RunRequest{
		Options: RunOptions{
			Scheme:  "flow",
			Produce: "sample",
			Format:  "bin",
		},
		Capture: CaptureInput{
			Packets: []PacketInput{
				{Type: packetInputTypeFlow, Hex: defaultIPFIXTemplateHex, ReceivedAt: "2026-06-02T04:00:00Z"},
				{Type: packetInputTypeFlow, Hex: defaultIPFIXDataHex, ReceivedAt: "2026-06-02T04:00:00.001Z"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 emitted flow record, got %d: %#v", len(result.Entries), result.Entries)
	}
	entry := result.Entries[0]
	if entry.ProtoB64 == "" || entry.ProtoHex == "" || entry.ProtoSize == 0 {
		t.Fatalf("expected protobuf payload fields, got ProtoB64=%q ProtoHex=%q ProtoSize=%d", entry.ProtoB64, entry.ProtoHex, entry.ProtoSize)
	}
	data, err := hex.DecodeString(entry.ProtoHex)
	if err != nil {
		t.Fatalf("decode proto hex: %v", err)
	}
	var msg flowmessage.FlowMessage
	if err := proto.Unmarshal(data, &msg); err != nil {
		t.Fatalf("expected raw protobuf FlowMessage payload, got unmarshal error: %v", err)
	}
	if msg.Type != flowmessage.FlowMessage_IPFIX {
		t.Fatalf("expected IPFIX protobuf payload, got %s", msg.Type)
	}
}

func TestDefaultGoFlow2ProtoOutputCanBeDelimited(t *testing.T) {
	result, err := Run(RunRequest{
		Options: RunOptions{
			Scheme:          "flow",
			Produce:         "sample",
			Format:          "bin",
			ProtobufFraming: "delimited",
		},
		Capture: CaptureInput{
			Packets: []PacketInput{
				{Type: packetInputTypeFlow, Hex: defaultIPFIXTemplateHex, ReceivedAt: "2026-06-02T04:00:00Z"},
				{Type: packetInputTypeFlow, Hex: defaultIPFIXDataHex, ReceivedAt: "2026-06-02T04:00:00.001Z"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Command.ProtobufFraming != "delimited" {
		t.Fatalf("expected delimited command framing, got %#v", result.Command)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 emitted flow record, got %d: %#v", len(result.Entries), result.Entries)
	}
	data, err := hex.DecodeString(result.Entries[0].ProtoHex)
	if err != nil {
		t.Fatalf("decode proto hex: %v", err)
	}
	size, prefixLen := protowire.ConsumeVarint(data)
	if prefixLen < 0 {
		t.Fatalf("expected protobuf varint length prefix")
	}
	if int(size) != len(data)-prefixLen {
		t.Fatalf("expected length prefix %d to cover %d bytes", size, len(data)-prefixLen)
	}
	var msg flowmessage.FlowMessage
	if err := proto.Unmarshal(data[prefixLen:], &msg); err != nil {
		t.Fatalf("expected delimited protobuf FlowMessage payload, got unmarshal error: %v", err)
	}
	if msg.Type != flowmessage.FlowMessage_IPFIX {
		t.Fatalf("expected IPFIX protobuf payload, got %s", msg.Type)
	}
}
