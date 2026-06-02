package goflow2wasm

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/netsampler/goflow2/v3/decoders/netflow"
	"github.com/netsampler/goflow2/v3/decoders/netflowlegacy"
	"github.com/netsampler/goflow2/v3/decoders/sflow"
	decoderutils "github.com/netsampler/goflow2/v3/decoders/utils"
	goflowconfig "github.com/netsampler/goflow2/v3/pkg/goflow2/config"
	"github.com/netsampler/goflow2/v3/producer"
	protoproducer "github.com/netsampler/goflow2/v3/producer/proto"
	rawproducer "github.com/netsampler/goflow2/v3/producer/raw"
	"github.com/netsampler/goflow2/v3/utils/store/samplingrate"
	"github.com/netsampler/goflow2/v3/utils/store/templates"
	"google.golang.org/protobuf/proto"
)

type binaryMarshaler interface {
	MarshalBinary() ([]byte, error)
}

func RunJSON(raw []byte) ([]byte, error) {
	var req RunRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("decode request: %w", err)
	}
	result, err := Run(req)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encode result: %w", err)
	}
	return data, nil
}

func Run(req RunRequest) (*RunResult, error) {
	runStarted := time.Now()
	cfg, err := commandConfig(req)
	if err != nil {
		return nil, err
	}
	datagrams, stats, warnings, err := readCapture(req.Capture)
	if err != nil {
		return nil, err
	}
	prod, err := newProducer(cfg, req.MappingYAML)
	if err != nil {
		return nil, err
	}
	defer prod.Close()

	templateStore := templates.NewTemplateFlowStore()
	templateStore.Start()
	defer templateStore.Close()

	var entries []OutputEntry
	var logs []string
	for _, datagram := range datagrams {
		decodeStarted := time.Now()
		msgs, protocol, err := decodeAndProduce(cfg.Scheme, datagram, prod, templateStore)
		stats.DecodeElapsedNs += time.Since(decodeStarted).Nanoseconds()
		if err != nil {
			stats.Errors++
			logs = append(logs, fmt.Sprintf("frame %d: %v", datagram.meta.Frame, err))
			continue
		}
		stats.Decoded++
		for _, msg := range msgs {
			entry, err := outputEntry(len(entries)+1, cfg, protocol, datagram.meta, msg)
			if err != nil {
				stats.Errors++
				logs = append(logs, fmt.Sprintf("frame %d: format %T: %v", datagram.meta.Frame, msg, err))
				continue
			}
			entries = append(entries, entry)
		}
		prod.Commit(msgs)
	}
	stats.Outputs = len(entries)
	stats.recordRunTiming(time.Since(runStarted), stats.UDPDatagrams)
	return &RunResult{
		Command:  cfg,
		Entries:  entries,
		Stats:    stats,
		Logs:     logs,
		Warnings: warnings,
	}, nil
}

func (stats *RunStats) recordRunTiming(elapsed time.Duration, packets int) {
	stats.TotalElapsedNs = elapsed.Nanoseconds()
	if packets > 0 {
		stats.NsPerPacket = stats.TotalElapsedNs / int64(packets)
	}
}

func newProducer(cfg CommandConfig, mappingYAML string) (producer.ProducerInterface, error) {
	if cfg.Produce == "raw" {
		return &rawproducer.RawProducer{}, nil
	}
	var producerConfig *protoproducer.ProducerConfig
	if cfg.UseMapping {
		mapping, err := goflowconfig.LoadMapping(strings.NewReader(mappingYAML))
		if err != nil {
			return nil, fmt.Errorf("load mapping: %w", err)
		}
		producerConfig = mapping
	}
	compiled, err := producerConfig.Compile()
	if err != nil {
		return nil, fmt.Errorf("compile mapping: %w", err)
	}
	return protoproducer.CreateProtoProducer(compiled, samplingrate.NewSamplingRateFlowStore())
}

func decodeAndProduce(scheme string, datagram udpDatagram, prod producer.ProducerInterface, templateStore netflow.ManagedTemplateStore) ([]producer.ProducerMessage, string, error) {
	switch scheme {
	case "sflow":
		msgs, err := decodeSFlow(datagram, prod)
		return msgs, "sflow", err
	case "netflow":
		return decodeNetFlow(datagram, prod, templateStore)
	case "flow":
		protocol := detectProtocol(datagram.payload)
		switch protocol {
		case "sflow":
			msgs, err := decodeSFlow(datagram, prod)
			return msgs, protocol, err
		case "netflowv5", "netflowv9", "ipfix":
			msgs, actual, err := decodeNetFlow(datagram, prod, templateStore)
			return msgs, actual, err
		default:
			return nil, "", fmt.Errorf("could not identify protocol")
		}
	default:
		return nil, "", fmt.Errorf("unsupported scheme %q", scheme)
	}
}

func decodeSFlow(datagram udpDatagram, prod producer.ProducerInterface) ([]producer.ProducerMessage, error) {
	var packet sflow.Packet
	if err := sflow.DecodeMessageVersion(bytes.NewBuffer(datagram.payload), &packet); err != nil {
		return nil, fmt.Errorf("sflow decode: %w", err)
	}
	args, err := produceArgs(datagram)
	if err != nil {
		return nil, err
	}
	msgs, err := prod.Produce(&packet, args)
	if err != nil {
		return nil, fmt.Errorf("sflow produce: %w", err)
	}
	return msgs, nil
}

func decodeNetFlow(datagram udpDatagram, prod producer.ProducerInterface, templateStore netflow.ManagedTemplateStore) ([]producer.ProducerMessage, string, error) {
	buf := bytes.NewBuffer(datagram.payload)
	var version uint16
	if err := decoderutils.BinaryDecoder(buf, &version); err != nil {
		return nil, "", fmt.Errorf("netflow version: %w", err)
	}
	args, err := produceArgs(datagram)
	if err != nil {
		return nil, "", err
	}
	ctx := netflow.FlowContext{RouterKey: args.Src.String()}
	var msgs []producer.ProducerMessage
	switch version {
	case 5:
		var packet netflowlegacy.PacketNetFlowV5
		packet.Version = 5
		if err := netflowlegacy.DecodeMessage(buf, &packet); err != nil {
			return nil, "netflowv5", fmt.Errorf("netflow v5 decode: %w", err)
		}
		msgs, err = prod.Produce(&packet, args)
		if err != nil {
			return nil, "netflowv5", fmt.Errorf("netflow v5 produce: %w", err)
		}
		return msgs, "netflowv5", nil
	case 9:
		var packet netflow.NFv9Packet
		packet.Version = 9
		if err := netflow.DecodeMessageNetFlow(buf, templateStore, ctx, &packet); err != nil {
			return nil, "netflowv9", fmt.Errorf("netflow v9 decode: %w", err)
		}
		msgs, err = prod.Produce(&packet, args)
		if err != nil {
			return nil, "netflowv9", fmt.Errorf("netflow v9 produce: %w", err)
		}
		return msgs, "netflowv9", nil
	case 10:
		var packet netflow.IPFIXPacket
		packet.Version = 10
		if err := netflow.DecodeMessageIPFIX(buf, templateStore, ctx, &packet); err != nil {
			return nil, "ipfix", fmt.Errorf("ipfix decode: %w", err)
		}
		msgs, err = prod.Produce(&packet, args)
		if err != nil {
			return nil, "ipfix", fmt.Errorf("ipfix produce: %w", err)
		}
		return msgs, "ipfix", nil
	default:
		return nil, "", fmt.Errorf("not a NetFlow/IPFIX packet")
	}
}

func outputEntry(index int, cfg CommandConfig, protocol string, meta PacketMeta, msg producer.ProducerMessage) (OutputEntry, error) {
	entry := OutputEntry{
		Index:    index,
		Protocol: protocol,
		Source:   meta,
	}
	if keyer, ok := msg.(interface{ Key() []byte }); ok {
		entry.Key = hex.EncodeToString(keyer.Key())
	}
	jsonData, err := json.Marshal(msg)
	if err != nil {
		return entry, fmt.Errorf("json marshal: %w", err)
	}
	entry.JSON = string(jsonData)
	var parsed interface{}
	if err := json.Unmarshal(jsonData, &parsed); err == nil {
		entry.Parsed = parsed
	}
	if cfg.Format == "bin" {
		data, err := protobufPayload(msg, cfg.ProtobufFraming)
		if err != nil {
			return entry, err
		}
		entry.ProtoHex = hex.EncodeToString(data)
		entry.ProtoB64 = base64.StdEncoding.EncodeToString(data)
		entry.ProtoSize = len(data)
	}
	return entry, nil
}

func protobufPayload(msg producer.ProducerMessage, framing string) ([]byte, error) {
	if framing == "delimited" {
		binaryMsg, ok := msg.(binaryMarshaler)
		if !ok {
			return nil, fmt.Errorf("message cannot be marshaled as delimited protobuf")
		}
		data, err := binaryMsg.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("protobuf marshal: %w", err)
		}
		return data, nil
	}
	if protoMsg, ok := msg.(proto.Message); ok {
		data, err := proto.Marshal(protoMsg)
		if err != nil {
			return nil, fmt.Errorf("protobuf marshal: %w", err)
		}
		return data, nil
	}
	binaryMsg, ok := msg.(binaryMarshaler)
	if !ok {
		return nil, fmt.Errorf("message cannot be marshaled as protobuf")
	}
	data, err := binaryMsg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal: %w", err)
	}
	return data, nil
}

func produceArgs(datagram udpDatagram) (*producer.ProduceArgs, error) {
	src, err := netip.ParseAddrPort(datagram.meta.Src)
	if err != nil {
		return nil, fmt.Errorf("parse source address: %w", err)
	}
	dst, err := netip.ParseAddrPort(datagram.meta.Dst)
	if err != nil {
		return nil, fmt.Errorf("parse destination address: %w", err)
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, datagram.meta.ReceivedAt)
	if err != nil {
		receivedAt = time.Now().UTC()
	}
	return &producer.ProduceArgs{
		Src:            src,
		Dst:            dst,
		TimeReceived:   receivedAt,
		SamplerAddress: src.Addr(),
		FlowContext:    &netflow.FlowContext{RouterKey: src.String()},
	}, nil
}

func detectProtocol(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	if binary.BigEndian.Uint32(payload[:4]) == 5 {
		return "sflow"
	}
	switch binary.BigEndian.Uint16(payload[:2]) {
	case 5:
		return "netflowv5"
	case 9:
		return "netflowv9"
	case 10:
		return "ipfix"
	default:
		return ""
	}
}
