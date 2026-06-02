package reflowwasm

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const jsonAggregateConfig = `
sources:
  - network: stream
    type: json
    json:
      flavor: reflow

processor:
  type: builtin

aggregators:
  - stream: flow_data
    window:
      idle_flush_after_ms: 60000
    fields:
      - key:src_addr
      - key:dst_addr
      - key:proto
      - key:src_port
      - key:dst_port
      - sum:bytes
      - sum:packets
      - first:start_time_unix
      - current:end_time_unix

encoder:
  type: json

sink:
  type: stdout
`

func TestBrowserConfigRejectsUnsupportedSourceAndSink(t *testing.T) {
	_, err := Run(t.Context(), RunRequest{
		ConfigYAML: `
sources:
  - network: udp
    address: ":6343"
    type: flow
encoder:
  type: json
sink:
  type: stdout
`,
		Input: InputRequest{Mode: "json", Text: `{}`},
	})
	if err == nil || !strings.Contains(err.Error(), "source.network=stream") {
		t.Fatalf("expected source.network rejection, got %v", err)
	}

	_, err = Run(t.Context(), RunRequest{
		ConfigYAML: `
sources:
  - network: stream
    type: json
encoder:
  type: json
sink:
  type: file
  path: /tmp/out.json
`,
		Input: InputRequest{Mode: "json", Text: `{}`},
	})
	if err == nil || !strings.Contains(err.Error(), "sink.type=stdout") {
		t.Fatalf("expected sink.type rejection, got %v", err)
	}
}

func TestJSONBatchAggregationFlushesAtEOF(t *testing.T) {
	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: jsonAggregateConfig,
		Input: InputRequest{
			Mode: "json",
			Text: `[
{"src_addr":"192.0.2.1","dst_addr":"198.51.100.2","proto":6,"src_port":12345,"dst_port":443,"bytes":10,"packets":1,"start_time_unix":1,"end_time_unix":2},
{"src_addr":"192.0.2.1","dst_addr":"198.51.100.2","proto":6,"src_port":12345,"dst_port":443,"bytes":20,"packets":2,"start_time_unix":1,"end_time_unix":3}
]`,
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Kind != "json" {
		t.Fatalf("expected JSON output, got %q", result.Kind)
	}
	if result.Stats.TotalElapsedNs <= 0 || result.Stats.NsPerPacket <= 0 {
		t.Fatalf("expected run timing stats, got %+v", result.Stats)
	}

	events := decodeOutputEvents(t, result.Text)
	found := false
	for _, evt := range events {
		fields, ok := evt["fields"].(map[string]any)
		if !ok || evt["stream"] != "flow_data" {
			continue
		}
		if fields["bytes"] == float64(30) && fields["packets"] == float64(3) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("did not find flushed aggregate in output:\n%s", result.Text)
	}
}

func TestJSONInputAcceptsMixedObjectAndTupleEntries(t *testing.T) {
	packet := ethernetIPv4TCPPacket()
	jsonReceivedAt := time.UnixMilli(1714483200123).UTC()
	bytesReceivedAt := time.UnixMilli(1714483200456).UTC()
	mixed := []any{
		[]any{"json", map[string]any{
			"src_addr":        "203.0.113.10",
			"dst_addr":        "198.51.100.20",
			"proto":           17,
			"src_port":        1234,
			"dst_port":        53,
			"bytes":           64,
			"packets":         1,
			"start_time_unix": 1,
			"end_time_unix":   2,
		}, jsonReceivedAt.UnixMilli()},
		[]any{"bytes", base64.StdEncoding.EncodeToString(packet), bytesReceivedAt.UnixMilli()},
	}
	input, err := json.Marshal(mixed)
	if err != nil {
		t.Fatalf("marshal mixed input: %v", err)
	}

	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: `
sources:
  - network: stream
    type: json
    json:
      flavor: reflow
  - network: stream
    type: bytes
  - network: stream
    type: flow
processor:
  type: builtin
encoder:
  type: json
  json:
    drop_fields: [header_data]
sink:
  type: stdout
`,
		Input: InputRequest{Mode: "json", Text: string(input)},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !strings.Contains(result.Text, `"src_addr":"203.0.113.10"`) {
		t.Fatalf("expected JSON object entry in output:\n%s", result.Text)
	}
	if !strings.Contains(result.Text, `"dst_port":80`) {
		t.Fatalf("expected bytes tuple packet fields in output:\n%s", result.Text)
	}
	foundBytesPacket := false
	foundTimedJSON := false
	for _, evt := range decodeOutputEvents(t, result.Text) {
		source, _ := evt["source"].(map[string]any)
		fields, _ := evt["fields"].(map[string]any)
		if source["type"] == "json" && evt["received_at"] == jsonReceivedAt.Format(time.RFC3339Nano) {
			foundTimedJSON = true
		}
		if source["type"] == "bytes" && fields["dst_port"] == float64(80) {
			if fields["start_time_unix"] != float64(bytesReceivedAt.UnixMilli()) {
				t.Fatalf("expected bytes tuple timestamp %d, got %#v", bytesReceivedAt.UnixMilli(), fields["start_time_unix"])
			}
			foundBytesPacket = true
		}
	}
	if !foundTimedJSON {
		t.Fatalf("expected JSON tuple received_at %s in output:\n%s", jsonReceivedAt.Format(time.RFC3339Nano), result.Text)
	}
	if !foundBytesPacket {
		t.Fatalf("expected bytes tuple to route through bytes stream source:\n%s", result.Text)
	}
}

func TestJSONInputAcceptsSingleTopLevelTuple(t *testing.T) {
	receivedAt := time.UnixMilli(1714483200123).UTC()
	input, err := json.Marshal([]any{
		"json",
		map[string]any{
			"src_addr":        "203.0.113.10",
			"dst_addr":        "198.51.100.20",
			"proto":           17,
			"src_port":        1234,
			"dst_port":        53,
			"bytes":           64,
			"packets":         1,
			"start_time_unix": 1,
			"end_time_unix":   2,
		},
		map[string]any{"received_at": receivedAt.Format(time.RFC3339Nano)},
	})
	if err != nil {
		t.Fatalf("marshal tuple input: %v", err)
	}

	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: `
sources:
  - network: stream
    type: json
    json:
      flavor: reflow
processor:
  type: builtin
encoder:
  type: json
sink:
  type: stdout
`,
		Input: InputRequest{Mode: "json", Text: string(input)},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	for _, evt := range decodeOutputEvents(t, result.Text) {
		source, _ := evt["source"].(map[string]any)
		if source["type"] == "json" && evt["received_at"] == receivedAt.Format(time.RFC3339Nano) {
			return
		}
	}
	t.Fatalf("expected single tuple received_at %s in output:\n%s", receivedAt.Format(time.RFC3339Nano), result.Text)
}

func TestNetFlowV5SkipsAggregationControlEvents(t *testing.T) {
	configYAML := strings.Replace(jsonAggregateConfig, "encoder:\n  type: json", "encoder:\n  type: netflowv5", 1)
	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: configYAML,
		Input: InputRequest{
			Mode: "json",
			Text: `[
{"src_addr":"192.0.2.1","dst_addr":"198.51.100.2","proto":6,"src_port":12345,"dst_port":443,"bytes":10,"packets":1,"start_time_unix":1,"end_time_unix":2},
{"src_addr":"192.0.2.1","dst_addr":"198.51.100.2","proto":6,"src_port":12345,"dst_port":443,"bytes":20,"packets":2,"start_time_unix":1,"end_time_unix":3}
]`,
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Kind != "bytes" {
		t.Fatalf("expected bytes output, got %q", result.Kind)
	}
	if len(result.Payloads) != 1 {
		t.Fatalf("expected one NetFlow v5 datagram, got %d", len(result.Payloads))
	}
	if result.WireView == nil || result.WireView.Filename != "reflow-netflowv5.pcap" {
		t.Fatalf("expected WireView NetFlow v5 capture, got %#v", result.WireView)
	}
}

func TestProtobufEncoderReturnsBytesMetadata(t *testing.T) {
	configYAML := strings.Replace(jsonAggregateConfig, "encoder:\n  type: json", "encoder:\n  type: protobuf", 1)
	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: configYAML,
		Input: InputRequest{
			Mode: "json",
			Text: `[
{"src_addr":"192.0.2.1","dst_addr":"198.51.100.2","proto":6,"src_port":12345,"dst_port":443,"bytes":10,"packets":1,"start_time_unix":1,"end_time_unix":2}
]`,
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Kind != "bytes" || result.EncoderType != "protobuf" {
		t.Fatalf("expected protobuf bytes result, got kind=%q encoder=%q", result.Kind, result.EncoderType)
	}
	if len(result.Payloads) != 1 || result.Payloads[0].Length == 0 {
		t.Fatalf("expected one protobuf payload, got %#v", result.Payloads)
	}
}

func TestBytesInputAsPacketProducesParsedJSON(t *testing.T) {
	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: `
sources:
  - network: stream
    type: bytes
processor:
  type: builtin
encoder:
  type: json
  json:
    drop_fields: [header_data]
sink:
  type: stdout
`,
		Input: InputRequest{
			Mode:     "bytes",
			Encoding: "hex",
			Text:     hexLines(ethernetIPv4TCPPacket()),
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !strings.Contains(result.Text, `"src_addr":"192.0.2.1"`) || !strings.Contains(result.Text, `"dst_port":80`) {
		t.Fatalf("expected parsed packet fields, got:\n%s", result.Text)
	}
}

func TestPcapEncodeErrorIncludesPacketDiagnostics(t *testing.T) {
	_, err := Run(t.Context(), RunRequest{
		ConfigYAML: `
sources:
  - network: stream
    type: json
    json:
      flavor: reflow
processor:
  type: builtin
aggregators: []
encoder:
  type: pcap
  pcap:
    packet_source: pseudo
    link_type: ethernet
sink:
  type: stdout
`,
		Input: InputRequest{
			Mode: "json",
			Text: `{"bytes":10,"packets":1}`,
		},
	})
	if err == nil {
		t.Fatalf("expected pcap encode error")
	}
	msg := err.Error()
	for _, want := range []string{
		"encode pcap: cannot build pseudo packet",
		"packet_source=pseudo",
		"source.type=json",
		"tuple_fields=missing src_addr,dst_addr,proto",
		"available_fields=bytes,packets",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("expected error to contain %q, got:\n%s", want, msg)
		}
	}
}

func TestBytesInputAsFlowUsesFlowDecoder(t *testing.T) {
	_, err := Run(t.Context(), RunRequest{
		ConfigYAML: `
sources:
  - network: stream
    type: flow
processor:
  type: builtin
encoder:
  type: json
sink:
  type: stdout
`,
		Input: InputRequest{
			Mode:     "bytes",
			Encoding: "hex",
			Text:     "00010000",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported version") {
		t.Fatalf("expected flow decoder error, got %v", err)
	}
}

func TestBytesInputAsFlowAcceptsIPFIXOptionsTemplate(t *testing.T) {
	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: `
sources:
  - network: stream
    type: flow
processor:
  type: builtin
encoder:
  type: json
sink:
  type: stdout
`,
		Input: InputRequest{
			Mode:     "bytes",
			Encoding: "hex",
			Text:     "000a00246553f100000001c80000031500030014012d0002000100950004002200040000",
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !strings.Contains(result.Text, `"flow_type":"ipfix_options_template"`) {
		t.Fatalf("expected IPFIX options template output, got:\n%s", result.Text)
	}
}

func TestFilePcapProducesPacketEvents(t *testing.T) {
	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("WriteFileHeader: %v", err)
	}
	packet := ethernetIPv4TCPPacket()
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Unix(1, 0).UTC(),
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: `
sources:
  - network: stream
    type: pcap
processor:
  type: builtin
encoder:
  type: json
  json:
    drop_fields: [header_data]
sink:
  type: stdout
`,
		Input: InputRequest{
			Mode: "file",
			Files: []InputFile{{
				Name: "sample.pcap",
				Data: base64.StdEncoding.EncodeToString(buf.Bytes()),
			}},
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !strings.Contains(result.Text, `"pcap_link_type_name":"Ethernet"`) || !strings.Contains(result.Text, `"src_addr":"192.0.2.1"`) {
		t.Fatalf("expected pcap packet fields, got:\n%s", result.Text)
	}
}

func TestImportCapturePcapCreatesPacketEntries(t *testing.T) {
	payload := []byte{0x00, 0x0a, 0x12, 0x34}
	packet := ethernetIPv4UDPPacket(t, payload)
	capturedAt := time.Unix(1714483200, 123000000).UTC()
	capture := pcapCapture(t, capturedAt, packet)

	result, err := ImportCapture(ImportCaptureRequest{
		Files: []InputFile{{
			Name: "sample.pcap",
			Data: base64.StdEncoding.EncodeToString(capture),
		}},
	})
	if err != nil {
		t.Fatalf("ImportCapture returned error: %v", err)
	}
	if result.Stats.Packets != 1 || result.Stats.Entries != 1 {
		t.Fatalf("expected one packet and one entry, got %#v", result.Stats)
	}
	entry := result.Entries[0]
	if entry.Type != "bytes" || entry.ReceivedAt != capturedAt.UnixMilli() || entry.Length != len(packet) {
		t.Fatalf("unexpected imported packet entry: %#v", entry)
	}
	decoded, err := base64.StdEncoding.DecodeString(entry.Payload)
	if err != nil {
		t.Fatalf("decode imported packet: %v", err)
	}
	if !bytes.Equal(decoded, packet) {
		t.Fatalf("expected full packet payload %x, got %x", packet, decoded)
	}
}

func TestImportCapturePayloadOnlyCreatesFlowEntries(t *testing.T) {
	payload := []byte{0x00, 0x0a, 0x12, 0x34, 0x56, 0x78}
	packet := ethernetIPv4UDPPacket(t, payload)
	capture := pcapCapture(t, time.Unix(1714483200, 0).UTC(), packet)

	result, err := ImportCapture(ImportCaptureRequest{
		Files: []InputFile{{
			Name: "sample.pcap",
			Data: base64.StdEncoding.EncodeToString(capture),
		}},
		PayloadOnly: true,
	})
	if err != nil {
		t.Fatalf("ImportCapture returned error: %v", err)
	}
	if result.Stats.Packets != 1 || result.Stats.Entries != 1 {
		t.Fatalf("expected one packet and one entry, got %#v", result.Stats)
	}
	entry := result.Entries[0]
	if entry.Type != "flow" || entry.Length != len(payload) {
		t.Fatalf("unexpected imported flow entry: %#v", entry)
	}
	decoded, err := base64.StdEncoding.DecodeString(entry.Payload)
	if err != nil {
		t.Fatalf("decode imported payload: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("expected application payload %x, got %x", payload, decoded)
	}
}

func TestWireViewCapturePassesThroughPcapOutput(t *testing.T) {
	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("WriteFileHeader: %v", err)
	}
	packet := ethernetIPv4TCPPacket()
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Unix(1, 0).UTC(),
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	result, err := formatOutput("pcap", outputCollector{payloads: timedPayloads(buf.Bytes())}, 1)
	if err != nil {
		t.Fatalf("formatOutput returned error: %v", err)
	}
	if result.WireView == nil || result.WireView.Filename != "reflow-output.pcap" {
		t.Fatalf("expected WireView pcap capture, got %#v", result.WireView)
	}
	if got, want := result.WireView.Timestamps, []int64{time.Unix(1, 0).UnixMilli()}; !equalInt64s(got, want) {
		t.Fatalf("expected WireView timestamps %v, got %v", want, got)
	}
	if got, want := result.WireView.Timeline, []WireViewPacketPoint{{Timestamp: time.Unix(1, 0).UnixMilli(), Type: "pcap packet"}}; !equalTimeline(got, want) {
		t.Fatalf("expected WireView timeline %v, got %v", want, got)
	}
	decoded, err := base64.StdEncoding.DecodeString(result.WireView.Base64)
	if err != nil {
		t.Fatalf("decode capture: %v", err)
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	if _, _, err := reader.ReadPacketData(); err != nil {
		t.Fatalf("read capture packet: %v", err)
	}
}

func TestWireViewCaptureFromPcapEncoderOutput(t *testing.T) {
	configYAML := strings.Replace(jsonAggregateConfig, "encoder:\n  type: json", "encoder:\n  type: pcap", 1)
	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: configYAML,
		Input: InputRequest{
			Mode: "json",
			Text: `[
{"src_addr":"192.0.2.1","dst_addr":"198.51.100.2","proto":6,"src_port":12345,"dst_port":443,"bytes":10,"packets":1,"start_time_unix":1,"end_time_unix":2},
{"src_addr":"192.0.2.1","dst_addr":"198.51.100.2","proto":6,"src_port":12345,"dst_port":443,"bytes":20,"packets":2,"start_time_unix":1,"end_time_unix":3}
]`,
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.WireView == nil || result.WireView.Filename != "reflow-output.pcap" {
		t.Fatalf("expected WireView pcap capture, got %#v", result.WireView)
	}
	if len(result.WireView.Timestamps) != 1 {
		t.Fatalf("expected one WireView timestamp, got %v", result.WireView.Timestamps)
	}
	if len(result.WireView.Timeline) != 1 || result.WireView.Timeline[0].Type != "pcap packet" {
		t.Fatalf("expected one pcap packet timeline point, got %v", result.WireView.Timeline)
	}
	decoded, err := base64.StdEncoding.DecodeString(result.WireView.Base64)
	if err != nil {
		t.Fatalf("decode capture: %v", err)
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	packetCount := 0
	for {
		if _, _, err := reader.ReadPacketData(); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("read capture packet %d: %v", packetCount+1, err)
		}
		packetCount++
	}
	if packetCount != 1 {
		t.Fatalf("expected one pcap packet, got %d", packetCount)
	}
}

func TestWireViewCaptureWrapsFlowDatagramsInPcap(t *testing.T) {
	payload := []byte{0, 0, 0, 5, 1, 2, 3, 4}
	receivedAt := time.Unix(1714483200, 123000000).UTC()
	result, err := formatOutput("sflow", outputCollector{payloads: []timedPayload{{Data: payload, ReceivedAt: receivedAt}}}, 1)
	if err != nil {
		t.Fatalf("formatOutput returned error: %v", err)
	}
	if result.WireView == nil || result.WireView.Filename != "reflow-sflow.pcap" {
		t.Fatalf("expected WireView sflow capture, got %#v", result.WireView)
	}
	if got, want := result.WireView.Timestamps, []int64{receivedAt.UnixMilli()}; !equalInt64s(got, want) {
		t.Fatalf("expected WireView timestamps %v, got %v", want, got)
	}
	if got, want := result.WireView.Timeline, []WireViewPacketPoint{{Timestamp: receivedAt.UnixMilli(), Type: "sflow data"}}; !equalTimeline(got, want) {
		t.Fatalf("expected WireView timeline %v, got %v", want, got)
	}
	decoded, err := base64.StdEncoding.DecodeString(result.WireView.Base64)
	if err != nil {
		t.Fatalf("decode capture: %v", err)
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	packetData, ci, err := reader.ReadPacketData()
	if err != nil {
		t.Fatalf("read capture packet: %v", err)
	}
	if !ci.Timestamp.Equal(receivedAt) {
		t.Fatalf("expected wrapped pcap timestamp %s, got %s", receivedAt, ci.Timestamp)
	}
	packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatalf("expected UDP layer in wrapped packet")
	}
	udp := udpLayer.(*layers.UDP)
	if udp.DstPort != 6343 || !bytes.Equal(udp.Payload, payload) {
		t.Fatalf("unexpected wrapped UDP datagram: dst=%d payload=%x", udp.DstPort, udp.Payload)
	}
}

func TestTimedIPFIXControlPacketsRefreshAndWireViewTimestamps(t *testing.T) {
	start := time.UnixMilli(1714483200123).UTC()
	second := start.Add(2500 * time.Millisecond)
	input, err := json.Marshal([]any{
		[]any{"json", map[string]any{
			"src_addr":        "192.0.2.1",
			"dst_addr":        "198.51.100.2",
			"proto":           6,
			"src_port":        12345,
			"dst_port":        443,
			"bytes":           10,
			"packets":         1,
			"start_time_unix": start.UnixMilli(),
			"end_time_unix":   start.UnixMilli(),
		}, start.UnixMilli()},
		[]any{"json", map[string]any{
			"src_addr":        "192.0.2.1",
			"dst_addr":        "198.51.100.2",
			"proto":           6,
			"src_port":        12345,
			"dst_port":        443,
			"bytes":           20,
			"packets":         2,
			"start_time_unix": start.UnixMilli(),
			"end_time_unix":   second.UnixMilli(),
		}, second.UnixMilli()},
	})
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	configYAML := strings.Replace(jsonAggregateConfig, "encoder:\n  type: json", `encoder:
  type: ipfix
  templated_flow:
    template_refresh_ms: 1000
    options_refresh_ms: 0`, 1)

	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: configYAML,
		Input:      InputRequest{Mode: "json", Text: string(input)},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.WireView == nil || result.WireView.Filename != "reflow-ipfix.pcap" {
		t.Fatalf("expected WireView IPFIX capture, got %#v", result.WireView)
	}
	if !containsTimelineType(result.WireView.Timeline, "ipfix template") || !containsTimelineType(result.WireView.Timeline, "ipfix data") {
		t.Fatalf("expected IPFIX timeline to include template and data points, got %v", result.WireView.Timeline)
	}

	templateTimes := ipfixTemplatePacketTimes(t, result.WireView.Base64)
	want := []time.Time{start, start.Add(time.Second), start.Add(2 * time.Second)}
	for _, expected := range want {
		if !containsUnixSecond(templateTimes, expected) {
			t.Fatalf("expected template/control packet at %s, got %v", expected, templateTimes)
		}
	}
}

func TestOutputLimitStopsScheduledPackets(t *testing.T) {
	start := time.UnixMilli(1714483200123).UTC()
	later := start.Add(10 * time.Second)
	input, err := json.Marshal([]any{
		[]any{"json", map[string]any{
			"src_addr":        "192.0.2.1",
			"dst_addr":        "198.51.100.2",
			"proto":           6,
			"src_port":        12345,
			"dst_port":        443,
			"bytes":           10,
			"packets":         1,
			"start_time_unix": start.UnixMilli(),
			"end_time_unix":   start.UnixMilli(),
		}, start.UnixMilli()},
		[]any{"json", map[string]any{
			"src_addr":        "192.0.2.1",
			"dst_addr":        "198.51.100.2",
			"proto":           6,
			"src_port":        12345,
			"dst_port":        443,
			"bytes":           20,
			"packets":         2,
			"start_time_unix": start.UnixMilli(),
			"end_time_unix":   later.UnixMilli(),
		}, later.UnixMilli()},
	})
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	limit := 3
	configYAML := strings.Replace(jsonAggregateConfig, "encoder:\n  type: json", `encoder:
  type: ipfix
  templated_flow:
    template_refresh_ms: 1000
    options_refresh_ms: 0`, 1)

	result, err := Run(t.Context(), RunRequest{
		ConfigYAML:  configYAML,
		Input:       InputRequest{Mode: "json", Text: string(input)},
		OutputLimit: &limit,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Stats.Outputs != limit || !result.Stats.Truncated || result.Stats.Limit != limit {
		t.Fatalf("expected truncated stats at limit %d, got %#v", limit, result.Stats)
	}
	if len(result.Payloads) != limit {
		t.Fatalf("expected %d payloads, got %d", limit, len(result.Payloads))
	}
	if result.WireView == nil || len(result.WireView.Timestamps) != limit {
		t.Fatalf("expected %d WireView timestamps, got %#v", limit, result.WireView)
	}
	if len(result.WireView.Timeline) != limit {
		t.Fatalf("expected %d WireView timeline points, got %#v", limit, result.WireView.Timeline)
	}
}

func TestNilOutputLimitDoesNotCapOutputs(t *testing.T) {
	inputs := make([]string, 0, 150)
	for i := 0; i < 150; i++ {
		inputs = append(inputs, fmt.Sprintf(`{"src_addr":"192.0.2.1","dst_addr":"198.51.100.2","proto":6,"src_port":%d,"dst_port":443,"bytes":10,"packets":1,"start_time_unix":1,"end_time_unix":2}`, 10000+i))
	}

	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: jsonAggregateConfig,
		Input: InputRequest{
			Mode: "json",
			Text: "[" + strings.Join(inputs, ",") + "]",
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Stats.Outputs <= 100 || result.Stats.Truncated || result.Stats.Limit != 0 {
		t.Fatalf("expected uncapped outputs for nil limit, got %#v", result.Stats)
	}
	if got := len(decodeOutputEvents(t, result.Text)); got <= 100 {
		t.Fatalf("expected more than 100 output events, got %d", got)
	}
}

func TestEncoderBatchFlushIntervalWithoutAggregationUsesSimulatedClock(t *testing.T) {
	start := time.UnixMilli(1714483200123).UTC()
	second := start.Add(2500 * time.Millisecond)
	input, err := json.Marshal([]any{
		[]any{"json", map[string]any{
			"src_addr":        "192.0.2.1",
			"dst_addr":        "198.51.100.2",
			"proto":           6,
			"src_port":        12345,
			"dst_port":        443,
			"bytes":           10,
			"packets":         1,
			"start_time_unix": start.UnixMilli(),
			"end_time_unix":   start.UnixMilli(),
		}, start.UnixMilli()},
		[]any{"json", map[string]any{
			"src_addr":        "192.0.2.1",
			"dst_addr":        "198.51.100.2",
			"proto":           6,
			"src_port":        12345,
			"dst_port":        443,
			"bytes":           20,
			"packets":         2,
			"start_time_unix": start.UnixMilli(),
			"end_time_unix":   second.UnixMilli(),
		}, second.UnixMilli()},
	})
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	configYAML := `
sources:
  - network: stream
    type: json
    json:
      flavor: reflow

processor:
  type: builtin

encoder:
  type: ipfix
  batch:
    enabled: true
    max_records: 100
    max_bytes: 4096
    flush_interval_ms: 1000

sink:
  type: stdout
`

	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: configYAML,
		Input:      InputRequest{Mode: "json", Text: string(input)},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.WireView == nil {
		t.Fatalf("expected WireView IPFIX capture")
	}
	if !containsTimelinePoint(result.WireView.Timeline, start.Add(time.Second), "ipfix template") {
		t.Fatalf("expected batched IPFIX flush at %s, got %v", start.Add(time.Second), result.WireView.Timeline)
	}
}

func TestTimedAggregationFlushUsesSimulatedClock(t *testing.T) {
	start := time.UnixMilli(1714483200123).UTC()
	second := start.Add(2500 * time.Millisecond)
	input, err := json.Marshal([]any{
		[]any{"json", map[string]any{
			"src_addr":        "192.0.2.1",
			"dst_addr":        "198.51.100.2",
			"proto":           6,
			"src_port":        12345,
			"dst_port":        443,
			"bytes":           10,
			"packets":         1,
			"start_time_unix": start.UnixMilli(),
			"end_time_unix":   start.UnixMilli(),
		}, start.UnixMilli()},
		[]any{"json", map[string]any{
			"src_addr":        "192.0.2.1",
			"dst_addr":        "198.51.100.2",
			"proto":           6,
			"src_port":        12345,
			"dst_port":        443,
			"bytes":           20,
			"packets":         2,
			"start_time_unix": start.UnixMilli(),
			"end_time_unix":   second.UnixMilli(),
		}, second.UnixMilli()},
	})
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	configYAML := strings.Replace(jsonAggregateConfig, "    window:\n      idle_flush_after_ms: 60000", `    periodic:
      every_ms: 1000`, 1)

	result, err := Run(t.Context(), RunRequest{
		ConfigYAML: configYAML,
		Input:      InputRequest{Mode: "json", Text: string(input)},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	events := decodeOutputEvents(t, result.Text)
	if !hasAggregateAt(events, start.Add(time.Second), 10) {
		t.Fatalf("expected periodic aggregate at %s with 10 bytes, got:\n%s", start.Add(time.Second), result.Text)
	}
}

func decodeOutputEvents(t *testing.T, text string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var evt map[string]any
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			t.Fatalf("decode output line %q: %v", line, err)
		}
		events = append(events, evt)
	}
	return events
}

func hasAggregateAt(events []map[string]any, at time.Time, bytes float64) bool {
	for _, evt := range events {
		if evt["stream"] != "flow_data" {
			continue
		}
		receivedAt, ok := evt["received_at"].(string)
		if !ok {
			continue
		}
		parsed, err := time.Parse(time.RFC3339Nano, receivedAt)
		if err != nil || !parsed.Equal(at) {
			continue
		}
		fields, ok := evt["fields"].(map[string]any)
		if ok && fields["bytes"] == bytes {
			return true
		}
	}
	return false
}

func timedPayloads(payloads ...[]byte) []timedPayload {
	out := make([]timedPayload, 0, len(payloads))
	for _, payload := range payloads {
		out = append(out, timedPayload{Data: payload})
	}
	return out
}

func ipfixTemplatePacketTimes(t *testing.T, captureBase64 string) []time.Time {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(captureBase64)
	if err != nil {
		t.Fatalf("decode capture: %v", err)
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	var times []time.Time
	for {
		packetData, ci, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				return times
			}
			t.Fatalf("read capture packet: %v", err)
		}
		packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp := udpLayer.(*layers.UDP)
		if len(udp.Payload) < 20 || binary.BigEndian.Uint16(udp.Payload[0:2]) != 10 {
			continue
		}
		if binary.BigEndian.Uint16(udp.Payload[16:18]) != 2 {
			continue
		}
		exportTime := time.Unix(int64(binary.BigEndian.Uint32(udp.Payload[4:8])), 0).UTC()
		if !ci.Timestamp.Equal(time.Unix(exportTime.Unix(), int64(ci.Timestamp.Nanosecond())).UTC()) {
			t.Fatalf("expected WireView timestamp to share IPFIX export second %s, got %s", exportTime, ci.Timestamp)
		}
		times = append(times, ci.Timestamp.UTC())
	}
}

func containsUnixSecond(times []time.Time, want time.Time) bool {
	for _, got := range times {
		if got.Unix() == want.Unix() {
			return true
		}
	}
	return false
}

func containsTimelineType(timeline []WireViewPacketPoint, want string) bool {
	for _, point := range timeline {
		if point.Type == want {
			return true
		}
	}
	return false
}

func containsTimelinePoint(timeline []WireViewPacketPoint, at time.Time, wantType string) bool {
	for _, point := range timeline {
		if point.Timestamp == at.UnixMilli() && point.Type == wantType {
			return true
		}
	}
	return false
}

func equalInt64s(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalTimeline(a, b []WireViewPacketPoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hexLines(data []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(data)*2)
	for i, b := range data {
		out[i*2] = alphabet[b>>4]
		out[i*2+1] = alphabet[b&0x0f]
	}
	return string(out)
}

func ethernetIPv4TCPPacket() []byte {
	return []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00,
		0xc0, 0x00, 0x02, 0x01,
		0xc6, 0x33, 0x64, 0x02,
		0x30, 0x39, 0x00, 0x50,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02, 0x20, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
}

func ethernetIPv4UDPPacket(t *testing.T, payload []byte) []byte {
	t.Helper()
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{192, 0, 2, 1},
		DstIP:    net.IP{198, 51, 100, 2},
	}
	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 2055,
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("SetNetworkLayerForChecksum: %v", err)
	}
	var buf gopacket.SerializeBuffer
	buf = gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethernet,
		ip,
		udp,
		gopacket.Payload(payload),
	); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return buf.Bytes()
}

func pcapCapture(t *testing.T, capturedAt time.Time, packets ...[]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("WriteFileHeader: %v", err)
	}
	for _, packet := range packets {
		if err := writer.WritePacket(gopacket.CaptureInfo{
			Timestamp:     capturedAt,
			CaptureLength: len(packet),
			Length:        len(packet),
		}, packet); err != nil {
			t.Fatalf("WritePacket: %v", err)
		}
	}
	return buf.Bytes()
}
