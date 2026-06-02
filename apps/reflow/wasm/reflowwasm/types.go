package reflowwasm

import (
	"encoding/json"
	"time"

	"github.com/netsampler/goflow2/v3/pkg/reflow/aggregate"
	"github.com/netsampler/goflow2/v3/pkg/reflow/config"
)

// RunRequest is the browser-facing request envelope for one finite run.
type RunRequest struct {
	ConfigYAML   string       `json:"configYaml"`
	Input        InputRequest `json:"input"`
	OutputLimit  *int         `json:"outputLimit,omitempty"`
	NativeBinary bool         `json:"-"`
}

// ImportCaptureRequest asks the WASM runtime to explode capture files into
// browser input entries without running the ReFlow pipeline.
type ImportCaptureRequest struct {
	Files        []InputFile `json:"files"`
	Format       string      `json:"format,omitempty"`
	PayloadOnly  bool        `json:"payloadOnly,omitempty"`
	NativeBinary bool        `json:"-"`
}

// InputRequest describes how browser input should be converted into ReFlow
// source events before the decode stage.
type InputRequest struct {
	Mode     string       `json:"mode"`
	Text     string       `json:"text"`
	Encoding string       `json:"encoding"`
	Files    []InputFile  `json:"files"`
	Entries  []InputEntry `json:"-"`
}

// InputFile carries a browser-selected file as base64 so it survives the JSON
// bridge into WASM.
type InputFile struct {
	Name  string `json:"name"`
	Data  string `json:"data"`
	Bytes []byte `json:"-"`
}

// InputEntry carries browser input that has already crossed the JS boundary as
// bytes, avoiding a base64 JSON tuple for large payloads.
type InputEntry struct {
	Type       string          `json:"-"`
	Payload    []byte          `json:"-"`
	JSON       json.RawMessage `json:"-"`
	ReceivedAt time.Time       `json:"-"`
	Label      string          `json:"-"`
}

// ImportCaptureResult is returned to JavaScript after a pcap/pcapng import.
type ImportCaptureResult struct {
	Entries []ImportedInputEntry `json:"entries"`
	Stats   ImportCaptureStats   `json:"stats"`
}

// ImportedInputEntry is the normalized entry shape used by the browser editor.
type ImportedInputEntry struct {
	Type       string `json:"type"`
	Payload    string `json:"payload"`
	Bytes      []byte `json:"-"`
	ReceivedAt int64  `json:"receivedAt,omitempty"`
	Length     int    `json:"length"`
}

// ImportCaptureStats reports how many capture packets were read and retained.
type ImportCaptureStats struct {
	Packets int `json:"packets"`
	Entries int `json:"entries"`
}

// RunResult is the serialized output returned to JavaScript.
type RunResult struct {
	Kind        string           `json:"kind"`
	EncoderType string           `json:"encoderType,omitempty"`
	Text        string           `json:"text,omitempty"`
	Payloads    []OutputPayload  `json:"payloads,omitempty"`
	WireView    *WireViewCapture `json:"wireview,omitempty"`
	Stats       RunStats         `json:"stats"`
}

// RunStats reports the amount of input consumed and output retained.
type RunStats struct {
	Inputs         int   `json:"inputs"`
	Outputs        int   `json:"outputs"`
	Limit          int   `json:"limit,omitempty"`
	Truncated      bool  `json:"truncated,omitempty"`
	TotalElapsedNs int64 `json:"totalElapsedNs,omitempty"`
	NsPerPacket    int64 `json:"nsPerPacket,omitempty"`
}

// OutputPayload exposes binary encoder output in both inspection-friendly and
// transport-friendly forms.
type OutputPayload struct {
	Length int    `json:"length"`
	Hex    string `json:"hex"`
	Base64 string `json:"base64"`
	Bytes  []byte `json:"-"`
}

// WireViewCapture is an optional packet capture that the UI can hand to the
// embedded WireView frame for packet-level inspection.
type WireViewCapture struct {
	Filename   string                `json:"filename"`
	MimeType   string                `json:"mimeType"`
	Base64     string                `json:"base64"`
	Bytes      []byte                `json:"-"`
	Timestamps []int64               `json:"timestamps,omitempty"`
	Timeline   []WireViewPacketPoint `json:"timeline,omitempty"`
}

// WireViewPacketPoint is a coarse timeline entry for a packet or datagram in a
// generated capture.
type WireViewPacketPoint struct {
	Timestamp int64  `json:"timestamp"`
	Type      string `json:"type"`
}

type worker struct {
	cfg          config.AggregatorConfig
	agg          aggregate.Aggregator
	nextFlushAt  time.Time
	clockOffset  time.Duration
	clockAligned bool
}

type timedPayload struct {
	Data       []byte
	ReceivedAt time.Time
}

type refreshPayload struct {
	Data       []byte
	NextAt     time.Time
	Interval   time.Duration
	EncoderTyp string
}

type outputCollector struct {
	payloads  []timedPayload
	limit     int
	truncated bool
}
