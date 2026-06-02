package goflow2wasm

type RunRequest struct {
	Command     string       `json:"command"`
	MappingYAML string       `json:"mappingYaml"`
	Capture     CaptureInput `json:"capture"`
	Options     RunOptions   `json:"options"`
}

type RunOptions struct {
	Scheme          string `json:"scheme"`
	Produce         string `json:"produce"`
	Format          string `json:"format"`
	UseMapping      bool   `json:"useMapping,omitempty"`
	ProtobufFraming string `json:"protobufFraming,omitempty"`
}

type CaptureInput struct {
	Name       string        `json:"name"`
	Data       string        `json:"data"`
	MimeType   string        `json:"mimeType"`
	ImportType string        `json:"importType,omitempty"`
	Packets    []PacketInput `json:"packets,omitempty"`
}

type PacketInput struct {
	Frame       int    `json:"frame,omitempty"`
	Type        string `json:"type,omitempty"`
	Hex         string `json:"hex"`
	LinkType    int    `json:"linkType,omitempty"`
	ReceivedAt  string `json:"receivedAt,omitempty"`
	CapturedLen int    `json:"capturedLen,omitempty"`
	OriginalLen int    `json:"originalLen,omitempty"`
	Src         string `json:"src,omitempty"`
	Dst         string `json:"dst,omitempty"`
}

type CaptureInspectResult struct {
	Name     string        `json:"name"`
	MimeType string        `json:"mimeType"`
	Packets  []PacketInput `json:"packets"`
	Stats    RunStats      `json:"stats"`
	Warnings []string      `json:"warnings,omitempty"`
}

type RunResult struct {
	Command  CommandConfig `json:"command"`
	Entries  []OutputEntry `json:"entries"`
	Stats    RunStats      `json:"stats"`
	Logs     []string      `json:"logs,omitempty"`
	Warnings []string      `json:"warnings,omitempty"`
}

type CommandConfig struct {
	Scheme          string `json:"scheme"`
	Produce         string `json:"produce"`
	Format          string `json:"format"`
	UseMapping      bool   `json:"useMapping"`
	ProtobufFraming string `json:"protobufFraming,omitempty"`
}

type OutputEntry struct {
	Index     int         `json:"index"`
	Protocol  string      `json:"protocol"`
	Key       string      `json:"key,omitempty"`
	JSON      string      `json:"json,omitempty"`
	Parsed    interface{} `json:"parsed,omitempty"`
	ProtoHex  string      `json:"protoHex,omitempty"`
	ProtoB64  string      `json:"protoBase64,omitempty"`
	ProtoSize int         `json:"protoSize,omitempty"`
	Source    PacketMeta  `json:"source"`
}

type PacketMeta struct {
	Frame      int    `json:"frame"`
	Src        string `json:"src"`
	Dst        string `json:"dst"`
	ReceivedAt string `json:"receivedAt"`
	PayloadLen int    `json:"payloadLen"`
}

type RunStats struct {
	Frames          int   `json:"frames"`
	UDPDatagrams    int   `json:"udpDatagrams"`
	Decoded         int   `json:"decoded"`
	Outputs         int   `json:"outputs"`
	Skipped         int   `json:"skipped"`
	Errors          int   `json:"errors"`
	TotalElapsedNs  int64 `json:"totalElapsedNs,omitempty"`
	NsPerPacket     int64 `json:"nsPerPacket,omitempty"`
	DecodeElapsedNs int64 `json:"decodeElapsedNs,omitempty"`
}

type udpDatagram struct {
	meta    PacketMeta
	payload []byte
}
