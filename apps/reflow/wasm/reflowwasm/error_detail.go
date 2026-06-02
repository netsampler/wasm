package reflowwasm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/netsampler/goflow2/v3/pkg/reflow/config"
	"github.com/netsampler/goflow2/v3/pkg/reflow/event"
)

func encodeEventError(cfg config.EncoderConfig, evt *event.Event, err error) error {
	if err == nil {
		return nil
	}
	if cfg.Type != "pcap" && cfg.Type != "pcapng" {
		return fmt.Errorf("encode event: %w", err)
	}
	text := err.Error()
	if !strings.Contains(text, "missing packet bytes") &&
		!strings.Contains(text, "missing header_data") &&
		!strings.Contains(text, "missing payload bytes") &&
		!strings.Contains(text, "cannot build pseudo packet") {
		return fmt.Errorf("encode event: %w", err)
	}
	return fmt.Errorf("encode event: %w (%s)", err, pcapEncodeDiagnostic(cfg, evt))
}

func pcapEncodeDiagnostic(cfg config.EncoderConfig, evt *event.Event) string {
	var parts []string
	parts = append(parts,
		"pcap encoder needs packet bytes or enough tuple fields to synthesize a pseudo packet",
		"encoder="+cfg.Type,
		"packet_source="+emptyAs(cfg.Pcap.PacketSource, "auto"),
	)
	if evt == nil {
		return strings.Join(append(parts, "event=nil"), "; ")
	}
	parts = append(parts,
		"source.type="+emptyAs(evt.Source.Type, "<empty>"),
		"source.network="+emptyAs(evt.Source.Network, "<empty>"),
		"stream="+emptyAs(evt.Stream, "<empty>"),
		"kind="+emptyAs(evt.Kind, "data"),
		fmt.Sprintf("has_header_data=%t", packetHeaderDataLen(evt.Fields) > 0),
		fmt.Sprintf("payload_bytes=%d", payloadBytesLen(evt.Payload)),
		"tuple_fields="+missingTupleFields(evt.Fields),
	)
	if len(evt.Fields) > 0 {
		parts = append(parts, "available_fields="+availableFieldList(evt.Fields, 18))
	}
	return strings.Join(parts, "; ")
}

func packetHeaderDataLen(fields map[string]any) int {
	if len(fields) == 0 {
		return 0
	}
	if data := bytesLikeLen(fields["header_data"]); data > 0 {
		return data
	}
	if text, ok := fields["header_hex"].(string); ok {
		return len(strings.TrimSpace(text))
	}
	return 0
}

func payloadBytesLen(payload any) int {
	return bytesLikeLen(payload)
}

func bytesLikeLen(value any) int {
	switch v := value.(type) {
	case []byte:
		return len(v)
	case string:
		return len(v)
	default:
		return 0
	}
}

func missingTupleFields(fields map[string]any) string {
	required := []string{"src_addr", "dst_addr", "proto"}
	var missing []string
	for _, key := range required {
		if !hasNonZeroField(fields, key) {
			missing = append(missing, key)
		}
	}
	if len(missing) == 0 {
		return "present"
	}
	return "missing " + strings.Join(missing, ",")
}

func hasNonZeroField(fields map[string]any, key string) bool {
	if len(fields) == 0 {
		return false
	}
	value, ok := fields[key]
	if !ok || value == nil {
		return false
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case []byte:
		return len(v) > 0
	case uint8, uint16, uint32, uint64, uint, int8, int16, int32, int64, int:
		return fmt.Sprint(v) != "0"
	default:
		return true
	}
}

func availableFieldList(fields map[string]any, limit int) string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if limit > 0 && len(keys) > limit {
		keys = append(keys[:limit], fmt.Sprintf("...+%d", len(keys)-limit))
	}
	if len(keys) == 0 {
		return "<none>"
	}
	return strings.Join(keys, ",")
}

func emptyAs(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
