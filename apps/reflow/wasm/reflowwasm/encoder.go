package reflowwasm

import (
	"encoding/binary"
	"time"

	"github.com/netsampler/goflow2/v3/pkg/reflow/config"
)

func encoderBatchFlushInterval(cfg config.EncoderConfig) time.Duration {
	if !cfg.Batch.IsEnabled() || cfg.Batch.FlushInterval <= 0 {
		return 0
	}
	switch cfg.Type {
	case "ipfix", "netflowv9", "sflow":
	default:
		return 0
	}
	return time.Duration(cfg.Batch.FlushInterval) * time.Millisecond
}

func encoderUsesInitControls(encoderType string) bool {
	switch encoderType {
	case "", "json", "ipfix", "netflowv9":
		return true
	default:
		return false
	}
}

// refreshPayloads records template/options datagrams that must be re-emitted
// on the simulated clock for collectors that expect periodic refreshes.
func refreshPayloads(cfg config.EncoderConfig, payloads [][]byte, receivedAt time.Time) []refreshPayload {
	if receivedAt.IsZero() {
		return nil
	}
	var out []refreshPayload
	for _, payload := range payloads {
		kind := templatedControlPayloadKind(cfg.Type, payload)
		var interval time.Duration
		switch kind {
		case "template":
			interval = time.Duration(cfg.TemplatedFlow.TemplateRefresh) * time.Millisecond
		case "options":
			interval = time.Duration(cfg.TemplatedFlow.OptionsRefresh) * time.Millisecond
		}
		if interval <= 0 {
			continue
		}
		out = append(out, refreshPayload{
			Data:       append([]byte(nil), payload...),
			NextAt:     receivedAt.Add(interval),
			Interval:   interval,
			EncoderTyp: cfg.Type,
		})
	}
	return out
}

func templatedControlPayloadKind(encoderType string, payload []byte) string {
	switch encoderType {
	case "ipfix":
		if len(payload) < 20 || binary.BigEndian.Uint16(payload[0:2]) != 10 {
			return ""
		}
		return ipfixControlPayloadKind(payload[16:])
	case "netflowv9":
		if len(payload) < 24 || binary.BigEndian.Uint16(payload[0:2]) != 9 {
			return ""
		}
		return nfv9ControlPayloadKind(payload[20:])
	default:
		return ""
	}
}

func ipfixControlPayloadKind(sets []byte) string {
	kind := ""
	for len(sets) >= 4 {
		setID := binary.BigEndian.Uint16(sets[0:2])
		setLen := int(binary.BigEndian.Uint16(sets[2:4]))
		if setLen < 4 || setLen > len(sets) {
			break
		}
		switch setID {
		case 2:
			kind = "template"
		case 3:
			return "options"
		}
		sets = sets[setLen:]
	}
	return kind
}

func nfv9ControlPayloadKind(sets []byte) string {
	kind := ""
	for len(sets) >= 4 {
		setID := binary.BigEndian.Uint16(sets[0:2])
		setLen := int(binary.BigEndian.Uint16(sets[2:4]))
		if setLen < 4 || setLen > len(sets) {
			break
		}
		switch setID {
		case 0:
			kind = "template"
		case 1:
			return "options"
		}
		sets = sets[setLen:]
	}
	return kind
}

// timestampEncodedPayload patches protocol export timestamps after encoding so
// browser output reflects input time rather than the host's wall clock.
func timestampEncodedPayload(encoderType string, payload []byte, receivedAt time.Time) []byte {
	out := append([]byte(nil), payload...)
	if receivedAt.IsZero() {
		return out
	}
	switch encoderType {
	case "ipfix":
		if len(out) >= 8 && binary.BigEndian.Uint16(out[0:2]) == 10 {
			binary.BigEndian.PutUint32(out[4:8], uint32(receivedAt.Unix()))
		}
	case "netflowv9":
		if len(out) >= 12 && binary.BigEndian.Uint16(out[0:2]) == 9 {
			binary.BigEndian.PutUint32(out[8:12], uint32(receivedAt.Unix()))
		}
	case "netflowv5":
		if len(out) >= 16 && binary.BigEndian.Uint16(out[0:2]) == 5 {
			binary.BigEndian.PutUint32(out[8:12], uint32(receivedAt.Unix()))
			binary.BigEndian.PutUint32(out[12:16], uint32(receivedAt.Nanosecond()))
		}
	}
	return out
}
