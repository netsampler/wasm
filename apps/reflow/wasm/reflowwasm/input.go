package reflowwasm

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/netsampler/goflow2/v3/pkg/reflow/config"
	"github.com/netsampler/goflow2/v3/pkg/reflow/event"
)

// buildInputEvents normalizes each browser input mode into source events that
// can be decoded by the same ReFlow code paths used outside WASM.
func buildInputEvents(sources []config.SourceConfig, input InputRequest) ([]*event.Event, error) {
	switch input.Mode {
	case "", "json":
		return jsonInputEvents(sources, []byte(input.Text))
	case "entries":
		return directInputEntryEvents(sources, input.Entries)
	case "bytes":
		data, err := decodeTextBytes(input.Text, input.Encoding)
		if err != nil {
			return nil, err
		}
		src, err := sourceForBytesInput(sources)
		if err != nil {
			return nil, err
		}
		return binaryInputEvents(src, data, "pasted bytes")
	case "file":
		src, err := sourceForInputType(sources, "")
		if err != nil {
			return nil, err
		}
		return fileInputEvents(src, input.Files)
	default:
		return nil, fmt.Errorf("unsupported input.mode %q", input.Mode)
	}
}

// jsonInputEvents accepts JSON objects, JSON arrays, NDJSON, and typed tuples.
// Tuples allow a single request to mix source types and explicit timestamps.
func jsonInputEvents(sources []config.SourceConfig, raw []byte) ([]*event.Event, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, nil
	}
	var records []json.RawMessage
	if raw[0] == '[' {
		if isJSONTupleRecord(raw) {
			records = append(records, append(json.RawMessage(nil), raw...))
		} else if err := json.Unmarshal(raw, &records); err != nil {
			return nil, fmt.Errorf("decode JSON array: %w", err)
		}
	} else if raw[0] == '{' {
		if !json.Valid(raw) {
			return nil, fmt.Errorf("decode JSON object: invalid JSON")
		}
		records = append(records, append(json.RawMessage(nil), raw...))
	} else {
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			if !json.Valid(line) {
				return nil, fmt.Errorf("decode NDJSON: invalid JSON line")
			}
			records = append(records, append(json.RawMessage(nil), line...))
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("read NDJSON: %w", err)
		}
	}
	return jsonRecordInputEvents(sources, records)
}

func jsonRecordInputEvents(sources []config.SourceConfig, records []json.RawMessage) ([]*event.Event, error) {
	events := make([]*event.Event, 0, len(records))
	for i, record := range records {
		record = bytes.TrimSpace(record)
		if len(record) == 0 {
			continue
		}
		switch record[0] {
		case '{':
			jsonSrc, err := sourceForInputType(sources, "json")
			if err != nil {
				return nil, fmt.Errorf("decode JSON entry %d: %w", i+1, err)
			}
			events = append(events, jsonMessageInputEvent(jsonSrc, record, time.Now().UTC()))
		case '[':
			tupleEvents, err := jsonTupleInputEvents(sources, record)
			if err != nil {
				return nil, fmt.Errorf("decode JSON tuple entry %d: %w", i+1, err)
			}
			events = append(events, tupleEvents...)
		default:
			return nil, fmt.Errorf("decode JSON entry %d: expected object or [type, payload, received_at?] tuple", i+1)
		}
	}
	return events, nil
}

func isJSONTupleRecord(raw json.RawMessage) bool {
	var tuple []json.RawMessage
	if err := json.Unmarshal(raw, &tuple); err != nil || (len(tuple) != 2 && len(tuple) != 3) {
		return false
	}
	var sourceType string
	return json.Unmarshal(tuple[0], &sourceType) == nil && strings.TrimSpace(sourceType) != ""
}

// jsonTupleInputEvents decodes [type, payload, received_at?] entries. JSON
// payloads stay as JSON; binary-like payloads are base64-decoded.
func jsonTupleInputEvents(sources []config.SourceConfig, raw json.RawMessage) ([]*event.Event, error) {
	var tuple []json.RawMessage
	if err := json.Unmarshal(raw, &tuple); err != nil {
		return nil, err
	}
	if len(tuple) != 2 && len(tuple) != 3 {
		return nil, fmt.Errorf("expected [type, payload, received_at?] tuple")
	}
	var sourceType string
	if err := json.Unmarshal(tuple[0], &sourceType); err != nil {
		return nil, fmt.Errorf("decode tuple type: %w", err)
	}
	tupleSrc, err := sourceForInputType(sources, sourceType)
	if err != nil {
		return nil, err
	}
	receivedAt := time.Now().UTC()
	if len(tuple) == 3 {
		receivedAt, err = parseTupleReceivedAt(tuple[2])
		if err != nil {
			return nil, fmt.Errorf("decode tuple received_at: %w", err)
		}
	}
	if tupleSrc.Type == "json" {
		payload := bytes.TrimSpace(tuple[1])
		if len(payload) == 0 || !json.Valid(payload) {
			return nil, fmt.Errorf("decode tuple JSON payload: invalid JSON")
		}
		return []*event.Event{jsonMessageInputEvent(tupleSrc, payload, receivedAt)}, nil
	}
	var encoded string
	if err := json.Unmarshal(tuple[1], &encoded); err != nil {
		return nil, fmt.Errorf("decode tuple base64 payload: %w", err)
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode tuple base64 payload: %w", err)
	}
	return binaryInputEventsAt(tupleSrc, [][]byte{data}, "JSON tuple "+tupleSrc.Type, receivedAt)
}

func jsonMessageInputEvent(src config.SourceConfig, message json.RawMessage, receivedAt time.Time) *event.Event {
	return &event.Event{
		ReceivedAt: receivedAt,
		Source: func() event.SourceMetadata {
			meta := sourceMetadata(src, "json")
			meta.JSON = event.JSONMetadata{Flavor: src.JSON.Flavor}
			return meta
		}(),
		Message: append(json.RawMessage(nil), message...),
	}
}

// parseTupleReceivedAt accepts the timestamp forms that are convenient from
// JavaScript callers: unix milliseconds, RFC3339 strings, or small objects.
func parseTupleReceivedAt(raw json.RawMessage) (time.Time, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return time.Now().UTC(), nil
	}
	var unixMS int64
	if err := json.Unmarshal(raw, &unixMS); err == nil {
		return time.UnixMilli(unixMS).UTC(), nil
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return parseReceivedAtString(text)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return time.Time{}, err
	}
	for _, key := range []string{"received_at_unix_ms", "time_unix_ms", "unix_ms"} {
		if val, ok := obj[key]; ok {
			return parseTupleReceivedAt(val)
		}
	}
	for _, key := range []string{"received_at_unix", "time_unix", "unix"} {
		if val, ok := obj[key]; ok {
			var sec int64
			if err := json.Unmarshal(val, &sec); err != nil {
				return time.Time{}, err
			}
			return time.Unix(sec, 0).UTC(), nil
		}
	}
	for _, key := range []string{"received_at", "time"} {
		if val, ok := obj[key]; ok {
			return parseTupleReceivedAt(val)
		}
	}
	return time.Time{}, fmt.Errorf("expected unix milliseconds, RFC3339 string, or received_at object")
}

func parseReceivedAtString(text string) (time.Time, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return time.Now().UTC(), nil
	}
	if unixMS, err := strconv.ParseInt(text, 10, 64); err == nil {
		return time.UnixMilli(unixMS).UTC(), nil
	}
	receivedAt, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return time.Time{}, err
	}
	return receivedAt.UTC(), nil
}

func sourceForInputType(sources []config.SourceConfig, inputType string) (config.SourceConfig, error) {
	normalized := strings.ToLower(strings.TrimSpace(inputType))
	if normalized == "" {
		if len(sources) == 0 {
			return config.SourceConfig{}, fmt.Errorf("no sources configured")
		}
		return sources[0], nil
	}
	for _, src := range sources {
		if src.Type == normalized {
			return src, nil
		}
	}
	return config.SourceConfig{}, fmt.Errorf("no stream source configured for input type %q", normalized)
}

func sourceForBytesInput(sources []config.SourceConfig) (config.SourceConfig, error) {
	if src, err := sourceForInputType(sources, "bytes"); err == nil {
		return src, nil
	}
	return sourceForInputType(sources, "flow")
}

func decodeTextBytes(text, encoding string) ([][]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "hex":
		var out [][]byte
		for _, line := range nonEmptyLines(text) {
			cleaned := strings.NewReplacer(" ", "", ":", "", "-", "", "0x", "", "0X", "").Replace(line)
			data, err := hex.DecodeString(cleaned)
			if err != nil {
				return nil, fmt.Errorf("decode hex bytes: %w", err)
			}
			out = append(out, data)
		}
		return out, nil
	case "base64":
		var out [][]byte
		for _, line := range nonEmptyLines(text) {
			data, err := base64.StdEncoding.DecodeString(line)
			if err != nil {
				return nil, fmt.Errorf("decode base64 bytes: %w", err)
			}
			out = append(out, data)
		}
		return out, nil
	case "text":
		if text == "" {
			return nil, nil
		}
		return [][]byte{[]byte(text)}, nil
	default:
		return nil, fmt.Errorf("unsupported bytes encoding %q", encoding)
	}
}

func nonEmptyLines(text string) []string {
	var out []string
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func fileInputEvents(src config.SourceConfig, files []InputFile) ([]*event.Event, error) {
	var out []*event.Event
	for _, file := range files {
		data := file.Bytes
		if len(data) == 0 && file.Data != "" {
			decoded, err := base64.StdEncoding.DecodeString(file.Data)
			if err != nil {
				return nil, fmt.Errorf("decode file %q: %w", file.Name, err)
			}
			data = decoded
		}
		events, err := binaryInputEvents(src, [][]byte{data}, file.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, events...)
	}
	return out, nil
}

func directInputEntryEvents(sources []config.SourceConfig, entries []InputEntry) ([]*event.Event, error) {
	var out []*event.Event
	for i, entry := range entries {
		sourceType := strings.ToLower(strings.TrimSpace(entry.Type))
		if sourceType == "" {
			sourceType = "json"
		}
		src, err := sourceForInputType(sources, sourceType)
		if err != nil {
			return nil, fmt.Errorf("decode entry %d: %w", i+1, err)
		}
		if src.Type == "json" {
			payload := bytes.TrimSpace(entry.JSON)
			if len(payload) == 0 {
				payload = bytes.TrimSpace(entry.Payload)
			}
			if len(payload) == 0 || !json.Valid(payload) {
				return nil, fmt.Errorf("decode entry %d JSON payload: invalid JSON", i+1)
			}
			receivedAt := entry.ReceivedAt
			if receivedAt.IsZero() {
				receivedAt = time.Now().UTC()
			}
			out = append(out, jsonMessageInputEvent(src, payload, receivedAt))
			continue
		}
		label := strings.TrimSpace(entry.Label)
		if label == "" {
			label = "entry " + strconv.Itoa(i+1)
		}
		events, err := binaryInputEventsAt(src, [][]byte{entry.Payload}, label, entry.ReceivedAt)
		if err != nil {
			return nil, fmt.Errorf("decode entry %d: %w", i+1, err)
		}
		out = append(out, events...)
	}
	return out, nil
}

func binaryInputEvents(src config.SourceConfig, chunks [][]byte, label string) ([]*event.Event, error) {
	return binaryInputEventsAt(src, chunks, label, time.Time{})
}

// binaryInputEventsAt handles raw bytes, flow datagrams, and capture files once
// the browser transport layer has decoded them from text or base64.
func binaryInputEventsAt(src config.SourceConfig, chunks [][]byte, label string, receivedAt time.Time) ([]*event.Event, error) {
	switch src.Type {
	case "json":
		var out []*event.Event
		for _, chunk := range chunks {
			events, err := jsonInputEvents([]config.SourceConfig{src}, chunk)
			if err != nil {
				return nil, fmt.Errorf("decode %s as JSON: %w", label, err)
			}
			out = append(out, events...)
		}
		return out, nil
	case "pcap":
		return readPcapEvents(src, chunks, label, false)
	case "pcapng":
		return readPcapEvents(src, chunks, label, true)
	case "bytes", "flow":
		out := make([]*event.Event, 0, len(chunks))
		for _, chunk := range chunks {
			if len(chunk) == 0 {
				continue
			}
			eventTime := receivedAt
			if eventTime.IsZero() {
				eventTime = time.Now().UTC()
			}
			out = append(out, &event.Event{
				ReceivedAt: eventTime,
				Source:     sourceMetadata(src, src.Type),
				Payload:    append([]byte(nil), chunk...),
			})
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported source.type %q", src.Type)
	}
}
