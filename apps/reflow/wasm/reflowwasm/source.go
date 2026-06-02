package reflowwasm

import (
	"strings"
	"time"

	"github.com/netsampler/goflow2/v3/pkg/reflow/config"
	"github.com/netsampler/goflow2/v3/pkg/reflow/event"
)

// sourceInitEvents builds the same control metadata a live source would emit,
// but anchored to the browser run's simulated timeline.
func sourceInitEvents(src config.SourceConfig) []*event.Event {
	return sourceInitEventsAt(src, time.Now().UTC())
}

func sourceInitEventsAt(src config.SourceConfig, now time.Time) []*event.Event {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	meta := sourceMetadata(src, src.Type)
	meta.CaptureInterface = streamInterfaceName(src.Address)
	payload := event.SourceInit{Stream: src.Type}
	if src.SourceID != nil {
		payload.SourceID = *src.SourceID
	}
	return []*event.Event{{
		ReceivedAt: now,
		Kind:       "control",
		Source:     meta,
		Control: &event.ControlMetadata{
			Type:   "source_init",
			Stream: src.Type,
		},
		Fields: map[string]any{
			"stream_type": src.Type,
		},
		Payload: payload,
	}}
}

// simulatedStartTime seeds the finite run with the first input timestamp when
// the caller supplied one, falling back to now for untimed inputs.
func simulatedStartTime(events []*event.Event) time.Time {
	for _, evt := range events {
		if evt != nil && !evt.ReceivedAt.IsZero() {
			return evt.ReceivedAt.UTC()
		}
	}
	return time.Now().UTC()
}

// simulatedEndTime is the final instant that scheduled flushes should replay
// before aggregators and encoders are closed.
func simulatedEndTime(events []*event.Event, fallback time.Time) time.Time {
	out := fallback
	for _, evt := range events {
		if evt == nil || evt.ReceivedAt.IsZero() {
			continue
		}
		if out.IsZero() || evt.ReceivedAt.After(out) {
			out = evt.ReceivedAt.UTC()
		}
	}
	if out.IsZero() {
		return time.Now().UTC()
	}
	return out
}

func stampEventTime(evt *event.Event, at time.Time, force bool) {
	if evt == nil || at.IsZero() {
		return
	}
	if force || evt.ReceivedAt.IsZero() {
		evt.ReceivedAt = at.UTC()
	}
}

func eventTimeOr(evt *event.Event, fallback time.Time) time.Time {
	if evt != nil && !evt.ReceivedAt.IsZero() {
		return evt.ReceivedAt.UTC()
	}
	if !fallback.IsZero() {
		return fallback.UTC()
	}
	return time.Now().UTC()
}

func sourceMetadata(src config.SourceConfig, sourceType string) event.SourceMetadata {
	meta := event.SourceMetadata{
		Network: src.Network,
		Address: src.Address,
		Type:    sourceType,
	}
	if src.SourceID != nil {
		meta.SourceID = *src.SourceID
		meta.SourceIDSet = true
	}
	return meta
}

func streamInterfaceName(address string) string {
	if address == "" || address == "-" {
		return "browser"
	}
	parts := strings.FieldsFunc(address, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	if len(parts) == 0 {
		return address
	}
	return parts[len(parts)-1]
}
