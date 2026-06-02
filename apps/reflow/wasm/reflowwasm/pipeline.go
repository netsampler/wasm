package reflowwasm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/netsampler/goflow2/v3/pkg/reflow/config"
	"github.com/netsampler/goflow2/v3/pkg/reflow/decode"
	"github.com/netsampler/goflow2/v3/pkg/reflow/encode"
	"github.com/netsampler/goflow2/v3/pkg/reflow/event"
	"github.com/netsampler/goflow2/v3/pkg/reflow/processor"
)

// RunJSON is the JSON boundary used by the browser-facing syscall/js wrapper.
func RunJSON(raw []byte) ([]byte, error) {
	var req RunRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("decode request: %w", err)
	}
	result, err := Run(context.Background(), req)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("encode result: %w", err)
	}
	return data, nil
}

// Run executes one finite browser batch through the ReFlow decode, processor,
// aggregation, and encode stages. It deliberately does not start sources, sinks,
// goroutines, or timers.
func Run(ctx context.Context, req RunRequest) (*RunResult, error) {
	runStarted := time.Now()
	cfg, err := config.LoadBytes("browser.yaml", []byte(req.ConfigYAML))
	if err != nil {
		return nil, err
	}
	if err := validateBrowserConfig(cfg); err != nil {
		return nil, err
	}

	sourceCfgs := cfg.Sources
	decoder := decode.NewWithCatalog(cfg.TemplatedFields.Catalog)
	defer decoder.Close()

	proc, err := processor.New(cfg.Processor)
	if err != nil {
		return nil, fmt.Errorf("init processor: %w", err)
	}
	enc, err := encode.New(cfg.Encoder)
	if err != nil {
		return nil, fmt.Errorf("init encoder: %w", err)
	}
	aggregateWorkers, err := initAggregators(cfg.Aggregators)
	if err != nil {
		return nil, err
	}

	inputEvents, err := buildInputEvents(sourceCfgs, req.Input)
	if err != nil {
		return nil, err
	}
	simulatedAt := simulatedStartTime(inputEvents)

	outputs := outputCollector{limit: runOutputLimit(req)}
	var refreshes []refreshPayload
	encoderFlushInterval := encoderBatchFlushInterval(cfg.Encoder)
	var nextEncoderFlushAt time.Time
	if encoderFlushInterval > 0 {
		nextEncoderFlushAt = simulatedAt.Add(encoderFlushInterval)
	}

	// Encoders emit raw datagrams or JSON lines. Stamping here keeps scheduled
	// control traffic and user-driven events on the same simulated timeline.
	appendPayloads := func(raw [][]byte, receivedAt time.Time) {
		if receivedAt.IsZero() {
			receivedAt = simulatedAt
		}
		for _, payload := range raw {
			if len(payload) == 0 {
				continue
			}
			data := timestampEncodedPayload(cfg.Encoder.Type, payload, receivedAt)
			outputs.Append(timedPayload{Data: data, ReceivedAt: receivedAt})
			if outputs.Done() {
				return
			}
		}
	}

	// Keep event encoding local to Run so refresh scheduling can observe the
	// control packets produced during initialization.
	encodeEvents := func(events []*event.Event, fallbackAt time.Time, controlsForRefresh bool, forceTime bool) error {
		for _, evt := range events {
			if outputs.Done() {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			stampEventTime(evt, fallbackAt, forceTime || evt == nil || evt.Kind == "control")
			out, err := enc.Encode(evt)
			if err != nil {
				return encodeEventError(cfg.Encoder, evt, err)
			}
			receivedAt := eventTimeOr(evt, fallbackAt)
			appendPayloads(out, receivedAt)
			if controlsForRefresh {
				refreshes = append(refreshes, refreshPayloads(cfg.Encoder, out, receivedAt)...)
			}
		}
		return nil
	}
	for i := range aggregateWorkers {
		item := &aggregateWorkers[i]
		alignWorkerClock(item, simulatedAt)
		if interval := item.agg.Interval(); interval > 0 {
			item.nextFlushAt = simulatedAt.Add(interval)
		}
	}

	// Replay the timer-driven parts of the normal daemon pipeline between input
	// timestamps. This keeps WASM execution finite while still producing encoder
	// refreshes, batch flushes, and periodic aggregate flushes at expected times.
	emitScheduledUntil := func(until time.Time) error {
		for {
			if outputs.Done() {
				return nil
			}
			nextRefreshIndex := -1
			nextWorkerIndex := -1
			nextEncoderFlush := false
			var nextAt time.Time
			for i, refresh := range refreshes {
				if refresh.NextAt.IsZero() || refresh.NextAt.After(until) {
					continue
				}
				if nextRefreshIndex == -1 && nextWorkerIndex == -1 && !nextEncoderFlush || refresh.NextAt.Before(nextAt) {
					nextRefreshIndex = i
					nextAt = refresh.NextAt
				}
			}
			for i := range aggregateWorkers {
				item := &aggregateWorkers[i]
				if item.nextFlushAt.IsZero() || item.nextFlushAt.After(until) {
					continue
				}
				if nextRefreshIndex == -1 && nextWorkerIndex == -1 && !nextEncoderFlush || item.nextFlushAt.Before(nextAt) {
					nextRefreshIndex = -1
					nextWorkerIndex = i
					nextEncoderFlush = false
					nextAt = item.nextFlushAt
				}
			}
			if !nextEncoderFlushAt.IsZero() && !nextEncoderFlushAt.After(until) {
				if nextRefreshIndex == -1 && nextWorkerIndex == -1 && !nextEncoderFlush || nextEncoderFlushAt.Before(nextAt) {
					nextRefreshIndex = -1
					nextWorkerIndex = -1
					nextEncoderFlush = true
					nextAt = nextEncoderFlushAt
				}
			}
			if nextRefreshIndex != -1 {
				refresh := &refreshes[nextRefreshIndex]
				data := timestampEncodedPayload(refresh.EncoderTyp, refresh.Data, refresh.NextAt)
				outputs.Append(timedPayload{Data: data, ReceivedAt: refresh.NextAt})
				refresh.NextAt = refresh.NextAt.Add(refresh.Interval)
				continue
			}
			if nextEncoderFlush {
				flushed, err := enc.Flush()
				if err != nil {
					return fmt.Errorf("flush encoder: %w", err)
				}
				appendPayloads(flushed, nextAt)
				nextEncoderFlushAt = nextEncoderFlushAt.Add(encoderFlushInterval)
				continue
			}
			if nextWorkerIndex != -1 {
				item := &aggregateWorkers[nextWorkerIndex]
				alignWorkerClock(item, nextAt)
				events, err := item.agg.Flush()
				if err != nil {
					return fmt.Errorf("flush aggregator %q: %w", item.cfg.Stream, err)
				}
				retimeWorkerEvents(events, nextAt, item.clockOffset)
				if err := encodeEvents(events, nextAt, false, true); err != nil {
					return err
				}
				item.nextFlushAt = item.nextFlushAt.Add(item.agg.Interval())
				continue
			}
			return nil
		}
	}

	// Template-based encoders need their initial control records before any data
	// record can be interpreted by downstream tooling such as WireView.
	if encoderUsesInitControls(cfg.Encoder.Type) {
		for i := range aggregateWorkers {
			item := &aggregateWorkers[i]
			initEvents, err := item.agg.InitEvents()
			if err != nil {
				return nil, fmt.Errorf("init aggregator events for %q: %w", item.cfg.Stream, err)
			}
			if err := encodeEvents(initEvents, simulatedAt, true, true); err != nil {
				return nil, err
			}
		}
		for _, sourceCfg := range sourceCfgs {
			if err := encodeEvents(sourceInitEventsAt(sourceCfg, simulatedAt), simulatedAt, true, true); err != nil {
				return nil, err
			}
		}
	}

	for _, input := range inputEvents {
		if outputs.Done() {
			break
		}
		inputAt := eventTimeOr(input, simulatedAt)
		if err := emitScheduledUntil(inputAt); err != nil {
			return nil, err
		}
		if outputs.Done() {
			break
		}
		decoded, err := decoder.Decode(input)
		if err != nil {
			return nil, fmt.Errorf("decode input: %w", err)
		}
		for _, decodedEvent := range decoded {
			if outputs.Done() {
				break
			}
			processed, err := proc.Process(decodedEvent)
			if err != nil {
				return nil, fmt.Errorf("process input: %w", err)
			}
			for _, processedEvent := range processed {
				if outputs.Done() {
					break
				}
				eventAt := eventTimeOr(processedEvent, inputAt)
				events, err := routeAggregate(aggregateWorkers, processedEvent, eventAt)
				if err != nil {
					return nil, err
				}
				if err := encodeEvents(events, eventAt, false, true); err != nil {
					return nil, err
				}
			}
		}
	}
	finalAt := simulatedEndTime(inputEvents, simulatedAt)
	if !outputs.Done() {
		if err := emitScheduledUntil(finalAt); err != nil {
			return nil, err
		}
	}
	for i := range aggregateWorkers {
		if outputs.Done() {
			break
		}
		item := &aggregateWorkers[i]
		alignWorkerClock(item, finalAt)
		events, err := item.agg.Close()
		if err != nil {
			return nil, fmt.Errorf("close aggregator %q: %w", item.cfg.Stream, err)
		}
		retimeWorkerEvents(events, finalAt, item.clockOffset)
		if err := encodeEvents(events, finalAt, false, true); err != nil {
			return nil, err
		}
	}
	if !outputs.Done() {
		flushed, err := enc.Flush()
		if err != nil {
			return nil, fmt.Errorf("flush encoder: %w", err)
		}
		appendPayloads(flushed, finalAt)
	}

	result, err := formatOutputWithOptions(cfg.Encoder.Type, outputs, len(inputEvents), req.NativeBinary)
	if err != nil {
		return nil, err
	}
	result.Stats.recordRunTiming(time.Since(runStarted), len(inputEvents))
	return result, nil
}

func (stats *RunStats) recordRunTiming(elapsed time.Duration, packets int) {
	stats.TotalElapsedNs = elapsed.Nanoseconds()
	if packets > 0 {
		stats.NsPerPacket = stats.TotalElapsedNs / int64(packets)
	}
}

func validateBrowserConfig(cfg *config.Config) error {
	if len(cfg.Sources) == 0 {
		return fmt.Errorf("browser runtime requires at least one source")
	}
	seenTypes := map[string]struct{}{}
	for i, src := range cfg.Sources {
		if src.Network != "stream" {
			return fmt.Errorf("browser runtime only supports source.network=stream for source %d, got %q", i+1, src.Network)
		}
		switch src.Type {
		case "json", "bytes", "flow", "pcap", "pcapng":
		default:
			return fmt.Errorf("browser runtime does not support source.type=%q for source %d", src.Type, i+1)
		}
		if _, ok := seenTypes[src.Type]; ok {
			return fmt.Errorf("browser runtime requires unique source.type values, got duplicate %q", src.Type)
		}
		seenTypes[src.Type] = struct{}{}
	}
	if cfg.Sink.Type != "" && cfg.Sink.Type != "stdout" {
		return fmt.Errorf("browser runtime only supports sink.type=stdout, got %q", cfg.Sink.Type)
	}
	return nil
}

func runOutputLimit(req RunRequest) int {
	if req.OutputLimit == nil {
		return 0
	}
	if *req.OutputLimit <= 0 {
		return 0
	}
	return *req.OutputLimit
}
