package reflowwasm

import (
	"fmt"
	"reflect"
	"time"
	"unsafe"

	"github.com/netsampler/goflow2/v3/pkg/reflow/aggregate"
	"github.com/netsampler/goflow2/v3/pkg/reflow/config"
	"github.com/netsampler/goflow2/v3/pkg/reflow/event"
)

func initAggregators(cfgs []config.AggregatorConfig) ([]worker, error) {
	workers := make([]worker, 0, len(cfgs))
	for _, cfg := range cfgs {
		agg, err := aggregate.New(cfg)
		if err != nil {
			return nil, fmt.Errorf("init aggregator %q: %w", cfg.Stream, err)
		}
		workers = append(workers, worker{cfg: cfg, agg: agg})
	}
	return workers, nil
}

// routeAggregate mirrors the daemon's fan-out into matching aggregators, while
// letting unmatched events continue directly to the encoder.
func routeAggregate(workers []worker, evt *event.Event, at time.Time) ([]*event.Event, error) {
	if len(workers) == 0 || evt == nil || evt.Kind == "control" {
		return []*event.Event{evt}, nil
	}
	var out []*event.Event
	matched := false
	for i := range workers {
		item := &workers[i]
		if !aggregatorMatches(item.cfg, evt) {
			continue
		}
		matched = true
		alignWorkerClock(item, at)
		events, err := item.agg.Process(evt)
		if err != nil {
			return nil, fmt.Errorf("aggregate %q: %w", item.cfg.Stream, err)
		}
		retimeWorkerEvents(events, at, item.clockOffset)
		out = append(out, events...)
	}
	if !matched {
		out = append(out, evt)
	}
	return out, nil
}

// alignWorkerClock lets aggregators that internally call time.Now behave as if
// time had advanced to the event timestamp supplied by the browser input.
func alignWorkerClock(item *worker, simulatedAt time.Time) {
	if item == nil || simulatedAt.IsZero() {
		return
	}
	offset := time.Now().Sub(simulatedAt)
	if !item.clockAligned {
		item.clockOffset = offset
		item.clockAligned = true
		return
	}
	delta := offset - item.clockOffset
	if delta == 0 {
		return
	}
	shiftAggregatorTimes(item.agg, delta)
	item.clockOffset = offset
}

// retimeWorkerEvents converts aggregate timestamps back from wall-clock values
// to the simulated clock used by the finite browser run.
func retimeWorkerEvents(events []*event.Event, at time.Time, clockOffset time.Duration) {
	if at.IsZero() {
		return
	}
	for _, evt := range events {
		if evt == nil {
			continue
		}
		evt.ReceivedAt = at.UTC()
		if evt.Aggregation == nil {
			continue
		}
		if evt.Aggregation.FirstSeenUnix != 0 {
			evt.Aggregation.FirstSeenUnix = simulatedUnixMillis(evt.Aggregation.FirstSeenUnix, clockOffset)
		}
		if evt.Aggregation.LastSeenUnix != 0 {
			evt.Aggregation.LastSeenUnix = simulatedUnixMillis(evt.Aggregation.LastSeenUnix, clockOffset)
		}
	}
}

func simulatedUnixMillis(wallMillis int64, clockOffset time.Duration) int64 {
	return time.UnixMilli(wallMillis).Add(-clockOffset).UTC().UnixMilli()
}

// shiftAggregatorTimes adjusts private aggregator state when the simulated
// clock jumps between sparse input events. The reflection is intentionally kept
// isolated here because the upstream aggregator does not expose this hook.
func shiftAggregatorTimes(agg aggregate.Aggregator, delta time.Duration) {
	if agg == nil || delta == 0 {
		return
	}
	v := reflect.ValueOf(agg)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return
	}
	v = v.Elem()
	if !v.IsValid() || !v.CanAddr() {
		return
	}
	shiftTimeField(v, "startedAt", delta)
	shiftTimeField(v, "lastPeriodicRun", delta)
	state := v.FieldByName("state")
	if !state.IsValid() || state.Kind() != reflect.Map || !state.CanAddr() {
		return
	}
	state = writableValue(state)
	for _, key := range state.MapKeys() {
		record := state.MapIndex(key)
		if !record.IsValid() {
			continue
		}
		shifted := reflect.New(record.Type()).Elem()
		shifted.Set(record)
		shiftTimeField(shifted, "FirstSeen", delta)
		shiftTimeField(shifted, "LastSeen", delta)
		state.SetMapIndex(key, shifted)
	}
}

func shiftTimeField(parent reflect.Value, name string, delta time.Duration) {
	field := parent.FieldByName(name)
	if !field.IsValid() || field.Type() != reflect.TypeOf(time.Time{}) || !field.CanAddr() {
		return
	}
	writable := writableValue(field)
	current := writable.Interface().(time.Time)
	if current.IsZero() {
		return
	}
	writable.Set(reflect.ValueOf(current.Add(delta)))
}

func writableValue(value reflect.Value) reflect.Value {
	return reflect.NewAt(value.Type(), unsafe.Pointer(value.UnsafeAddr())).Elem()
}

func aggregatorMatches(cfg config.AggregatorConfig, evt *event.Event) bool {
	for key, want := range cfg.Match {
		if eventMatchValue(evt, key) != want {
			return false
		}
	}
	return true
}

func eventMatchValue(evt *event.Event, key string) string {
	if evt == nil {
		return ""
	}
	switch key {
	case "stream":
		return evt.Stream
	case "kind":
		return evt.Kind
	case "source.type":
		return evt.Source.Type
	case "source.network":
		return evt.Source.Network
	case "source.address":
		return evt.Source.Address
	}
	if evt.Fields == nil {
		return ""
	}
	if val, ok := evt.Fields[key]; ok {
		return fmt.Sprint(val)
	}
	return ""
}
