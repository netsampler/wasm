//go:build js && wasm

package main

import (
	"encoding/json"
	"sync"
	"syscall/js"

	"github.com/netsampler/goflow2-wasm/wasm/goflow2wasm"
)

var (
	goflowVersion   = "unknown"
	goflowCommit    = "unknown"
	goflowModule    = "github.com/netsampler/goflow2/v3"
	goflowBuildTime = "unknown"
	wasmRuntimeID   = "current"
)

func main() {
	done := make(chan struct{})
	var stopOnce sync.Once

	api := js.Global().Get("Object").New()
	runFunc := js.FuncOf(run)
	inspectCaptureFunc := js.FuncOf(inspectCapture)
	shutdownFunc := js.FuncOf(func(_ js.Value, _ []js.Value) any {
		stopOnce.Do(func() {
			js.Global().Set("goflow2", js.Null())
			close(done)
			runFunc.Release()
			inspectCaptureFunc.Release()
		})
		return nil
	})
	api.Set("metadata", jsObject(map[string]any{
		"id":        wasmRuntimeID,
		"version":   goflowVersion,
		"commit":    goflowCommit,
		"module":    goflowModule,
		"builtAt":   goflowBuildTime,
		"userAgent": js.Global().Get("navigator").Get("userAgent").String(),
	}))
	api.Set("run", runFunc)
	api.Set("inspectCapture", inspectCaptureFunc)
	api.Set("shutdown", shutdownFunc)
	js.Global().Set("goflow2", api)
	<-done
	shutdownFunc.Release()
}

func run(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsObject(map[string]any{
			"ok":    false,
			"error": "missing request",
		})
	}
	raw := js.Global().Get("JSON").Call("stringify", args[0]).String()
	result, err := goflow2wasm.RunJSON([]byte(raw))
	if err != nil {
		return jsObject(map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
	}
	envelope := append([]byte(`{"ok":true,"result":`), result...)
	envelope = append(envelope, '}')
	return js.Global().Get("JSON").Call("parse", string(envelope))
}

func inspectCapture(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsObject(map[string]any{
			"ok":    false,
			"error": "missing capture",
		})
	}
	raw := js.Global().Get("JSON").Call("stringify", args[0]).String()
	result, err := goflow2wasm.InspectCaptureJSON([]byte(raw))
	if err != nil {
		return jsObject(map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
	}
	envelope := append([]byte(`{"ok":true,"result":`), result...)
	envelope = append(envelope, '}')
	return js.Global().Get("JSON").Call("parse", string(envelope))
}

func jsObject(value map[string]any) js.Value {
	data, _ := json.Marshal(value)
	return js.Global().Get("JSON").Call("parse", string(data))
}
