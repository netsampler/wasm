//go:build js && wasm

package main

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"github.com/netsampler/reflow-wasm/wasm/reflowwasm"
)

var (
	// These values are filled by the WASM build script using -ldflags so the
	// browser can show which ReFlow runtime is currently loaded.
	reflowVersion   = "unknown"
	reflowCommit    = "unknown"
	reflowModule    = "github.com/netsampler/goflow2/v3"
	reflowBuildTime = "unknown"
	wasmRuntimeID   = "current"
)

func main() {
	done := make(chan struct{})
	var stopOnce sync.Once

	// Expose a tiny JavaScript API and then park forever. The Go WASM runtime
	// exits when main returns, which would tear down the exported js.Func.
	api := js.Global().Get("Object").New()
	runFunc := js.FuncOf(run)
	importCaptureFunc := js.FuncOf(importCapture)
	shutdownFunc := js.FuncOf(func(_ js.Value, _ []js.Value) any {
		stopOnce.Do(func() {
			js.Global().Set("reflow", js.Null())
			close(done)
			runFunc.Release()
			importCaptureFunc.Release()
		})
		return nil
	})
	api.Set("metadata", jsObject(map[string]any{
		"id":        wasmRuntimeID,
		"version":   reflowVersion,
		"commit":    reflowCommit,
		"module":    reflowModule,
		"builtAt":   reflowBuildTime,
		"userAgent": js.Global().Get("navigator").Get("userAgent").String(),
	}))
	api.Set("run", runFunc)
	api.Set("importCapture", importCaptureFunc)
	api.Set("shutdown", shutdownFunc)
	js.Global().Set("reflow", api)
	<-done
	shutdownFunc.Release()
}

// run is the syscall/js boundary. It keeps large binary payloads as typed arrays
// while the pipeline code works with typed Go structs.
func run(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errorObject("missing request")
	}
	req, err := runRequestFromJS(args[0])
	if err != nil {
		return errorObject(err.Error())
	}
	result, err := reflowwasm.Run(context.Background(), req)
	if err != nil {
		return errorObject(err.Error())
	}
	return okObject(runResultToJS(result))
}

// importCapture is the syscall/js boundary for exploding pcap and pcapng files
// into browser input entries.
func importCapture(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return errorObject("missing request")
	}
	req, err := importCaptureRequestFromJS(args[0])
	if err != nil {
		return errorObject(err.Error())
	}
	result, err := reflowwasm.ImportCapture(req)
	if err != nil {
		return errorObject(err.Error())
	}
	return okObject(importCaptureResultToJS(result))
}

func runRequestFromJS(value js.Value) (reflowwasm.RunRequest, error) {
	input := value.Get("input")
	req := reflowwasm.RunRequest{
		ConfigYAML:   stringValue(value.Get("configYaml")),
		Input:        reflowwasm.InputRequest{Mode: firstNonEmpty(stringValue(input.Get("mode")), "json")},
		NativeBinary: true,
	}
	if limit := value.Get("outputLimit"); limit.Type() == js.TypeNumber {
		outputLimit := limit.Int()
		req.OutputLimit = &outputLimit
	}
	switch req.Input.Mode {
	case "entries":
		entries, err := inputEntriesFromJS(input.Get("entries"))
		if err != nil {
			return req, err
		}
		req.Input.Entries = entries
	case "file":
		files, err := inputFilesFromJS(input.Get("files"))
		if err != nil {
			return req, err
		}
		req.Input.Files = files
	default:
		req.Input.Text = stringValue(input.Get("text"))
		req.Input.Encoding = stringValue(input.Get("encoding"))
	}
	return req, nil
}

func importCaptureRequestFromJS(value js.Value) (reflowwasm.ImportCaptureRequest, error) {
	files, err := inputFilesFromJS(value.Get("files"))
	if err != nil {
		return reflowwasm.ImportCaptureRequest{}, err
	}
	return reflowwasm.ImportCaptureRequest{
		Files:        files,
		Format:       stringValue(value.Get("format")),
		PayloadOnly:  boolValue(value.Get("payloadOnly")),
		NativeBinary: true,
	}, nil
}

func inputEntriesFromJS(value js.Value) ([]reflowwasm.InputEntry, error) {
	var entries []reflowwasm.InputEntry
	for i := 0; i < arrayLength(value); i++ {
		item := value.Index(i)
		entry := reflowwasm.InputEntry{
			Type:  stringValue(item.Get("type")),
			Label: stringValue(item.Get("label")),
		}
		if receivedAt, err := receivedAtFromJS(item.Get("receivedAt")); err != nil {
			return nil, err
		} else {
			entry.ReceivedAt = receivedAt
		}
		if strings.EqualFold(entry.Type, "json") {
			entry.JSON = json.RawMessage(jsonTextFromJS(item.Get("json")))
		} else {
			bytes, err := bytesFromJS(item.Get("bytes"))
			if err != nil {
				return nil, err
			}
			entry.Payload = bytes
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func inputFilesFromJS(value js.Value) ([]reflowwasm.InputFile, error) {
	var files []reflowwasm.InputFile
	for i := 0; i < arrayLength(value); i++ {
		item := value.Index(i)
		bytes, err := bytesFromJS(item.Get("bytes"))
		if err != nil {
			return nil, err
		}
		files = append(files, reflowwasm.InputFile{
			Name:  stringValue(item.Get("name")),
			Data:  stringValue(item.Get("data")),
			Bytes: bytes,
		})
	}
	return files, nil
}

func runResultToJS(result *reflowwasm.RunResult) js.Value {
	value := js.Global().Get("Object").New()
	value.Set("kind", result.Kind)
	value.Set("encoderType", result.EncoderType)
	value.Set("text", result.Text)
	value.Set("stats", statsToJS(result.Stats))
	payloads := js.Global().Get("Array").New()
	for _, payload := range result.Payloads {
		payloads.Call("push", outputPayloadToJS(payload))
	}
	value.Set("payloads", payloads)
	if result.WireView != nil {
		value.Set("wireview", wireViewCaptureToJS(*result.WireView))
	}
	return value
}

func importCaptureResultToJS(result *reflowwasm.ImportCaptureResult) js.Value {
	value := js.Global().Get("Object").New()
	entries := js.Global().Get("Array").New()
	for _, entry := range result.Entries {
		item := js.Global().Get("Object").New()
		item.Set("type", entry.Type)
		item.Set("payload", entry.Payload)
		item.Set("bytes", bytesToJS(entry.Bytes))
		item.Set("receivedAt", entry.ReceivedAt)
		item.Set("length", entry.Length)
		entries.Call("push", item)
	}
	value.Set("entries", entries)
	stats := js.Global().Get("Object").New()
	stats.Set("packets", result.Stats.Packets)
	stats.Set("entries", result.Stats.Entries)
	value.Set("stats", stats)
	return value
}

func outputPayloadToJS(payload reflowwasm.OutputPayload) js.Value {
	value := js.Global().Get("Object").New()
	value.Set("length", payload.Length)
	value.Set("hex", payload.Hex)
	value.Set("base64", payload.Base64)
	value.Set("bytes", bytesToJS(payload.Bytes))
	return value
}

func wireViewCaptureToJS(capture reflowwasm.WireViewCapture) js.Value {
	value := js.Global().Get("Object").New()
	value.Set("filename", capture.Filename)
	value.Set("mimeType", capture.MimeType)
	value.Set("base64", capture.Base64)
	value.Set("bytes", bytesToJS(capture.Bytes))
	value.Set("timestamps", int64ArrayToJS(capture.Timestamps))
	timeline := js.Global().Get("Array").New()
	for _, point := range capture.Timeline {
		item := js.Global().Get("Object").New()
		item.Set("timestamp", point.Timestamp)
		item.Set("type", point.Type)
		timeline.Call("push", item)
	}
	value.Set("timeline", timeline)
	return value
}

func statsToJS(stats reflowwasm.RunStats) js.Value {
	value := js.Global().Get("Object").New()
	value.Set("inputs", stats.Inputs)
	value.Set("outputs", stats.Outputs)
	value.Set("limit", stats.Limit)
	value.Set("truncated", stats.Truncated)
	value.Set("totalElapsedNs", stats.TotalElapsedNs)
	value.Set("nsPerPacket", stats.NsPerPacket)
	return value
}

func int64ArrayToJS(values []int64) js.Value {
	array := js.Global().Get("Array").New()
	for _, value := range values {
		array.Call("push", value)
	}
	return array
}

func bytesFromJS(value js.Value) ([]byte, error) {
	if value.Type() == js.TypeUndefined || value.Type() == js.TypeNull {
		return nil, nil
	}
	if value.InstanceOf(js.Global().Get("ArrayBuffer")) {
		value = js.Global().Get("Uint8Array").New(value)
	}
	length := value.Get("byteLength").Int()
	out := make([]byte, length)
	if length == 0 {
		return out, nil
	}
	copied := js.CopyBytesToGo(out, value)
	if copied != length {
		return nil, strconv.ErrSyntax
	}
	return out, nil
}

func bytesToJS(data []byte) js.Value {
	array := js.Global().Get("Uint8Array").New(len(data))
	if len(data) > 0 {
		js.CopyBytesToJS(array, data)
	}
	return array
}

func jsonTextFromJS(value js.Value) string {
	if value.Type() == js.TypeString {
		return value.String()
	}
	if value.Type() == js.TypeUndefined || value.Type() == js.TypeNull {
		return "{}"
	}
	return js.Global().Get("JSON").Call("stringify", value).String()
}

func receivedAtFromJS(value js.Value) (time.Time, error) {
	switch value.Type() {
	case js.TypeUndefined, js.TypeNull:
		return time.Time{}, nil
	case js.TypeNumber:
		return time.UnixMilli(int64(value.Float())).UTC(), nil
	case js.TypeString:
		text := strings.TrimSpace(value.String())
		if text == "" {
			return time.Time{}, nil
		}
		if unixMS, err := strconv.ParseInt(text, 10, 64); err == nil {
			return time.UnixMilli(unixMS).UTC(), nil
		}
		return time.Parse(time.RFC3339Nano, text)
	default:
		return time.Time{}, nil
	}
}

func arrayLength(value js.Value) int {
	if value.Type() == js.TypeUndefined || value.Type() == js.TypeNull {
		return 0
	}
	return value.Get("length").Int()
}

func stringValue(value js.Value) string {
	if value.Type() == js.TypeUndefined || value.Type() == js.TypeNull {
		return ""
	}
	return value.String()
}

func boolValue(value js.Value) bool {
	return value.Type() == js.TypeBoolean && value.Bool()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func okObject(result js.Value) js.Value {
	value := js.Global().Get("Object").New()
	value.Set("ok", true)
	value.Set("result", result)
	return value
}

func errorObject(message string) js.Value {
	value := js.Global().Get("Object").New()
	value.Set("ok", false)
	value.Set("error", message)
	return value
}

// jsObject creates JavaScript objects without hand-maintaining a second
// reflection layer for the small metadata and error envelopes.
func jsObject(value map[string]any) js.Value {
	data, _ := json.Marshal(value)
	return js.Global().Get("JSON").Call("parse", string(data))
}
