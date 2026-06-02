package reflowwasm

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// formatOutput chooses the JSON or binary response shape expected by the
// frontend and attaches WireView capture data when the encoder can be inspected.
func formatOutput(encoderType string, outputs outputCollector, inputs int) (*RunResult, error) {
	return formatOutputWithOptions(encoderType, outputs, inputs, false)
}

func formatOutputWithOptions(encoderType string, outputs outputCollector, inputs int, nativeBinary bool) (*RunResult, error) {
	payloads := outputs.payloads
	if encoderType == "" || encoderType == "json" {
		lines := make([]string, 0, len(payloads))
		for _, payload := range payloads {
			lines = append(lines, string(payload.Data))
		}
		return &RunResult{
			Kind:        "json",
			EncoderType: encoderType,
			Text:        strings.Join(lines, "\n"),
			Stats:       outputs.Stats(inputs),
		}, nil
	}
	out := make([]OutputPayload, 0, len(payloads))
	for _, payload := range payloads {
		item := OutputPayload{
			Length: len(payload.Data),
		}
		if nativeBinary {
			item.Bytes = append([]byte(nil), payload.Data...)
		} else {
			item.Hex = hex.EncodeToString(payload.Data)
			item.Base64 = base64.StdEncoding.EncodeToString(payload.Data)
		}
		out = append(out, item)
	}
	capture, err := wireViewCapture(encoderType, payloads, nativeBinary)
	if err != nil {
		return nil, err
	}
	return &RunResult{
		Kind:        "bytes",
		EncoderType: encoderType,
		Payloads:    out,
		WireView:    capture,
		Stats:       outputs.Stats(inputs),
	}, nil
}
