package goflow2wasm

import (
	"fmt"
	"strings"
)

func commandConfig(req RunRequest) (CommandConfig, error) {
	cfg := CommandConfig{
		Scheme:          firstNonEmpty(req.Options.Scheme, "flow"),
		Produce:         firstNonEmpty(req.Options.Produce, "sample"),
		Format:          firstNonEmpty(req.Options.Format, "json"),
		UseMapping:      req.Options.UseMapping,
		ProtobufFraming: req.Options.ProtobufFraming,
	}
	args, err := splitCommand(req.Command)
	if err != nil {
		return cfg, err
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "" || arg == "goflow2" {
			continue
		}
		name, value, hasInline := strings.Cut(arg, "=")
		if !strings.HasPrefix(name, "-") {
			continue
		}
		name = strings.TrimLeft(name, "-")
		if !hasInline {
			if i+1 >= len(args) {
				return cfg, fmt.Errorf("flag -%s is missing a value", name)
			}
			i++
			value = args[i]
		}
		switch name {
		case "listen":
			if scheme, _, ok := strings.Cut(value, "://"); ok && scheme != "" {
				cfg.Scheme = scheme
			}
		case "scheme":
			cfg.Scheme = value
		case "produce":
			cfg.Produce = value
		case "format":
			if value == "proto" || value == "protobuf" {
				value = "bin"
			}
			cfg.Format = value
		}
	}
	if cfg.Scheme != "flow" && cfg.Scheme != "sflow" && cfg.Scheme != "netflow" {
		return cfg, fmt.Errorf("unsupported scheme %q; use flow, sflow, or netflow", cfg.Scheme)
	}
	if cfg.Produce != "sample" && cfg.Produce != "raw" {
		return cfg, fmt.Errorf("unsupported producer %q; use sample or raw", cfg.Produce)
	}
	if cfg.Format != "json" && cfg.Format != "bin" {
		return cfg, fmt.Errorf("unsupported format %q; use json or bin", cfg.Format)
	}
	if cfg.Format == "bin" && cfg.Produce == "raw" {
		return cfg, fmt.Errorf("binary proto output requires -produce sample")
	}
	if cfg.ProtobufFraming != "" && cfg.ProtobufFraming != "delimited" {
		return cfg, fmt.Errorf("unsupported protobuf framing %q; use delimited", cfg.ProtobufFraming)
	}
	if cfg.Format != "bin" {
		cfg.ProtobufFraming = ""
	}
	return cfg, nil
}

func splitCommand(input string) ([]string, error) {
	var args []string
	var current strings.Builder
	var quote rune
	escaped := false
	for _, r := range input {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case ' ', '\t', '\n', '\r':
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if escaped {
		current.WriteRune('\\')
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in command")
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
