package goflow2wasm

import (
	"strings"
	"testing"
)

func TestCommandConfigUseMappingOptionEnablesMapping(t *testing.T) {
	cfg, err := commandConfig(RunRequest{
		Command: "goflow2 -listen flow://pcap -produce sample -format json",
		Options: RunOptions{UseMapping: true},
	})
	if err != nil {
		t.Fatalf("command config: %v", err)
	}
	if !cfg.UseMapping {
		t.Fatalf("expected mapping to be enabled")
	}
}

func TestCommandConfigMappingFlagDoesNotEnableMapping(t *testing.T) {
	cfg, err := commandConfig(RunRequest{
		Command: "goflow2 -listen flow://pcap -produce sample -format json -mapping mapping.yaml",
	})
	if err != nil {
		t.Fatalf("command config: %v", err)
	}
	if cfg.UseMapping {
		t.Fatalf("expected mapping to be disabled")
	}
}

func TestCommandConfigMappingFalseFlagDoesNotDisableMappingOption(t *testing.T) {
	cfg, err := commandConfig(RunRequest{
		Command: "goflow2 -listen flow://pcap -produce sample -format json -mapping=false",
		Options: RunOptions{UseMapping: true},
	})
	if err != nil {
		t.Fatalf("command config: %v", err)
	}
	if !cfg.UseMapping {
		t.Fatalf("expected mapping to stay enabled")
	}
}

func TestNewProducerSkipsInvalidMappingWhenDisabled(t *testing.T) {
	prod, err := newProducer(CommandConfig{Produce: "sample"}, "not: [valid")
	if err != nil {
		t.Fatalf("new producer: %v", err)
	}
	prod.Close()
}

func TestNewProducerLoadsMappingWhenEnabled(t *testing.T) {
	prod, err := newProducer(CommandConfig{Produce: "sample", UseMapping: true}, "not: [valid")
	if err == nil {
		prod.Close()
		t.Fatalf("expected invalid mapping error")
	}
	if !strings.Contains(err.Error(), "load mapping") {
		t.Fatalf("expected load mapping error, got %v", err)
	}
}

func TestNewProducerLoadsDefaultMappingWithFlowDirection(t *testing.T) {
	const mappingYAML = `formatter:
  fields:
    - type
    - time_received_ns
    - sequence_num
    - sampling_rate
    - flow_direction
    - sampler_address
    - time_flow_start_ns
    - time_flow_end_ns
    - bytes
    - packets
    - src_addr
    - dst_addr
    - proto
    - src_port
    - dst_port
    - in_if
    - out_if
  key:
    - sampler_address
  protobuf:
    - name: flow_direction
      index: 42
      type: varint
  render:
    time_received_ns: datetimenano
ipfix:
  mapping:
    - field: 61
      destination: flow_direction
netflowv9:
  mapping:
    - field: 61
      destination: flow_direction
`
	prod, err := newProducer(CommandConfig{Produce: "sample", UseMapping: true}, mappingYAML)
	if err != nil {
		t.Fatalf("new producer: %v", err)
	}
	prod.Close()
}
