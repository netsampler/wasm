package reflowwasm

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/netsampler/goflow2/v3/pkg/reflow/config"
	"github.com/netsampler/goflow2/v3/pkg/reflow/event"
)

type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// readPcapEvents turns uploaded pcap or pcapng files into byte-stream source
// events while preserving packet timestamps and link-layer metadata.
func readPcapEvents(src config.SourceConfig, chunks [][]byte, label string, ng bool) ([]*event.Event, error) {
	var out []*event.Event
	for _, chunk := range chunks {
		reader := bytes.NewReader(chunk)
		if ng {
			ngReader, err := pcapgo.NewNgReader(reader, pcapgo.NgReaderOptions{WantMixedLinkType: true})
			if err != nil {
				return nil, fmt.Errorf("open %s as pcapng: %w", label, err)
			}
			events, err := readPacketEvents(src, ngReader, 0)
			if err != nil {
				return nil, err
			}
			out = append(out, events...)
			continue
		}
		pcapReader, err := pcapgo.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("open %s as pcap: %w", label, err)
		}
		events, err := readPacketEvents(src, pcapReader, pcapReader.LinkType())
		if err != nil {
			return nil, err
		}
		out = append(out, events...)
	}
	return out, nil
}

func readPacketEvents(src config.SourceConfig, reader packetReader, defaultLink layers.LinkType) ([]*event.Event, error) {
	var events []*event.Event
	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				return events, nil
			}
			return nil, fmt.Errorf("read packet: %w", err)
		}
		linkType := defaultLink
		if len(ci.AncillaryData) > 0 {
			if typed, ok := ci.AncillaryData[0].(layers.LinkType); ok {
				linkType = typed
			}
		}
		receivedAt := ci.Timestamp.UTC()
		if receivedAt.IsZero() {
			receivedAt = time.Now().UTC()
		}
		fields := map[string]any{
			"capture_length":      ci.CaptureLength,
			"wire_length":         ci.Length,
			"pcap_link_type":      uint32(linkType),
			"pcap_link_type_name": linkType.String(),
			"stream_type":         src.Type,
		}
		if protocol := sampledHeaderProtocol(linkType, data); protocol != 0 {
			fields["header_protocol"] = protocol
			fields["protocol"] = protocol
		}
		events = append(events, &event.Event{
			ReceivedAt: receivedAt,
			Source:     sourceMetadata(src, "bytes"),
			Payload:    append([]byte(nil), data...),
			Fields:     fields,
		})
	}
}

func sampledHeaderProtocol(linkType layers.LinkType, data []byte) uint32 {
	switch linkType {
	case layers.LinkTypeEthernet:
		return 1
	case layers.LinkTypeIPv4:
		return 11
	case layers.LinkTypeIPv6:
		return 12
	case layers.LinkTypeRaw:
		if len(data) == 0 {
			return 0
		}
		switch data[0] >> 4 {
		case 4:
			return 11
		case 6:
			return 12
		}
	}
	return 0
}
