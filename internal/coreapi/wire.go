package coreapi

import (
	"encoding/binary"
	"math"
	"unicode/utf8"
)

// These public wire field numbers were checked against upstream 1.14.0 and
// 1.14.3. This is an independent, deliberately small protobuf wire decoder;
// neither upstream generated code nor its GPL implementation is incorporated.
type Status struct {
	Memory           uint64 `json:"memory"`
	Goroutines       int64  `json:"goroutines"`
	ConnectionsIn    int64  `json:"connections_in"`
	ConnectionsOut   int64  `json:"connections_out"`
	TrafficAvailable bool   `json:"traffic_available"`
	Uplink           int64  `json:"uplink"`
	Downlink         int64  `json:"downlink"`
	UplinkTotal      int64  `json:"uplink_total"`
	DownlinkTotal    int64  `json:"downlink_total"`
}

type Connection struct {
	ID            string `json:"id"`
	Inbound       string `json:"inbound"`
	InboundType   string `json:"inbound_type"`
	Network       string `json:"network"`
	Source        string `json:"source"`
	Destination   string `json:"destination"`
	Domain        string `json:"domain"`
	Protocol      string `json:"protocol"`
	User          string `json:"user"`
	FromOutbound  string `json:"from_outbound"`
	CreatedAt     int64  `json:"created_at"`
	ClosedAt      int64  `json:"closed_at"`
	UplinkTotal   int64  `json:"uplink_total"`
	DownlinkTotal int64  `json:"downlink_total"`
	Outbound      string `json:"outbound"`
	OutboundType  string `json:"outbound_type"`
}

type ConnectionEvent struct {
	Type          int64       `json:"type"` // 0=new, 1=update delta, 2=closed
	ID            string      `json:"id"`
	Connection    *Connection `json:"connection,omitempty"`
	UplinkDelta   int64       `json:"uplink_delta"`
	DownlinkDelta int64       `json:"downlink_delta"`
	ClosedAt      int64       `json:"closed_at"`
}

type ConnectionBatch struct {
	Events []ConnectionEvent `json:"events"`
	Reset  bool              `json:"reset"`
}

type wireField struct {
	number  int
	kind    byte
	integer uint64
	data    []byte
}

func fields(data []byte, visit func(wireField) error) error {
	for len(data) > 0 {
		tag, used := binary.Uvarint(data)
		if used <= 0 || tag>>3 == 0 || tag>>3 > (1<<29)-1 {
			return ErrProtocol
		}
		data = data[used:]
		f := wireField{number: int(tag >> 3), kind: byte(tag & 7)}
		switch f.kind {
		case 0:
			f.integer, used = binary.Uvarint(data)
			if used <= 0 {
				return ErrProtocol
			}
			data = data[used:]
		case 1:
			if len(data) < 8 {
				return ErrProtocol
			}
			data = data[8:]
		case 2:
			length, used := binary.Uvarint(data)
			if used <= 0 || length > uint64(len(data)-used) {
				return ErrProtocol
			}
			data = data[used:]
			f.data = data[:int(length)]
			data = data[int(length):]
		case 5:
			if len(data) < 4 {
				return ErrProtocol
			}
			data = data[4:]
		default:
			return ErrProtocol
		}
		if err := visit(f); err != nil {
			return err
		}
	}
	return nil
}

func nonnegative(f wireField) (int64, error) {
	if f.kind != 0 || f.integer > math.MaxInt64 {
		return 0, ErrProtocol
	}
	return int64(f.integer), nil
}
func textField(f wireField) (string, error) {
	if f.kind != 2 || !utf8.Valid(f.data) {
		return "", ErrProtocol
	}
	return string(f.data), nil
}
func appendVarint(data []byte, value uint64) []byte { return binary.AppendUvarint(data, value) }

func decodeStatus(data []byte) (result Status, err error) {
	err = fields(data, func(f wireField) error {
		if f.number < 1 || f.number > 9 {
			return nil
		}
		if f.kind != 0 {
			return ErrProtocol
		}
		if f.number == 1 {
			result.Memory = f.integer
			return nil
		}
		v, err := nonnegative(f)
		if err != nil {
			return err
		}
		switch f.number {
		case 2:
			result.Goroutines = v
		case 3:
			result.ConnectionsIn = v
		case 4:
			result.ConnectionsOut = v
		case 5:
			result.TrafficAvailable = v != 0
		case 6:
			result.Uplink = v
		case 7:
			result.Downlink = v
		case 8:
			result.UplinkTotal = v
		case 9:
			result.DownlinkTotal = v
		}
		return nil
	})
	return
}

func decodeConnectionBatch(data []byte) (result ConnectionBatch, err error) {
	err = fields(data, func(f wireField) error {
		switch f.number {
		case 1:
			if f.kind != 2 || len(result.Events) >= 16384 {
				return ErrProtocol
			}
			event, err := decodeConnectionEvent(f.data)
			if err != nil {
				return err
			}
			result.Events = append(result.Events, event)
		case 2:
			v, err := nonnegative(f)
			if err != nil {
				return err
			}
			result.Reset = v != 0
		}
		return nil
	})
	return
}

func decodeConnectionEvent(data []byte) (result ConnectionEvent, err error) {
	err = fields(data, func(f wireField) error {
		switch f.number {
		case 1, 4, 5, 6:
			v, err := nonnegative(f)
			if err != nil {
				return err
			}
			switch f.number {
			case 1:
				result.Type = v
			case 4:
				result.UplinkDelta = v
			case 5:
				result.DownlinkDelta = v
			case 6:
				result.ClosedAt = v
			}
		case 2:
			var err error
			result.ID, err = textField(f)
			return err
		case 3:
			if f.kind != 2 {
				return ErrProtocol
			}
			connection, err := decodeConnection(f.data)
			if err != nil {
				return err
			}
			result.Connection = &connection
		}
		return nil
	})
	if err == nil && (result.Type > 2 || result.ID == "" || result.Connection != nil && result.Connection.ID != result.ID) {
		err = ErrProtocol
	}
	return
}

func decodeConnection(data []byte) (result Connection, err error) {
	err = fields(data, func(f wireField) error {
		switch f.number {
		case 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 19, 20:
			v, err := textField(f)
			if err != nil {
				return err
			}
			switch f.number {
			case 1:
				result.ID = v
			case 2:
				result.Inbound = v
			case 3:
				result.InboundType = v
			case 5:
				result.Network = v
			case 6:
				result.Source = v
			case 7:
				result.Destination = v
			case 8:
				result.Domain = v
			case 9:
				result.Protocol = v
			case 10:
				result.User = v
			case 11:
				result.FromOutbound = v
			case 19:
				result.Outbound = v
			case 20:
				result.OutboundType = v
			}
		case 12, 13, 16, 17:
			v, err := nonnegative(f)
			if err != nil {
				return err
			}
			switch f.number {
			case 12:
				result.CreatedAt = v
			case 13:
				result.ClosedAt = v
			case 16:
				result.UplinkTotal = v
			case 17:
				result.DownlinkTotal = v
			}
		}
		return nil
	})
	return
}
