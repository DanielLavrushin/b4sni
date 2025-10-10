package mangle

import (
	"errors"
	"net"
)

type Verdict int

const (
	VerdictAccept Verdict = iota
	VerdictDrop
	VerdictModify
)

type Result struct {
	Verdict  Verdict
	Modified []byte
}

var (
	ErrInvalidPacket = errors.New("invalid packet structure")
	ErrUnsupported   = errors.New("unsupported protocol")
	ErrNoPayload     = errors.New("no payload found")
)

type TCPPacket struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Seq      uint32
	Ack      uint32
	Flags    uint8
	Window   uint16
	Payload  []byte
	Original []byte
}

type UDPPacket struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Payload  []byte
	Original []byte
}
