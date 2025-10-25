package sni

import (
	"sync"
	"time"
)

type TCPStream struct {
	buffer   []byte
	lastSeen time.Time
	sniFound bool
}

type TCPStreamKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

type TCPStreamTracker struct {
	mu      sync.RWMutex
	streams map[TCPStreamKey]*TCPStream
}

type SNIExtractor struct {
	fd         int
	TcpTracker *TCPStreamTracker
}

type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}
