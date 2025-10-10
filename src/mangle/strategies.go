package mangle

import (
	"net"
)

type TCPStrategy interface {
	ApplyTCP(ip net.IP, pkt TCPPacket) (TCPPacket, Verdict, error)
}

type UDPStrategy interface {
	ApplyUDP(ip net.IP, pkt UDPPacket) (UDPPacket, Verdict, error)
}

type NoOpTCPStrategy struct{}

func (s *NoOpTCPStrategy) ApplyTCP(ip net.IP, pkt TCPPacket) (TCPPacket, Verdict, error) {
	return pkt, VerdictAccept, nil
}

type NoOpUDPStrategy struct{}

func (s *NoOpUDPStrategy) ApplyUDP(ip net.IP, pkt UDPPacket) (UDPPacket, Verdict, error) {
	return pkt, VerdictAccept, nil
}

type DropAllTCPStrategy struct{}

func (s *DropAllTCPStrategy) ApplyTCP(ip net.IP, pkt TCPPacket) (TCPPacket, Verdict, error) {
	return pkt, VerdictDrop, nil
}

type DropAllUDPStrategy struct{}

func (s *DropAllUDPStrategy) ApplyUDP(ip net.IP, pkt UDPPacket) (UDPPacket, Verdict, error) {
	return pkt, VerdictDrop, nil
}
