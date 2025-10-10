// path: src/mangle/mangle.go
package mangle

import (
	"encoding/binary"
	"net"

	"github.com/daniellavrushin/b4sni/config"
)

func ProcessPacket(cfg *config.Config, raw []byte) (Result, error) {
	if len(raw) < 20 {
		return Result{Verdict: VerdictAccept}, ErrInvalidPacket
	}

	version := raw[0] >> 4
	if version != 4 && version != 6 {
		return Result{Verdict: VerdictAccept}, ErrUnsupported
	}

	if cfg.Mangle == nil || !cfg.Mangle.Enabled {
		return Result{Verdict: VerdictAccept}, nil
	}

	switch version {
	case 4:
		return processIPv4(cfg, raw)
	case 6:
		return processIPv6(cfg, raw)
	default:
		return Result{Verdict: VerdictAccept}, nil
	}
}

func processIPv4(cfg *config.Config, raw []byte) (Result, error) {
	if len(raw) < 20 {
		return Result{Verdict: VerdictAccept}, ErrInvalidPacket
	}

	ihl := int((raw[0] & 0x0f) << 2)
	if ihl < 20 || len(raw) < ihl {
		return Result{Verdict: VerdictAccept}, ErrInvalidPacket
	}

	totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if totalLen > len(raw) {
		totalLen = len(raw)
	}

	protocol := raw[9]
	srcIP := net.IPv4(raw[12], raw[13], raw[14], raw[15])
	dstIP := net.IPv4(raw[16], raw[17], raw[18], raw[19])

	transportData := raw[ihl:totalLen]

	switch protocol {
	case 6:
		return processTCP(cfg, srcIP, dstIP, transportData, raw, 4)
	case 17:
		return processUDP(cfg, srcIP, dstIP, transportData, raw, 4)
	default:
		return Result{Verdict: VerdictAccept}, nil
	}
}

func processIPv6(cfg *config.Config, raw []byte) (Result, error) {
	if len(raw) < 40 {
		return Result{Verdict: VerdictAccept}, ErrInvalidPacket
	}

	payloadLen := int(binary.BigEndian.Uint16(raw[4:6]))
	nextHeader := raw[6]
	srcIP := net.IP(raw[8:24])
	dstIP := net.IP(raw[24:40])

	if 40+payloadLen > len(raw) {
		return Result{Verdict: VerdictAccept}, ErrInvalidPacket
	}

	transportData := raw[40 : 40+payloadLen]

	switch nextHeader {
	case 6:
		return processTCP(cfg, srcIP, dstIP, transportData, raw, 6)
	case 17:
		return processUDP(cfg, srcIP, dstIP, transportData, raw, 6)
	default:
		return Result{Verdict: VerdictAccept}, nil
	}
}

func processTCP(cfg *config.Config, srcIP, dstIP net.IP, tcpData []byte, fullPacket []byte, ipVersion int) (Result, error) {
	if len(tcpData) < 20 {
		return Result{Verdict: VerdictAccept}, ErrInvalidPacket
	}

	srcPort := binary.BigEndian.Uint16(tcpData[0:2])
	dstPort := binary.BigEndian.Uint16(tcpData[2:4])
	seqNum := binary.BigEndian.Uint32(tcpData[4:8])
	ackNum := binary.BigEndian.Uint32(tcpData[8:12])
	dataOffset := int((tcpData[12] >> 4) << 2)
	flags := tcpData[13]
	window := binary.BigEndian.Uint16(tcpData[14:16])

	if dataOffset < 20 || len(tcpData) < dataOffset {
		return Result{Verdict: VerdictAccept}, ErrInvalidPacket
	}

	payload := tcpData[dataOffset:]

	tcpPkt := TCPPacket{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Seq:      seqNum,
		Ack:      ackNum,
		Flags:    flags,
		Window:   window,
		Payload:  payload,
		Original: fullPacket,
	}

	if cfg.Mangle.TCPStrategies != nil {
		for _, strategyIface := range cfg.Mangle.TCPStrategies {
			if strategyIface == nil {
				continue
			}
			strategy, ok := strategyIface.(TCPStrategy)
			if !ok {
				continue
			}
			modifiedPkt, verdict, err := strategy.ApplyTCP(srcIP, tcpPkt)
			if err != nil {
				continue
			}
			if verdict == VerdictDrop {
				return Result{Verdict: VerdictDrop}, nil
			}
			if verdict == VerdictModify {
				modified, err := serializeTCP(modifiedPkt, ipVersion)
				if err != nil {
					return Result{Verdict: VerdictAccept}, err
				}
				return Result{Verdict: VerdictModify, Modified: modified}, nil
			}
			tcpPkt = modifiedPkt
		}
	}

	return Result{Verdict: VerdictAccept}, nil
}

func processUDP(cfg *config.Config, srcIP, dstIP net.IP, udpData []byte, fullPacket []byte, ipVersion int) (Result, error) {
	if len(udpData) < 8 {
		return Result{Verdict: VerdictAccept}, ErrInvalidPacket
	}

	srcPort := binary.BigEndian.Uint16(udpData[0:2])
	dstPort := binary.BigEndian.Uint16(udpData[2:4])
	length := binary.BigEndian.Uint16(udpData[4:6])

	if int(length) > len(udpData) {
		return Result{Verdict: VerdictAccept}, ErrInvalidPacket
	}

	payload := udpData[8:]

	udpPkt := UDPPacket{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Payload:  payload,
		Original: fullPacket,
	}

	if cfg.Mangle.UDPStrategies != nil {
		for _, strategyIface := range cfg.Mangle.UDPStrategies {
			if strategyIface == nil {
				continue
			}
			strategy, ok := strategyIface.(UDPStrategy)
			if !ok {
				continue
			}
			modifiedPkt, verdict, err := strategy.ApplyUDP(srcIP, udpPkt)
			if err != nil {
				continue
			}
			if verdict == VerdictDrop {
				return Result{Verdict: VerdictDrop}, nil
			}
			if verdict == VerdictModify {
				modified, err := serializeUDP(modifiedPkt, ipVersion)
				if err != nil {
					return Result{Verdict: VerdictAccept}, err
				}
				return Result{Verdict: VerdictModify, Modified: modified}, nil
			}
			udpPkt = modifiedPkt
		}
	}

	return Result{Verdict: VerdictAccept}, nil
}

func serializeTCP(pkt TCPPacket, ipVersion int) ([]byte, error) {
	return rebuildPacket(pkt.Original, pkt.Payload, ipVersion, 6)
}

func serializeUDP(pkt UDPPacket, ipVersion int) ([]byte, error) {
	return rebuildPacket(pkt.Original, pkt.Payload, ipVersion, 17)
}

func rebuildPacket(original []byte, newPayload []byte, ipVersion int, protocol uint8) ([]byte, error) {
	result := make([]byte, len(original)-getPayloadOffset(original, ipVersion, protocol)+len(newPayload))
	payloadOffset := getPayloadOffset(original, ipVersion, protocol)
	copy(result, original[:payloadOffset])
	copy(result[payloadOffset:], newPayload)

	if ipVersion == 4 {
		updateIPv4Length(result, len(result))
		recalcIPv4Checksum(result)
	} else {
		updateIPv6Length(result, len(result)-40)
	}

	if protocol == 6 {
		recalcTCPChecksum(result, ipVersion)
	} else if protocol == 17 {
		recalcUDPChecksum(result, ipVersion)
	}

	return result, nil
}

func getPayloadOffset(pkt []byte, ipVersion int, protocol uint8) int {
	if ipVersion == 4 {
		ihl := int((pkt[0] & 0x0f) << 2)
		if protocol == 6 && len(pkt) > ihl+12 {
			tcpOffset := int((pkt[ihl+12] >> 4) << 2)
			return ihl + tcpOffset
		} else if protocol == 17 {
			return ihl + 8
		}
	} else if ipVersion == 6 {
		if protocol == 6 && len(pkt) > 40+12 {
			tcpOffset := int((pkt[40+12] >> 4) << 2)
			return 40 + tcpOffset
		} else if protocol == 17 {
			return 40 + 8
		}
	}
	return len(pkt)
}

func updateIPv4Length(pkt []byte, length int) {
	binary.BigEndian.PutUint16(pkt[2:4], uint16(length))
}

func updateIPv6Length(pkt []byte, payloadLen int) {
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payloadLen))
}
